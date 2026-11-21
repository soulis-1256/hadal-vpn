use std::ffi::CString;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::watch;

use hadal_core::{DaemonRequest, DaemonResponse, Result};

use super::controller::DaemonController;

/// Process newline-delimited JSON IPC requests over any async read/write stream.
pub async fn handle_ipc_stream<R, W>(
    reader: R,
    mut writer: W,
    controller: Arc<DaemonController>,
    shutdown_tx: watch::Sender<bool>,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut lines = BufReader::new(reader).lines();

    while let Some(line) = lines.next_line().await? {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let resp = match serde_json::from_str::<DaemonRequest>(trimmed) {
            Ok(req) => controller.dispatch_request(req, Some(&shutdown_tx)).await,
            Err(e) => DaemonResponse::Error {
                message: format!("Invalid JSON request: {e}"),
            },
        };

        let mut out = serde_json::to_string(&resp)?;
        out.push('\n');
        writer.write_all(out.as_bytes()).await?;
        writer.flush().await?;
    }

    Ok(())
}

pub fn configure_socket_permissions(path: &Path, group_name: &str) {
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660));
    if let Ok(c_group) = CString::new(group_name) {
        unsafe {
            let grp = libc::getgrnam(c_group.as_ptr());
            if !grp.is_null() {
                let gid = (*grp).gr_gid;
                if let Ok(c_path) = CString::new(path.to_string_lossy().as_bytes()) {
                    let _ = libc::chown(c_path.as_ptr(), u32::MAX, gid);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use futures_util::future::BoxFuture;
    use hadal_core::{PingStats, TunnelState, WanGamingProbe};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    use crate::daemon::DaemonBackends;
    use crate::net::control::ControlBackend;
    use crate::net::dns::DnsBackend;
    use crate::net::firewall::{FirewallBackend, FirewallSpec};
    use crate::net::probe::TunnelProber;
    use crate::net::routing::{RoutingBackend, RoutingConfig};
    use crate::net::sock_diag::SockDiagBackend;
    use crate::net::wireguard::{WgPeerConfig, WgTelemetry, WireGuardBackend};

    struct NoopWg;
    impl WireGuardBackend for NoopWg {
        fn ensure_interface<'a>(&'a self, _i: &'a str, _a: &'a str, _m: u16) -> BoxFuture<'a, Result<u32>> { Box::pin(async { Ok(1) }) }
        fn delete_interface<'a>(&'a self, _i: &'a str) -> BoxFuture<'a, Result<()>> { Box::pin(async { Ok(()) }) }
        fn get_ifindex<'a>(&'a self, _i: &'a str) -> BoxFuture<'a, Result<Option<u32>>> { Box::pin(async { Ok(None) }) }
        fn apply_config(&self, _cfg: &WgPeerConfig) -> Result<()> { Ok(()) }
        fn read_telemetry(&self, _iface: &str) -> Option<WgTelemetry> { None }
    }
    struct NoopFw;
    impl FirewallBackend for NoopFw {
        fn apply_firewall(&self, _spec: &FirewallSpec) -> Result<()> { Ok(()) }
        fn clear_firewall(&self) -> Result<()> { Ok(()) }
    }
    struct NoopRt;
    impl RoutingBackend for NoopRt {
        fn configure_routing<'a>(&'a self, _cfg: &'a RoutingConfig) -> BoxFuture<'a, Result<()>> { Box::pin(async { Ok(()) }) }
        fn teardown_routing(&self) -> BoxFuture<'_, Result<()>> { Box::pin(async { Ok(()) }) }
        fn add_host_route(&self, _ifindex: u32, _dest: Ipv4Addr) -> BoxFuture<'_, Result<()>> { Box::pin(async { Ok(()) }) }
    }
    struct NoopDns;
    impl DnsBackend for NoopDns {
        fn apply_dns<'a>(&'a self, _i: u32, _s: &'a [Ipv4Addr]) -> BoxFuture<'a, Result<()>> { Box::pin(async { Ok(()) }) }
        fn revert_dns(&self, _i: Option<u32>) -> BoxFuture<'_, Result<()>> { Box::pin(async { Ok(()) }) }
    }
    struct NoopDiag;
    impl SockDiagBackend for NoopDiag {
        fn reset_app_sockets(&self, _pids: &[u32]) -> usize { 0 }
    }
    struct NoopCtrl;
    impl ControlBackend for NoopCtrl {
        fn http_fetch<'a>(&'a self, _m: &'a str, _u: &'a str, _h: &'a [(String, String)], _b: Option<Vec<u8>>) -> BoxFuture<'a, Result<(u16, Vec<u8>)>> { Box::pin(async { Ok((200, Vec::new())) }) }
        fn prepare_endpoint<'a>(&'a self, _d: &'a str, _p: bool) -> BoxFuture<'a, Result<(String, Option<u16>)>> { Box::pin(async { Ok(("1.2.3.4".into(), None)) }) }
        fn probe_wan_gaming<'a>(&'a self, _t: &'a str, _d: &'a [String]) -> BoxFuture<'a, Result<WanGamingProbe>> {
            Box::pin(async { Ok(WanGamingProbe { baseline_direct: None, wan_pmtu: 1492, game_cidrs: vec![], endpoints: vec![] }) })
        }
    }
    struct NoopProber;
    impl TunnelProber for NoopProber {
        fn measure_icmp_on_iface<'a>(&'a self, _i: &'a str, _t: &'a str, _c: u32) -> BoxFuture<'a, Option<PingStats>> { Box::pin(async { None }) }
    }

    #[tokio::test]
    async fn handle_ipc_stream_processes_status_invalid_json_and_shutdown() {
        let ctrl = Arc::new(DaemonController::new(
            "hadal-wg".into(),
            DaemonBackends {
                wg: Arc::new(NoopWg),
                firewall: Arc::new(NoopFw),
                routing: Arc::new(NoopRt),
                dns: Arc::new(NoopDns),
                sock_diag: Arc::new(NoopDiag),
                control: Arc::new(NoopCtrl),
                prober: Arc::new(NoopProber),
            },
        ));
        let (tx, rx) = watch::channel(false);
        let (client_stream, server_stream) = tokio::io::duplex(4096);
        let (srv_r, srv_w) = tokio::io::split(server_stream);
        let srv_task = tokio::spawn(handle_ipc_stream(srv_r, srv_w, ctrl, tx));

        let (cli_r, mut cli_w) = tokio::io::split(client_stream);
        let mut cli_lines = BufReader::new(cli_r).lines();

        cli_w.write_all(b"\n{\"op\":\"status\"}\n").await.unwrap();
        let line1 = cli_lines.next_line().await.unwrap().unwrap();
        let resp1: DaemonResponse = serde_json::from_str(&line1).unwrap();
        assert!(matches!(resp1, DaemonResponse::Status(st) if st.state == TunnelState::Disconnected));

        cli_w.write_all(b"not json\n").await.unwrap();
        let line2 = cli_lines.next_line().await.unwrap().unwrap();
        let resp2: DaemonResponse = serde_json::from_str(&line2).unwrap();
        assert!(matches!(resp2, DaemonResponse::Error { message } if message.contains("Invalid JSON")));

        cli_w.write_all(b"{\"op\":\"shutdown\"}\n").await.unwrap();
        let line3 = cli_lines.next_line().await.unwrap().unwrap();
        let resp3: DaemonResponse = serde_json::from_str(&line3).unwrap();
        assert!(matches!(resp3, DaemonResponse::Ok));
        assert!(*rx.borrow());

        cli_w.shutdown().await.unwrap();
        drop(cli_w);
        drop(cli_lines);
        srv_task.await.unwrap().unwrap();
    }
}
