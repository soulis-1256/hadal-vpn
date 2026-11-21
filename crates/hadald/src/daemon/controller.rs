use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::sync::{watch, Mutex};
use tracing::{error, info, warn};

use hadal_core::{
    ConnectSpec, DaemonRequest, DaemonResponse, DaemonStatus, Result, HadalError, SplitMode,
    SplitTunnelConfig, TunnelState, VerifiedTunnelResult, VerifyTarget,
};

use super::DaemonBackends;
use crate::net::firewall::FirewallSpec;
use crate::net::routing::RoutingConfig;
use crate::net::wireguard::WgPeerConfig;

const PROBE_IFACE: &str = "hadal-probe";

struct DaemonInner {
    iface: String,
    status: DaemonStatus,
    endpoint_ip: Option<Ipv4Addr>,
    endpoint_port: u16,
}

impl DaemonInner {
    fn firewall_spec(&self, tunnel_active: bool) -> FirewallSpec {
        FirewallSpec {
            wg_iface: self.iface.clone(),
            endpoint_ip: self.endpoint_ip,
            endpoint_port: self.endpoint_port,
            killswitch: self.status.killswitch,
            ipv6_block: self.status.ipv6_block,
            bypass_lan: self.status.bypass_lan,
            split_mode: self.status.split_mode,
            split_cgroup_paths: self.status.split_cgroup_paths.clone(),
            game_only_cidrs: self.status.game_only_cidrs.clone(),
            tunnel_active,
        }
    }

    fn clear_tunnel_metadata(&mut self) {
        self.endpoint_ip = None;
        self.status.cluster_id = None;
        self.status.domain = None;
        self.status.endpoint = None;
        self.status.location = None;
        self.status.country = None;
        self.status.address = None;
        self.status.mtu = None;
        self.status.dns.clear();
        self.status.game_only_cidrs.clear();
        self.status.rx_bytes = 0;
        self.status.tx_bytes = 0;
        self.status.last_handshake_epoch = None;
    }
}

/// Orchestrates tunnel lifecycle, killswitch/firewall invariants, split-tunneling, and control-plane IPC.
pub struct DaemonController {
    state: Arc<Mutex<DaemonInner>>,
    probe_lock: Arc<Mutex<()>>,
    probe_cancelled: Arc<AtomicBool>,
    backends: DaemonBackends,
}

impl DaemonController {
    pub fn new(iface: String, backends: DaemonBackends) -> Self {
        Self {
            state: Arc::new(Mutex::new(DaemonInner {
                iface: iface.clone(),
                status: DaemonStatus {
                    interface: iface,
                    split_mode: SplitMode::Off,
                    ..Default::default()
                },
                endpoint_ip: None,
                endpoint_port: 51820,
            })),
            probe_lock: Arc::new(Mutex::new(())),
            probe_cancelled: Arc::new(AtomicBool::new(false)),
            backends,
        }
    }

    pub async fn status(&self) -> DaemonStatus {
        let mut guard = self.state.lock().await;
        self.refresh_telemetry_locked(&mut guard).await;
        guard.status.clone()
    }

    pub async fn connect(&self, spec: ConnectSpec) -> Result<DaemonStatus> {
        let endpoint_ip: Ipv4Addr = spec.endpoint_ip.parse().map_err(|e| {
            HadalError::WireGuard(format!("Invalid endpoint IP '{}': {e}", spec.endpoint_ip))
        })?;
        let dns_ips: Vec<Ipv4Addr> = spec
            .dns
            .iter()
            .filter_map(|s| s.trim().parse::<Ipv4Addr>().ok())
            .collect();

        // Cancel any background gaming tunnel verification before transitioning into Connecting.
        self.probe_cancelled.store(true, Ordering::SeqCst);

        let mut guard = self.state.lock().await;
        let prev_status = guard.status.clone();
        let prev_endpoint_ip = guard.endpoint_ip;
        let prev_endpoint_port = guard.endpoint_port;

        guard.status.state = TunnelState::Connecting;
        guard.status.last_error = None;
        guard.status.killswitch = spec.killswitch;
        guard.status.ipv6_block = spec.ipv6_block;
        guard.status.bypass_lan = spec.bypass_lan;
        guard.status.split_mode = spec.split_mode;
        guard.status.split_cgroup_paths = spec.split_cgroup_paths.clone();
        guard.status.game_only_cidrs = spec.game_only_cidrs.clone();
        guard.endpoint_ip = Some(endpoint_ip);
        guard.endpoint_port = spec.endpoint_port;

        // Fail-closed: arm firewall killswitch BEFORE bringing up/rebuilding tunnel.
        if spec.killswitch || spec.ipv6_block {
            if let Err(err) = self
                .backends
                .firewall
                .apply_firewall(&guard.firewall_spec(false))
            {
                guard.status = prev_status;
                guard.endpoint_ip = prev_endpoint_ip;
                guard.endpoint_port = prev_endpoint_port;
                guard.status.last_error = Some(err.to_string());
                return Err(err);
            }
        }

        let iface = guard.iface.clone();
        let fw_active_spec = guard.firewall_spec(true);
        let setup_res: Result<()> = async {
            let ifindex = self
                .backends
                .wg
                .ensure_interface(&iface, &spec.address, spec.mtu)
                .await?;
            // Arm routing + mangle_in BEFORE apply_config sends the first handshake packet
            // so strict rp_filter=1 never drops the handshake response in a race.
            let routing_cfg = RoutingConfig {
                ifindex,
                split_mode: spec.split_mode,
                bypass_lan: spec.bypass_lan,
                game_only_cidrs: spec.game_only_cidrs.clone(),
                dns_ips: dns_ips.clone(),
            };
            self.backends.routing.configure_routing(&routing_cfg).await?;
            self.backends.dns.apply_dns(ifindex, &dns_ips).await?;
            self.backends.firewall.apply_firewall(&fw_active_spec)?;
            self.backends.wg.apply_config(&WgPeerConfig {
                iface: iface.clone(),
                priv_key_b64: spec.priv_key.clone(),
                peer_pub_key_b64: spec.pub_key.clone(),
                endpoint_ip,
                endpoint_port: spec.endpoint_port,
                allowed_cidrs: spec.game_only_cidrs.clone(),
                dns_ips: dns_ips.clone(),
            })?;
            Ok(())
        }
        .await;

        if let Err(err) = setup_res {
            error!("Connect failed: {err}");
            self.cleanup_tunnel_only_locked(&guard.iface).await;
            guard.clear_tunnel_metadata();
            guard.status.last_error = Some(err.to_string());
            if guard.status.killswitch {
                guard.status.state = TunnelState::KillswitchLocked;
                let _ = self
                    .backends
                    .firewall
                    .apply_firewall(&guard.firewall_spec(false));
            } else {
                guard.status.split_mode = prev_status.split_mode;
                guard.status.split_cgroup_paths = prev_status.split_cgroup_paths;
                guard.status.bypass_lan = prev_status.bypass_lan;
                guard.status.ipv6_block = prev_status.ipv6_block;
                guard.status.state = TunnelState::Disconnected;
                let _ = self.backends.firewall.clear_firewall();
            }
            return Err(err);
        }

        guard.status.state = TunnelState::Protected;
        guard.status.cluster_id = spec.cluster_id;
        guard.status.domain = Some(spec.domain);
        guard.status.endpoint = Some(format!("{endpoint_ip}:{}", spec.endpoint_port));
        guard.status.location = spec.location;
        guard.status.country = spec.country;
        guard.status.address = Some(spec.address);
        guard.status.mtu = Some(spec.mtu);
        guard.status.dns = spec.dns;
        self.refresh_telemetry_locked(&mut guard).await;

        info!(
            "Tunnel protected via {} ({})",
            guard.status.endpoint.as_deref().unwrap_or("-"),
            guard.iface
        );
        Ok(guard.status.clone())
    }

    pub async fn disconnect(&self, keep_killswitch: bool) -> Result<DaemonStatus> {
        self.probe_cancelled.store(true, Ordering::SeqCst);
        let mut guard = self.state.lock().await;
        let iface = guard.iface.clone();
        self.cleanup_tunnel_only_locked(&iface).await;
        guard.clear_tunnel_metadata();
        guard.status.last_error = None;
        guard.status.killswitch = keep_killswitch;

        if keep_killswitch {
            self.backends
                .firewall
                .apply_firewall(&guard.firewall_spec(false))?;
            guard.status.state = TunnelState::KillswitchLocked;
            info!("Disconnected with killswitch locked");
        } else {
            let _ = self.backends.firewall.clear_firewall();
            guard.status.state = TunnelState::Disconnected;
            info!("Disconnected cleanly (firewall cleared)");
        }
        Ok(guard.status.clone())
    }

    pub async fn set_killswitch(
        &self,
        enabled: bool,
        ipv6_block: bool,
        bypass_lan: bool,
    ) -> Result<DaemonStatus> {
        if enabled {
            self.probe_cancelled.store(true, Ordering::SeqCst);
        }
        let mut guard = self.state.lock().await;
        guard.status.killswitch = enabled;
        guard.status.ipv6_block = ipv6_block;
        guard.status.bypass_lan = bypass_lan;

        let tunnel_active = guard.status.state == TunnelState::Protected;
        if !tunnel_active {
            guard.status.state = if enabled {
                TunnelState::KillswitchLocked
            } else {
                TunnelState::Disconnected
            };
        }
        self.backends
            .firewall
            .apply_firewall(&guard.firewall_spec(tunnel_active))?;
        Ok(guard.status.clone())
    }

    pub async fn update_split_tunnel(&self, cfg: SplitTunnelConfig) -> Result<DaemonStatus> {
        let mut guard = self.state.lock().await;
        if guard.status.split_mode == cfg.mode
            && guard.status.split_cgroup_paths == cfg.cgroup_paths
            && guard.status.game_only_cidrs == cfg.game_only_cidrs
        {
            return Ok(guard.status.clone());
        }

        guard.status.split_mode = cfg.mode;
        guard.status.split_cgroup_paths = cfg.cgroup_paths;
        guard.status.game_only_cidrs = cfg.game_only_cidrs;

        let tunnel_active = guard.status.state == TunnelState::Protected;
        if tunnel_active {
            let dns_ips: Vec<Ipv4Addr> = guard
                .status
                .dns
                .iter()
                .filter_map(|s| s.trim().parse::<Ipv4Addr>().ok())
                .collect();
            if let Some(ifindex) = self.backends.wg.get_ifindex(&guard.iface).await? {
                let routing_cfg = RoutingConfig {
                    ifindex,
                    split_mode: guard.status.split_mode,
                    bypass_lan: guard.status.bypass_lan,
                    game_only_cidrs: guard.status.game_only_cidrs.clone(),
                    dns_ips,
                };
                self.backends.routing.configure_routing(&routing_cfg).await?;
            }
        }
        self.backends
            .firewall
            .apply_firewall(&guard.firewall_spec(tunnel_active))?;
        Ok(guard.status.clone())
    }

    pub fn reset_app_sockets(&self, pids: &[u32]) -> usize {
        let closed = self.backends.sock_diag.reset_app_sockets(pids);
        info!(
            "Reset {closed} stale socket(s) across {} moved PID(s)",
            pids.len()
        );
        closed
    }

    pub async fn verify_gaming_tunnels(
        &self,
        target_ip: String,
        priv_key: String,
        address: String,
        mtu: u16,
        targets: Vec<VerifyTarget>,
        samples: Option<u32>,
    ) -> Result<Vec<VerifiedTunnelResult>> {
        if self.state.lock().await.status.state != TunnelState::Disconnected {
            return Ok(Vec::new());
        }
        let target_ipv4: Ipv4Addr = target_ip.parse().map_err(|e| {
            HadalError::WireGuard(format!("Invalid probe target IP '{target_ip}': {e}"))
        })?;
        let sample_count = samples.unwrap_or(4).clamp(2, 16);

        let _probe_guard = self.probe_lock.lock().await;
        if self.state.lock().await.status.state != TunnelState::Disconnected {
            return Ok(Vec::new());
        }
        self.probe_cancelled.store(false, Ordering::SeqCst);

        let _ = self.backends.wg.delete_interface(PROBE_IFACE).await;
        let ifindex = self
            .backends
            .wg
            .ensure_interface(PROBE_IFACE, &address, mtu)
            .await?;

        let probe_res: Result<Vec<VerifiedTunnelResult>> = async {
            self.backends
                .routing
                .add_host_route(ifindex, target_ipv4)
                .await?;

            let allowed = vec![format!("{target_ipv4}/32")];
            let dst = target_ipv4.to_string();
            let mut results = Vec::new();
            for target in targets.into_iter().take(16) {
                if self.probe_cancelled.load(Ordering::SeqCst)
                    || self.state.lock().await.status.state != TunnelState::Disconnected
                {
                    break;
                }
                let Ok(ep_ip) = target.endpoint_ip.parse::<Ipv4Addr>() else {
                    continue;
                };
                if self
                    .backends
                    .wg
                    .apply_config(&WgPeerConfig {
                        iface: PROBE_IFACE.to_string(),
                        priv_key_b64: priv_key.clone(),
                        peer_pub_key_b64: target.pub_key.clone(),
                        endpoint_ip: ep_ip,
                        endpoint_port: target.endpoint_port,
                        allowed_cidrs: allowed.clone(),
                        dns_ips: Vec::new(),
                    })
                    .is_err()
                {
                    continue;
                }

                // Complete Noise handshake with 1 warmup echo before taking steady-state samples.
                let warmup_ok = self
                    .backends
                    .prober
                    .measure_icmp_on_iface(PROBE_IFACE, &dst, 1)
                    .await
                    .is_some()
                    || self
                        .backends
                        .prober
                        .measure_icmp_on_iface(PROBE_IFACE, &dst, 1)
                        .await
                        .is_some();
                if !warmup_ok {
                    continue;
                }

                if self.probe_cancelled.load(Ordering::SeqCst)
                    || self.state.lock().await.status.state != TunnelState::Disconnected
                {
                    break;
                }

                if let Some(st) = self
                    .backends
                    .prober
                    .measure_icmp_on_iface(PROBE_IFACE, &dst, sample_count)
                    .await
                {
                    results.push(VerifiedTunnelResult {
                        cluster_id: target.cluster_id,
                        endpoint_ip: target.endpoint_ip,
                        min_ms: st.min_ms,
                        avg_ms: st.avg_ms,
                        mdev_ms: st.mdev_ms,
                        loss_pct: st.loss_pct,
                    });
                }
            }
            Ok(results)
        }
        .await;

        let _ = self.backends.wg.delete_interface(PROBE_IFACE).await;
        probe_res
    }

    pub async fn dispatch_request(
        &self,
        req: DaemonRequest,
        shutdown_tx: Option<&watch::Sender<bool>>,
    ) -> DaemonResponse {
        match req {
            DaemonRequest::ControlHttp {
                method,
                url,
                headers,
                body,
            } => match self
                .backends
                .control
                .http_fetch(&method, &url, &headers, body)
                .await
            {
                Ok((status, body)) => DaemonResponse::Http { status, body },
                Err(e) => DaemonResponse::Error {
                    message: e.to_string(),
                },
            },
            DaemonRequest::PrepareEndpoint {
                domain,
                discover_pmtu,
            } => match self
                .backends
                .control
                .prepare_endpoint(&domain, discover_pmtu)
                .await
            {
                Ok((endpoint_ip, wan_pmtu)) => DaemonResponse::Prepared {
                    endpoint_ip,
                    wan_pmtu,
                },
                Err(e) => DaemonResponse::Error {
                    message: e.to_string(),
                },
            },
            DaemonRequest::ProbeWanGaming {
                target_host,
                domains,
            } => match self
                .backends
                .control
                .probe_wan_gaming(&target_host, &domains)
                .await
            {
                Ok(probe) => DaemonResponse::WanGamingProbed(probe),
                Err(e) => DaemonResponse::Error {
                    message: e.to_string(),
                },
            },
            DaemonRequest::Status => DaemonResponse::Status(self.status().await),
            DaemonRequest::Connect(spec) => match self.connect(spec).await {
                Ok(st) => DaemonResponse::Status(st),
                Err(e) => DaemonResponse::Error {
                    message: e.to_string(),
                },
            },
            DaemonRequest::Disconnect { keep_killswitch } => {
                match self.disconnect(keep_killswitch).await {
                    Ok(st) => DaemonResponse::Status(st),
                    Err(e) => DaemonResponse::Error {
                        message: e.to_string(),
                    },
                }
            }
            DaemonRequest::SetKillswitch {
                enabled,
                ipv6_block,
                bypass_lan,
            } => match self.set_killswitch(enabled, ipv6_block, bypass_lan).await {
                Ok(st) => DaemonResponse::Status(st),
                Err(e) => DaemonResponse::Error {
                    message: e.to_string(),
                },
            },
            DaemonRequest::UpdateSplitTunnel(cfg) => match self.update_split_tunnel(cfg).await {
                Ok(st) => DaemonResponse::Status(st),
                Err(e) => DaemonResponse::Error {
                    message: e.to_string(),
                },
            },
            DaemonRequest::ResetAppSockets { pids } => {
                self.reset_app_sockets(&pids);
                DaemonResponse::Ok
            }
            DaemonRequest::VerifyGamingTunnels {
                target_ip,
                priv_key,
                address,
                mtu,
                targets,
                samples,
            } => match self
                .verify_gaming_tunnels(target_ip, priv_key, address, mtu, targets, samples)
                .await
            {
                Ok(res) => DaemonResponse::GamingTunnelsVerified(res),
                Err(e) => DaemonResponse::Error {
                    message: e.to_string(),
                },
            },
            DaemonRequest::Shutdown => {
                if let Some(tx) = shutdown_tx {
                    let _ = tx.send(true);
                }
                DaemonResponse::Ok
            }
        }
    }

    async fn cleanup_tunnel_only_locked(&self, iface: &str) {
        let ifindex = self.backends.wg.get_ifindex(iface).await.ok().flatten();
        let _ = self.backends.dns.revert_dns(ifindex).await;
        let _ = self.backends.routing.teardown_routing().await;
        let _ = self.backends.wg.delete_interface(iface).await;
    }

    async fn refresh_telemetry_locked(&self, guard: &mut DaemonInner) {
        let iface_exists = self
            .backends
            .wg
            .get_ifindex(&guard.iface)
            .await
            .ok()
            .flatten()
            .is_some();

        if guard.status.state == TunnelState::Protected && !iface_exists {
            warn!("Interface {} disappeared unexpectedly!", guard.iface);
            let _ = self.backends.dns.revert_dns(None).await;
            let _ = self.backends.routing.teardown_routing().await;
            guard.clear_tunnel_metadata();
            guard.status.state = if guard.status.killswitch {
                TunnelState::KillswitchLocked
            } else {
                TunnelState::Disconnected
            };
            let _ = self
                .backends
                .firewall
                .apply_firewall(&guard.firewall_spec(false));
            return;
        }

        if guard.status.state == TunnelState::Protected {
            if let Some(tel) = self.backends.wg.read_telemetry(&guard.iface) {
                guard.status.rx_bytes = tel.rx_bytes;
                guard.status.tx_bytes = tel.tx_bytes;
                guard.status.last_handshake_epoch = tel.last_handshake_epoch;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Mutex as StdMutex;
    use futures_util::future::BoxFuture;
    use hadal_core::{PingStats, WanGamingProbe};
    use crate::net::control::ControlBackend;
    use crate::net::dns::DnsBackend;
    use crate::net::firewall::FirewallBackend;
    use crate::net::probe::TunnelProber;
    use crate::net::routing::RoutingBackend;
    use crate::net::sock_diag::SockDiagBackend;
    use crate::net::wireguard::{WgTelemetry, WireGuardBackend};

    #[derive(Default)]
    struct FakeWg {
        ifindex: StdMutex<Option<u32>>,
        telemetry: StdMutex<Option<WgTelemetry>>,
        deleted: StdMutex<Vec<String>>,
        fail_apply: AtomicBool,
    }

    impl WireGuardBackend for FakeWg {
        fn ensure_interface<'a>(&'a self, _iface: &'a str, _addr: &'a str, _mtu: u16) -> BoxFuture<'a, Result<u32>> {
            Box::pin(async {
                *self.ifindex.lock().unwrap() = Some(42);
                Ok(42)
            })
        }
        fn delete_interface<'a>(&'a self, iface: &'a str) -> BoxFuture<'a, Result<()>> {
            let iface = iface.to_string();
            Box::pin(async move {
                self.deleted.lock().unwrap().push(iface.clone());
                if iface == "hadal-wg" {
                    *self.ifindex.lock().unwrap() = None;
                }
                Ok(())
            })
        }
        fn get_ifindex<'a>(&'a self, _iface: &'a str) -> BoxFuture<'a, Result<Option<u32>>> {
            Box::pin(async { Ok(*self.ifindex.lock().unwrap()) })
        }
        fn apply_config(&self, _cfg: &WgPeerConfig) -> Result<()> {
            if self.fail_apply.load(Ordering::SeqCst) {
                return Err(HadalError::WireGuard("wg apply failed".into()));
            }
            Ok(())
        }
        fn read_telemetry(&self, _iface: &str) -> Option<WgTelemetry> {
            self.telemetry.lock().unwrap().clone()
        }
    }

    #[derive(Default)]
    struct FakeFirewall {
        applied: StdMutex<Vec<FirewallSpec>>,
        cleared: AtomicUsize,
    }
    impl FirewallBackend for FakeFirewall {
        fn apply_firewall(&self, spec: &FirewallSpec) -> Result<()> {
            self.applied.lock().unwrap().push(spec.clone());
            Ok(())
        }
        fn clear_firewall(&self) -> Result<()> {
            self.cleared.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeRouting {
        configs: StdMutex<Vec<RoutingConfig>>,
        teardowns: AtomicUsize,
    }
    impl RoutingBackend for FakeRouting {
        fn configure_routing<'a>(&'a self, cfg: &'a RoutingConfig) -> BoxFuture<'a, Result<()>> {
            let cfg = cfg.clone();
            Box::pin(async move {
                self.configs.lock().unwrap().push(cfg);
                Ok(())
            })
        }
        fn teardown_routing(&self) -> BoxFuture<'_, Result<()>> {
            Box::pin(async {
                self.teardowns.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        }
        fn add_host_route(&self, _ifindex: u32, _dest: Ipv4Addr) -> BoxFuture<'_, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    #[derive(Default)]
    struct FakeDns {
        reverted: AtomicUsize,
    }
    impl DnsBackend for FakeDns {
        fn apply_dns<'a>(&'a self, _ifindex: u32, _servers: &'a [Ipv4Addr]) -> BoxFuture<'a, Result<()>> {
            Box::pin(async { Ok(()) })
        }
        fn revert_dns(&self, _ifindex: Option<u32>) -> BoxFuture<'_, Result<()>> {
            Box::pin(async {
                self.reverted.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        }
    }

    #[derive(Default)]
    struct FakeSockDiag;
    impl SockDiagBackend for FakeSockDiag {
        fn reset_app_sockets(&self, pids: &[u32]) -> usize {
            pids.len()
        }
    }

    #[derive(Default)]
    struct FakeControl;
    impl ControlBackend for FakeControl {
        fn http_fetch<'a>(&'a self, _m: &'a str, _u: &'a str, _h: &'a [(String, String)], _b: Option<Vec<u8>>) -> BoxFuture<'a, Result<(u16, Vec<u8>)>> {
            Box::pin(async { Ok((200, Vec::new())) })
        }
        fn prepare_endpoint<'a>(&'a self, _d: &'a str, _p: bool) -> BoxFuture<'a, Result<(String, Option<u16>)>> {
            Box::pin(async { Ok(("192.0.2.1".into(), Some(1492))) })
        }
        fn probe_wan_gaming<'a>(&'a self, _t: &'a str, _d: &'a [String]) -> BoxFuture<'a, Result<WanGamingProbe>> {
            Box::pin(async {
                Ok(WanGamingProbe {
                    baseline_direct: None,
                    wan_pmtu: 1492,
                    game_cidrs: Vec::new(),
                    endpoints: Vec::new(),
                })
            })
        }
    }

    #[derive(Default)]
    struct SlowProber {
        delay_ms: u64,
    }
    impl TunnelProber for SlowProber {
        fn measure_icmp_on_iface<'a>(&'a self, _iface: &'a str, target_ip: &'a str, _count: u32) -> BoxFuture<'a, Option<PingStats>> {
            let target = target_ip.to_string();
            let d = self.delay_ms;
            Box::pin(async move {
                if d > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(d)).await;
                }
                Some(PingStats {
                    target,
                    min_ms: 11.0,
                    avg_ms: 12.5,
                    max_ms: 14.0,
                    mdev_ms: 0.7,
                    loss_pct: 0.0,
                })
            })
        }
    }

    fn test_backends(wg: Arc<FakeWg>, fw: Arc<FakeFirewall>, prober: Arc<SlowProber>) -> DaemonBackends {
        DaemonBackends {
            wg,
            firewall: fw,
            routing: Arc::new(FakeRouting::default()),
            dns: Arc::new(FakeDns::default()),
            sock_diag: Arc::new(FakeSockDiag),
            control: Arc::new(FakeControl),
            prober,
        }
    }

    fn sample_spec(killswitch: bool) -> ConnectSpec {
        ConnectSpec {
            cluster_id: Some("de-fra".into()),
            domain: "de-fra.prod.surfshark.com".into(),
            endpoint_ip: "138.199.19.164".into(),
            endpoint_port: 51820,
            pub_key: "pub".into(),
            priv_key: "priv".into(),
            address: "10.14.0.2/16".into(),
            dns: vec!["1.1.1.1".into()],
            mtu: 1412,
            killswitch,
            ipv6_block: true,
            bypass_lan: true,
            split_mode: SplitMode::Off,
            split_cgroup_paths: vec![],
            game_only_cidrs: vec!["3.66.0.0/16".into()],
            location: Some("Frankfurt".into()),
            country: Some("Germany".into()),
        }
    }

    #[tokio::test]
    async fn connect_failure_rolls_back_endpoint_and_keeps_killswitch_locked() {
        let wg = Arc::new(FakeWg::default());
        wg.fail_apply.store(true, Ordering::SeqCst);
        let fw = Arc::new(FakeFirewall::default());
        let ctrl = DaemonController::new("hadal-wg".into(), test_backends(wg, fw.clone(), Arc::new(SlowProber::default())));

        let err = ctrl.connect(sample_spec(true)).await.unwrap_err();
        assert!(err.to_string().contains("wg apply failed"));

        let st = ctrl.status().await;
        assert_eq!(st.state, TunnelState::KillswitchLocked);
        assert!(st.endpoint.is_none());
        assert!(st.game_only_cidrs.is_empty());
        assert!(st.last_error.is_some());

        let last_fw = fw.applied.lock().unwrap().last().cloned().unwrap();
        assert!(!last_fw.tunnel_active);
        assert!(last_fw.endpoint_ip.is_none());
        assert!(last_fw.killswitch);
    }

    #[tokio::test]
    async fn update_split_tunnel_clears_game_only_cidrs_and_disconnect_resets_them() {
        let wg = Arc::new(FakeWg::default());
        let fw = Arc::new(FakeFirewall::default());
        let ctrl = DaemonController::new("hadal-wg".into(), test_backends(wg, fw, Arc::new(SlowProber::default())));

        let st = ctrl.connect(sample_spec(true)).await.unwrap();
        assert_eq!(st.game_only_cidrs, vec!["3.66.0.0/16"]);

        let updated = ctrl
            .update_split_tunnel(SplitTunnelConfig {
                mode: SplitMode::Bypass,
                game_only_cidrs: vec![],
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(updated.game_only_cidrs.is_empty());
        assert_eq!(updated.split_mode, SplitMode::Bypass);

        let disc = ctrl.disconnect(false).await.unwrap();
        assert_eq!(disc.state, TunnelState::Disconnected);
        assert!(disc.game_only_cidrs.is_empty());
    }

    #[tokio::test]
    async fn verify_gaming_tunnels_does_not_starve_status_queries() {
        let wg = Arc::new(FakeWg::default());
        let fw = Arc::new(FakeFirewall::default());
        let prober = Arc::new(SlowProber { delay_ms: 80 });
        let ctrl = Arc::new(DaemonController::new("hadal-wg".into(), test_backends(wg.clone(), fw, prober)));

        let probe_ctrl = ctrl.clone();
        let probe_task = tokio::spawn(async move {
            probe_ctrl
                .verify_gaming_tunnels(
                    "1.1.1.1".into(),
                    "priv".into(),
                    "10.14.0.2/16".into(),
                    1412,
                    vec![VerifyTarget {
                        cluster_id: "c1".into(),
                        endpoint_ip: "192.0.2.10".into(),
                        endpoint_port: 51820,
                        pub_key: "pub".into(),
                    }],
                    Some(4),
                )
                .await
        });

        tokio::time::sleep(std::time::Duration::from_millis(15)).await;
        let status_res = tokio::time::timeout(
            std::time::Duration::from_millis(40),
            ctrl.status(),
        )
        .await
        .expect("Status must not block behind VerifyGamingTunnels");
        assert_eq!(status_res.state, TunnelState::Disconnected);

        let verified = probe_task.await.unwrap().unwrap();
        assert_eq!(verified.len(), 1);
        assert!(wg.deleted.lock().unwrap().iter().any(|n| n == PROBE_IFACE));
    }
}
