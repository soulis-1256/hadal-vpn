use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use futures_util::future::BoxFuture;
use hadal_core::{
    ConnectSpec, DaemonClient, DaemonRequest, DaemonResponse, PingStats, Result, HadalError,
    SplitMode, SplitTunnelConfig, TunnelState, UnixDaemonClient, VerifiedTunnelResult,
    VerifyTarget, WanGamingProbe,
};
use hadald::daemon::controller::DaemonController;
use hadald::daemon::{
    handle_ipc_stream, run_daemon_with_backends, DaemonBackends, DaemonConfig,
};
use hadald::net::control::ControlBackend;
use hadald::net::dns::{dot_sni_for_ip, DnsBackend, DnsManager, DnsMode, Resolve1Client};
use hadald::net::firewall::{render_nftables_script_with_cgroups, FirewallBackend, FirewallSpec};
use hadald::net::probe::TunnelProber;
use hadald::net::routing::{
    build_routing_plan, RoutingBackend, RoutingConfig, BYPASS_FWMARK, CONTROL_FWMARK,
    ONLY_VPN_FWMARK, PREF_BYPASS_RULE, PREF_CONTROL_RULE, PREF_DNS_RULE, PREF_LAN_SUPPRESS_RULE,
    PREF_TUNNEL_RULE, HADAL_RT_TABLE,
};
use hadald::net::sock_diag::SockDiagBackend;
use hadald::net::wireguard::{WgPeerConfig, WgTelemetry, WireGuardBackend, WG_FWMARK};
use tokio::sync::{watch, Notify};

static TEMP_SEQ: AtomicUsize = AtomicUsize::new(1);

struct TempDir(PathBuf);

impl TempDir {
    fn new(prefix: &str) -> Self {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "hadald-test-{prefix}-{}-{seq}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

type ProbeCall = (String, String, u32);
type ExDnsCall = (i32, Vec<(i32, Vec<u8>, u16, &'static str)>);
type PlainDnsCall = (i32, Vec<(i32, Vec<u8>)>);
type DomainDnsCall = (i32, Vec<(String, bool)>);

#[derive(Default)]
struct RecordingWg {
    events: Arc<StdMutex<Vec<String>>>,
    ifindex: StdMutex<Option<u32>>,
    telemetry: StdMutex<Option<WgTelemetry>>,
    ensured: StdMutex<Vec<(String, String, u16)>>,
    applied_configs: StdMutex<Vec<WgPeerConfig>>,
    deleted: StdMutex<Vec<String>>,
    fail_ensure: AtomicBool,
    fail_apply: AtomicBool,
    fail_probe_apply_for_ip: StdMutex<Option<Ipv4Addr>>,
}

impl RecordingWg {
    fn with_events(events: Arc<StdMutex<Vec<String>>>) -> Self {
        Self {
            events,
            ..Default::default()
        }
    }
}

impl WireGuardBackend for RecordingWg {
    fn ensure_interface<'a>(
        &'a self,
        iface: &'a str,
        address_cidr: &'a str,
        mtu: u16,
    ) -> BoxFuture<'a, Result<u32>> {
        let iface = iface.to_string();
        let address = address_cidr.to_string();
        Box::pin(async move {
            self.events
                .lock()
                .unwrap()
                .push(format!("wg.ensure:{iface}"));
            if self.fail_ensure.load(Ordering::SeqCst) {
                return Err(HadalError::WireGuard("ensure_interface failed".into()));
            }
            self.ensured.lock().unwrap().push((iface.clone(), address, mtu));
            let idx = if iface == "hadal-probe" { 77 } else { 42 };
            *self.ifindex.lock().unwrap() = Some(idx);
            Ok(idx)
        })
    }

    fn delete_interface<'a>(&'a self, iface: &'a str) -> BoxFuture<'a, Result<()>> {
        let iface = iface.to_string();
        Box::pin(async move {
            self.events
                .lock()
                .unwrap()
                .push(format!("wg.delete:{iface}"));
            self.deleted.lock().unwrap().push(iface.clone());
            if iface != "hadal-probe" {
                *self.ifindex.lock().unwrap() = None;
            }
            Ok(())
        })
    }

    fn get_ifindex<'a>(&'a self, _iface: &'a str) -> BoxFuture<'a, Result<Option<u32>>> {
        Box::pin(async { Ok(*self.ifindex.lock().unwrap()) })
    }

    fn apply_config(&self, cfg: &WgPeerConfig) -> Result<()> {
        self.events
            .lock()
            .unwrap()
            .push(format!("wg.apply:{}", cfg.iface));
        if cfg.iface == "hadal-probe" {
            if let Some(bad_ip) = *self.fail_probe_apply_for_ip.lock().unwrap() {
                if cfg.endpoint_ip == bad_ip {
                    return Err(HadalError::WireGuard("probe peer apply rejected".into()));
                }
            }
        }
        if self.fail_apply.load(Ordering::SeqCst) {
            return Err(HadalError::WireGuard("wg apply failed".into()));
        }
        self.applied_configs.lock().unwrap().push(cfg.clone());
        Ok(())
    }

    fn read_telemetry(&self, _iface: &str) -> Option<WgTelemetry> {
        self.telemetry.lock().unwrap().clone()
    }
}

#[derive(Default)]
struct RecordingFirewall {
    events: Arc<StdMutex<Vec<String>>>,
    applied: StdMutex<Vec<FirewallSpec>>,
    cleared: AtomicUsize,
    fail_on_call_num: StdMutex<Option<usize>>,
    calls: AtomicUsize,
}

impl RecordingFirewall {
    fn with_events(events: Arc<StdMutex<Vec<String>>>) -> Self {
        Self {
            events,
            ..Default::default()
        }
    }
}

impl FirewallBackend for RecordingFirewall {
    fn apply_firewall(&self, spec: &FirewallSpec) -> Result<()> {
        let call_idx = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        self.events.lock().unwrap().push(format!(
            "fw.apply:active={},ks={}",
            spec.tunnel_active, spec.killswitch
        ));
        if self
            .fail_on_call_num
            .lock()
            .unwrap()
            .is_some_and(|n| n == call_idx)
        {
            return Err(HadalError::WireGuard("nft failed".into()));
        }
        self.applied.lock().unwrap().push(spec.clone());
        Ok(())
    }

    fn clear_firewall(&self) -> Result<()> {
        self.events.lock().unwrap().push("fw.clear".into());
        self.cleared.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[derive(Default)]
struct RecordingRouting {
    events: Arc<StdMutex<Vec<String>>>,
    configs: StdMutex<Vec<RoutingConfig>>,
    host_routes: StdMutex<Vec<(u32, Ipv4Addr)>>,
    teardowns: AtomicUsize,
    fail_configure: AtomicBool,
    fail_host_route: AtomicBool,
}

impl RecordingRouting {
    fn with_events(events: Arc<StdMutex<Vec<String>>>) -> Self {
        Self {
            events,
            ..Default::default()
        }
    }
}

impl RoutingBackend for RecordingRouting {
    fn configure_routing<'a>(&'a self, cfg: &'a RoutingConfig) -> BoxFuture<'a, Result<()>> {
        let cfg = cfg.clone();
        Box::pin(async move {
            self.events.lock().unwrap().push("routing.configure".into());
            if self.fail_configure.load(Ordering::SeqCst) {
                return Err(HadalError::WireGuard("routing setup failed".into()));
            }
            self.configs.lock().unwrap().push(cfg);
            Ok(())
        })
    }

    fn teardown_routing(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async {
            self.events.lock().unwrap().push("routing.teardown".into());
            self.teardowns.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
    }

    fn add_host_route(&self, ifindex: u32, dest: Ipv4Addr) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            self.events
                .lock()
                .unwrap()
                .push(format!("routing.host:{dest}"));
            if self.fail_host_route.load(Ordering::SeqCst) {
                return Err(HadalError::WireGuard("host route failed".into()));
            }
            self.host_routes.lock().unwrap().push((ifindex, dest));
            Ok(())
        })
    }
}

#[derive(Default)]
struct RecordingDns {
    events: Arc<StdMutex<Vec<String>>>,
    applied: StdMutex<Vec<(u32, Vec<Ipv4Addr>)>>,
    reverted: StdMutex<Vec<Option<u32>>>,
    fail_apply: AtomicBool,
}

impl RecordingDns {
    fn with_events(events: Arc<StdMutex<Vec<String>>>) -> Self {
        Self {
            events,
            ..Default::default()
        }
    }
}

impl DnsBackend for RecordingDns {
    fn apply_dns<'a>(&'a self, ifindex: u32, servers: &'a [Ipv4Addr]) -> BoxFuture<'a, Result<()>> {
        let servers = servers.to_vec();
        Box::pin(async move {
            self.events.lock().unwrap().push("dns.apply".into());
            if self.fail_apply.load(Ordering::SeqCst) {
                return Err(HadalError::WireGuard("dns apply failed".into()));
            }
            self.applied.lock().unwrap().push((ifindex, servers));
            Ok(())
        })
    }

    fn revert_dns(&self, ifindex: Option<u32>) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            self.events.lock().unwrap().push("dns.revert".into());
            self.reverted.lock().unwrap().push(ifindex);
            Ok(())
        })
    }
}

#[derive(Default)]
struct RecordingSockDiag {
    calls: StdMutex<Vec<Vec<u32>>>,
    return_count: StdMutex<Option<usize>>,
}

impl SockDiagBackend for RecordingSockDiag {
    fn reset_app_sockets(&self, pids: &[u32]) -> usize {
        self.calls.lock().unwrap().push(pids.to_vec());
        self.return_count
            .lock()
            .unwrap()
            .unwrap_or_else(|| pids.len() * 2)
    }
}

#[derive(Default)]
struct RecordingControl {
    fail_http: AtomicBool,
}

impl ControlBackend for RecordingControl {
    fn http_fetch<'a>(
        &'a self,
        method: &'a str,
        url: &'a str,
        headers: &'a [(String, String)],
        body: Option<Vec<u8>>,
    ) -> BoxFuture<'a, Result<(u16, Vec<u8>)>> {
        let method = method.to_string();
        let url = url.to_string();
        let hdr_count = headers.len();
        let body_len = body.as_ref().map_or(0, Vec::len);
        Box::pin(async move {
            if self.fail_http.load(Ordering::SeqCst) {
                return Err(HadalError::Custom("upstream blocked".into()));
            }
            let payload = format!("{method} {url} hdrs={hdr_count} body={body_len}");
            Ok((201, payload.into_bytes()))
        })
    }

    fn prepare_endpoint<'a>(
        &'a self,
        domain: &'a str,
        discover_pmtu: bool,
    ) -> BoxFuture<'a, Result<(String, Option<u16>)>> {
        let domain = domain.to_string();
        Box::pin(async move {
            let pmtu = if discover_pmtu { Some(1492) } else { None };
            let ip = if domain.contains("nl") {
                "198.51.100.77"
            } else {
                "138.199.19.164"
            };
            Ok((ip.to_string(), pmtu))
        })
    }

    fn probe_wan_gaming<'a>(
        &'a self,
        target_host: &'a str,
        domains: &'a [String],
    ) -> BoxFuture<'a, Result<WanGamingProbe>> {
        let target_host = target_host.to_string();
        let domain_count = domains.len();
        Box::pin(async move {
            Ok(WanGamingProbe {
                baseline_direct: Some(PingStats {
                    target: target_host,
                    min_ms: 14.0,
                    avg_ms: 15.0,
                    max_ms: 16.0,
                    mdev_ms: 0.5,
                    loss_pct: 0.0,
                }),
                wan_pmtu: 1492 + domain_count as u16,
                game_cidrs: vec!["3.66.0.0/16".into()],
                endpoints: vec![],
            })
        })
    }
}

#[derive(Default)]
struct ControlledProber {
    calls: StdMutex<Vec<ProbeCall>>,
    fail_on_calls: StdMutex<Vec<usize>>,
    wait_on_call_num: StdMutex<Option<usize>>,
    started: Arc<Notify>,
    release: Arc<Notify>,
}

impl TunnelProber for ControlledProber {
    fn measure_icmp_on_iface<'a>(
        &'a self,
        iface: &'a str,
        target_ip: &'a str,
        count: u32,
    ) -> BoxFuture<'a, Option<PingStats>> {
        let iface = iface.to_string();
        let target = target_ip.to_string();
        Box::pin(async move {
            let call_num = {
                let mut calls = self.calls.lock().unwrap();
                calls.push((iface, target.clone(), count));
                calls.len()
            };
            if self
                .wait_on_call_num
                .lock()
                .unwrap()
                .is_some_and(|n| n == call_num)
            {
                self.started.notify_waiters();
                self.release.notified().await;
            }
            if self.fail_on_calls.lock().unwrap().contains(&call_num) {
                return None;
            }
            Some(PingStats {
                target,
                min_ms: 11.0,
                avg_ms: 12.5,
                max_ms: 14.0,
                mdev_ms: 0.6,
                loss_pct: 0.0,
            })
        })
    }
}

struct Harness {
    events: Arc<StdMutex<Vec<String>>>,
    wg: Arc<RecordingWg>,
    fw: Arc<RecordingFirewall>,
    routing: Arc<RecordingRouting>,
    dns: Arc<RecordingDns>,
    sock_diag: Arc<RecordingSockDiag>,
    control: Arc<RecordingControl>,
    prober: Arc<ControlledProber>,
}

impl Harness {
    fn new() -> Self {
        let events = Arc::new(StdMutex::new(Vec::new()));
        Self {
            wg: Arc::new(RecordingWg::with_events(events.clone())),
            fw: Arc::new(RecordingFirewall::with_events(events.clone())),
            routing: Arc::new(RecordingRouting::with_events(events.clone())),
            dns: Arc::new(RecordingDns::with_events(events.clone())),
            sock_diag: Arc::new(RecordingSockDiag::default()),
            control: Arc::new(RecordingControl::default()),
            prober: Arc::new(ControlledProber::default()),
            events,
        }
    }

    fn backends(&self) -> DaemonBackends {
        DaemonBackends {
            wg: self.wg.clone(),
            firewall: self.fw.clone(),
            routing: self.routing.clone(),
            dns: self.dns.clone(),
            sock_diag: self.sock_diag.clone(),
            control: self.control.clone(),
            prober: self.prober.clone(),
        }
    }

    fn controller(&self) -> Arc<DaemonController> {
        Arc::new(DaemonController::new("hadal-wg".into(), self.backends()))
    }
}

fn sample_spec(killswitch: bool) -> ConnectSpec {
    ConnectSpec {
        cluster_id: Some("de-fra".into()),
        domain: "de-fra.prod.surfshark.com".into(),
        endpoint_ip: "138.199.19.164".into(),
        endpoint_port: 51820,
        pub_key: "server-pub".into(),
        priv_key: "client-priv".into(),
        address: "10.14.0.2/16".into(),
        dns: vec!["1.1.1.1".into()],
        mtu: 1412,
        killswitch,
        ipv6_block: true,
        bypass_lan: true,
        split_mode: SplitMode::Off,
        split_cgroup_paths: vec![],
        game_only_cidrs: vec![],
        location: Some("Frankfurt".into()),
        country: Some("Germany".into()),
    }
}

#[tokio::test]
async fn connect_orders_backends_safely_and_disconnect_restores_expected_state() {
    let h = Harness::new();
    *h.wg.telemetry.lock().unwrap() = Some(WgTelemetry {
        rx_bytes: 1024,
        tx_bytes: 512,
        last_handshake_epoch: Some(1_700_000_000),
    });
    let ctrl = h.controller();

    let st = ctrl.connect(sample_spec(true)).await.unwrap();
    assert_eq!(st.state, TunnelState::Protected);
    assert_eq!(st.endpoint.as_deref(), Some("138.199.19.164:51820"));
    assert_eq!(st.rx_bytes, 1024);
    assert_eq!(st.tx_bytes, 512);
    assert_eq!(st.last_handshake_epoch, Some(1_700_000_000));

    // Order guarantee: arm killswitch(false) -> wg.ensure -> routing -> dns -> firewall(true) -> wg.apply
    let events = h.events.lock().unwrap().clone();
    assert_eq!(
        events,
        vec![
            "fw.apply:active=false,ks=true",
            "wg.ensure:hadal-wg",
            "routing.configure",
            "dns.apply",
            "fw.apply:active=true,ks=true",
            "wg.apply:hadal-wg",
        ]
    );

    // Disconnect keeping killswitch locks host cleanly without leaking
    let locked = ctrl.disconnect(true).await.unwrap();
    assert_eq!(locked.state, TunnelState::KillswitchLocked);
    assert!(locked.killswitch);
    assert!(locked.endpoint.is_none());
    assert_eq!(h.dns.reverted.lock().unwrap().len(), 1);
    assert_eq!(h.routing.teardowns.load(Ordering::SeqCst), 1);

    // Full disconnect clears firewall & resets killswitch
    let clean = ctrl.disconnect(false).await.unwrap();
    assert_eq!(clean.state, TunnelState::Disconnected);
    assert!(!clean.killswitch);
    assert_eq!(h.fw.cleared.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn connect_validation_and_rollback_preserve_fail_closed_invariants() {
    // 1. Invalid endpoint IP rejects immediately without touching backends
    let h_bad_ip = Harness::new();
    let ctrl_bad_ip = h_bad_ip.controller();
    let mut bad_spec = sample_spec(true);
    bad_spec.endpoint_ip = "not-an-ip".into();
    let err = ctrl_bad_ip.connect(bad_spec).await.unwrap_err();
    assert!(err.to_string().contains("Invalid endpoint IP"));
    assert!(h_bad_ip.events.lock().unwrap().is_empty());

    // 2. Pre-arm firewall failure aborts before WireGuard interface creation & keeps previous status
    let h_pre_fw = Harness::new();
    *h_pre_fw.fw.fail_on_call_num.lock().unwrap() = Some(1);
    let ctrl_pre_fw = h_pre_fw.controller();
    let mut spec = sample_spec(true);
    spec.split_mode = SplitMode::Bypass;
    let err = ctrl_pre_fw.connect(spec).await.unwrap_err();
    assert!(err.to_string().contains("nft failed"));
    assert!(h_pre_fw.wg.ensured.lock().unwrap().is_empty());
    let st = ctrl_pre_fw.status().await;
    assert_eq!(st.state, TunnelState::Disconnected);
    assert!(!st.killswitch);
    assert_eq!(st.split_mode, SplitMode::Off);
    assert!(st.last_error.is_some());

    // 3. Mid-connect failure (routing) with killswitch=true cleans up tunnel and locks firewall
    let h_route_fail = Harness::new();
    h_route_fail.routing.fail_configure.store(true, Ordering::SeqCst);
    let ctrl_route = h_route_fail.controller();
    let err = ctrl_route.connect(sample_spec(true)).await.unwrap_err();
    assert!(err.to_string().contains("routing setup failed"));
    let st = ctrl_route.status().await;
    assert_eq!(st.state, TunnelState::KillswitchLocked);
    assert!(st.endpoint.is_none());
    let last_fw = h_route_fail.fw.applied.lock().unwrap().last().cloned().unwrap();
    assert!(!last_fw.tunnel_active);
    assert!(last_fw.killswitch);
    assert!(last_fw.endpoint_ip.is_none());

    // 4. Mid-connect failure (DNS) with killswitch=false restores previous split/lan settings & clears firewall
    let h_dns_fail = Harness::new();
    h_dns_fail.dns.fail_apply.store(true, Ordering::SeqCst);
    let ctrl_dns = h_dns_fail.controller();
    let mut non_ks = sample_spec(false);
    non_ks.ipv6_block = true;
    non_ks.split_mode = SplitMode::Bypass;
    non_ks.split_cgroup_paths = vec!["/user.slice/app.scope".into()];
    let err = ctrl_dns.connect(non_ks).await.unwrap_err();
    assert!(err.to_string().contains("dns apply failed"));
    let st = ctrl_dns.status().await;
    assert_eq!(st.state, TunnelState::Disconnected);
    assert_eq!(st.split_mode, SplitMode::Off);
    assert!(st.split_cgroup_paths.is_empty());
    assert_eq!(h_dns_fail.fw.cleared.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn abrupt_interface_loss_transitions_state_and_reapplies_firewall() {
    for killswitch in [true, false] {
        let h = Harness::new();
        let ctrl = h.controller();
        let connected = ctrl.connect(sample_spec(killswitch)).await.unwrap();
        assert_eq!(connected.state, TunnelState::Protected);

        // Simulate kernel deleting hadal-wg out from under hadald
        *h.wg.ifindex.lock().unwrap() = None;
        let dropped = ctrl.status().await;
        assert_eq!(
            dropped.state,
            if killswitch {
                TunnelState::KillswitchLocked
            } else {
                TunnelState::Disconnected
            }
        );
        assert!(dropped.endpoint.is_none());
        assert_eq!(h.dns.reverted.lock().unwrap().as_slice(), &[None]);
        assert_eq!(h.routing.teardowns.load(Ordering::SeqCst), 1);
        let last_fw = h.fw.applied.lock().unwrap().last().cloned().unwrap();
        assert!(!last_fw.tunnel_active);
        assert_eq!(last_fw.killswitch, killswitch);
    }
}

#[tokio::test]
async fn set_killswitch_and_split_tunnel_updates_work_across_states() {
    let h = Harness::new();
    let ctrl = h.controller();

    // Toggling killswitch on while Disconnected locks immediately
    let locked = ctrl.set_killswitch(true, true, false).await.unwrap();
    assert_eq!(locked.state, TunnelState::KillswitchLocked);
    assert!(!locked.bypass_lan);

    let unlocked = ctrl.set_killswitch(false, false, true).await.unwrap();
    assert_eq!(unlocked.state, TunnelState::Disconnected);
    assert!(!unlocked.ipv6_block);

    // Connect and test idempotent no-op + live split update + game_only_cidrs reset + Protected killswitch toggle
    ctrl.connect(sample_spec(true)).await.unwrap();
    let fw_count_after_connect = h.fw.applied.lock().unwrap().len();
    let rt_count_after_connect = h.routing.configs.lock().unwrap().len();

    // Exact same split config is a strict no-op
    ctrl.update_split_tunnel(SplitTunnelConfig {
        mode: SplitMode::Off,
        cgroup_paths: vec![],
        game_only_cidrs: vec![],
        ..Default::default()
    })
    .await
    .unwrap();
    assert_eq!(h.fw.applied.lock().unwrap().len(), fw_count_after_connect);
    assert_eq!(h.routing.configs.lock().unwrap().len(), rt_count_after_connect);

    // Live split update while Protected re-configures routing + firewall with game CIDRs preserved & cleared
    let gaming_split = ctrl
        .update_split_tunnel(SplitTunnelConfig {
            mode: SplitMode::OnlyVpn,
            cgroup_paths: vec!["user.slice/game.scope".into()],
            game_only_cidrs: vec!["3.66.0.0/16".into()],
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(gaming_split.split_mode, SplitMode::OnlyVpn);
    assert_eq!(gaming_split.game_only_cidrs, vec!["3.66.0.0/16"]);
    assert_eq!(
        h.routing.configs.lock().unwrap().len(),
        rt_count_after_connect + 1
    );

    let cleared = ctrl
        .update_split_tunnel(SplitTunnelConfig {
            mode: SplitMode::Bypass,
            cgroup_paths: vec!["user.slice/browser.scope".into()],
            game_only_cidrs: vec![],
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(cleared.split_mode, SplitMode::Bypass);
    assert!(cleared.game_only_cidrs.is_empty());

    // Toggling killswitch off while Protected keeps state Protected while refreshing firewall
    let still_up = ctrl.set_killswitch(false, true, false).await.unwrap();
    assert_eq!(still_up.state, TunnelState::Protected);
    assert!(!still_up.killswitch);
    let last_fw = h.fw.applied.lock().unwrap().last().cloned().unwrap();
    assert!(last_fw.tunnel_active);
    assert!(!last_fw.killswitch);
    assert!(!last_fw.bypass_lan);

    // Socket reset forwarding
    assert_eq!(ctrl.reset_app_sockets(&[101, 202]), 4);
    assert_eq!(
        h.sock_diag.calls.lock().unwrap().as_slice(),
        &[vec![101, 202]]
    );
}

#[tokio::test]
async fn verify_gaming_tunnels_validates_clamps_cleans_up_and_avoids_starvation() {
    // 1. Not disconnected -> returns empty immediately without creating probe iface
    let h_busy = Harness::new();
    let ctrl_busy = h_busy.controller();
    ctrl_busy.set_killswitch(true, true, true).await.unwrap();
    let skipped = ctrl_busy
        .verify_gaming_tunnels(
            "1.1.1.1".into(),
            "priv".into(),
            "10.14.0.2/16".into(),
            1412,
            vec![VerifyTarget {
                cluster_id: "c1".into(),
                endpoint_ip: "198.51.100.1".into(),
                endpoint_port: 51820,
                pub_key: "pub".into(),
            }],
            Some(4),
        )
        .await
        .unwrap();
    assert!(skipped.is_empty());
    assert!(h_busy.wg.ensured.lock().unwrap().is_empty());

    // 2. Host route error cleans up hadal-probe
    let h_err = Harness::new();
    h_err.routing.fail_host_route.store(true, Ordering::SeqCst);
    let ctrl_err = h_err.controller();
    let err = ctrl_err
        .verify_gaming_tunnels(
            "1.1.1.1".into(),
            "priv".into(),
            "10.14.0.2/16".into(),
            1412,
            vec![],
            None,
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("host route failed"));
    assert!(h_err
        .wg
        .deleted
        .lock()
        .unwrap()
        .iter()
        .any(|d| d == "hadal-probe"));

    // 3. Clamping + bad IP/warmup failure skip + concurrent non-starvation & cancellation
    let h = Harness::new();
    *h.wg.fail_probe_apply_for_ip.lock().unwrap() = Some(Ipv4Addr::new(198, 51, 100, 11));
    *h.prober.fail_on_calls.lock().unwrap() = vec![1, 2]; // target 3 fails both warmup attempts
    *h.prober.wait_on_call_num.lock().unwrap() = Some(4); // pause during steady-state call of target 4
    let started = h.prober.started.clone();
    let release = h.prober.release.clone();
    let ctrl = h.controller();

    let targets = vec![
        VerifyTarget {
            cluster_id: "bad-ip".into(),
            endpoint_ip: "invalid".into(),
            endpoint_port: 51820,
            pub_key: "p0".into(),
        },
        VerifyTarget {
            cluster_id: "apply-err".into(),
            endpoint_ip: "198.51.100.11".into(),
            endpoint_port: 51820,
            pub_key: "p1".into(),
        },
        VerifyTarget {
            cluster_id: "warmup-drop".into(),
            endpoint_ip: "198.51.100.12".into(),
            endpoint_port: 51820,
            pub_key: "p2".into(),
        },
        VerifyTarget {
            cluster_id: "good".into(),
            endpoint_ip: "198.51.100.13".into(),
            endpoint_port: 51820,
            pub_key: "p3".into(),
        },
        VerifyTarget {
            cluster_id: "cancelled-next".into(),
            endpoint_ip: "198.51.100.14".into(),
            endpoint_port: 51820,
            pub_key: "p4".into(),
        },
    ];

    let probe_ctrl = ctrl.clone();
    let probe_task = tokio::spawn(async move {
        probe_ctrl
            .verify_gaming_tunnels(
                "1.1.1.1".into(),
                "priv".into(),
                "10.14.0.2/16".into(),
                1412,
                targets,
                Some(99), // clamped down to 16
            )
            .await
    });

    started.notified().await;
    // Status query & connect/killswitch cancellation must not starve while probe is waiting
    let st = tokio::time::timeout(Duration::from_millis(50), ctrl.status())
        .await
        .expect("status query must not block behind probe_lock");
    assert_eq!(st.state, TunnelState::Disconnected);

    ctrl.set_killswitch(true, true, true).await.unwrap();
    release.notify_waiters();

    let verified: Vec<VerifiedTunnelResult> = probe_task.await.unwrap().unwrap();
    assert_eq!(verified.len(), 1);
    assert_eq!(verified[0].cluster_id, "good");
    assert_eq!(
        h.prober.calls.lock().unwrap().as_slice(),
        &[
            ("hadal-probe".into(), "1.1.1.1".into(), 1),
            ("hadal-probe".into(), "1.1.1.1".into(), 1),
            ("hadal-probe".into(), "1.1.1.1".into(), 1),
            ("hadal-probe".into(), "1.1.1.1".into(), 16),
        ]
    );
}

#[tokio::test]
async fn ipc_stream_and_unix_daemon_lifecycle_roundtrip() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let h = Harness::new();
    let ctrl = h.controller();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (client_io, server_io) = tokio::io::duplex(16 * 1024);
    let (srv_r, srv_w) = tokio::io::split(server_io);

    let srv_task = tokio::spawn(async move {
        handle_ipc_stream(srv_r, srv_w, ctrl, shutdown_tx).await
    });

    let (cli_r, mut cli_w) = tokio::io::split(client_io);
    let mut lines = BufReader::new(cli_r).lines();

    // Send blank line + invalid JSON + ControlHttp + PrepareEndpoint + ProbeWanGaming + Shutdown
    let reqs = vec![
        String::new(),
        "{bad json".into(),
        serde_json::to_string(&DaemonRequest::ControlHttp {
            method: "POST".into(),
            url: "https://api.example/v1".into(),
            headers: vec![("Authorization".into(), "Bearer tok".into())],
            body: Some(b"hello".to_vec()),
        })
        .unwrap(),
        serde_json::to_string(&DaemonRequest::PrepareEndpoint {
            domain: "nl-ams.prod.surfshark.com".into(),
            discover_pmtu: true,
        })
        .unwrap(),
        serde_json::to_string(&DaemonRequest::ProbeWanGaming {
            target_host: "3.66.1.1".into(),
            domains: vec!["de-fra.prod.surfshark.com".into()],
        })
        .unwrap(),
        serde_json::to_string(&DaemonRequest::Shutdown).unwrap(),
    ];

    for r in &reqs {
        cli_w.write_all(r.as_bytes()).await.unwrap();
        cli_w.write_all(b"\n").await.unwrap();
    }
    cli_w.flush().await.unwrap();
    cli_w.shutdown().await.unwrap();
    drop(cli_w);

    let mut responses = Vec::new();
    while let Some(line) = lines.next_line().await.unwrap() {
        responses.push(serde_json::from_str::<DaemonResponse>(&line).unwrap());
    }
    srv_task.await.unwrap().unwrap();

    assert!(matches!(&responses[0], DaemonResponse::Error { message } if message.contains("Invalid JSON")));
    assert!(matches!(&responses[1], DaemonResponse::Http { status: 201, body } if String::from_utf8_lossy(body).contains("POST https://api.example/v1 hdrs=1 body=5")));
    assert!(matches!(&responses[2], DaemonResponse::Prepared { endpoint_ip, wan_pmtu: Some(1492) } if endpoint_ip == "198.51.100.77"));
    assert!(matches!(&responses[3], DaemonResponse::WanGamingProbed(p) if p.wan_pmtu == 1493 && p.game_cidrs == vec!["3.66.0.0/16"]));
    assert!(matches!(responses[4], DaemonResponse::Ok));
    assert!(*shutdown_rx.borrow());

    // Real Unix domain socket daemon harness test via run_daemon_with_backends + UnixDaemonClient
    let tmp = TempDir::new("unix-daemon");
    let sock_path = tmp.path().join("hadald.sock");
    let state_dir = tmp.path().join("state");
    let h2 = Harness::new();
    let cfg = DaemonConfig {
        socket_path: sock_path.clone(),
        state_dir,
        iface: "hadal-wg".into(),
        dns_mode: DnsMode::ResolvConf,
        resolv_conf_path: tmp.path().join("resolv.conf"),
        socket_group: "root".into(),
    };

    let daemon_task = tokio::spawn(run_daemon_with_backends(cfg, h2.backends()));
    for _ in 0..40 {
        if sock_path.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(sock_path.exists(), "hadald failed to bind Unix socket");

    let client = UnixDaemonClient::new(sock_path.clone());
    let conn_resp = client
        .send(&DaemonRequest::Connect(sample_spec(true)))
        .await
        .unwrap();
    assert!(matches!(
        conn_resp,
        DaemonResponse::Status(s) if s.state == TunnelState::Protected
    ));
    let st_resp = client.send(&DaemonRequest::Status).await.unwrap();
    assert!(matches!(
        st_resp,
        DaemonResponse::Status(s) if s.state == TunnelState::Protected
    ));

    let ok = client.send(&DaemonRequest::Shutdown).await.unwrap();
    assert!(matches!(ok, DaemonResponse::Ok));

    daemon_task.await.unwrap().unwrap();
    assert!(!sock_path.exists(), "shutdown should remove Unix socket");
    assert_eq!(h2.fw.cleared.load(Ordering::SeqCst), 1);
}

#[test]
fn nftables_script_enforces_leak_locks_split_tunnel_and_game_cidrs() {
    // 1. Protected + Bypass split mode + cgroup normalization
    let bypass_spec = FirewallSpec {
        wg_iface: "hadal-wg".into(),
        endpoint_ip: Some(Ipv4Addr::new(138, 199, 19, 164)),
        endpoint_port: 51820,
        killswitch: true,
        ipv6_block: true,
        bypass_lan: true,
        split_mode: SplitMode::Bypass,
        split_cgroup_paths: vec![],
        game_only_cidrs: vec![],
        tunnel_active: true,
    };
    let script = render_nftables_script_with_cgroups(
        &bypass_spec,
        &["/user.slice/user-1000.slice/app-steam.scope/".into()],
    );
    assert!(script.starts_with("table inet hadal_vpn\ndelete table inet hadal_vpn\n"));
    let v6_pos = script
        .find("meta nfproto ipv6 counter reject with icmpv6 type admin-prohibited")
        .unwrap();
    let est_pos = script.find("ct state established,related accept").unwrap();
    assert!(v6_pos < est_pos);
    assert!(script.contains(&format!(
        "ip saddr 138.199.19.164 udp sport 51820 meta mark set 0x{WG_FWMARK:x}"
    )));
    assert!(script.contains(&format!(
        "socket cgroupv2 level 3 \"user.slice/user-1000.slice/app-steam.scope\" meta mark set 0x{BYPASS_FWMARK:x}"
    )));
    assert!(script.contains(&format!(
        "meta nfproto ipv4 meta mark 0x{BYPASS_FWMARK:x} oifname != \"lo\" masquerade"
    )));
    assert!(script.contains(&format!(
        "meta mark 0x{CONTROL_FWMARK:x} meta nfproto ipv4 tcp dport 443 accept"
    )));
    assert!(script.contains(&format!(
        "meta mark 0x{CONTROL_FWMARK:x} meta nfproto ipv4 ip protocol icmp accept"
    )));
    assert!(script.contains("ip daddr { 10.0.0.0/8, 172.16.0.0/12"));

    // 2. OnlyVpn split mode drops unmarked-to-WAN DNS + ONLY_VPN outside WG and skips LAN accept
    let only_vpn = FirewallSpec {
        split_mode: SplitMode::OnlyVpn,
        bypass_lan: true,
        ..bypass_spec.clone()
    };
    let only_script =
        render_nftables_script_with_cgroups(&only_vpn, &["user.slice/app.scope".into()]);
    assert!(only_script.contains(&format!(
        "meta nfproto ipv4 meta mark 0x{ONLY_VPN_FWMARK:x} oifname \"hadal-wg\" masquerade"
    )));
    assert!(only_script.contains(&format!("meta mark 0x{ONLY_VPN_FWMARK:x} counter drop")));
    assert!(only_script.contains("meta nfproto ipv4 accept"));
    assert!(!only_script.contains("10.0.0.0/8"));

    // 3. Game-only CIDRs block non-tunnel leaks to game servers while letting LAN/other WAN remain accept
    let game_spec = FirewallSpec {
        split_mode: SplitMode::Off,
        bypass_lan: false,
        game_only_cidrs: vec!["3.66.0.0/16".into(), "52.94.0.0/16".into()],
        ..bypass_spec.clone()
    };
    let game_script = render_nftables_script_with_cgroups(&game_spec, &[]);
    assert!(game_script.contains("ip daddr { 3.66.0.0/16, 52.94.0.0/16 } counter drop"));

    // 4. KillswitchLocked (inactive tunnel) preserves control-plane HTTPS/ICMP and drops other WAN
    let locked_spec = FirewallSpec {
        tunnel_active: false,
        endpoint_ip: None,
        split_mode: SplitMode::Off,
        bypass_lan: false,
        ..bypass_spec
    };
    let locked_script = render_nftables_script_with_cgroups(&locked_spec, &[]);
    assert!(!locked_script.contains("chain mangle_in"));
    assert!(locked_script.contains("policy drop"));
    assert!(locked_script.contains(&format!("meta mark 0x{CONTROL_FWMARK:x} meta nfproto ipv4 tcp dport 443 accept")));
    assert!(!locked_script.contains("10.0.0.0/8"));
}

#[test]
fn routing_plan_handles_off_bypass_only_vpn_and_game_cidrs() {
    let default_plan = build_routing_plan(&RoutingConfig {
        ifindex: 7,
        split_mode: SplitMode::Off,
        bypass_lan: true,
        game_only_cidrs: vec![],
        dns_ips: vec![Ipv4Addr::new(1, 1, 1, 1)],
    })
    .unwrap();
    assert_eq!(default_plan.routes, vec![(Ipv4Addr::UNSPECIFIED, 0)]);
    assert_eq!(default_plan.rules[0].priority, PREF_CONTROL_RULE);
    assert_eq!(default_plan.rules[0].fwmark, Some(CONTROL_FWMARK));
    assert!(default_plan
        .rules
        .iter()
        .any(|r| r.priority == PREF_LAN_SUPPRESS_RULE && r.suppress_prefixlen_zero));
    assert!(default_plan.rules.iter().any(|r| r.priority == PREF_TUNNEL_RULE
        && r.table == HADAL_RT_TABLE
        && r.fwmark == Some(WG_FWMARK)
        && r.invert));

    let bypass_plan = build_routing_plan(&RoutingConfig {
        ifindex: 7,
        split_mode: SplitMode::Bypass,
        bypass_lan: false,
        game_only_cidrs: vec![],
        dns_ips: vec![],
    })
    .unwrap();
    assert!(bypass_plan
        .rules
        .iter()
        .any(|r| r.priority == PREF_BYPASS_RULE && r.fwmark == Some(BYPASS_FWMARK) && r.table == 254));
    assert!(!bypass_plan
        .rules
        .iter()
        .any(|r| r.priority == PREF_LAN_SUPPRESS_RULE));

    let only_vpn_plan = build_routing_plan(&RoutingConfig {
        ifindex: 7,
        split_mode: SplitMode::OnlyVpn,
        bypass_lan: true,
        game_only_cidrs: vec![],
        dns_ips: vec![Ipv4Addr::new(1, 1, 1, 1)],
    })
    .unwrap();
    assert!(only_vpn_plan
        .rules
        .iter()
        .any(|r| r.priority == PREF_DNS_RULE && r.dest_prefix == Some((Ipv4Addr::new(1, 1, 1, 1), 32))));
    assert!(only_vpn_plan.rules.iter().any(|r| r.priority == PREF_TUNNEL_RULE
        && r.fwmark == Some(ONLY_VPN_FWMARK)
        && !r.invert));

    let game_plan = build_routing_plan(&RoutingConfig {
        ifindex: 7,
        split_mode: SplitMode::OnlyVpn,
        bypass_lan: true,
        game_only_cidrs: vec!["3.66.0.0/16".into()],
        dns_ips: vec![Ipv4Addr::new(1, 1, 1, 1)],
    })
    .unwrap();
    assert_eq!(
        game_plan.routes,
        vec![
            (Ipv4Addr::new(3, 66, 0, 0), 16),
            (Ipv4Addr::new(1, 1, 1, 1), 32),
        ]
    );

    let err = build_routing_plan(&RoutingConfig {
        ifindex: 7,
        split_mode: SplitMode::Off,
        bypass_lan: false,
        game_only_cidrs: vec!["bad-cidr".into()],
        dns_ips: vec![],
    })
    .unwrap_err();
    assert!(err.to_string().contains("Invalid game CIDR"));
}

#[derive(Default)]
struct FakeResolve1 {
    available: bool,
    transient_failures: AtomicUsize,
    ex_calls: StdMutex<Vec<ExDnsCall>>,
    plain_calls: StdMutex<Vec<PlainDnsCall>>,
    domains: StdMutex<Vec<DomainDnsCall>>,
    default_routes: StdMutex<Vec<(i32, bool)>>,
    dot_modes: StdMutex<Vec<(i32, String)>>,
    reverted: StdMutex<Vec<i32>>,
    flushed: AtomicUsize,
}

impl Resolve1Client for FakeResolve1 {
    fn is_available(&self) -> BoxFuture<'_, bool> {
        Box::pin(async { self.available })
    }

    fn set_link_dns<'a>(
        &'a self,
        ifindex: i32,
        addresses: Vec<(i32, Vec<u8>)>,
    ) -> BoxFuture<'a, std::result::Result<(), String>> {
        Box::pin(async move {
            self.plain_calls.lock().unwrap().push((ifindex, addresses));
            Ok(())
        })
    }

    fn set_link_dns_ex<'a>(
        &'a self,
        ifindex: i32,
        addresses: Vec<(i32, Vec<u8>, u16, &'static str)>,
    ) -> BoxFuture<'a, std::result::Result<(), String>> {
        Box::pin(async move {
            let rem = self.transient_failures.load(Ordering::SeqCst);
            if rem > 0 {
                self.transient_failures.fetch_sub(1, Ordering::SeqCst);
                return Err("NoSuchLink: interface pending".into());
            }
            self.ex_calls.lock().unwrap().push((ifindex, addresses));
            Ok(())
        })
    }

    fn set_link_domains<'a>(
        &'a self,
        ifindex: i32,
        domains: Vec<(&'a str, bool)>,
    ) -> BoxFuture<'a, std::result::Result<(), String>> {
        let owned = domains
            .into_iter()
            .map(|(d, r)| (d.to_string(), r))
            .collect();
        Box::pin(async move {
            self.domains.lock().unwrap().push((ifindex, owned));
            Ok(())
        })
    }

    fn set_link_default_route(
        &self,
        ifindex: i32,
        enable: bool,
    ) -> BoxFuture<'_, std::result::Result<(), String>> {
        Box::pin(async move {
            self.default_routes.lock().unwrap().push((ifindex, enable));
            Ok(())
        })
    }

    fn set_link_dns_over_tls<'a>(
        &'a self,
        ifindex: i32,
        mode: &'a str,
    ) -> BoxFuture<'a, std::result::Result<(), String>> {
        let mode = mode.to_string();
        Box::pin(async move {
            self.dot_modes.lock().unwrap().push((ifindex, mode));
            Ok(())
        })
    }

    fn revert_link(&self, ifindex: i32) -> BoxFuture<'_, std::result::Result<(), String>> {
        Box::pin(async move {
            self.reverted.lock().unwrap().push(ifindex);
            Ok(())
        })
    }

    fn flush_caches(&self) -> BoxFuture<'_, std::result::Result<(), String>> {
        Box::pin(async {
            self.flushed.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
    }
}

#[tokio::test]
async fn dns_manager_covers_resolved_dot_retries_and_resolv_conf_fallback() {
    assert_eq!(dot_sni_for_ip(Ipv4Addr::new(1, 1, 1, 1)), Some("cloudflare-dns.com"));
    assert_eq!(dot_sni_for_ip(Ipv4Addr::new(9, 9, 9, 9)), Some("dns.quad9.net"));
    assert_eq!(dot_sni_for_ip(Ipv4Addr::new(10, 14, 0, 1)), None);

    // 1. Resolved mode retries NoSuchLink + installs DoT SNI + reverts cleanly
    let tmp = TempDir::new("dns");
    let resolved = Arc::new(FakeResolve1 {
        available: true,
        transient_failures: AtomicUsize::new(1),
        ..Default::default()
    });
    let mgr_resolved = DnsManager::with_resolved_client(
        DnsMode::Auto,
        tmp.path().join("resolv.conf"),
        tmp.path(),
        resolved.clone(),
    );
    mgr_resolved
        .apply_dns(12, &[Ipv4Addr::new(1, 1, 1, 1)])
        .await
        .unwrap();
    assert_eq!(resolved.ex_calls.lock().unwrap().len(), 1);
    assert_eq!(
        resolved.domains.lock().unwrap().as_slice(),
        &[(12, vec![(".".into(), true)])]
    );
    assert_eq!(
        resolved.default_routes.lock().unwrap().as_slice(),
        &[(12, true)]
    );
    assert_eq!(
        resolved.dot_modes.lock().unwrap().as_slice(),
        &[(12, "yes".into())]
    );
    mgr_resolved.revert_dns(Some(12)).await.unwrap();
    assert_eq!(resolved.reverted.lock().unwrap().as_slice(), &[12]);
    assert_eq!(resolved.flushed.load(Ordering::SeqCst), 2);

    // 2. Auto mode falls back to resolv.conf backup/restore when resolved is unavailable
    let resolv_path = tmp.path().join("etc-resolv.conf");
    let orig = "nameserver 192.168.1.1\nsearch home.arpa\n";
    std::fs::write(&resolv_path, orig).unwrap();
    let mgr_fallback = DnsManager::with_resolved_client(
        DnsMode::Auto,
        resolv_path.clone(),
        tmp.path(),
        Arc::new(FakeResolve1 {
            available: false,
            ..Default::default()
        }),
    );
    mgr_fallback
        .apply_dns(12, &[Ipv4Addr::new(10, 14, 0, 1), Ipv4Addr::new(1, 1, 1, 1)])
        .await
        .unwrap();
    let updated = std::fs::read_to_string(&resolv_path).unwrap();
    assert!(updated.contains("nameserver 10.14.0.1\nnameserver 1.1.1.1\n"));
    mgr_fallback.revert_dns(Some(12)).await.unwrap();
    assert_eq!(std::fs::read_to_string(&resolv_path).unwrap(), orig);
    assert!(!tmp.path().join("resolv.conf.backup").exists());
}
