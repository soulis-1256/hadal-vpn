use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use hadal_core::auth::{AuthResponse, RemoteCodeResponse, UserMe};
use hadal_core::{
    AppSettings, Cluster, Coordinates, DaemonRequest, DaemonResponse, DaemonStatus,
    DesktopAppEntry, EndpointCandidate, GamingScanReport, RegisterPublicKeyResponse,
    SplitAppStatus, SplitMode, TunnelState, UserLocation, BYPASS_SLICE, VPN_SLICE,
};
use hadal_gui_lib::backend::{
    AccountApi, BoxFuture, DaemonBridge, DaemonIpcError, SettingsAndSplitBackend, StatusEmitter,
    TrayUpdater, WindowPresenter,
};
use hadal_gui_lib::hyprland::{
    build_popover_rule_lua, classify_socket2_event, HyprlandController, HyprlandTransport,
    Socket2Action, POPOVER_H, POPOVER_W,
};
use hadal_gui_lib::notifications::{
    format_connected_notification, ConnectionNotifier, NotificationTransport,
};
use hadal_gui_lib::state::{AppController, AppServices, DaemonEnvelope};
use hadal_gui_lib::tray::{
    badge_dot_rgb, format_tray_label, handle_tray_menu_action, render_tray_badge, BADGE_BODY_RGB,
    BADGE_MARK_RGB,
};

type ConnectPrepareCall = (String, bool, Option<u16>, Option<String>, Option<u16>);
type ScanGamingCall = (String, String, Option<String>);

fn make_cluster(id: &str, location: &str, country: &str, load: u32) -> Cluster {
    Cluster {
        id: id.into(),
        country: Some(country.into()),
        country_code: None,
        region: None,
        region_code: None,
        location: Some(location.into()),
        connection_name: Some(format!("{id}.prod.surfshark.com")),
        pub_key: Some(format!("pk-{id}")),
        tags: vec![],
        load: Some(load),
        coordinates: Some(Coordinates {
            latitude: Some(50.11),
            longitude: Some(8.68),
        }),
        flag_url: None,
        cluster_type: None,
    }
}

struct FakeAccount {
    logged_in: AtomicBool,
    clusters: StdMutex<Vec<Cluster>>,
    cluster_fetches: AtomicUsize,
    cleared: AtomicUsize,
    registered_keys: StdMutex<Vec<String>>,
}

impl Default for FakeAccount {
    fn default() -> Self {
        Self {
            logged_in: AtomicBool::new(true),
            clusters: StdMutex::new(vec![
                make_cluster("de-fra", "Frankfurt", "Germany", 22),
                make_cluster("nl-ams", "Amsterdam", "Netherlands", 12),
            ]),
            cluster_fetches: AtomicUsize::new(0),
            cleared: AtomicUsize::new(0),
            registered_keys: StdMutex::new(Vec::new()),
        }
    }
}

impl AccountApi for FakeAccount {
    fn is_logged_in(&self) -> BoxFuture<'_, bool> {
        Box::pin(async { self.logged_in.load(Ordering::SeqCst) })
    }

    fn create_remote_login(&self) -> BoxFuture<'_, Result<RemoteCodeResponse, String>> {
        Box::pin(async {
            Ok(RemoteCodeResponse {
                code: "HADAL99".into(),
                hash: "hash-99".into(),
                expires_at: Some(9_999_999),
            })
        })
    }

    fn poll_remote_login<'a>(
        &'a self,
        hash: &'a str,
    ) -> BoxFuture<'a, Result<AuthResponse, String>> {
        let valid = hash == "hash-99";
        Box::pin(async move {
            if valid {
                Ok(AuthResponse {
                    token: Some("pair-jwt".into()),
                    token_expires_at: None,
                    renew_token: Some("pair-ren".into()),
                    extra: Default::default(),
                })
            } else {
                Err("expired".into())
            }
        })
    }

    fn get_user_me(&self) -> BoxFuture<'_, Result<UserMe, String>> {
        Box::pin(async {
            Ok(UserMe {
                id: Some("u1".into()),
                email: Some("user@example.com".into()),
                status: Some("active".into()),
                expires_at: None,
                extra: Default::default(),
            })
        })
    }

    fn clear_session(&self) -> BoxFuture<'_, ()> {
        Box::pin(async {
            self.logged_in.store(false, Ordering::SeqCst);
            self.cleared.fetch_add(1, Ordering::SeqCst);
        })
    }

    fn get_clusters(&self) -> BoxFuture<'_, Result<Vec<Cluster>, String>> {
        Box::pin(async {
            self.cluster_fetches.fetch_add(1, Ordering::SeqCst);
            Ok(self.clusters.lock().unwrap().clone())
        })
    }

    fn get_user_location(&self) -> BoxFuture<'_, Result<UserLocation, String>> {
        Box::pin(async {
            Ok(UserLocation {
                ip: "198.51.100.5".into(),
                isp: Some("Example ISP".into()),
                country_code: Some("DE".into()),
                country: Some("Germany".into()),
                region: None,
                city: Some("Frankfurt".into()),
                secured: false,
            })
        })
    }

    fn register_public_key<'a>(
        &'a self,
        pub_key: &'a str,
    ) -> BoxFuture<'a, Result<RegisterPublicKeyResponse, String>> {
        let key = pub_key.to_string();
        Box::pin(async move {
            self.registered_keys.lock().unwrap().push(key);
            Ok(RegisterPublicKeyResponse {
                ip: Some("10.14.0.9".into()),
                extra: Default::default(),
            })
        })
    }
}

#[derive(Default)]
struct FakeDaemon {
    unreachable: AtomicBool,
    reject_update_split: AtomicBool,
    status: StdMutex<DaemonStatus>,
    sent_requests: StdMutex<Vec<DaemonRequest>>,
    prepare_calls: StdMutex<Vec<ConnectPrepareCall>>,
    scan_calls: StdMutex<Vec<ScanGamingCall>>,
    scan_report: StdMutex<Option<GamingScanReport>>,
}

impl DaemonBridge for FakeDaemon {
    fn query_status(&self) -> BoxFuture<'_, Result<DaemonStatus, DaemonIpcError>> {
        Box::pin(async {
            if self.unreachable.load(Ordering::SeqCst) {
                return Err(DaemonIpcError::unreachable(
                    "Cannot reach hadald at /run/hadald/hadald.sock",
                ));
            }
            Ok(self.status.lock().unwrap().clone())
        })
    }

    fn send(&self, req: DaemonRequest) -> BoxFuture<'_, Result<DaemonResponse, DaemonIpcError>> {
        Box::pin(async move {
            self.sent_requests.lock().unwrap().push(req.clone());
            if self.unreachable.load(Ordering::SeqCst) {
                return Err(DaemonIpcError::unreachable(
                    "Cannot reach hadald at /run/hadald/hadald.sock",
                ));
            }
            if self.reject_update_split.load(Ordering::SeqCst)
                && matches!(req, DaemonRequest::UpdateSplitTunnel(_))
            {
                return Err(DaemonIpcError::rejected("nft rule error"));
            }

            let mut guard = self.status.lock().unwrap();
            match req {
                DaemonRequest::Connect(spec) => {
                    guard.state = TunnelState::Protected;
                    guard.cluster_id = spec.cluster_id;
                    guard.domain = Some(spec.domain);
                    guard.endpoint = Some(format!("{}:{}", spec.endpoint_ip, spec.endpoint_port));
                    guard.location = spec.location;
                    guard.country = spec.country;
                    guard.mtu = Some(spec.mtu);
                    guard.killswitch = spec.killswitch;
                    guard.ipv6_block = spec.ipv6_block;
                    guard.bypass_lan = spec.bypass_lan;
                    guard.split_mode = spec.split_mode;
                    guard.split_cgroup_paths = spec.split_cgroup_paths;
                    guard.game_only_cidrs = spec.game_only_cidrs;
                    Ok(DaemonResponse::Status(guard.clone()))
                }
                DaemonRequest::Disconnect { keep_killswitch } => {
                    guard.killswitch = keep_killswitch;
                    guard.state = if keep_killswitch {
                        TunnelState::KillswitchLocked
                    } else {
                        TunnelState::Disconnected
                    };
                    guard.endpoint = None;
                    guard.game_only_cidrs.clear();
                    Ok(DaemonResponse::Status(guard.clone()))
                }
                DaemonRequest::SetKillswitch {
                    enabled,
                    ipv6_block,
                    bypass_lan,
                } => {
                    guard.killswitch = enabled;
                    guard.ipv6_block = ipv6_block;
                    guard.bypass_lan = bypass_lan;
                    if guard.state != TunnelState::Protected {
                        guard.state = if enabled {
                            TunnelState::KillswitchLocked
                        } else {
                            TunnelState::Disconnected
                        };
                    }
                    Ok(DaemonResponse::Status(guard.clone()))
                }
                DaemonRequest::UpdateSplitTunnel(cfg) => {
                    guard.split_mode = cfg.mode;
                    guard.split_cgroup_paths = cfg.cgroup_paths;
                    guard.game_only_cidrs = cfg.game_only_cidrs;
                    Ok(DaemonResponse::Status(guard.clone()))
                }
                DaemonRequest::ResetAppSockets { .. } | DaemonRequest::Shutdown => {
                    Ok(DaemonResponse::Ok)
                }
                _ => Ok(DaemonResponse::Status(guard.clone())),
            }
        })
    }

    fn prepare_connect_target<'a>(
        &'a self,
        domain: &'a str,
        auto_mtu: bool,
        manual_mtu: Option<u16>,
        endpoint_override: Option<&'a str>,
        mtu_override: Option<u16>,
    ) -> BoxFuture<'a, Result<(String, u16, u16), String>> {
        self.prepare_calls.lock().unwrap().push((
            domain.to_string(),
            auto_mtu,
            manual_mtu,
            endpoint_override.map(ToString::to_string),
            mtu_override,
        ));
        let ip = endpoint_override
            .and_then(|s| s.split(':').next())
            .unwrap_or("192.0.2.50")
            .to_string();
        let mtu = mtu_override.or(manual_mtu).unwrap_or(1412);
        Box::pin(async move { Ok((ip, 51820, mtu)) })
    }

    fn scan_gaming<'a>(
        &'a self,
        _clusters: &'a [Cluster],
        game_id: &'a str,
        region_id: &'a str,
        custom_host: Option<&'a str>,
    ) -> BoxFuture<'a, Result<GamingScanReport, String>> {
        self.scan_calls.lock().unwrap().push((
            game_id.to_string(),
            region_id.to_string(),
            custom_host.map(ToString::to_string),
        ));
        let report = self.scan_report.lock().unwrap().clone();
        Box::pin(async move { report.ok_or_else(|| "no report".to_string()) })
    }
}

#[derive(Default)]
struct FakeSettingsSplit {
    settings: StdMutex<AppSettings>,
    moved_pids: StdMutex<Vec<u32>>,
    reconcile_calls: StdMutex<Vec<(Vec<String>, SplitMode)>>,
    status_slices: StdMutex<Vec<Option<&'static str>>>,
    launched: StdMutex<Vec<(String, String)>>,
}

impl SettingsAndSplitBackend for FakeSettingsSplit {
    fn load_settings(&self) -> AppSettings {
        self.settings.lock().unwrap().clone()
    }

    fn save_settings(&self, settings: &AppSettings) -> Result<(), String> {
        *self.settings.lock().unwrap() = settings.clone();
        Ok(())
    }

    fn ensure_user_slice_dir(&self, slice: &str) -> Option<String> {
        Some(format!("user.slice/user-1000.slice/app.slice/{slice}"))
    }

    fn reconcile_split_slices(&self, apps: Vec<String>, mode: SplitMode) -> BoxFuture<'_, Vec<u32>> {
        self.reconcile_calls.lock().unwrap().push((apps, mode));
        Box::pin(async { self.moved_pids.lock().unwrap().clone() })
    }

    fn discover_desktop_apps(&self) -> BoxFuture<'_, Vec<DesktopAppEntry>> {
        Box::pin(async {
            vec![DesktopAppEntry {
                id: "steam".into(),
                name: "Steam".into(),
                exec: "steam".into(),
                bin: "steam".into(),
                wm_class: Some("steam".into()),
                running: true,
            }]
        })
    }

    fn app_statuses(
        &self,
        apps: Vec<String>,
        slice: Option<&'static str>,
    ) -> BoxFuture<'_, Vec<SplitAppStatus>> {
        self.status_slices.lock().unwrap().push(slice);
        Box::pin(async move {
            apps.into_iter()
                .map(|app| SplitAppStatus {
                    display_name: app.clone(),
                    name: app,
                    running: true,
                    pids: vec![123],
                    in_split_slice: slice.is_some(),
                    slice: slice.map(ToString::to_string),
                })
                .collect()
        })
    }

    fn launch_app_in_slice(&self, command: &str, slice: &str) -> Result<u32, String> {
        self.launched
            .lock()
            .unwrap()
            .push((command.to_string(), slice.to_string()));
        Ok(4242)
    }
}

#[derive(Default)]
struct FakeTray {
    updates: StdMutex<Vec<DaemonStatus>>,
}

impl TrayUpdater for FakeTray {
    fn update_status<'a>(&'a self, status: &'a DaemonStatus) -> BoxFuture<'a, ()> {
        let st = status.clone();
        Box::pin(async move {
            self.updates.lock().unwrap().push(st);
        })
    }
}

#[derive(Default)]
struct FakeEmitter {
    events: StdMutex<Vec<DaemonEnvelope>>,
}

impl StatusEmitter for FakeEmitter {
    fn emit_daemon_status(&self, env: &DaemonEnvelope) {
        self.events.lock().unwrap().push(env.clone());
    }
}

#[derive(Default)]
struct FakeNotifier {
    notes: StdMutex<Vec<(String, String)>>,
}

impl NotificationTransport for FakeNotifier {
    fn notify_connected<'a>(&'a self, summary: &'a str, body: &'a str) -> BoxFuture<'a, ()> {
        let s = summary.to_string();
        let b = body.to_string();
        Box::pin(async move {
            self.notes.lock().unwrap().push((s, b));
        })
    }
}

#[derive(Default)]
struct FakePresenter {
    toggles: AtomicUsize,
    exits: AtomicUsize,
}

impl WindowPresenter for FakePresenter {
    fn toggle_main_window(&self, _click_hint: Option<(i32, i32)>) {
        self.toggles.fetch_add(1, Ordering::SeqCst);
    }
    fn exit_app(&self) {
        self.exits.fetch_add(1, Ordering::SeqCst);
    }
}

struct ControllerHarness {
    ctrl: AppController,
    account: Arc<FakeAccount>,
    daemon: Arc<FakeDaemon>,
    settings_split: Arc<FakeSettingsSplit>,
    tray: Arc<FakeTray>,
    emitter: Arc<FakeEmitter>,
    notifier: Arc<FakeNotifier>,
}

fn new_harness() -> ControllerHarness {
    let account = Arc::new(FakeAccount::default());
    let daemon = Arc::new(FakeDaemon::default());
    let settings_split = Arc::new(FakeSettingsSplit::default());
    let tray = Arc::new(FakeTray::default());
    let emitter = Arc::new(FakeEmitter::default());
    let notifier = Arc::new(FakeNotifier::default());
    let ctrl = AppController::new(AppServices {
        account: account.clone(),
        daemon: daemon.clone(),
        settings_split: settings_split.clone(),
        notifier_transport: notifier.clone(),
        tray: tray.clone(),
        emitter: emitter.clone(),
    });
    ControllerHarness {
        ctrl,
        account,
        daemon,
        settings_split,
        tray,
        emitter,
        notifier,
    }
}

fn sample_gaming_report() -> GamingScanReport {
    GamingScanReport {
        game_id: "fortnite".into(),
        region_id: "eu-de".into(),
        target_host: "ping-de.ds.on.epicgames.com".into(),
        baseline_direct: None,
        active_tunnel_ping: None,
        active_tunnel_label: None,
        wan_pmtu: 1500,
        recommended_mtu: 1420,
        candidates: vec![EndpointCandidate {
            cluster_id: "de-fra".into(),
            domain: "de-fra.prod.surfshark.com".into(),
            endpoint_ip: "156.146.33.77".into(),
            location: "Frankfurt".into(),
            country: "Germany".into(),
            load: Some(22),
            direct_rtt_ms: 21.0,
            estimated_total_ms: 29.0,
            verified_tunnel_ms: Some(28.5),
            verified_mdev_ms: Some(0.3),
            verified_loss_pct: Some(0.0),
        }],
        game_cidrs: vec!["3.66.90.0/24".into()],
    }
}

#[tokio::test]
async fn auth_server_cache_connect_disconnect_and_killswitch_lifecycle() {
    let h = new_harness();

    assert!(h.ctrl.is_logged_in().await);
    assert_eq!(h.ctrl.create_remote_login().await.unwrap().code, "HADAL99");
    assert_eq!(
        h.ctrl.poll_remote_login("hash-99").await.unwrap().token.as_deref(),
        Some("pair-jwt")
    );
    assert_eq!(
        h.ctrl.get_user_me().await.unwrap().email.as_deref(),
        Some("user@example.com")
    );
    assert_eq!(h.ctrl.get_user_location().await.unwrap().ip, "198.51.100.5");

    // Cluster caching + forced refresh + logout cache eviction
    let first = h.ctrl.resolve_clusters(false).await.unwrap();
    let second = h.ctrl.resolve_clusters(false).await.unwrap();
    assert_eq!(first.len(), 2);
    assert_eq!(second.len(), 2);
    assert_eq!(h.account.cluster_fetches.load(Ordering::SeqCst), 1);

    let _ = h.ctrl.resolve_clusters(true).await.unwrap();
    assert_eq!(h.account.cluster_fetches.load(Ordering::SeqCst), 2);

    h.ctrl.logout().await.unwrap();
    assert!(!h.ctrl.is_logged_in().await);
    let _ = h.ctrl.resolve_clusters(false).await.unwrap();
    assert_eq!(h.account.cluster_fetches.load(Ordering::SeqCst), 3);

    // Quick connect selects lowest-load server (nl-ams = 12) when last_cluster_id is None
    let qc = h.ctrl.quick_connect().await.unwrap();
    assert_eq!(qc.state, TunnelState::Protected);
    assert_eq!(qc.cluster_id.as_deref(), Some("nl-ams"));
    assert_eq!(
        h.settings_split.settings.lock().unwrap().last_cluster_id.as_deref(),
        Some("nl-ams")
    );
    assert_eq!(h.account.registered_keys.lock().unwrap().len(), 1);
    assert_eq!(h.tray.updates.lock().unwrap().len(), 1);
    assert_eq!(h.notifier.notes.lock().unwrap().len(), 1);
    assert_eq!(h.emitter.events.lock().unwrap().len(), 1);

    // Explicit cluster connect validates missing fields & forwards overrides
    let err_missing = h
        .ctrl
        .connect_cluster("does-not-exist", None, None, vec![])
        .await
        .unwrap_err();
    assert!(err_missing.contains("not found"));

    h.account.clusters.lock().unwrap().push(Cluster {
        id: "broken-dom".into(),
        connection_name: None,
        ..make_cluster("broken-dom", "X", "Y", 1)
    });
    h.account.clusters.lock().unwrap().push(Cluster {
        id: "broken-pk".into(),
        pub_key: None,
        ..make_cluster("broken-pk", "X", "Y", 1)
    });
    h.ctrl.resolve_clusters(true).await.unwrap();
    assert!(h
        .ctrl
        .connect_cluster("broken-dom", None, None, vec![])
        .await
        .unwrap_err()
        .contains("no WireGuard domain"));
    assert!(h
        .ctrl
        .connect_cluster("broken-pk", None, None, vec![])
        .await
        .unwrap_err()
        .contains("no WireGuard public key"));

    let st = h
        .ctrl
        .connect_cluster(
            "de-fra",
            Some("198.51.100.88:51820"),
            Some(1400),
            vec!["3.66.0.0/16".into()],
        )
        .await
        .unwrap();
    assert_eq!(st.endpoint.as_deref(), Some("198.51.100.88:51820"));
    assert_eq!(st.mtu, Some(1400));
    assert_eq!(st.game_only_cidrs, vec!["3.66.0.0/16"]);

    // Disconnect & SetKillswitch persist settings + respect ipv6_block & bypass_lan
    let ks_st = h.ctrl.set_killswitch(false, true, false).await.unwrap();
    assert!(!ks_st.killswitch);
    assert!(ks_st.ipv6_block);
    assert!(!ks_st.bypass_lan);

    let disc = h.ctrl.disconnect_tunnel(true).await.unwrap();
    assert_eq!(disc.state, TunnelState::KillswitchLocked);
    assert!(h.settings_split.settings.lock().unwrap().killswitch);
}

#[tokio::test]
async fn settings_sync_split_tunnel_gaming_polling_and_tray_actions() {
    let h = new_harness();
    *h.daemon.status.lock().unwrap() = DaemonStatus {
        state: TunnelState::Protected,
        cluster_id: Some("de-fra".into()),
        location: Some("Frankfurt".into()),
        country: Some("Germany".into()),
        domain: Some("de-fra.prod.surfshark.com".into()),
        game_only_cidrs: vec!["3.66.0.0/16".into()],
        ..DaemonStatus::default()
    };
    *h.settings_split.moved_pids.lock().unwrap() = vec![701, 702];

    // 1. Save settings preserves custom cgroups, clears stale managed slice, preserves game CIDRs, syncs killswitch & resets sockets
    let mut next = AppSettings {
        killswitch: true,
        ipv6_block: false,
        bypass_lan: false,
        ..AppSettings::default()
    };
    next.split_tunnel.mode = SplitMode::OnlyVpn;
    next.split_tunnel.only_vpn_apps = vec!["steam".into()];
    next.split_tunnel.cgroup_paths = vec![
        "custom.slice/pinned.scope".into(),
        format!("user.slice/{BYPASS_SLICE}"),
    ];
    let saved = h.ctrl.save_settings_and_sync(next).await.unwrap();
    assert!(saved.split_tunnel.cgroup_paths.contains(&"custom.slice/pinned.scope".into()));
    assert!(!saved
        .split_tunnel
        .cgroup_paths
        .iter()
        .any(|p| p.ends_with(BYPASS_SLICE)));
    assert!(saved
        .split_tunnel
        .cgroup_paths
        .iter()
        .any(|p| p.ends_with(VPN_SLICE)));
    assert_eq!(
        h.settings_split.reconcile_calls.lock().unwrap().as_slice(),
        &[(vec!["steam".into()], SplitMode::OnlyVpn)]
    );

    let sent = h.daemon.sent_requests.lock().unwrap().clone();
    assert!(sent.iter().any(|r| matches!(
        r,
        DaemonRequest::UpdateSplitTunnel(cfg) if cfg.game_only_cidrs == vec!["3.66.0.0/16"]
    )));
    assert!(sent.iter().any(|r| matches!(
        r,
        DaemonRequest::SetKillswitch { enabled: true, ipv6_block: false, bypass_lan: false }
    )));
    assert!(sent.iter().any(|r| matches!(
        r,
        DaemonRequest::ResetAppSockets { pids } if pids == &vec![701, 702]
    )));

    // Reachable daemon rejection must surface as Err; unreachable daemon must succeed locally
    h.daemon.reject_update_split.store(true, Ordering::SeqCst);
    let rej_err = h
        .ctrl
        .save_settings_and_sync(saved.clone())
        .await
        .unwrap_err();
    assert!(rej_err.contains("nft rule error"));

    h.daemon.unreachable.store(true, Ordering::SeqCst);
    assert!(h.ctrl.save_settings_and_sync(saved.clone()).await.is_ok());

    // 2. split_launch_app launches in right slice and syncs daemon when reachable
    h.daemon.unreachable.store(false, Ordering::SeqCst);
    h.daemon.reject_update_split.store(false, Ordering::SeqCst);
    let pid = h
        .ctrl
        .split_launch_app("steam", SplitMode::OnlyVpn)
        .await
        .unwrap();
    assert_eq!(pid, 4242);
    assert_eq!(
        h.settings_split.launched.lock().unwrap().as_slice(),
        &[("steam".into(), VPN_SLICE.into())]
    );
    let apps = h
        .ctrl
        .get_split_app_statuses(vec!["steam".into()], SplitMode::Bypass)
        .await;
    assert_eq!(apps.len(), 1);
    assert_eq!(h.ctrl.discover_split_apps().await.len(), 1);

    // 3. Gaming scan + connect_gaming_best + gaming_quick_connect
    *h.daemon.scan_report.lock().unwrap() = Some(sample_gaming_report());
    let report = h
        .ctrl
        .scan_gaming("fortnite", "eu-de", Some("   "))
        .await
        .unwrap();
    assert_eq!(report.wan_pmtu, 1500);
    assert_eq!(
        h.daemon.scan_calls.lock().unwrap().last().unwrap().2,
        None
    );

    let g_rep = h
        .ctrl
        .connect_gaming_best("fortnite", "eu-de", Some("1.2.3.4"), true)
        .await
        .unwrap();
    assert_eq!(g_rep.recommended_mtu, 1420);
    let conn_status = h.daemon.status.lock().unwrap().clone();
    assert_eq!(conn_status.endpoint.as_deref(), Some("156.146.33.77:51820"));
    assert_eq!(conn_status.mtu, Some(1420));
    assert_eq!(conn_status.game_only_cidrs, vec!["3.66.90.0/24"]);

    // 4. poll_once passive startup suppresses spurious initial notification, then area change fires notification once
    let h_poll = new_harness();
    *h_poll.daemon.status.lock().unwrap() = DaemonStatus {
        state: TunnelState::Protected,
        cluster_id: Some("de-fra".into()),
        location: Some("Frankfurt".into()),
        country: Some("Germany".into()),
        ..DaemonStatus::default()
    };
    h_poll.ctrl.poll_once().await;
    assert!(h_poll.notifier.notes.lock().unwrap().is_empty());
    assert_eq!(h_poll.emitter.events.lock().unwrap().len(), 1);

    // Repeating identical poll does not re-emit
    h_poll.ctrl.poll_once().await;
    assert_eq!(h_poll.emitter.events.lock().unwrap().len(), 1);

    // Switching server area triggers 1 notification + new emission
    *h_poll.daemon.status.lock().unwrap() = DaemonStatus {
        state: TunnelState::Protected,
        cluster_id: Some("nl-ams".into()),
        location: Some("Amsterdam".into()),
        country: Some("Netherlands".into()),
        ..DaemonStatus::default()
    };
    h_poll.ctrl.poll_once().await;
    assert_eq!(h_poll.notifier.notes.lock().unwrap().len(), 1);
    assert_eq!(
        h_poll.notifier.notes.lock().unwrap()[0].0,
        "Connected to Amsterdam, Netherlands"
    );
    assert_eq!(h_poll.emitter.events.lock().unwrap().len(), 2);

    // 5. Tray menu actions
    let presenter = Arc::new(FakePresenter::default());
    handle_tray_menu_action("toggle", &h.ctrl, presenter.as_ref()).await;
    handle_tray_menu_action("disconnect", &h.ctrl, presenter.as_ref()).await;
    handle_tray_menu_action("quick_connect", &h.ctrl, presenter.as_ref()).await;
    handle_tray_menu_action("gaming_connect", &h.ctrl, presenter.as_ref()).await;
    handle_tray_menu_action("quit", &h.ctrl, presenter.as_ref()).await;
    assert_eq!(presenter.toggles.load(Ordering::SeqCst), 1);
    assert_eq!(presenter.exits.load(Ordering::SeqCst), 1);
}

#[test]
fn tray_badge_palette_and_label_formatting_match_abyssal_precision() {
    assert_eq!(badge_dot_rgb(TunnelState::Protected), (16, 209, 144));
    assert_eq!(badge_dot_rgb(TunnelState::Connecting), (34, 211, 238));
    assert_eq!(badge_dot_rgb(TunnelState::KillswitchLocked), (244, 63, 94));
    assert_eq!(badge_dot_rgb(TunnelState::Disconnected), (100, 116, 139));

    for state in [
        TunnelState::Protected,
        TunnelState::Connecting,
        TunnelState::KillswitchLocked,
        TunnelState::Disconnected,
    ] {
        let img = render_tray_badge(state);
        assert_eq!(img.width(), 64);
        assert_eq!(img.height(), 64);
        let rgba = img.rgba();
        // Top-left corner (0,0) outside squircle must stay transparent
        assert_eq!(&rgba[0..4], &[0, 0, 0, 0]);

        let has_rgb = |target: (u8, u8, u8)| {
            rgba.as_chunks::<4>()
                .0
                .iter()
                .any(|p| p[3] == 255 && (p[0], p[1], p[2]) == target)
        };
        assert!(has_rgb(BADGE_BODY_RGB));
        assert!(has_rgb(BADGE_MARK_RGB));
        assert!(has_rgb(badge_dot_rgb(state)));
    }

    assert_eq!(
        format_tray_label(&DaemonStatus {
            state: TunnelState::Protected,
            location: Some("Frankfurt".into()),
            ..DaemonStatus::default()
        }),
        "Protected · Frankfurt"
    );
    assert_eq!(
        format_tray_label(&DaemonStatus {
            state: TunnelState::Connecting,
            ..DaemonStatus::default()
        }),
        "Connecting tunnel…"
    );
    assert_eq!(
        format_tray_label(&DaemonStatus {
            state: TunnelState::KillswitchLocked,
            ..DaemonStatus::default()
        }),
        "Killswitch Locked"
    );
    assert_eq!(
        format_tray_label(&DaemonStatus::default()),
        "Disconnected"
    );
}

struct FakeHyprTransport {
    enabled: bool,
    monitors_json: String,
    cursor_json: String,
    clients_sequence: StdMutex<Vec<String>>,
    evals: StdMutex<Vec<String>>,
    pid: u32,
}

impl HyprlandTransport for FakeHyprTransport {
    fn is_hyprland(&self) -> bool {
        self.enabled
    }

    fn query_raw_json(&self, subcmd: &str) -> Option<String> {
        match subcmd {
            "monitors" => Some(self.monitors_json.clone()),
            "cursorpos" => Some(self.cursor_json.clone()),
            "clients" => {
                let mut seq = self.clients_sequence.lock().unwrap();
                if seq.len() > 1 {
                    Some(seq.remove(0))
                } else {
                    seq.first().cloned()
                }
            }
            _ => None,
        }
    }

    fn eval_lua(&self, lua: &str) {
        self.evals.lock().unwrap().push(lua.to_string());
    }

    fn current_pid(&self) -> u32 {
        self.pid
    }

    fn socket2_path(&self) -> Option<std::path::PathBuf> {
        None
    }
}

#[test]
fn hyprland_layout_window_snapping_and_notifier_invariants() {
    assert_eq!(
        classify_socket2_event("configreloaded>>1"),
        Socket2Action::ConfigReloaded
    );
    assert_eq!(
        classify_socket2_event("openwindow>>0xabc,1,hadal-gui,Hadal VPN"),
        Socket2Action::HadalWindowOpened
    );
    assert_eq!(
        classify_socket2_event("openwindow>>0xabc,1,firefox,Mozilla"),
        Socket2Action::Ignore
    );
    assert!(build_popover_rule_lua(Some((120, 48)))
        .contains(&format!("size = {{ {POPOVER_W}, {POPOVER_H} }}, move = \"120 48\"")));

    // Scaled & rotated secondary monitor with top bar reserved=40px
    let transport = Arc::new(FakeHyprTransport {
        enabled: true,
        monitors_json: serde_json::json!([
            {"x": 0, "y": 0, "width": 1920, "height": 1080, "scale": 1.0, "reserved": [0, 0, 0, 44], "focused": true},
            {"x": 1920, "y": 0, "width": 2160, "height": 3840, "scale": 1.5, "transform": 1, "reserved": [0, 40, 0, 0], "focused": false}
        ])
        .to_string(),
        cursor_json: r#"{"x": 3000, "y": 20}"#.into(),
        clients_sequence: StdMutex::new(vec![
            "[]".into(),
            serde_json::json!([
                {"address": "0x11", "pid": 9999, "mapped": true, "tags": []},
                {"address": "0x22", "pid": 4242, "mapped": true, "tags": []}
            ])
            .to_string(),
        ]),
        evals: StdMutex::new(Vec::new()),
        pid: 4242,
    });

    let hypr = HyprlandController::new(transport.clone());
    // Logical size of monitor 2 after transform=1 + scale=1.5 is (2560, 1440), top reserved=40 => y = 0 + 40 + 10 = 50
    let pos = hypr.compute_tray_popover_pos(Some((3000, 20))).unwrap();
    assert_eq!(pos, (3000 - POPOVER_W / 2, 50));

    assert!(hypr.snap_window_to_tray_with_attempts(Some((3000, 20)), 3, Duration::ZERO));
    let evals = transport.evals.lock().unwrap();
    assert!(evals.iter().any(|l| l.contains("hl.window_rule")));
    assert!(evals
        .iter()
        .any(|l| l.contains("address:0x22") && l.contains(&format!("y = {}", pos.1))));
    drop(evals);

    hypr.handle_socket2_event("configreloaded");
    assert!(transport.evals.lock().unwrap().len() >= 3);

    // ConnectionNotifier + Game-only detail formatting
    let mut notifier = ConnectionNotifier::default();
    let game_st = DaemonStatus {
        state: TunnelState::Protected,
        cluster_id: Some("de-fra".into()),
        location: Some("Frankfurt".into()),
        country: Some("Germany".into()),
        domain: Some("de-fra.prod.surfshark.com".into()),
        mtu: Some(1412),
        game_only_cidrs: vec!["3.66.0.0/16".into()],
        ..DaemonStatus::default()
    };
    let (summary, body) = format_connected_notification(&game_st).unwrap();
    assert_eq!(summary, "Connected to Frankfurt, Germany");
    assert!(body.contains("MTU 1412"));
    assert!(body.contains("Game-only"));

    // Passive poll suppresses initial alert; unreachable resets baseline so recovery alerts once
    assert_eq!(notifier.record_and_check(true, &game_st, false), None);
    assert_eq!(notifier.record_and_check(false, &game_st, false), None);
    assert!(notifier.record_and_check(true, &game_st, false).is_some());
}
