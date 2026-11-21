use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use hadal_core::auth::{AuthResponse, RemoteCodeResponse, UserMe};
use hadal_core::{
    active_slice_for_mode, find_game_region, AppSettings, Cluster, ConnectSpec, DaemonRequest,
    DaemonResponse, DaemonStatus, DesktopAppEntry, GamingScanReport, SplitAppStatus, SplitMode,
    TunnelState, UserLocation, WgKeyPair, BYPASS_SLICE, DEFAULT_WG_PORT, VPN_SLICE,
    default_tunnel_dns,
};

use crate::backend::{
    AccountApi, DaemonBridge, DaemonIpcError, SettingsAndSplitBackend, StatusEmitter, TrayUpdater,
};
use crate::notifications::{ConnectionNotifier, NotificationTransport};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonEnvelope {
    pub reachable: bool,
    pub status: DaemonStatus,
    pub error: Option<String>,
}

/// Core injectable Tauri backend services.
#[derive(Clone)]
pub struct AppServices {
    pub account: Arc<dyn AccountApi>,
    pub daemon: Arc<dyn DaemonBridge>,
    pub settings_split: Arc<dyn SettingsAndSplitBackend>,
    pub notifier_transport: Arc<dyn NotificationTransport>,
    pub tray: Arc<dyn TrayUpdater>,
    pub emitter: Arc<dyn StatusEmitter>,
}

/// Stateful backend orchestrator driving all Tauri IPC commands, tray actions, and background polling.
pub struct AppController {
    services: AppServices,
    clusters_cache: Mutex<Vec<Cluster>>,
    notifier: Mutex<ConnectionNotifier>,
    prev_poll_key: Mutex<String>,
}

impl AppController {
    pub fn new(services: AppServices) -> Self {
        Self {
            services,
            clusters_cache: Mutex::new(Vec::new()),
            notifier: Mutex::new(ConnectionNotifier::default()),
            prev_poll_key: Mutex::new(String::new()),
        }
    }

    pub fn build_split_cgroups(&self, mode: SplitMode, custom_paths: &[String]) -> Vec<String> {
        let mut out: Vec<String> = custom_paths
            .iter()
            .filter(|p| !is_managed_slice_path(p))
            .cloned()
            .collect();
        if let Some(slice) = active_slice_for_mode(mode) {
            if let Some(rel) = self.services.settings_split.ensure_user_slice_dir(slice) {
                if !out.contains(&rel) {
                    out.push(rel);
                }
            }
        }
        out
    }

    pub async fn is_logged_in(&self) -> bool {
        self.services.account.is_logged_in().await
    }

    pub async fn create_remote_login(&self) -> Result<RemoteCodeResponse, String> {
        self.services.account.create_remote_login().await
    }

    pub async fn poll_remote_login(&self, hash: &str) -> Result<AuthResponse, String> {
        self.services.account.poll_remote_login(hash).await
    }

    pub async fn get_user_me(&self) -> Result<UserMe, String> {
        self.services.account.get_user_me().await
    }

    pub async fn logout(&self) -> Result<(), String> {
        self.services.account.clear_session().await;
        *self.clusters_cache.lock().await = Vec::new();
        Ok(())
    }

    pub async fn resolve_clusters(&self, force_refresh: bool) -> Result<Vec<Cluster>, String> {
        if !force_refresh {
            let cached = self.clusters_cache.lock().await;
            if !cached.is_empty() {
                return Ok(cached.clone());
            }
        }
        let fresh = self.services.account.get_clusters().await?;
        *self.clusters_cache.lock().await = fresh.clone();
        Ok(fresh)
    }

    pub async fn get_user_location(&self) -> Result<UserLocation, String> {
        self.services.account.get_user_location().await
    }

    pub async fn fetch_envelope(&self) -> DaemonEnvelope {
        match self.services.daemon.query_status().await {
            Ok(status) => DaemonEnvelope {
                reachable: true,
                status,
                error: None,
            },
            Err(e) => DaemonEnvelope {
                reachable: false,
                status: DaemonStatus::default(),
                error: Some(e.message),
            },
        }
    }

    pub async fn get_daemon_status(&self) -> DaemonEnvelope {
        let env = self.fetch_envelope().await;
        if env.reachable {
            self.services.tray.update_status(&env.status).await;
        }
        env
    }

    pub async fn connect_cluster(
        &self,
        cluster_id: &str,
        endpoint_override: Option<&str>,
        mtu_override: Option<u16>,
        game_only_cidrs: Vec<String>,
    ) -> Result<DaemonStatus, String> {
        let clusters = self.resolve_clusters(false).await?;
        let cluster = clusters
            .into_iter()
            .find(|c| c.id == cluster_id)
            .ok_or_else(|| format!("Cluster '{cluster_id}' not found"))?;
        self.execute_cluster_connect(&cluster, endpoint_override, mtu_override, game_only_cidrs)
            .await
    }

    pub async fn quick_connect(&self) -> Result<DaemonStatus, String> {
        let clusters = self.resolve_clusters(false).await?;
        let settings = self.services.settings_split.load_settings();
        let chosen = settings
            .last_cluster_id
            .as_deref()
            .and_then(|cid| clusters.iter().find(|c| c.id == cid).cloned())
            .or_else(|| clusters.into_iter().min_by_key(|c| c.load.unwrap_or(999)))
            .ok_or_else(|| "No servers available".to_string())?;
        self.execute_cluster_connect(&chosen, None, None, Vec::new())
            .await
    }

    pub async fn execute_cluster_connect(
        &self,
        cluster: &Cluster,
        endpoint_override: Option<&str>,
        mtu_override: Option<u16>,
        game_only_cidrs: Vec<String>,
    ) -> Result<DaemonStatus, String> {
        let domain = cluster.connection_name.as_deref().unwrap_or("");
        if domain.is_empty() {
            return Err("Selected server has no WireGuard domain".to_string());
        }
        let pub_key = cluster.pub_key.clone().unwrap_or_default();
        if pub_key.is_empty() {
            return Err("Selected server has no WireGuard public key".to_string());
        }

        let mut settings = self.services.settings_split.load_settings();
        let (ep_ip, ep_port, effective_mtu) = self
            .services
            .daemon
            .prepare_connect_target(
                domain,
                settings.auto_mtu,
                settings.manual_mtu,
                endpoint_override,
                mtu_override,
            )
            .await?;

        let keys = WgKeyPair::generate();
        let reg = self
            .services
            .account
            .register_public_key(&keys.public_key)
            .await?;

        let split_cgroups = self.build_split_cgroups(
            settings.split_tunnel.mode,
            &settings.split_tunnel.cgroup_paths,
        );

        let spec = ConnectSpec {
            cluster_id: Some(cluster.id.clone()),
            domain: domain.to_string(),
            endpoint_ip: ep_ip,
            endpoint_port: ep_port,
            pub_key,
            priv_key: keys.private_key,
            address: reg.wireguard_address(),
            dns: default_tunnel_dns(),
            mtu: effective_mtu,
            killswitch: settings.killswitch,
            ipv6_block: settings.ipv6_block,
            bypass_lan: settings.bypass_lan,
            split_mode: settings.split_tunnel.mode,
            split_cgroup_paths: split_cgroups,
            game_only_cidrs,
            location: cluster.location.clone(),
            country: cluster.country.clone(),
        };

        let resp = self
            .services
            .daemon
            .send(DaemonRequest::Connect(spec))
            .await
            .map_err(String::from)?;

        settings.last_cluster_id = Some(cluster.id.clone());
        let _ = self.services.settings_split.save_settings(&settings);

        match resp {
            DaemonResponse::Status(st) => {
                self.notify_status_changed(&st, true).await;
                Ok(st)
            }
            other => Err(format!("Unexpected daemon response: {other:?}")),
        }
    }

    pub async fn disconnect_tunnel(&self, keep_killswitch: bool) -> Result<DaemonStatus, String> {
        let mut settings = self.services.settings_split.load_settings();
        if settings.killswitch != keep_killswitch {
            settings.killswitch = keep_killswitch;
            let _ = self.services.settings_split.save_settings(&settings);
        }

        let resp = self
            .services
            .daemon
            .send(DaemonRequest::Disconnect { keep_killswitch })
            .await
            .map_err(String::from)?;
        match resp {
            DaemonResponse::Status(st) => {
                self.notify_status_changed(&st, false).await;
                Ok(st)
            }
            other => Err(format!("Unexpected daemon response: {other:?}")),
        }
    }

    pub async fn set_killswitch(
        &self,
        enabled: bool,
        ipv6_block: bool,
        bypass_lan: bool,
    ) -> Result<DaemonStatus, String> {
        let mut settings = self.services.settings_split.load_settings();
        settings.killswitch = enabled;
        settings.ipv6_block = ipv6_block;
        settings.bypass_lan = bypass_lan;
        let _ = self.services.settings_split.save_settings(&settings);

        let resp = self
            .services
            .daemon
            .send(DaemonRequest::SetKillswitch {
                enabled,
                ipv6_block,
                bypass_lan,
            })
            .await
            .map_err(String::from)?;
        match resp {
            DaemonResponse::Status(st) => {
                self.notify_status_changed(&st, false).await;
                Ok(st)
            }
            other => Err(format!("Unexpected daemon response: {other:?}")),
        }
    }

    pub fn get_settings(&self) -> AppSettings {
        self.services.settings_split.load_settings()
    }

    pub async fn save_settings_and_sync(
        &self,
        mut settings: AppSettings,
    ) -> Result<AppSettings, String> {
        let prev = self.services.settings_split.load_settings();
        settings.split_tunnel.sync_active_apps();
        settings.split_tunnel.cgroup_paths = self.build_split_cgroups(
            settings.split_tunnel.mode,
            &settings.split_tunnel.cgroup_paths,
        );
        self.services.settings_split.save_settings(&settings)?;

        let active_apps = settings
            .split_tunnel
            .apps_for_mode(settings.split_tunnel.mode)
            .to_vec();
        let mode = settings.split_tunnel.mode;
        let moved_pids = self
            .services
            .settings_split
            .reconcile_split_slices(active_apps, mode)
            .await;

        let cur_status = match self.services.daemon.query_status().await {
            Ok(st) => st,
            Err(DaemonIpcError {
                unreachable: true, ..
            }) => return Ok(settings),
            Err(err) => return Err(err.message),
        };

        let mut split_req = settings.split_tunnel.clone();
        if split_req.game_only_cidrs.is_empty() && !cur_status.game_only_cidrs.is_empty() {
            split_req.game_only_cidrs = cur_status.game_only_cidrs;
        }

        let mut st = match self
            .services
            .daemon
            .send(DaemonRequest::UpdateSplitTunnel(split_req))
            .await
        {
            Ok(DaemonResponse::Status(st)) => st,
            Ok(other) => return Err(format!("Unexpected daemon response: {other:?}")),
            Err(e) => return Err(e.message),
        };

        if prev.killswitch != settings.killswitch
            || prev.bypass_lan != settings.bypass_lan
            || prev.ipv6_block != settings.ipv6_block
        {
            match self
                .services
                .daemon
                .send(DaemonRequest::SetKillswitch {
                    enabled: settings.killswitch,
                    ipv6_block: settings.ipv6_block,
                    bypass_lan: settings.bypass_lan,
                })
                .await
            {
                Ok(DaemonResponse::Status(st2)) => st = st2,
                Ok(other) => return Err(format!("Unexpected daemon response: {other:?}")),
                Err(e) => return Err(e.message),
            }
        }

        if !moved_pids.is_empty() && st.state == TunnelState::Protected {
            if let Err(e) = self
                .services
                .daemon
                .send(DaemonRequest::ResetAppSockets { pids: moved_pids })
                .await
            {
                return Err(e.message);
            }
        }

        self.notify_status_changed(&st, false).await;
        Ok(settings)
    }

    pub async fn run_gaming_scan(
        &self,
        game_id: &str,
        region_id: &str,
        custom_host: Option<&str>,
    ) -> Result<(Vec<Cluster>, GamingScanReport), String> {
        let clusters = self.resolve_clusters(false).await?;
        let host_opt = custom_host.map(str::trim).filter(|s| !s.is_empty());
        let report = self
            .services
            .daemon
            .scan_gaming(&clusters, game_id, region_id, host_opt)
            .await?;
        Ok((clusters, report))
    }

    pub async fn scan_gaming(
        &self,
        game_id: &str,
        region_id: &str,
        custom_host: Option<&str>,
    ) -> Result<GamingScanReport, String> {
        let (_, report) = self
            .run_gaming_scan(game_id, region_id, custom_host)
            .await?;
        Ok(report)
    }

    pub async fn connect_gaming_best(
        &self,
        game_id: &str,
        region_id: &str,
        custom_host: Option<&str>,
        game_only: bool,
    ) -> Result<GamingScanReport, String> {
        let (clusters, report) = self
            .run_gaming_scan(game_id, region_id, custom_host)
            .await?;

        let best = report
            .candidates
            .first()
            .ok_or_else(|| "No reachable Surfshark gaming endpoints found".to_string())?;
        let cluster = clusters
            .into_iter()
            .find(|c| c.id == best.cluster_id)
            .ok_or_else(|| "Best cluster missing from list".to_string())?;

        let cidrs = if game_only {
            report.game_cidrs.clone()
        } else {
            Vec::new()
        };
        let ep = format!("{}:{DEFAULT_WG_PORT}", best.endpoint_ip);
        self.execute_cluster_connect(&cluster, Some(&ep), Some(report.recommended_mtu), cidrs)
            .await?;

        Ok(report)
    }

    pub async fn gaming_quick_connect(&self) -> Result<GamingScanReport, String> {
        let settings = self.services.settings_split.load_settings();
        if find_game_region(&settings.favorite_game, &settings.favorite_game_region).is_none() {
            return Err("Configured favorite game/region is unknown".into());
        }
        self.connect_gaming_best(
            &settings.favorite_game,
            &settings.favorite_game_region,
            None,
            settings.game_only_routing,
        )
        .await
    }

    pub async fn get_split_app_statuses(
        &self,
        apps: Vec<String>,
        mode: SplitMode,
    ) -> Vec<SplitAppStatus> {
        self.services
            .settings_split
            .app_statuses(apps, active_slice_for_mode(mode))
            .await
    }

    pub async fn discover_split_apps(&self) -> Vec<DesktopAppEntry> {
        self.services.settings_split.discover_desktop_apps().await
    }

    pub async fn split_launch_app(&self, command: &str, mode: SplitMode) -> Result<u32, String> {
        let slice = active_slice_for_mode(mode).unwrap_or(BYPASS_SLICE);
        let pid = self
            .services
            .settings_split
            .launch_app_in_slice(command, slice)?;

        let mut settings = self.services.settings_split.load_settings();
        settings.split_tunnel.mode = mode;
        settings.split_tunnel.sync_active_apps();
        settings.split_tunnel.cgroup_paths =
            self.build_split_cgroups(mode, &settings.split_tunnel.cgroup_paths);

        if let Ok(cur_status) = self.services.daemon.query_status().await {
            let mut split_req = settings.split_tunnel.clone();
            if split_req.game_only_cidrs.is_empty() && !cur_status.game_only_cidrs.is_empty() {
                split_req.game_only_cidrs = cur_status.game_only_cidrs;
            }
            if let Err(err) = self
                .services
                .daemon
                .send(DaemonRequest::UpdateSplitTunnel(split_req))
                .await
            {
                if !err.unreachable {
                    return Err(err.message);
                }
            }
        }
        Ok(pid)
    }

    pub async fn poll_once(&self) {
        let env = self.fetch_envelope().await;
        self.maybe_notify_connected(env.reachable, &env.status, false)
            .await;

        let cfg = self.services.settings_split.load_settings();
        let active_apps = cfg
            .split_tunnel
            .apps_for_mode(cfg.split_tunnel.mode)
            .to_vec();

        if env.reachable
            && matches!(
                env.status.state,
                TunnelState::Protected | TunnelState::Connecting
            )
        {
            let moved_pids = self
                .services
                .settings_split
                .reconcile_split_slices(active_apps, cfg.split_tunnel.mode)
                .await;
            if !moved_pids.is_empty() && env.status.state == TunnelState::Protected {
                let _ = self
                    .services
                    .daemon
                    .send(DaemonRequest::ResetAppSockets { pids: moved_pids })
                    .await;
            }
        }

        let key = format!(
            "{}:{:?}:{}:{}:{}:{:?}:{}:{}:{}",
            env.reachable,
            env.status.state,
            env.status.location.as_deref().unwrap_or(""),
            env.status.endpoint.as_deref().unwrap_or(""),
            env.status.killswitch,
            env.status.split_mode,
            env.status.last_error.as_deref().unwrap_or(""),
            env.status.rx_bytes,
            env.status.tx_bytes
        );

        let mut prev = self.prev_poll_key.lock().await;
        if *prev != key {
            *prev = key;
            drop(prev);
            self.services.tray.update_status(&env.status).await;
            self.services.emitter.emit_daemon_status(&env);
        }
    }

    async fn maybe_notify_connected(
        &self,
        reachable: bool,
        status: &DaemonStatus,
        explicit_connect: bool,
    ) {
        let note = {
            let mut guard = self.notifier.lock().await;
            guard.record_and_check(reachable, status, explicit_connect)
        };
        if let Some((summary, body)) = note {
            self.services
                .notifier_transport
                .notify_connected(&summary, &body)
                .await;
        }
    }

    async fn notify_status_changed(&self, st: &DaemonStatus, explicit_connect: bool) {
        self.services.tray.update_status(st).await;
        self.maybe_notify_connected(true, st, explicit_connect).await;
        let env = DaemonEnvelope {
            reachable: true,
            status: st.clone(),
            error: None,
        };
        self.services.emitter.emit_daemon_status(&env);
    }
}

fn is_managed_slice_path(path: &str) -> bool {
    let trimmed = path.trim().trim_end_matches('/');
    trimmed.ends_with(BYPASS_SLICE) || trimmed.ends_with(VPN_SLICE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex as StdMutex;
    use crate::backend::BoxFuture;
    use hadal_core::RegisterPublicKeyResponse;

    #[derive(Default)]
    struct FakeAccount;
    impl AccountApi for FakeAccount {
        fn is_logged_in(&self) -> BoxFuture<'_, bool> {
            Box::pin(async { true })
        }
        fn create_remote_login(&self) -> BoxFuture<'_, Result<RemoteCodeResponse, String>> {
            Box::pin(async { Err("unused".into()) })
        }
        fn poll_remote_login<'a>(&'a self, _h: &'a str) -> BoxFuture<'a, Result<AuthResponse, String>> {
            Box::pin(async { Err("unused".into()) })
        }
        fn get_user_me(&self) -> BoxFuture<'_, Result<UserMe, String>> {
            Box::pin(async {
                Ok(UserMe {
                    id: Some("1".into()),
                    email: Some("u@test".into()),
                    status: None,
                    expires_at: None,
                    extra: serde_json::Value::Null,
                })
            })
        }
        fn clear_session(&self) -> BoxFuture<'_, ()> {
            Box::pin(async {})
        }
        fn get_clusters(&self) -> BoxFuture<'_, Result<Vec<Cluster>, String>> {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn get_user_location(&self) -> BoxFuture<'_, Result<UserLocation, String>> {
            Box::pin(async { Err("unused".into()) })
        }
        fn register_public_key<'a>(&'a self, _pk: &'a str) -> BoxFuture<'a, Result<RegisterPublicKeyResponse, String>> {
            Box::pin(async { Err("unused".into()) })
        }
    }

    #[derive(Default)]
    struct FakeDaemon {
        unreachable: AtomicBool,
        reject_update_split: AtomicBool,
        status: StdMutex<DaemonStatus>,
        sent_requests: StdMutex<Vec<DaemonRequest>>,
    }

    impl DaemonBridge for FakeDaemon {
        fn query_status(&self) -> BoxFuture<'_, Result<DaemonStatus, DaemonIpcError>> {
            Box::pin(async {
                if self.unreachable.load(Ordering::SeqCst) {
                    return Err(DaemonIpcError::unreachable("Cannot reach hadald at /run/hadald/hadald.sock"));
                }
                Ok(self.status.lock().unwrap().clone())
            })
        }
        fn send(&self, req: DaemonRequest) -> BoxFuture<'_, Result<DaemonResponse, DaemonIpcError>> {
            Box::pin(async move {
                self.sent_requests.lock().unwrap().push(req.clone());
                if self.unreachable.load(Ordering::SeqCst) {
                    return Err(DaemonIpcError::unreachable("Cannot reach hadald at /run/hadald/hadald.sock"));
                }
                if self.reject_update_split.load(Ordering::SeqCst)
                    && matches!(req, DaemonRequest::UpdateSplitTunnel(_))
                {
                    return Err(DaemonIpcError::rejected("nft failed"));
                }
                let st = self.status.lock().unwrap().clone();
                match req {
                    DaemonRequest::ResetAppSockets { .. } => Ok(DaemonResponse::Ok),
                    _ => Ok(DaemonResponse::Status(st)),
                }
            })
        }
        fn prepare_connect_target<'a>(&'a self, _d: &'a str, _a: bool, _m: Option<u16>, _e: Option<&'a str>, _mo: Option<u16>) -> BoxFuture<'a, Result<(String, u16, u16), String>> {
            Box::pin(async { Ok(("192.0.2.1".into(), 51820, 1412)) })
        }
        fn scan_gaming<'a>(&'a self, _c: &'a [Cluster], _g: &'a str, _r: &'a str, _ch: Option<&'a str>) -> BoxFuture<'a, Result<GamingScanReport, String>> {
            Box::pin(async { Err("unused".into()) })
        }
    }

    #[derive(Default)]
    struct FakeSettingsSplit {
        settings: StdMutex<AppSettings>,
        moved_pids: StdMutex<Vec<u32>>,
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
            Some(format!("user.slice/app.slice/{slice}"))
        }
        fn reconcile_split_slices(&self, _apps: Vec<String>, _mode: SplitMode) -> BoxFuture<'_, Vec<u32>> {
            Box::pin(async { self.moved_pids.lock().unwrap().clone() })
        }
        fn discover_desktop_apps(&self) -> BoxFuture<'_, Vec<DesktopAppEntry>> {
            Box::pin(async { Vec::new() })
        }
        fn app_statuses(&self, _apps: Vec<String>, _slice: Option<&'static str>) -> BoxFuture<'_, Vec<SplitAppStatus>> {
            Box::pin(async { Vec::new() })
        }
        fn launch_app_in_slice(&self, command: &str, slice: &str) -> Result<u32, String> {
            self.launched.lock().unwrap().push((command.into(), slice.into()));
            Ok(999)
        }
    }

    #[derive(Default)]
    struct FakeTray {
        updates: StdMutex<Vec<TunnelState>>,
    }
    impl TrayUpdater for FakeTray {
        fn update_status<'a>(&'a self, status: &'a DaemonStatus) -> BoxFuture<'a, ()> {
            let state = status.state;
            Box::pin(async move {
                self.updates.lock().unwrap().push(state);
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

    struct TestHarness {
        ctrl: AppController,
        daemon: Arc<FakeDaemon>,
        settings_split: Arc<FakeSettingsSplit>,
        tray: Arc<FakeTray>,
        emitter: Arc<FakeEmitter>,
        notifier: Arc<FakeNotifier>,
    }

    fn make_controller() -> TestHarness {
        let daemon = Arc::new(FakeDaemon::default());
        let settings_split = Arc::new(FakeSettingsSplit::default());
        let tray = Arc::new(FakeTray::default());
        let emitter = Arc::new(FakeEmitter::default());
        let notifier = Arc::new(FakeNotifier::default());
        let ctrl = AppController::new(AppServices {
            account: Arc::new(FakeAccount),
            daemon: daemon.clone(),
            settings_split: settings_split.clone(),
            notifier_transport: notifier.clone(),
            tray: tray.clone(),
            emitter: emitter.clone(),
        });
        TestHarness {
            ctrl,
            daemon,
            settings_split,
            tray,
            emitter,
            notifier,
        }
    }

    #[tokio::test]
    async fn save_settings_preserves_custom_cgroups_respects_ipv6_and_propagates_errors() {
        let h = make_controller();
        *h.daemon.status.lock().unwrap() = DaemonStatus {
            state: TunnelState::Protected,
            game_only_cidrs: vec!["3.66.0.0/16".into()],
            ..DaemonStatus::default()
        };
        *h.settings_split.moved_pids.lock().unwrap() = vec![1234];

        let mut next = AppSettings {
            ipv6_block: false,
            ..Default::default()
        };
        next.split_tunnel.mode = SplitMode::OnlyVpn;
        next.split_tunnel.cgroup_paths = vec![
            "user.slice/app.slice/app-hadal_bypass.slice".into(),
            "custom.slice/gaming".into(),
        ];

        let saved = h.ctrl.save_settings_and_sync(next.clone()).await.unwrap();
        assert!(!saved.ipv6_block);
        assert_eq!(
            saved.split_tunnel.cgroup_paths,
            vec![
                "custom.slice/gaming".to_string(),
                format!("user.slice/app.slice/{VPN_SLICE}")
            ]
        );

        let sent = h.daemon.sent_requests.lock().unwrap().clone();
        assert!(matches!(&sent[0], DaemonRequest::UpdateSplitTunnel(cfg) if cfg.game_only_cidrs == vec!["3.66.0.0/16"]));
        assert!(matches!(&sent[1], DaemonRequest::SetKillswitch { ipv6_block: false, .. }));
        assert!(matches!(&sent[2], DaemonRequest::ResetAppSockets { pids } if pids == &[1234]));

        // Daemon rejection must propagate rather than silently succeed
        h.daemon.reject_update_split.store(true, Ordering::SeqCst);
        let err = h.ctrl.save_settings_and_sync(next.clone()).await.unwrap_err();
        assert_eq!(err, "nft failed");

        // Unreachable daemon still persists settings locally cleanly
        h.daemon.reject_update_split.store(false, Ordering::SeqCst);
        h.daemon.unreachable.store(true, Ordering::SeqCst);
        let offline_saved = h.ctrl.save_settings_and_sync(next).await.unwrap();
        assert!(!offline_saved.ipv6_block);
    }

    #[tokio::test]
    async fn split_launch_syncs_daemon_and_poll_once_notifies_on_new_connection() {
        let h = make_controller();
        let pid = h.ctrl.split_launch_app("steam", SplitMode::Bypass).await.unwrap();
        assert_eq!(pid, 999);
        assert!(h
            .daemon
            .sent_requests
            .lock()
            .unwrap()
            .iter()
            .any(|r| matches!(r, DaemonRequest::UpdateSplitTunnel(_))));

        // First poll observes Disconnected baseline
        h.ctrl.poll_once().await;
        assert!(h.notifier.notes.lock().unwrap().is_empty());
        assert_eq!(h.emitter.events.lock().unwrap().len(), 1);

        // Transition to Protected emits event, updates tray, notifies once, and resets moved PIDs
        *h.daemon.status.lock().unwrap() = DaemonStatus {
            state: TunnelState::Protected,
            cluster_id: Some("de-fra".into()),
            location: Some("Frankfurt".into()),
            country: Some("Germany".into()),
            ..DaemonStatus::default()
        };
        *h.settings_split.moved_pids.lock().unwrap() = vec![444];
        h.ctrl.poll_once().await;

        assert_eq!(h.notifier.notes.lock().unwrap().len(), 1);
        assert_eq!(
            h.notifier.notes.lock().unwrap()[0].0,
            "Connected to Frankfurt, Germany"
        );
        assert!(h.tray.updates.lock().unwrap().contains(&TunnelState::Protected));
        assert!(h
            .daemon
            .sent_requests
            .lock()
            .unwrap()
            .iter()
            .any(|r| matches!(r, DaemonRequest::ResetAppSockets { pids } if pids == &[444])));
    }
}
