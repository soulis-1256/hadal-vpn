use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use hadal_core::auth::{AuthResponse, RemoteCodeResponse, UserMe};
use hadal_core::{
    app_statuses, daemon_socket_path, discover_desktop_apps, ensure_user_slice_dir,
    launch_app_in_slice, load_settings, prepare_connect_target, query_daemon_status,
    reconcile_split_slices, save_settings, scan_gaming_with_daemon, send_request, AppSettings,
    Cluster, DaemonRequest, DaemonResponse, DaemonStatus, DesktopAppEntry, GamingScanReport,
    HadalClient, HadalError, PersistedWgKey, RegisterPublicKeyResponse, SplitAppStatus, SplitMode,
    UserLocation, WgKeyPair,
};

use crate::state::DaemonEnvelope;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Structured error distinguishing an offline daemon socket from a daemon-side rejection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonIpcError {
    pub unreachable: bool,
    pub message: String,
}

impl DaemonIpcError {
    pub fn unreachable(message: impl Into<String>) -> Self {
        Self {
            unreachable: true,
            message: message.into(),
        }
    }

    pub fn rejected(message: impl Into<String>) -> Self {
        Self {
            unreachable: false,
            message: message.into(),
        }
    }

    pub fn from_hadal_error(err: HadalError) -> Self {
        let message = err.to_string();
        let unreachable = matches!(err, HadalError::Io(_))
            || message.starts_with("Cannot reach hadald at ")
            || message == "hadald closed IPC connection unexpectedly";
        Self {
            unreachable,
            message,
        }
    }
}

impl std::fmt::Display for DaemonIpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl From<DaemonIpcError> for String {
    fn from(err: DaemonIpcError) -> Self {
        err.message
    }
}

/// Surfshark account & server API abstraction for Tauri backend testing.
pub trait AccountApi: Send + Sync {
    fn is_logged_in(&self) -> BoxFuture<'_, bool>;
    fn create_remote_login(&self) -> BoxFuture<'_, Result<RemoteCodeResponse, String>>;
    fn poll_remote_login<'a>(
        &'a self,
        hash: &'a str,
    ) -> BoxFuture<'a, Result<AuthResponse, String>>;
    fn get_user_me(&self) -> BoxFuture<'_, Result<UserMe, String>>;
    fn clear_session(&self) -> BoxFuture<'_, ()>;
    fn get_clusters(&self) -> BoxFuture<'_, Result<Vec<Cluster>, String>>;
    fn get_user_location(&self) -> BoxFuture<'_, Result<UserLocation, String>>;
    fn register_public_key<'a>(
        &'a self,
        pub_key: &'a str,
    ) -> BoxFuture<'a, Result<RegisterPublicKeyResponse, String>>;
    fn ensure_wireguard_key(&self) -> BoxFuture<'_, Result<PersistedWgKey, String>> {
        Box::pin(async move {
            let pair = WgKeyPair::generate();
            let reg = self.register_public_key(&pair.public_key).await?;
            Ok(PersistedWgKey::from_registration(pair, &reg, None))
        })
    }
}

pub struct HadalAccountApi {
    client: Arc<HadalClient>,
}

impl HadalAccountApi {
    pub fn new(client: Arc<HadalClient>) -> Self {
        Self { client }
    }
}

impl AccountApi for HadalAccountApi {
    fn is_logged_in(&self) -> BoxFuture<'_, bool> {
        Box::pin(async {
            let session = self.client.get_session().await;
            session.has_access_token() || session.has_renew_token()
        })
    }

    fn create_remote_login(&self) -> BoxFuture<'_, Result<RemoteCodeResponse, String>> {
        Box::pin(async {
            self.client
                .create_remote_login()
                .await
                .map_err(|e| e.to_string())
        })
    }

    fn poll_remote_login<'a>(
        &'a self,
        hash: &'a str,
    ) -> BoxFuture<'a, Result<AuthResponse, String>> {
        Box::pin(async move {
            self.client
                .poll_remote_login(hash)
                .await
                .map_err(|e| e.to_string())
        })
    }

    fn get_user_me(&self) -> BoxFuture<'_, Result<UserMe, String>> {
        Box::pin(async { self.client.get_user_me().await.map_err(|e| e.to_string()) })
    }

    fn clear_session(&self) -> BoxFuture<'_, ()> {
        Box::pin(async {
            self.client.logout().await;
        })
    }

    fn get_clusters(&self) -> BoxFuture<'_, Result<Vec<Cluster>, String>> {
        Box::pin(async { self.client.get_clusters().await.map_err(|e| e.to_string()) })
    }

    fn get_user_location(&self) -> BoxFuture<'_, Result<UserLocation, String>> {
        Box::pin(async {
            self.client
                .get_user_location()
                .await
                .map_err(|e| e.to_string())
        })
    }

    fn register_public_key<'a>(
        &'a self,
        pub_key: &'a str,
    ) -> BoxFuture<'a, Result<RegisterPublicKeyResponse, String>> {
        Box::pin(async move {
            self.client
                .register_public_key(pub_key)
                .await
                .map_err(|e| e.to_string())
        })
    }

    fn ensure_wireguard_key(&self) -> BoxFuture<'_, Result<PersistedWgKey, String>> {
        Box::pin(async move {
            self.client
                .ensure_wireguard_key()
                .await
                .map_err(|e| e.to_string())
        })
    }
}

/// Abstraction over `hadald` Unix-socket IPC and daemon-assisted probing.
pub trait DaemonBridge: Send + Sync {
    fn query_status(&self) -> BoxFuture<'_, Result<DaemonStatus, DaemonIpcError>>;
    fn send(&self, req: DaemonRequest) -> BoxFuture<'_, Result<DaemonResponse, DaemonIpcError>>;
    fn prepare_connect_target<'a>(
        &'a self,
        domain: &'a str,
        auto_mtu: bool,
        manual_mtu: Option<u16>,
        endpoint_override: Option<&'a str>,
        mtu_override: Option<u16>,
    ) -> BoxFuture<'a, Result<(String, u16, u16), String>>;
    fn scan_gaming<'a>(
        &'a self,
        clusters: &'a [Cluster],
        game_id: &'a str,
        region_id: &'a str,
        custom_host: Option<&'a str>,
    ) -> BoxFuture<'a, Result<GamingScanReport, String>>;
}

pub struct UnixDaemonBridge {
    client: Arc<HadalClient>,
    socket_override: Option<PathBuf>,
}

impl UnixDaemonBridge {
    pub fn new(client: Arc<HadalClient>) -> Self {
        Self {
            client,
            socket_override: None,
        }
    }

    #[allow(dead_code)]
    pub fn with_socket_path(client: Arc<HadalClient>, socket_path: PathBuf) -> Self {
        Self {
            client,
            socket_override: Some(socket_path),
        }
    }

    fn socket_path(&self) -> PathBuf {
        self.socket_override
            .clone()
            .unwrap_or_else(daemon_socket_path)
    }
}

impl DaemonBridge for UnixDaemonBridge {
    fn query_status(&self) -> BoxFuture<'_, Result<DaemonStatus, DaemonIpcError>> {
        Box::pin(async {
            let sock = self.socket_path();
            query_daemon_status(&sock)
                .await
                .map_err(DaemonIpcError::from_hadal_error)
        })
    }

    fn send(&self, req: DaemonRequest) -> BoxFuture<'_, Result<DaemonResponse, DaemonIpcError>> {
        Box::pin(async move {
            let sock = self.socket_path();
            send_request(&sock, &req)
                .await
                .map_err(DaemonIpcError::from_hadal_error)
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
        Box::pin(async move {
            let sock = self.socket_path();
            prepare_connect_target(
                &sock,
                domain,
                auto_mtu,
                manual_mtu,
                endpoint_override,
                mtu_override,
            )
            .await
            .map_err(|e| e.to_string())
        })
    }

    fn scan_gaming<'a>(
        &'a self,
        clusters: &'a [Cluster],
        game_id: &'a str,
        region_id: &'a str,
        custom_host: Option<&'a str>,
    ) -> BoxFuture<'a, Result<GamingScanReport, String>> {
        Box::pin(async move {
            let sock = self.socket_path();
            scan_gaming_with_daemon(
                &sock,
                clusters,
                game_id,
                region_id,
                custom_host,
                None,
                Some(self.client.as_ref()),
            )
            .await
            .map_err(|e| e.to_string())
        })
    }
}

/// Abstraction over persisted `AppSettings` and cgroupv2 split-tunnel OS operations.
pub trait SettingsAndSplitBackend: Send + Sync {
    fn load_settings(&self) -> AppSettings;
    fn save_settings(&self, settings: &AppSettings) -> Result<(), String>;
    fn ensure_user_slice_dir(&self, slice: &str) -> Option<String>;
    fn reconcile_split_slices(&self, apps: Vec<String>, mode: SplitMode) -> BoxFuture<'_, Vec<u32>>;
    fn discover_desktop_apps(&self) -> BoxFuture<'_, Vec<DesktopAppEntry>>;
    fn app_statuses(
        &self,
        apps: Vec<String>,
        slice: Option<&'static str>,
    ) -> BoxFuture<'_, Vec<SplitAppStatus>>;
    fn launch_app_in_slice(&self, command: &str, slice: &str) -> Result<u32, String>;
}

pub struct SystemSettingsAndSplitBackend;

impl SettingsAndSplitBackend for SystemSettingsAndSplitBackend {
    fn load_settings(&self) -> AppSettings {
        load_settings()
    }

    fn save_settings(&self, settings: &AppSettings) -> Result<(), String> {
        save_settings(settings).map_err(|e| e.to_string())
    }

    fn ensure_user_slice_dir(&self, slice: &str) -> Option<String> {
        ensure_user_slice_dir(slice)
    }

    fn reconcile_split_slices(&self, apps: Vec<String>, mode: SplitMode) -> BoxFuture<'_, Vec<u32>> {
        Box::pin(async move {
            tokio::task::spawn_blocking(move || reconcile_split_slices(&apps, mode))
                .await
                .unwrap_or_default()
        })
    }

    fn discover_desktop_apps(&self) -> BoxFuture<'_, Vec<DesktopAppEntry>> {
        Box::pin(async {
            tokio::task::spawn_blocking(discover_desktop_apps)
                .await
                .unwrap_or_default()
        })
    }

    fn app_statuses(
        &self,
        apps: Vec<String>,
        slice: Option<&'static str>,
    ) -> BoxFuture<'_, Vec<SplitAppStatus>> {
        Box::pin(async move {
            tokio::task::spawn_blocking(move || app_statuses(&apps, slice))
                .await
                .unwrap_or_default()
        })
    }

    fn launch_app_in_slice(&self, command: &str, slice: &str) -> Result<u32, String> {
        launch_app_in_slice(command, slice).map_err(|e| e.to_string())
    }
}

/// Sink for pushing daemon status updates to the UI webview.
pub trait StatusEmitter: Send + Sync {
    fn emit_daemon_status(&self, env: &DaemonEnvelope);
}

/// Sink for updating system tray icon, tooltip, and status menu item.
pub trait TrayUpdater: Send + Sync {
    fn update_status<'a>(&'a self, status: &'a DaemonStatus) -> BoxFuture<'a, ()>;
}

/// Window visibility & app lifecycle presenter used by tray menu handlers.
pub trait WindowPresenter: Send + Sync {
    fn toggle_main_window(&self, click_hint: Option<(i32, i32)>);
    fn exit_app(&self);
}
