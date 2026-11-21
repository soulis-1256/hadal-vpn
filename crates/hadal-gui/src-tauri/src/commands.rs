use std::sync::Arc;

use tauri::State;

use hadal_core::auth::{AuthResponse, RemoteCodeResponse, UserMe};
use hadal_core::{
    builtin_games, AppSettings, Cluster, DaemonStatus, DesktopAppEntry, GameProfile,
    GamingScanReport, SplitAppStatus, SplitMode, UserLocation,
};

use crate::state::{AppController, DaemonEnvelope};

#[tauri::command]
pub async fn is_logged_in(state: State<'_, Arc<AppController>>) -> Result<bool, String> {
    Ok(state.is_logged_in().await)
}

#[tauri::command]
pub async fn create_remote_login(
    state: State<'_, Arc<AppController>>,
) -> Result<RemoteCodeResponse, String> {
    state.create_remote_login().await
}

#[tauri::command]
pub async fn poll_remote_login(
    state: State<'_, Arc<AppController>>,
    hash: String,
) -> Result<AuthResponse, String> {
    state.poll_remote_login(&hash).await
}

#[tauri::command]
pub async fn get_user_me(state: State<'_, Arc<AppController>>) -> Result<UserMe, String> {
    state.get_user_me().await
}

#[tauri::command]
pub async fn logout(state: State<'_, Arc<AppController>>) -> Result<(), String> {
    state.logout().await
}

#[tauri::command]
pub async fn get_servers(
    state: State<'_, Arc<AppController>>,
    force_refresh: Option<bool>,
) -> Result<Vec<Cluster>, String> {
    state
        .resolve_clusters(force_refresh.unwrap_or(false))
        .await
}

#[tauri::command]
pub async fn get_user_location(
    state: State<'_, Arc<AppController>>,
) -> Result<UserLocation, String> {
    state.get_user_location().await
}

#[tauri::command]
pub async fn get_daemon_status(
    state: State<'_, Arc<AppController>>,
) -> Result<DaemonEnvelope, String> {
    Ok(state.get_daemon_status().await)
}

#[tauri::command]
pub async fn connect_cluster(
    state: State<'_, Arc<AppController>>,
    cluster_id: String,
    endpoint_override: Option<String>,
    mtu_override: Option<u16>,
    game_only_cidrs: Option<Vec<String>>,
) -> Result<DaemonStatus, String> {
    state
        .connect_cluster(
            &cluster_id,
            endpoint_override.as_deref(),
            mtu_override,
            game_only_cidrs.unwrap_or_default(),
        )
        .await
}

#[tauri::command]
pub async fn disconnect_tunnel(
    state: State<'_, Arc<AppController>>,
    keep_killswitch: bool,
) -> Result<DaemonStatus, String> {
    state.disconnect_tunnel(keep_killswitch).await
}

#[tauri::command]
pub async fn set_killswitch(
    state: State<'_, Arc<AppController>>,
    enabled: bool,
    ipv6_block: bool,
    bypass_lan: bool,
) -> Result<DaemonStatus, String> {
    state.set_killswitch(enabled, ipv6_block, bypass_lan).await
}

#[tauri::command]
pub fn get_settings(state: State<'_, Arc<AppController>>) -> AppSettings {
    state.get_settings()
}

#[tauri::command]
pub async fn save_settings_cmd(
    state: State<'_, Arc<AppController>>,
    settings: AppSettings,
) -> Result<AppSettings, String> {
    state.save_settings_and_sync(settings).await
}

#[tauri::command]
pub fn get_builtin_games() -> Vec<GameProfile> {
    builtin_games()
}

#[tauri::command]
pub async fn scan_gaming(
    state: State<'_, Arc<AppController>>,
    game_id: String,
    region_id: String,
    custom_host: Option<String>,
) -> Result<GamingScanReport, String> {
    state
        .scan_gaming(&game_id, &region_id, custom_host.as_deref())
        .await
}

#[tauri::command]
pub async fn connect_gaming_best(
    state: State<'_, Arc<AppController>>,
    game_id: String,
    region_id: String,
    custom_host: Option<String>,
    game_only: bool,
) -> Result<GamingScanReport, String> {
    state
        .connect_gaming_best(&game_id, &region_id, custom_host.as_deref(), game_only)
        .await
}

#[tauri::command]
pub async fn get_split_app_statuses(
    state: State<'_, Arc<AppController>>,
    apps: Vec<String>,
    mode: SplitMode,
) -> Result<Vec<SplitAppStatus>, String> {
    Ok(state.get_split_app_statuses(apps, mode).await)
}

#[tauri::command]
pub async fn discover_split_apps(
    state: State<'_, Arc<AppController>>,
) -> Result<Vec<DesktopAppEntry>, String> {
    Ok(state.discover_split_apps().await)
}

#[tauri::command]
pub async fn split_launch_app(
    state: State<'_, Arc<AppController>>,
    command: String,
    mode: SplitMode,
) -> Result<u32, String> {
    state.split_launch_app(&command, mode).await
}

#[tauri::command]
pub fn hide_window(window: tauri::Window) {
    let _ = window.hide();
}

#[tauri::command]
pub fn quit_app(app: tauri::AppHandle) {
    app.exit(0);
}
