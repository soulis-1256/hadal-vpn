pub mod backend;
pub mod commands;
pub mod hyprland;
pub mod notifications;
pub mod state;
pub mod tray;

use std::sync::Arc;
use std::time::Duration;

use hadal_core::HadalClient;
use tauri::{AppHandle, Emitter, Manager, WindowEvent};

use crate::backend::{
    HadalAccountApi, StatusEmitter, SystemSettingsAndSplitBackend, UnixDaemonBridge,
    WindowPresenter,
};
use crate::notifications::{DbusSniWatcherChecker, FreedesktopNotifier};
use crate::state::{AppController, AppServices, DaemonEnvelope};
use crate::tray::{setup_tray, spawn_deferred_tray_registration, TauriTrayUpdater};

struct TauriStatusEmitter {
    app: AppHandle,
}

impl StatusEmitter for TauriStatusEmitter {
    fn emit_daemon_status(&self, env: &DaemonEnvelope) {
        let _ = self.app.emit("daemon-status", env);
    }
}

struct TauriWindowPresenter {
    app: AppHandle,
}

impl TauriWindowPresenter {
    fn show_main_window(&self, click_hint: Option<(i32, i32)>) {
        let pos = hyprland::compute_tray_popover_pos(click_hint);
        hyprland::install_popover_rule(pos);
        if let Some(win) = self.app.get_webview_window("main") {
            let _ = win.show();
            let _ = win.set_focus();
            std::thread::spawn(move || hyprland::snap_window_to_tray(click_hint));
        }
    }
}

impl WindowPresenter for TauriWindowPresenter {
    fn toggle_main_window(&self, click_hint: Option<(i32, i32)>) {
        if let Some(win) = self.app.get_webview_window("main") {
            let visible = win.is_visible().unwrap_or(false);
            if visible {
                let _ = win.hide();
            } else {
                self.show_main_window(click_hint);
            }
        }
    }

    fn exit_app(&self) {
        self.app.exit(0);
    }
}

pub fn run_with_context(context: tauri::Context) {
    let client = Arc::new(HadalClient::new());

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .setup(move |app| {
            let app_handle = app.handle().clone();
            let presenter = Arc::new(TauriWindowPresenter {
                app: app_handle.clone(),
            });

            let initial_tray = match setup_tray(&app_handle, presenter.clone()) {
                Ok(handles) => Some(handles),
                Err(err) => {
                    eprintln!("Tray watcher not ready yet ({err}); deferring tray registration");
                    None
                }
            };
            let needs_deferred_tray = initial_tray.is_none();

            let tray_updater = Arc::new(TauriTrayUpdater::new(initial_tray));
            let controller = Arc::new(AppController::new(AppServices {
                account: Arc::new(HadalAccountApi::new(client.clone())),
                daemon: Arc::new(UnixDaemonBridge::new(client.clone())),
                settings_split: Arc::new(SystemSettingsAndSplitBackend),
                notifier_transport: Arc::new(FreedesktopNotifier),
                tray: tray_updater.clone(),
                emitter: Arc::new(TauriStatusEmitter {
                    app: app_handle.clone(),
                }),
            }));

            app.manage(controller.clone());

            if needs_deferred_tray {
                spawn_deferred_tray_registration(
                    app_handle.clone(),
                    tray_updater,
                    controller.clone(),
                    presenter.clone(),
                    Arc::new(DbusSniWatcherChecker),
                );
            }

            hyprland::spawn_rule_watcher();

            let poll_ctrl = controller.clone();
            tauri::async_runtime::spawn(async move {
                loop {
                    poll_ctrl.poll_once().await;
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            });

            if let Some(win) = app.get_webview_window("main") {
                let win_clone = win.clone();
                win.on_window_event(move |event| {
                    if let WindowEvent::CloseRequested { api, .. } = event {
                        // Hide to SNI tray instead of terminating app
                        api.prevent_close();
                        let _ = win_clone.hide();
                    }
                });
                if std::env::args().any(|arg| arg == "--show") {
                    presenter.show_main_window(None);
                }
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::is_logged_in,
            commands::create_remote_login,
            commands::poll_remote_login,
            commands::get_user_me,
            commands::logout,
            commands::get_servers,
            commands::get_user_location,
            commands::get_daemon_status,
            commands::connect_cluster,
            commands::disconnect_tunnel,
            commands::set_killswitch,
            commands::get_settings,
            commands::save_settings_cmd,
            commands::get_builtin_games,
            commands::scan_gaming,
            commands::connect_gaming_best,
            commands::discover_split_apps,
            commands::get_split_app_statuses,
            commands::split_launch_app,
            commands::hide_window,
            commands::quit_app,
        ])
        .run(context)
        .expect("error while running Hadal VPN");
}
