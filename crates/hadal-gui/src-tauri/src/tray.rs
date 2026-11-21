use std::sync::Arc;
use std::time::Duration;

use hadal_core::{DaemonStatus, TunnelState};
use tauri::image::Image;
use tauri::menu::{MenuBuilder, MenuItem, MenuItemBuilder};
use tauri::tray::{MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager};
use tokio::sync::Mutex;

use crate::backend::{BoxFuture, TrayUpdater, WindowPresenter};
use crate::notifications::SniWatcherChecker;
use crate::state::AppController;

pub struct TrayHandles {
    tray: TrayIcon,
    status_item: MenuItem<tauri::Wry>,
}

/// Abyssal Precision tray badge colors matching `DESIGN.md` / `tokens.css`.
pub const BADGE_BODY_RGB: (u8, u8, u8) = (12, 16, 22);
pub const BADGE_RIM_RGB: (u8, u8, u8) = (42, 56, 74);
pub const BADGE_MARK_RGB: (u8, u8, u8) = (241, 245, 249);

pub fn badge_dot_rgb(state: TunnelState) -> (u8, u8, u8) {
    match state {
        TunnelState::Protected => (16, 209, 144),
        TunnelState::Connecting => (34, 211, 238),
        TunnelState::KillswitchLocked => (244, 63, 94),
        TunnelState::Disconnected => (100, 116, 139),
    }
}

/// Render a sharp 64x64 Abyssal Precision orbital Hadal status badge icon into RGBA memory.
pub fn render_tray_badge(state: TunnelState) -> Image<'static> {
    const SIZE: usize = 64;
    let mut rgba = vec![0u8; SIZE * SIZE * 4];
    let (dot_r, dot_g, dot_b) = badge_dot_rgb(state);

    let center = (SIZE as f32 - 1.0) * 0.5;
    let radius = 29.0_f32;
    for y in 0..SIZE {
        for x in 0..SIZE {
            let nx = (x as f32 - center) / radius;
            let ny = (y as f32 - center) / radius;
            let idx = (y * SIZE + x) * 4;

            let squircle = nx.abs().powf(3.6) + ny.abs().powf(3.6);
            if squircle > 1.0 {
                continue;
            }

            let (mut r, mut g, mut b) = if squircle > 0.86 {
                BADGE_RIM_RGB
            } else {
                BADGE_BODY_RGB
            };

            // Crisp open orbital crescent + depth core mark
            let mdx = nx + 0.04;
            let mdy = ny + 0.04;
            let mdist = (mdx * mdx + mdy * mdy).sqrt();
            let in_core = mdist <= 0.14;
            let in_ring = (0.31..=0.47).contains(&mdist) && !(mdx > 0.08 && mdy > 0.08);
            if in_core || in_ring {
                (r, g, b) = BADGE_MARK_RGB;
            }

            // High-visibility bottom-right status beacon dot
            let bdx = nx - 0.52;
            let bdy = ny - 0.52;
            let bdist = (bdx * bdx + bdy * bdy).sqrt();
            if bdist <= 0.34 {
                if bdist <= 0.24 {
                    (r, g, b) = (dot_r, dot_g, dot_b);
                } else {
                    (r, g, b) = BADGE_BODY_RGB;
                }
            }

            rgba[idx] = r;
            rgba[idx + 1] = g;
            rgba[idx + 2] = b;
            rgba[idx + 3] = 255;
        }
    }
    Image::new_owned(rgba, SIZE as u32, SIZE as u32)
}

pub fn format_tray_label(st: &DaemonStatus) -> String {
    match st.state {
        TunnelState::Protected => {
            let place = st
                .location
                .as_deref()
                .or(st.country.as_deref())
                .unwrap_or("Protected");
            format!("Protected · {place}")
        }
        TunnelState::Connecting => "Connecting tunnel…".to_string(),
        TunnelState::KillswitchLocked => "Killswitch Locked".to_string(),
        TunnelState::Disconnected => "Disconnected".to_string(),
    }
}

pub struct TauriTrayUpdater {
    handles: Mutex<Option<TrayHandles>>,
}

impl TauriTrayUpdater {
    pub fn new(initial: Option<TrayHandles>) -> Self {
        Self {
            handles: Mutex::new(initial),
        }
    }

    pub async fn set_handles(&self, handles: TrayHandles) {
        *self.handles.lock().await = Some(handles);
    }
}

impl TrayUpdater for TauriTrayUpdater {
    fn update_status<'a>(&'a self, st: &'a DaemonStatus) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let guard = self.handles.lock().await;
            if let Some(handles) = guard.as_ref() {
                let summary = format_tray_label(st);
                let _ = handles.status_item.set_text(format!("Hadal VPN · {summary}"));
                let _ = handles
                    .tray
                    .set_tooltip(Some(format!("Hadal VPN — {summary}")));
                let _ = handles.tray.set_icon(Some(render_tray_badge(st.state)));
            }
        })
    }
}

/// Dispatch a tray menu action against the DI `AppController` and `WindowPresenter`.
pub async fn handle_tray_menu_action(
    id: &str,
    controller: &AppController,
    presenter: &dyn WindowPresenter,
) {
    match id {
        "toggle" => presenter.toggle_main_window(None),
        "quit" => presenter.exit_app(),
        "disconnect" => {
            let keep_killswitch = controller.get_settings().killswitch;
            let _ = controller.disconnect_tunnel(keep_killswitch).await;
        }
        "quick_connect" => {
            let _ = controller.quick_connect().await;
        }
        "gaming_connect" => {
            let _ = controller.gaming_quick_connect().await;
        }
        _ => {}
    }
}

pub fn setup_tray(
    app: &AppHandle,
    presenter: Arc<dyn WindowPresenter>,
) -> tauri::Result<TrayHandles> {
    let status_item = MenuItemBuilder::with_id("status", "Hadal VPN · Checking daemon…")
        .enabled(false)
        .build(app)?;
    let quick_connect = MenuItemBuilder::with_id("quick_connect", "Quick Connect").build(app)?;
    let gaming_connect =
        MenuItemBuilder::with_id("gaming_connect", "Connect Fastest · Gaming").build(app)?;
    let disconnect_item = MenuItemBuilder::with_id("disconnect", "Disconnect").build(app)?;
    let toggle_win = MenuItemBuilder::with_id("toggle", "Show / Hide Window").build(app)?;
    let quit_item = MenuItemBuilder::with_id("quit", "Quit Hadal VPN").build(app)?;

    let menu = MenuBuilder::new(app)
        .item(&status_item)
        .separator()
        .item(&quick_connect)
        .item(&gaming_connect)
        .item(&disconnect_item)
        .separator()
        .item(&toggle_win)
        .item(&quit_item)
        .build()?;

    let click_presenter = presenter.clone();
    let menu_presenter = presenter;

    let tray = TrayIconBuilder::with_id("hadal-tray")
        .title("Hadal VPN")
        .icon(render_tray_badge(TunnelState::Disconnected))
        .tooltip("Hadal VPN")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_tray_icon_event(move |_tray_handle, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                position,
                ..
            } = event
            {
                click_presenter.toggle_main_window(Some((position.x as i32, position.y as i32)));
            }
        })
        .on_menu_event(move |app, event| {
            let id = event.id().as_ref().to_string();
            let app_clone = app.clone();
            let p = menu_presenter.clone();
            tauri::async_runtime::spawn(async move {
                let controller = app_clone.state::<Arc<AppController>>();
                handle_tray_menu_action(&id, controller.inner(), p.as_ref()).await;
            });
        })
        .build(app)?;

    Ok(TrayHandles { tray, status_item })
}

pub fn spawn_deferred_tray_registration(
    app: AppHandle,
    tray_updater: Arc<TauriTrayUpdater>,
    controller: Arc<AppController>,
    presenter: Arc<dyn WindowPresenter>,
    checker: Arc<dyn SniWatcherChecker>,
) {
    tauri::async_runtime::spawn(async move {
        let _ = checker.wait_for_watcher(Duration::from_secs(30)).await;
        for _ in 0..20 {
            let (tx, rx) = tokio::sync::oneshot::channel();
            let inner_app = app.clone();
            let inner_presenter = presenter.clone();
            if app
                .run_on_main_thread(move || {
                    let _ = tx.send(setup_tray(&inner_app, inner_presenter));
                })
                .is_err()
            {
                break;
            }
            if let Ok(Ok(handles)) = rx.await {
                tray_updater.set_handles(handles).await;
                let env = controller.get_daemon_status().await;
                if env.reachable {
                    tray_updater.update_status(&env.status).await;
                }
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tray_badge_uses_abyssal_precision_palette() {
        let img = render_tray_badge(TunnelState::Protected);
        assert_eq!(img.width(), 64);
        assert_eq!(img.height(), 64);

        let rgba = img.rgba();
        // Beacon dot center (~nx=0.52, ny=0.52 => pixel ~46,46) uses Protected mint-emerald (16, 209, 144)
        let dot_px = (46 * 64 + 46) * 4;
        assert_eq!(
            (rgba[dot_px], rgba[dot_px + 1], rgba[dot_px + 2], rgba[dot_px + 3]),
            (16, 209, 144, 255)
        );
        // Body pixel outside orbital mark & dot (~18,46 => nx=-0.46, ny=0.50) uses Abyssal body (12, 16, 22)
        let body_px = (46 * 64 + 18) * 4;
        assert_eq!(
            (rgba[body_px], rgba[body_px + 1], rgba[body_px + 2]),
            BADGE_BODY_RGB
        );

        assert_eq!(badge_dot_rgb(TunnelState::Connecting), (34, 211, 238));
        assert_eq!(badge_dot_rgb(TunnelState::KillswitchLocked), (244, 63, 94));
        assert_eq!(badge_dot_rgb(TunnelState::Disconnected), (100, 116, 139));
    }

    #[test]
    fn formats_tray_labels_for_all_states() {
        let mut st = DaemonStatus::default();
        assert_eq!(format_tray_label(&st), "Disconnected");
        st.state = TunnelState::Connecting;
        assert_eq!(format_tray_label(&st), "Connecting tunnel…");
        st.state = TunnelState::KillswitchLocked;
        assert_eq!(format_tray_label(&st), "Killswitch Locked");
        st.state = TunnelState::Protected;
        st.location = Some("Frankfurt".into());
        assert_eq!(format_tray_label(&st), "Protected · Frankfurt");
    }
}
