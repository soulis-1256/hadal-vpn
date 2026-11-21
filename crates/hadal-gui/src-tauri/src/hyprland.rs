use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::UnixStream;

pub const POPOVER_W: i32 = 360;
pub const POPOVER_H: i32 = 540;
const EDGE_GAP: i32 = 10;

/// Abstraction over Hyprland IPC/CLI interactions for unit-testing popover placement & rule syncing.
pub trait HyprlandTransport: Send + Sync {
    fn is_hyprland(&self) -> bool;
    fn query_raw_json(&self, subcmd: &str) -> Option<String>;
    fn eval_lua(&self, lua: &str);
    fn current_pid(&self) -> u32;
    fn socket2_path(&self) -> Option<PathBuf>;
}

/// Real `hyprctl` + environment Hyprland transport.
pub struct SystemHyprlandTransport;

impl HyprlandTransport for SystemHyprlandTransport {
    fn is_hyprland(&self) -> bool {
        is_hyprland()
    }

    fn query_raw_json(&self, subcmd: &str) -> Option<String> {
        let out = Command::new("hyprctl").args([subcmd, "-j"]).output().ok()?;
        if !out.status.success() {
            return None;
        }
        String::from_utf8(out.stdout).ok()
    }

    fn eval_lua(&self, lua: &str) {
        let _ = Command::new("hyprctl").args(["eval", lua]).output();
    }

    fn current_pid(&self) -> u32 {
        std::process::id()
    }

    fn socket2_path(&self) -> Option<PathBuf> {
        hyprland_socket2_path()
    }
}

#[derive(Debug, Deserialize)]
struct HyprMonitor {
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    scale: f64,
    #[serde(default)]
    transform: i32,
    #[serde(default)]
    reserved: [i32; 4], // [left, top, right, bottom]
    #[serde(default)]
    focused: bool,
}

#[derive(Debug, Deserialize)]
struct HyprCursor {
    x: i32,
    y: i32,
}

#[derive(Debug, Deserialize)]
struct HyprClient {
    address: String,
    pid: u32,
    #[serde(default)]
    mapped: bool,
    #[serde(default)]
    tags: Vec<String>,
}

pub fn is_hyprland() -> bool {
    std::env::var_os("HYPRLAND_INSTANCE_SIGNATURE").is_some()
}

fn logical_size(m: &HyprMonitor) -> (i32, i32) {
    let scale = if m.scale > 0.05 { m.scale } else { 1.0 };
    let (w, h) = if m.transform % 2 == 1 {
        (m.height, m.width)
    } else {
        (m.width, m.height)
    };
    (
        ((w as f64) / scale).round() as i32,
        ((h as f64) / scale).round() as i32,
    )
}

#[derive(Debug, PartialEq, Eq)]
pub enum Socket2Action {
    ConfigReloaded,
    HadalWindowOpened,
    Ignore,
}

pub fn classify_socket2_event(line: &str) -> Socket2Action {
    let trimmed = line.trim();
    if trimmed == "configreloaded" || trimmed.starts_with("configreloaded>>") {
        return Socket2Action::ConfigReloaded;
    }
    if let Some(rest) = trimmed.strip_prefix("openwindow>>") {
        let mut parts = rest.splitn(4, ',');
        let _addr = parts.next();
        let _ws = parts.next();
        if let Some(class) = parts.next() {
            if matches!(class, "hadal-gui" | "Hadal-gui" | "com.hadalvpn.app") {
                return Socket2Action::HadalWindowOpened;
            }
        }
    }
    Socket2Action::Ignore
}

pub fn build_popover_rule_lua(initial_pos: Option<(i32, i32)>) -> String {
    let move_field = match initial_pos {
        Some((x, y)) => format!(", move = \"{x} {y}\""),
        None => String::new(),
    };
    format!(
        "local rule = {{ \
            name = \"hadal-vpn-popover\", \
            match = {{ class = \"^(hadal-gui|Hadal-gui|com\\\\.hadalvpn\\\\.app)$\" }}, \
            float = true, \
            pin = true, \
            border_size = 0, \
            rounding = 8, \
            opaque = true, \
            no_blur = true, \
            tag = \"+nobar\", \
            size = {{ {POPOVER_W}, {POPOVER_H} }}{move_field} \
        }} \
        if hl.plugin and hl.plugin.hyprbars then \
            rule[\"hyprbars:no_bar\"] = true \
        end \
        hl.window_rule(rule)"
    )
}

fn build_reapply_window_lua(address: &str) -> String {
    format!(
        "local w = hl.get_window(\"address:{address}\") \
         if w then \
           pcall(function() hl.dispatch(hl.dsp.window.tag({{ tag = \"+nobar\", window = w }})) end) \
           pcall(function() hl.dispatch(hl.dsp.window.tag({{ tag = \"+hadalreapply\", window = w }})) end) \
           pcall(function() hl.dispatch(hl.dsp.window.tag({{ tag = \"-hadalreapply\", window = w }})) end) \
         end"
    )
}

/// Injectable Hyprland popover layout & rule controller.
pub struct HyprlandController {
    transport: Arc<dyn HyprlandTransport>,
}

impl HyprlandController {
    pub fn new(transport: Arc<dyn HyprlandTransport>) -> Self {
        Self { transport }
    }

    fn query_json<T: for<'de> Deserialize<'de>>(&self, subcmd: &str) -> Option<T> {
        let raw = self.transport.query_raw_json(subcmd)?;
        serde_json::from_str(&raw).ok()
    }

    pub fn compute_tray_popover_pos(&self, click_hint: Option<(i32, i32)>) -> Option<(i32, i32)> {
        if !self.transport.is_hyprland() {
            return None;
        }

        let monitors: Vec<HyprMonitor> = self.query_json("monitors")?;
        if monitors.is_empty() {
            return None;
        }

        let cursor = click_hint
            .filter(|&(x, y)| x > 0 || y > 0)
            .or_else(|| self.query_json::<HyprCursor>("cursorpos").map(|c| (c.x, c.y)));

        let mon = cursor
            .and_then(|(cx, cy)| {
                monitors.iter().find(|m| {
                    let (lw, lh) = logical_size(m);
                    cx >= m.x && cx < m.x + lw && cy >= m.y && cy < m.y + lh
                })
            })
            .or_else(|| monitors.iter().find(|m| m.focused))
            .unwrap_or(&monitors[0]);

        let (lw, lh) = logical_size(mon);
        let [r_left, r_top, r_right, r_bottom] = mon.reserved;

        let min_x = mon.x + r_left + EDGE_GAP;
        let max_x = (mon.x + lw - r_right - POPOVER_W - EDGE_GAP).max(min_x);
        let min_y = mon.y + r_top + EDGE_GAP;
        let max_y = (mon.y + lh - r_bottom - POPOVER_H - EDGE_GAP).max(min_y);

        let bar_at_top = r_top > 0 && r_bottom == 0;
        let ny = if bar_at_top { min_y } else { max_y };

        let nx = if let Some((cx, cy)) = cursor {
            let near_bottom = r_bottom > 0 && cy >= mon.y + lh - r_bottom - 48;
            let near_top = r_top > 0 && cy <= mon.y + r_top + 48;
            if near_bottom || near_top {
                (cx - POPOVER_W / 2).clamp(min_x, max_x)
            } else {
                max_x
            }
        } else {
            max_x
        };

        Some((nx, ny))
    }

    pub fn install_popover_rule(&self, initial_pos: Option<(i32, i32)>) {
        if !self.transport.is_hyprland() {
            return;
        }
        let lua = build_popover_rule_lua(initial_pos);
        self.transport.eval_lua(&lua);
    }

    pub fn reapply_popover_to_open_windows(&self) {
        if !self.transport.is_hyprland() {
            return;
        }
        let my_pid = self.transport.current_pid();
        let Some(clients) = self.query_json::<Vec<HyprClient>>("clients") else {
            return;
        };
        for win in clients.into_iter().filter(|c| c.pid == my_pid && c.mapped) {
            self.transport.eval_lua(&build_reapply_window_lua(&win.address));
        }
    }

    pub fn snap_window_to_tray_with_attempts(
        &self,
        click_hint: Option<(i32, i32)>,
        attempts: usize,
        poll_delay: Duration,
    ) -> bool {
        if !self.transport.is_hyprland() {
            return false;
        }
        let Some((nx, ny)) = self.compute_tray_popover_pos(click_hint) else {
            return false;
        };
        let my_pid = self.transport.current_pid();

        for _ in 0..attempts {
            if let Some(clients) = self.query_json::<Vec<HyprClient>>("clients") {
                if let Some(win) = clients.into_iter().find(|c| c.pid == my_pid && c.mapped) {
                    let needs_reapply = !win.tags.iter().any(|t| t == "nobar");
                    if needs_reapply {
                        self.install_popover_rule(Some((nx, ny)));
                    }
                    let reapply_prefix = if needs_reapply {
                        "pcall(function() hl.dispatch(hl.dsp.window.tag({ tag = \"+nobar\", window = w })) end) \
                         pcall(function() hl.dispatch(hl.dsp.window.tag({ tag = \"+hadalreapply\", window = w })) end) \
                         pcall(function() hl.dispatch(hl.dsp.window.tag({ tag = \"-hadalreapply\", window = w })) end) "
                    } else {
                        ""
                    };
                    let lua = format!(
                        "local w = hl.get_window(\"address:{}\") \
                         if w then \
                           {reapply_prefix}\
                           pcall(function() hl.dispatch(hl.dsp.window.resize({{ x = {POPOVER_W}, y = {POPOVER_H}, window = w }})) end) \
                           pcall(function() hl.dispatch(hl.dsp.window.move({{ x = {nx}, y = {ny}, window = w }})) end) \
                           pcall(function() hl.dispatch(hl.dsp.focus({{ window = w }})) end) \
                         end",
                        win.address
                    );
                    self.transport.eval_lua(&lua);
                    return true;
                }
            }
            if !poll_delay.is_zero() {
                std::thread::sleep(poll_delay);
            }
        }
        false
    }

    pub fn handle_socket2_event(&self, line: &str) {
        match classify_socket2_event(line) {
            Socket2Action::ConfigReloaded => {
                self.install_popover_rule(None);
                self.reapply_popover_to_open_windows();
            }
            Socket2Action::HadalWindowOpened => {
                let my_pid = self.transport.current_pid();
                if let Some(clients) = self.query_json::<Vec<HyprClient>>("clients") {
                    for win in clients.into_iter().filter(|c| c.pid == my_pid && c.mapped) {
                        if !win.tags.iter().any(|t| t == "nobar") {
                            self.install_popover_rule(None);
                            self.transport.eval_lua(&build_reapply_window_lua(&win.address));
                        }
                    }
                }
            }
            Socket2Action::Ignore => {}
        }
    }
}

pub fn compute_tray_popover_pos(click_hint: Option<(i32, i32)>) -> Option<(i32, i32)> {
    HyprlandController::new(Arc::new(SystemHyprlandTransport)).compute_tray_popover_pos(click_hint)
}

pub fn install_popover_rule(initial_pos: Option<(i32, i32)>) {
    HyprlandController::new(Arc::new(SystemHyprlandTransport)).install_popover_rule(initial_pos);
}

pub fn snap_window_to_tray(click_hint: Option<(i32, i32)>) {
    let _ = HyprlandController::new(Arc::new(SystemHyprlandTransport))
        .snap_window_to_tray_with_attempts(click_hint, 40, Duration::from_millis(25));
}

fn hyprland_socket2_path() -> Option<PathBuf> {
    let sig = std::env::var_os("HYPRLAND_INSTANCE_SIGNATURE")?;
    let runtime =
        dirs::runtime_dir().or_else(|| std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from))?;
    Some(runtime.join("hypr").join(sig).join(".socket2.sock"))
}

/// Keep the Hyprland popover rule installed across config reloads so Hyprbars never attaches.
pub fn spawn_rule_watcher() {
    let transport: Arc<dyn HyprlandTransport> = Arc::new(SystemHyprlandTransport);
    if !transport.is_hyprland() {
        return;
    }

    tauri::async_runtime::spawn(async move {
        let controller = Arc::new(HyprlandController::new(transport.clone()));
        let init_ctrl = controller.clone();
        let _ = tokio::task::spawn_blocking(move || {
            init_ctrl.install_popover_rule(None);
            init_ctrl.reapply_popover_to_open_windows();
        })
        .await;

        let Some(sock_path) = transport.socket2_path() else {
            return;
        };

        loop {
            match UnixStream::connect(&sock_path).await {
                Ok(stream) => {
                    let mut lines = BufReader::new(stream).lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        let c = controller.clone();
                        let _ = tokio::task::spawn_blocking(move || c.handle_socket2_event(&line))
                            .await;
                    }
                }
                Err(_) => {
                    if !transport.is_hyprland() {
                        return;
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct FakeHyprland {
        active: bool,
        monitors_json: String,
        cursor_json: String,
        clients_json: String,
        evals: Mutex<Vec<String>>,
    }

    impl HyprlandTransport for FakeHyprland {
        fn is_hyprland(&self) -> bool {
            self.active
        }
        fn query_raw_json(&self, subcmd: &str) -> Option<String> {
            match subcmd {
                "monitors" => Some(self.monitors_json.clone()),
                "cursorpos" => Some(self.cursor_json.clone()),
                "clients" => Some(self.clients_json.clone()),
                _ => None,
            }
        }
        fn eval_lua(&self, lua: &str) {
            self.evals.lock().unwrap().push(lua.to_string());
        }
        fn current_pid(&self) -> u32 {
            4242
        }
        fn socket2_path(&self) -> Option<PathBuf> {
            None
        }
    }

    #[test]
    fn rule_lua_guards_hyprbars_plugin_and_matches_classes() {
        let lua = build_popover_rule_lua(Some((100, 200)));
        assert!(lua.contains("if hl.plugin and hl.plugin.hyprbars then"));
        assert!(lua.contains("rule[\"hyprbars:no_bar\"] = true"));
        assert!(lua.contains("tag = \"+nobar\""));
        assert!(lua.contains("move = \"100 200\""));
        assert!(lua.contains("hadal-gui|Hadal-gui|com\\\\.hadalvpn\\\\.app"));
    }

    #[test]
    fn classifies_socket2_reload_and_hadal_openwindow() {
        assert_eq!(
            classify_socket2_event("configreloaded>>"),
            Socket2Action::ConfigReloaded
        );
        assert_eq!(
            classify_socket2_event("openwindow>>55e11,2,hadal-gui,Hadal VPN"),
            Socket2Action::HadalWindowOpened
        );
        assert_eq!(
            classify_socket2_event("openwindow>>55e11,2,com.hadalvpn.app,Hadal VPN"),
            Socket2Action::HadalWindowOpened
        );
        assert_eq!(
            classify_socket2_event("openwindow>>55e11,1,ghostty,Terminal"),
            Socket2Action::Ignore
        );
    }

    #[test]
    fn computes_scaled_popover_pos_above_bottom_bar_and_snaps_window() {
        let fake = Arc::new(FakeHyprland {
            active: true,
            monitors_json: r#"[{"x":0,"y":0,"width":2560,"height":1440,"scale":1.0,"transform":0,"reserved":[0,0,0,40],"focused":true}]"#.into(),
            cursor_json: r#"{"x":2400,"y":1420}"#.into(),
            clients_json: r#"[{"address":"0xabc","pid":4242,"mapped":true,"tags":[]}]"#.into(),
            evals: Mutex::new(Vec::new()),
        });
        let ctrl = HyprlandController::new(fake.clone());
        let pos = ctrl.compute_tray_popover_pos(Some((2400, 1420))).unwrap();
        // Max x = 2560 - 0 - 360 - 10 = 2190; y = 1440 - 40 - 540 - 10 = 850
        assert_eq!(pos, (2190, 850));

        assert!(ctrl.snap_window_to_tray_with_attempts(Some((2400, 1420)), 2, Duration::ZERO));
        let evals = fake.evals.lock().unwrap();
        assert_eq!(evals.len(), 2); // install_popover_rule + snap move/focus
        assert!(evals[1].contains("x = 2190, y = 850"));
        assert!(evals[1].contains("+nobar"));
    }
}
