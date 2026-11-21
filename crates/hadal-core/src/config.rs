use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::split_tunnel::{SplitMode, SplitTunnelConfig};

pub const DEFAULT_SOCKET_PATH: &str = "/run/hadald/hadald.sock";
pub const DEFAULT_WG_IFACE: &str = "hadal-wg";
pub const DEFAULT_WG_PORT: u16 = 51820;

/// Encrypted Cloudflare DoT resolvers so plaintext exit-node DNS cannot spoof responses.
pub fn default_tunnel_dns() -> Vec<String> {
    vec!["1.1.1.1".to_string(), "1.0.0.1".to_string()]
}

pub fn hadal_config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".config")
        })
        .join("hadal-vpn")
}

pub fn daemon_socket_path() -> PathBuf {
    if let Ok(path) = std::env::var("HADALD_SOCKET") {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    PathBuf::from(DEFAULT_SOCKET_PATH)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct AppSettings {
    pub killswitch: bool,
    pub ipv6_block: bool,
    pub bypass_lan: bool,
    pub auto_mtu: bool,
    pub manual_mtu: Option<u16>,
    pub split_tunnel: SplitTunnelConfig,
    pub favorite_game: String,
    pub favorite_game_region: String,
    pub game_only_routing: bool,
    pub last_cluster_id: Option<String>,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            killswitch: true,
            ipv6_block: true,
            bypass_lan: true,
            auto_mtu: true,
            manual_mtu: None,
            split_tunnel: SplitTunnelConfig::default(),
            favorite_game: "fortnite".to_string(),
            favorite_game_region: "eu-de".to_string(),
            game_only_routing: false,
            last_cluster_id: None,
        }
    }
}

/// Persistence abstraction for [`AppSettings`] so CLI/core callers can inject test stores.
pub trait SettingsStore: Send + Sync {
    fn load(&self) -> AppSettings;
    fn save(&self, settings: &AppSettings) -> Result<()>;
}

/// JSON-file [`SettingsStore`] rooted in a specific config directory.
#[derive(Debug, Clone)]
pub struct FileSettingsStore {
    dir: PathBuf,
}

impl FileSettingsStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn system() -> Self {
        Self::new(hadal_config_dir())
    }

    pub fn path(&self) -> PathBuf {
        settings_path_in(&self.dir)
    }
}

impl Default for FileSettingsStore {
    fn default() -> Self {
        Self::system()
    }
}

impl SettingsStore for FileSettingsStore {
    fn load(&self) -> AppSettings {
        load_settings_from(&self.dir)
    }

    fn save(&self, settings: &AppSettings) -> Result<()> {
        save_settings_to(&self.dir, settings)
    }
}

pub fn settings_path() -> PathBuf {
    settings_path_in(&hadal_config_dir())
}

pub fn settings_path_in(dir: &Path) -> PathBuf {
    dir.join("settings.json")
}

pub fn load_settings() -> AppSettings {
    load_settings_from(&hadal_config_dir())
}

pub fn load_settings_from(dir: &Path) -> AppSettings {
    let path = settings_path_in(dir);
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return AppSettings::default();
    };
    let Ok(mut parsed) = serde_json::from_str::<AppSettings>(&raw) else {
        return AppSettings::default();
    };
    migrate_legacy_split_lists(&raw, &mut parsed.split_tunnel);
    parsed.split_tunnel.sync_active_apps();
    parsed
}

fn migrate_legacy_split_lists(raw: &str, split_tunnel: &mut SplitTunnelConfig) {
    let Ok(val) = serde_json::from_str::<serde_json::Value>(raw) else {
        return;
    };
    let st_val = val.get("split_tunnel");
    let has_split_lists = st_val.and_then(|v| v.get("bypass_apps")).is_some()
        || st_val.and_then(|v| v.get("only_vpn_apps")).is_some();
    if has_split_lists || split_tunnel.apps.is_empty() {
        return;
    }
    if split_tunnel.mode == SplitMode::OnlyVpn {
        split_tunnel.only_vpn_apps = split_tunnel.apps.clone();
        split_tunnel.bypass_apps.clear();
    } else {
        split_tunnel.bypass_apps = split_tunnel.apps.clone();
    }
}

pub fn save_settings(settings: &AppSettings) -> Result<()> {
    save_settings_to(&hadal_config_dir(), settings)
}

pub fn save_settings_to(dir: &Path, settings: &AppSettings) -> Result<()> {
    let path = settings_path_in(dir);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, serde_json::to_string_pretty(settings)?)?;
    Ok(())
}

pub fn endpoint_for_domain(domain: &str) -> String {
    let domain = domain.trim();
    if domain.is_empty() {
        return format!("127.0.0.1:{DEFAULT_WG_PORT}");
    }
    if domain.starts_with('[') {
        if domain.contains("]:") {
            return domain.to_string();
        }
        return format!("{domain}:{DEFAULT_WG_PORT}");
    }
    if let Some((host, port)) = domain.rsplit_once(':') {
        if !host.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
            return domain.to_string();
        }
    }
    format!("{domain}:{DEFAULT_WG_PORT}")
}

pub fn split_host_port_u16(endpoint: &str) -> (String, u16) {
    let normalized = endpoint_for_domain(endpoint);
    if let Some((h, p)) = normalized.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            return (h.to_string(), port);
        }
    }
    (normalized, DEFAULT_WG_PORT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_for_domain_appends_port() {
        assert_eq!(
            endpoint_for_domain("de-fra.prod.surfshark.com"),
            "de-fra.prod.surfshark.com:51820"
        );
        assert_eq!(
            endpoint_for_domain("138.199.19.164:51820"),
            "138.199.19.164:51820"
        );
    }

    #[test]
    fn default_settings_enable_leak_protections() {
        let s = AppSettings::default();
        assert!(s.killswitch);
        assert!(s.ipv6_block);
        assert!(s.bypass_lan);
        assert!(s.auto_mtu);
    }
}
