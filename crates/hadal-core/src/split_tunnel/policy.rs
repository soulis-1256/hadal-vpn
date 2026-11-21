use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::config::SettingsStore;
use crate::error::Result;

pub const BYPASS_SLICE: &str = "app-hadal_bypass.slice";
pub const VPN_SLICE: &str = "app-hadal_vpn.slice";
pub const DEFAULT_SLICE: &str = "app-hadal_default.slice";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum SplitMode {
    #[default]
    Bypass,
    OnlyVpn,
    Off,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct SplitTunnelConfig {
    pub mode: SplitMode,
    /// Active mode's app list kept synchronized for daemon/GUI compatibility.
    pub apps: Vec<String>,
    /// Apps excluded from VPN when `mode == SplitMode::Bypass`.
    pub bypass_apps: Vec<String>,
    /// Apps exclusively routed through VPN when `mode == SplitMode::OnlyVpn`.
    pub only_vpn_apps: Vec<String>,
    /// Optional explicit cgroupv2 relative paths (e.g. `user.slice/.../app-hadal_bypass.slice`).
    pub cgroup_paths: Vec<String>,
    /// Optional destination CIDRs routed exclusively via VPN in game-only split mode.
    pub game_only_cidrs: Vec<String>,
}

impl Default for SplitTunnelConfig {
    fn default() -> Self {
        let initial_bypass = vec!["steam".to_string(), "discord".to_string()];
        Self {
            mode: SplitMode::Bypass,
            apps: initial_bypass.clone(),
            bypass_apps: initial_bypass,
            only_vpn_apps: Vec::new(),
            cgroup_paths: Vec::new(),
            game_only_cidrs: Vec::new(),
        }
    }
}

impl SplitTunnelConfig {
    pub fn apps_for_mode(&self, mode: SplitMode) -> &[String] {
        match mode {
            SplitMode::Bypass => &self.bypass_apps,
            SplitMode::OnlyVpn => &self.only_vpn_apps,
            SplitMode::Off => &[],
        }
    }

    pub fn apps_for_mode_mut(&mut self, mode: SplitMode) -> &mut Vec<String> {
        match mode {
            SplitMode::Bypass | SplitMode::Off => &mut self.bypass_apps,
            SplitMode::OnlyVpn => &mut self.only_vpn_apps,
        }
    }

    pub fn sync_active_apps(&mut self) {
        self.apps = self.apps_for_mode(self.mode).to_vec();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SplitAppStatus {
    pub name: String,
    pub display_name: String,
    pub running: bool,
    pub in_split_slice: bool,
    pub slice: Option<String>,
    pub pids: Vec<u32>,
}

pub fn active_slice_for_mode(mode: SplitMode) -> Option<&'static str> {
    match mode {
        SplitMode::Bypass => Some(BYPASS_SLICE),
        SplitMode::OnlyVpn => Some(VPN_SLICE),
        SplitMode::Off => None,
    }
}

/// Persistence seam for split-tunnel policy configuration.
pub trait PolicyStore: Send + Sync {
    fn load_policy(&self) -> Result<SplitTunnelConfig>;
    fn save_policy(&self, policy: &SplitTunnelConfig) -> Result<()>;
}

/// [`PolicyStore`] backed by a [`SettingsStore`] implementation.
#[derive(Clone)]
pub struct SettingsPolicyStore {
    settings: Arc<dyn SettingsStore>,
}

impl SettingsPolicyStore {
    pub fn new(settings: Arc<dyn SettingsStore>) -> Self {
        Self { settings }
    }
}

impl PolicyStore for SettingsPolicyStore {
    fn load_policy(&self) -> Result<SplitTunnelConfig> {
        Ok(self.settings.load().split_tunnel)
    }

    fn save_policy(&self, policy: &SplitTunnelConfig) -> Result<()> {
        let mut settings = self.settings.load();
        settings.split_tunnel = policy.clone();
        settings.split_tunnel.sync_active_apps();
        self.settings.save(&settings)
    }
}
