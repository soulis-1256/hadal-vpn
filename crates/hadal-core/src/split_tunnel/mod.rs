pub mod cgroup;
pub mod desktop;
pub mod manager;
pub mod policy;
pub mod process;

pub use cgroup::{
    derive_slice_rel_path, ensure_user_slice_dir, is_in_slice_child_cgroup, parse_self_cgroup_v2,
    resolve_user_slice_cgroup_path, CgroupManager, SystemdCgroupManager, TRACKED_LEAF_CGROUP,
};
pub use desktop::{
    aliases_for_entry, app_aliases, derive_primary_bin, find_desktop_entry,
    load_desktop_entries_from, parse_desktop_file, resolve_aliases_with_entries, split_exec_tokens,
    xdg_application_dirs, xdg_application_dirs_from, AppCatalog, DesktopAppEntry, XdgAppCatalog,
};
pub use manager::{
    app_statuses, discover_desktop_apps, find_app_pids, launch_app_in_slice, move_app_to_slice,
    reconcile_split_slices, SplitTunnelManager,
};
pub use policy::{
    active_slice_for_mode, PolicyStore, SettingsPolicyStore, SplitAppStatus, SplitMode,
    SplitTunnelConfig, BYPASS_SLICE, DEFAULT_SLICE, VPN_SLICE,
};
pub use process::{
    find_matching_pids_by_aliases, process_matches, resolve_app_binary, ProcessInspector,
    ProcessSnapshot, SysinfoProcessInspector,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cgroup_v2_line_and_derives_slice_path() {
        let proc_cg = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/kitty.scope\n";
        let rel = parse_self_cgroup_v2(proc_cg).expect("v2 path");
        assert_eq!(
            derive_slice_rel_path(&rel, BYPASS_SLICE),
            "user.slice/user-1000.slice/user@1000.service/app.slice/app-hadal_bypass.slice"
        );
    }

    #[test]
    fn derives_slice_when_inside_session_scope() {
        let rel = "user.slice/user-1000.slice/session-1.scope";
        assert_eq!(
            derive_slice_rel_path(rel, VPN_SLICE),
            "user.slice/user-1000.slice/app.slice/app-hadal_vpn.slice"
        );
    }

    #[test]
    fn parses_desktop_entry_ignoring_actions_and_field_codes() {
        let desktop = "\
[Desktop Entry]
Type=Application
Name=Zen Browser
Exec=env MOZ_ENABLE_WAYLAND=1 /opt/zen-browser-bin/zen-bin %u
StartupWMClass=zen-alpha

[Desktop Action new-private-window]
Name=New Private Window
Exec=/opt/zen-browser-bin/zen-bin --private-window %u
";
        let parsed = parse_desktop_file("zen-browser", desktop).expect("desktop entry");
        assert_eq!(parsed.name, "Zen Browser");
        assert_eq!(parsed.bin, "zen-bin");
        assert_eq!(parsed.wm_class.as_deref(), Some("zen-alpha"));
        assert!(!parsed.exec.contains("%u"));
        assert!(parsed.exec.contains("/opt/zen-browser-bin/zen-bin"));
    }

    #[test]
    fn skips_nodisplay_and_extracts_flatpak_app_id() {
        let hidden =
            "[Desktop Entry]\nType=Application\nName=Helper\nExec=/bin/true\nNoDisplay=true\n";
        assert!(parse_desktop_file("helper", hidden).is_none());

        let flatpak = "[Desktop Entry]\nType=Application\nName=Discord\nExec=/usr/bin/flatpak run --branch=stable com.discordapp.Discord\n";
        let parsed = parse_desktop_file("com.discordapp.Discord", flatpak).expect("flatpak");
        assert_eq!(parsed.bin, "com.discordapp.Discord");
        assert_eq!(parsed.name, "Discord");
    }

    #[test]
    fn keeps_bypass_and_only_vpn_lists_independent() {
        let mut cfg = SplitTunnelConfig::default();
        assert_eq!(cfg.apps_for_mode(SplitMode::Bypass), &["steam", "discord"]);
        assert!(cfg.apps_for_mode(SplitMode::OnlyVpn).is_empty());

        cfg.apps_for_mode_mut(SplitMode::OnlyVpn)
            .push("zen-browser".into());
        cfg.mode = SplitMode::OnlyVpn;
        cfg.sync_active_apps();

        assert_eq!(cfg.apps, &["zen-browser"]);
        assert_eq!(cfg.bypass_apps, &["steam", "discord"]);
        assert_eq!(cfg.only_vpn_apps, &["zen-browser"]);
    }

    #[test]
    fn distinguishes_slice_root_from_leaf_and_scope_children() {
        assert!(!is_in_slice_child_cgroup(
            "user.slice/user-1000.slice/user@1000.service/app.slice/app-hadal_bypass.slice",
            BYPASS_SLICE
        ));
        assert!(is_in_slice_child_cgroup(
            "user.slice/user-1000.slice/user@1000.service/app.slice/app-hadal_bypass.slice/tracked",
            BYPASS_SLICE
        ));
        assert!(is_in_slice_child_cgroup(
            "user.slice/user-1000.slice/user@1000.service/app.slice/app-hadal_bypass.slice/run-123.scope",
            BYPASS_SLICE
        ));
    }
}
