use std::fmt::Write as _;

use hadal_core::auth::UserMe;
use hadal_core::{
    Cluster, DaemonStatus, GameProfile, GamingScanReport, SplitAppStatus, SplitMode, UserLocation,
};

pub fn format_me(me: &UserMe) -> String {
    format!(
        "User: {}\nStatus: {}",
        me.email.as_deref().unwrap_or("Unknown"),
        me.status.as_deref().unwrap_or("Active")
    )
}

pub fn format_user_location_line(prefix: &str, loc: &UserLocation, show_secured: bool) -> String {
    if show_secured {
        format!(
            "{prefix}{} ({:?}, {:?}) - Secured: {}",
            loc.ip, loc.country, loc.city, loc.secured
        )
    } else {
        format!("{prefix}{} ({:?}, {:?})", loc.ip, loc.country, loc.city)
    }
}

pub fn format_servers_table(clusters: &[Cluster], limit: usize) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{:<22} {:<15} {:<28} {:<6} {:<6}",
        "LOCATION", "COUNTRY", "ENDPOINT", "LOAD", "TAGS"
    );
    let _ = writeln!(out, "{}", "-".repeat(82));
    for c in clusters.iter().take(limit) {
        let _ = writeln!(
            out,
            "{:<22} {:<15} {:<28} {:<6} {:<6}",
            c.location.as_deref().unwrap_or("Unknown"),
            c.country.as_deref().unwrap_or("Unknown"),
            c.connection_name.as_deref().unwrap_or("-"),
            c.load
                .map(|l| format!("{l}%"))
                .unwrap_or_else(|| "-".into()),
            c.tags.join(",")
        );
    }
    out.trim_end_matches('\n').to_string()
}

pub fn format_status(st: &DaemonStatus, location: Option<&UserLocation>) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "State:      {:?}", st.state);
    let _ = writeln!(out, "Interface:  {}", st.interface);
    if let Some(ep) = &st.endpoint {
        let _ = writeln!(
            out,
            "Endpoint:   {} ({}, {})",
            ep,
            st.location.as_deref().unwrap_or("-"),
            st.country.as_deref().unwrap_or("-")
        );
    }
    if let Some(addr) = &st.address {
        let _ = writeln!(
            out,
            "Address:    {addr} | MTU: {}",
            st.mtu.map(|m| m.to_string()).unwrap_or_else(|| "-".into())
        );
    }
    let _ = writeln!(
        out,
        "Shields:    killswitch={} ipv6_block={} bypass_lan={}",
        st.killswitch, st.ipv6_block, st.bypass_lan
    );
    let _ = writeln!(
        out,
        "Split Mode: {:?} (cgroups: {:?}, game_cidrs: {:?})",
        st.split_mode, st.split_cgroup_paths, st.game_only_cidrs
    );
    let _ = writeln!(
        out,
        "Traffic:    rx={} B | tx={} B",
        st.rx_bytes, st.tx_bytes
    );
    if let Some(loc) = location {
        let _ = writeln!(
            out,
            "{}",
            format_user_location_line("Exit IP:    ", loc, true)
        );
    }
    out.trim_end_matches('\n').to_string()
}

pub fn format_gaming_list(games: &[GameProfile]) -> String {
    let mut out = String::new();
    for g in games {
        let _ = writeln!(out, "Game: {} ({})", g.name, g.id);
        for r in &g.regions {
            let _ = writeln!(out, "  {:<10} {:<34} {}", r.id, r.label, r.ping_host);
        }
    }
    out.trim_end_matches('\n').to_string()
}

pub fn format_gaming_report(report: &GamingScanReport) -> String {
    let mut out = String::new();
    if let Some(ref b) = report.baseline_direct {
        let _ = writeln!(
            out,
            "Direct Baseline: min={:.2} avg={:.2} max={:.2} mdev={:.2} ms (loss {:.0}%)",
            b.min_ms, b.avg_ms, b.max_ms, b.mdev_ms, b.loss_pct
        );
    }
    if let Some(ref tun) = report.active_tunnel_ping {
        let label = report
            .active_tunnel_label
            .as_deref()
            .unwrap_or("Active VPN");
        let _ = writeln!(
            out,
            "Via {label}:      min={:.2} avg={:.2} max={:.2} mdev={:.2} ms (loss {:.0}%)",
            tun.min_ms, tun.avg_ms, tun.max_ms, tun.mdev_ms, tun.loss_pct
        );
    }
    let _ = writeln!(
        out,
        "WAN PMTU: {} -> Recommended WG MTU: {}",
        report.wan_pmtu, report.recommended_mtu
    );
    let _ = writeln!(
        out,
        "\n{:<3} {:<20} {:<15} {:<16} {:<9} {:<9} {:<17} {:<6}",
        "#", "CITY", "COUNTRY", "ENDPOINT IP", "DIRECT", "EST.TOT", "VERIFIED", "LOAD"
    );
    let _ = writeln!(out, "{}", "-".repeat(103));
    for (i, c) in report.candidates.iter().enumerate() {
        let verified = c
            .verified_tunnel_ms
            .map(|v| {
                let mdev = c.verified_mdev_ms.unwrap_or(0.0);
                let loss = c.verified_loss_pct.unwrap_or(0.0);
                if loss > 0.0 {
                    format!("{v:.2}±{mdev:.1} ({loss:.0}%)")
                } else {
                    format!("{v:.2}ms ±{mdev:.1}")
                }
            })
            .unwrap_or_else(|| "-".into());
        let _ = writeln!(
            out,
            "{:<3} {:<20} {:<15} {:<16} {:>6.2}ms  {:>6.2}ms  {:<17} {}%",
            i + 1,
            c.location,
            c.country,
            c.endpoint_ip,
            c.direct_rtt_ms,
            c.estimated_total_ms,
            verified,
            c.load.map(|l| l.to_string()).unwrap_or_else(|| "-".into()),
        );
    }
    out.trim_end_matches('\n').to_string()
}

pub fn format_split_status(
    mode: SplitMode,
    expected_slice: Option<&str>,
    statuses: &[SplitAppStatus],
) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Split Mode: {mode:?} (slice {expected_slice:?})");
    for st in statuses {
        let _ = writeln!(
            out,
            "  {:<16} running={:<5} in_slice={:<5} pids={:?}",
            st.name, st.running, st.in_split_slice, st.pids
        );
    }
    out.trim_end_matches('\n').to_string()
}

pub fn format_install_info() -> &'static str {
    "One-command local build & install (from repo root):\n\
     \x20 ./scripts/install.sh --reconnect\n\
     \n\
     Manual install:\n\
     \x20 sudo install -Dm755 target/release/hadald /usr/local/bin/hadald\n\
     \x20 sudo install -Dm755 target/release/hadal-cli /usr/local/bin/hadal-cli\n\
     \x20 sudo install -Dm755 target/release/hadal-gui /usr/local/bin/hadal-gui\n\
     \x20 sudo install -Dm644 contrib/hadald.service /etc/systemd/system/hadald.service\n\
     \x20 sudo install -Dm644 contrib/hadal-vpn.desktop /usr/local/share/applications/hadal-vpn.desktop\n\
     \x20 sudo install -Dm644 crates/hadal-gui/src-tauri/icons/128x128.png /usr/local/share/icons/hicolor/128x128/apps/hadal-vpn.png\n\
     \x20 install -Dm644 contrib/hadal-gui.service ~/.config/systemd/user/hadal-gui.service\n\
     \x20 sudo groupadd -f network && sudo usermod -aG network \"$USER\"\n\
     \x20 sudo systemctl daemon-reload && sudo systemctl enable --now hadald\n\
     \x20 systemctl --user daemon-reload && systemctl --user enable --now hadal-gui\n\
     \n\
     Fast dev loop (no hadald restart):\n\
     \x20 ./scripts/dev.sh gui        # hot-reload Tauri + SolidJS UI\n\
     \x20 ./scripts/dev.sh cli status # run CLI against live hadald\n\
     \n\
     Optional Hyprland 0.55+/0.57+ Lua tray popover rules:\n\
     \x20 hadal-gui applies rules automatically via `hyprctl eval`, or copy/require\n\
     \x20 `contrib/hyprland-hadal.lua` in your Hyprland Lua config."
}
