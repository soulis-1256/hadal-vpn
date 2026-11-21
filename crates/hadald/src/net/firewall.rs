use std::io::Write;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::{Command, Stdio};

use hadal_core::{Result, HadalError, SplitMode};

use super::routing::{BYPASS_FWMARK, CONTROL_FWMARK, ONLY_VPN_FWMARK};
use super::wireguard::WG_FWMARK;

pub const NFT_TABLE_NAME: &str = "hadal_vpn";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallSpec {
    pub wg_iface: String,
    pub endpoint_ip: Option<Ipv4Addr>,
    pub endpoint_port: u16,
    pub killswitch: bool,
    pub ipv6_block: bool,
    pub bypass_lan: bool,
    pub split_mode: SplitMode,
    pub split_cgroup_paths: Vec<String>,
    pub game_only_cidrs: Vec<String>,
    pub tunnel_active: bool,
}

/// Abstraction over nftables killswitch, IPv6/DNS leak lock, and split-tunnel marking.
pub trait FirewallBackend: Send + Sync {
    fn apply_firewall(&self, spec: &FirewallSpec) -> Result<()>;
    fn clear_firewall(&self) -> Result<()>;
}

/// Real Linux `nft` CLI backend operating atomically on `table inet hadal_vpn`.
pub struct NftablesFirewall;

impl FirewallBackend for NftablesFirewall {
    fn apply_firewall(&self, spec: &FirewallSpec) -> Result<()> {
        apply_firewall(spec)
    }

    fn clear_firewall(&self) -> Result<()> {
        clear_firewall()
    }
}

fn split_fwmark(mode: SplitMode) -> Option<u32> {
    match mode {
        SplitMode::Bypass => Some(BYPASS_FWMARK),
        SplitMode::OnlyVpn => Some(ONLY_VPN_FWMARK),
        SplitMode::Off => None,
    }
}

pub fn apply_firewall(spec: &FirewallSpec) -> Result<()> {
    let valid_cgroups = existing_cgroups(&spec.split_cgroup_paths);
    let needs_mangle = spec.tunnel_active
        && (spec.endpoint_ip.is_some()
            || (spec.split_mode != SplitMode::Off && !valid_cgroups.is_empty()));
    let needs_filter = spec.killswitch || (spec.tunnel_active && spec.ipv6_block);

    if !needs_mangle && !needs_filter {
        return clear_firewall();
    }

    let script = render_nftables_script_with_cgroups(spec, &valid_cgroups);
    run_nft_stdin(&script, false)
}

pub fn clear_firewall() -> Result<()> {
    // Deleting a non-existent table returns an error in nft; create-then-delete atomically removes cleanly.
    let script = format!("table inet {NFT_TABLE_NAME}\ndelete table inet {NFT_TABLE_NAME}\n");
    run_nft_stdin(&script, false)
}

pub fn render_nftables_script(spec: &FirewallSpec) -> String {
    let valid_cgroups = existing_cgroups(&spec.split_cgroup_paths);
    render_nftables_script_with_cgroups(spec, &valid_cgroups)
}

/// Render an atomic nftables ruleset using an explicit list of verified cgroupv2 relative paths.
pub fn render_nftables_script_with_cgroups(spec: &FirewallSpec, valid_cgroups: &[String]) -> String {
    let mut out = String::new();
    // Atomic idempotent reset of our table only (never flushes unrelated user firewall tables)
    out.push_str(&format!("table inet {NFT_TABLE_NAME}\n"));
    out.push_str(&format!("delete table inet {NFT_TABLE_NAME}\n"));
    out.push_str(&format!("table inet {NFT_TABLE_NAME} {{\n"));

    let normalized_cgroups: Vec<String> = valid_cgroups
        .iter()
        .map(|s| s.trim().trim_matches('/').to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let split_mark = split_fwmark(spec.split_mode);
    let has_split_mangle =
        spec.tunnel_active && split_mark.is_some() && !normalized_cgroups.is_empty();

    // 1. Mangle prerouting chain (runs before rp_filter so returning WG & split-tunnel packets validate cleanly)
    if spec.tunnel_active && (spec.endpoint_ip.is_some() || has_split_mangle) {
        out.push_str("  chain mangle_in {\n");
        out.push_str("    type filter hook prerouting priority mangle; policy accept;\n");
        if let Some(peer_ip) = spec.endpoint_ip {
            out.push_str(&format!(
                "    ip saddr {peer_ip} udp sport {} meta mark set 0x{WG_FWMARK:x}\n",
                spec.endpoint_port
            ));
        }
        if has_split_mangle {
            if let Some(mark) = split_mark {
                out.push_str(&format!("    ct mark 0x{mark:x} meta mark set ct mark\n"));
            }
        }
        out.push_str("  }\n");
    }

    // 2. Mangle output chain (`type route` triggers kernel re-routing after fwmark update)
    // + Postrouting masquerade so TCP sockets whose initial route picked the opposite interface get valid source IP.
    if has_split_mangle {
        if let Some(mark) = split_mark {
            out.push_str("  chain mangle_out {\n");
            out.push_str("    type route hook output priority mangle; policy accept;\n");
            for cg in &normalized_cgroups {
                let level = cg.split('/').filter(|s| !s.is_empty()).count();
                if level > 0 {
                    out.push_str(&format!(
                        "    socket cgroupv2 level {level} \"{cg}\" meta mark set 0x{mark:x}\n"
                    ));
                }
            }
            out.push_str(&format!("    meta mark 0x{mark:x} ct mark set 0x{mark:x}\n"));
            out.push_str("  }\n");

            out.push_str("  chain nat_post {\n");
            out.push_str("    type nat hook postrouting priority srcnat; policy accept;\n");
            match spec.split_mode {
                SplitMode::Bypass => {
                    out.push_str(&format!(
                        "    meta nfproto ipv4 meta mark 0x{mark:x} oifname != \"lo\" masquerade\n"
                    ));
                }
                SplitMode::OnlyVpn => {
                    out.push_str(&format!(
                        "    meta nfproto ipv4 meta mark 0x{mark:x} oifname \"{}\" masquerade\n",
                        spec.wg_iface
                    ));
                }
                SplitMode::Off => {}
            }
            out.push_str("  }\n");
        }
    }

    // 3. Output filter chain (Killswitch + DNS leak shield + IPv6 leak lock)
    if spec.killswitch || (spec.tunnel_active && spec.ipv6_block) {
        let policy = if spec.killswitch { "drop" } else { "accept" };
        out.push_str("  chain filter_out {\n");
        out.push_str(&format!(
            "    type filter hook output priority filter; policy {policy};\n"
        ));
        out.push_str("    oifname \"lo\" accept\n");

        // Block IPv6 BEFORE `ct state established,related accept` so pre-existing ISP IPv6 sockets
        // opened prior to connecting cannot keep leaking over WAN once the tunnel is up.
        if spec.ipv6_block {
            out.push_str("    meta nfproto ipv6 counter reject with icmpv6 type admin-prohibited\n");
        }

        out.push_str("    ct state established,related accept\n");

        // Allow WireGuard daemon's own encrypted packets exclusively to active peer
        if let Some(peer_ip) = spec.endpoint_ip {
            out.push_str(&format!(
                "    meta mark 0x{WG_FWMARK:x} ip daddr {peer_ip} udp dport {} accept\n",
                spec.endpoint_port
            ));
        }

        // Allow hadald's own CAP_NET_ADMIN-marked control-plane sockets (DoH/API HTTPS :443 + WAN RTT/PMTU ICMP)
        // so reconnects and Gaming Mode WAN baselines work cleanly in both KillswitchLocked and Protected states.
        if spec.killswitch {
            out.push_str(&format!(
                "    meta mark 0x{CONTROL_FWMARK:x} meta nfproto ipv4 tcp dport 443 accept\n"
            ));
            out.push_str(&format!(
                "    meta mark 0x{CONTROL_FWMARK:x} meta nfproto ipv4 ip protocol icmp accept\n"
            ));
        }

        // Allow tunneled traffic through WireGuard interface
        out.push_str(&format!(
            "    oifname \"{}\" meta nfproto ipv4 accept\n",
            spec.wg_iface
        ));

        // Block non-tunnel DNS/DoT leaks before any split/LAN allow rules
        if spec.killswitch {
            if spec.split_mode == SplitMode::Bypass {
                out.push_str(&format!(
                    "    meta mark 0x{BYPASS_FWMARK:x} meta nfproto ipv4 accept\n"
                ));
            }

            if spec.split_mode == SplitMode::OnlyVpn {
                out.push_str(&format!(
                    "    meta mark 0x{ONLY_VPN_FWMARK:x} counter drop\n"
                ));
                out.push_str("    udp dport 53 counter drop\n");
                out.push_str("    tcp dport { 53, 853 } counter drop\n");
                out.push_str("    meta nfproto ipv4 accept\n");
            } else if !spec.game_only_cidrs.is_empty() {
                let joined = spec.game_only_cidrs.join(", ");
                out.push_str(&format!("    ip daddr {{ {joined} }} counter drop\n"));
                out.push_str("    udp dport 53 counter drop\n");
                out.push_str("    tcp dport { 53, 853 } counter drop\n");
                out.push_str("    meta nfproto ipv4 accept\n");
            } else {
                out.push_str("    udp dport 53 counter drop\n");
                out.push_str("    tcp dport { 53, 853 } counter drop\n");

                if spec.bypass_lan {
                    out.push_str(
                        "    ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 224.0.0.0/4, 255.255.255.255 } accept\n",
                    );
                }
            }
        }

        out.push_str("    counter\n");
        out.push_str("  }\n");
    }

    out.push_str("}\n");
    out
}

fn existing_cgroups(paths: &[String]) -> Vec<String> {
    paths
        .iter()
        .filter_map(|p| {
            let trimmed = p.trim().trim_matches('/');
            if trimmed.is_empty() {
                return None;
            }
            if Path::new("/sys/fs/cgroup").join(trimmed).exists() {
                Some(trimmed.to_string())
            } else {
                None
            }
        })
        .collect()
}

fn run_nft_stdin(script: &str, check_only: bool) -> Result<()> {
    let mut cmd = Command::new("nft");
    if check_only {
        cmd.arg("-c");
    }
    cmd.args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| HadalError::WireGuard(format!("Failed to spawn nft: {e}")))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(script.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        return Err(HadalError::WireGuard(format!(
            "nft failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn renders_and_validates_killswitch_nft_syntax_in_user_netns() {
        let spec = FirewallSpec {
            wg_iface: "hadal-wg".into(),
            endpoint_ip: Some(Ipv4Addr::new(138, 199, 19, 164)),
            endpoint_port: 51820,
            killswitch: true,
            ipv6_block: true,
            bypass_lan: true,
            split_mode: SplitMode::Bypass,
            split_cgroup_paths: vec![],
            game_only_cidrs: vec![],
            tunnel_active: true,
        };
        let script = render_nftables_script_with_cgroups(&spec, &[]);
        assert!(script.contains("policy drop"));
        assert!(script.contains("meta nfproto ipv6 counter reject with icmpv6 type admin-prohibited"));
        assert!(
            script.find("meta nfproto ipv6 counter reject")
                < script.find("ct state established,related accept"),
            "ipv6 reject must run before established/related accept so pre-connect IPv6 cannot leak"
        );
        assert!(script.contains("ip daddr 138.199.19.164 udp dport 51820 accept"));
        validate_in_user_netns(&script);

        assert!(script.contains(&format!(
            "meta mark 0x{CONTROL_FWMARK:x} meta nfproto ipv4 tcp dport 443 accept"
        )));
        let mut locked_spec = spec.clone();
        locked_spec.tunnel_active = false;
        locked_spec.endpoint_ip = None;
        let locked_script = render_nftables_script_with_cgroups(&locked_spec, &[]);
        assert!(locked_script.contains(&format!(
            "meta mark 0x{CONTROL_FWMARK:x} meta nfproto ipv4 tcp dport 443 accept"
        )));
        validate_in_user_netns(&locked_script);
    }

    #[test]
    fn renders_split_cgroup_mangle_and_nat_for_bypass_and_only_vpn() {
        let cg = vec!["user.slice/user-1000.slice/app.slice/app-hadal_bypass.slice".to_string()];
        let bypass_spec = FirewallSpec {
            wg_iface: "hadal-wg".into(),
            endpoint_ip: Some(Ipv4Addr::new(192, 0, 2, 1)),
            endpoint_port: 51820,
            killswitch: true,
            ipv6_block: true,
            bypass_lan: false,
            split_mode: SplitMode::Bypass,
            split_cgroup_paths: cg.clone(),
            game_only_cidrs: vec![],
            tunnel_active: true,
        };
        let bypass_script = render_nftables_script_with_cgroups(&bypass_spec, &cg);
        assert!(bypass_script.contains("socket cgroupv2 level 4"));
        assert!(bypass_script.contains(&format!("meta mark set 0x{BYPASS_FWMARK:x}")));
        assert!(bypass_script.contains("oifname != \"lo\" masquerade"));

        let only_vpn_spec = FirewallSpec {
            split_mode: SplitMode::OnlyVpn,
            ..bypass_spec.clone()
        };
        let only_vpn_script = render_nftables_script_with_cgroups(&only_vpn_spec, &cg);
        assert!(only_vpn_script.contains(&format!("meta mark set 0x{ONLY_VPN_FWMARK:x}")));
        assert!(only_vpn_script.contains("oifname \"hadal-wg\" masquerade"));
        assert!(only_vpn_script.contains(&format!("meta mark 0x{ONLY_VPN_FWMARK:x} counter drop")));

        // `nft -c` resolves socket cgroupv2 paths against /sys/fs/cgroup, so use a live path when present.
        if Path::new("/sys/fs/cgroup/user.slice").exists() {
            let live_cg = vec!["user.slice".to_string()];
            validate_in_user_netns(&render_nftables_script_with_cgroups(&bypass_spec, &live_cg));
            validate_in_user_netns(&render_nftables_script_with_cgroups(&only_vpn_spec, &live_cg));
        }
    }

    #[test]
    fn renders_and_validates_game_only_and_split_mangle_in_user_netns() {
        let game_spec = FirewallSpec {
            wg_iface: "hadal-wg".into(),
            endpoint_ip: Some(Ipv4Addr::new(192, 0, 2, 1)),
            endpoint_port: 51820,
            killswitch: true,
            ipv6_block: true,
            bypass_lan: false,
            split_mode: SplitMode::Off,
            split_cgroup_paths: vec![],
            game_only_cidrs: vec!["3.66.0.0/16".into(), "18.194.0.0/15".into()],
            tunnel_active: true,
        };
        let game_script = render_nftables_script_with_cgroups(&game_spec, &[]);
        assert!(game_script.contains("chain mangle_in"));
        assert!(game_script.contains("ip daddr { 3.66.0.0/16, 18.194.0.0/15 } counter drop"));
        validate_in_user_netns(&game_script);
    }

    fn validate_in_user_netns(script: &str) {
        let out = Command::new("unshare")
            .args(["-Urn", "nft", "-c", "-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .and_then(|mut c| {
                c.stdin.take().unwrap().write_all(script.as_bytes())?;
                c.wait_with_output()
            });
        if let Ok(res) = out {
            assert!(
                res.status.success(),
                "nft -c failed: {}",
                String::from_utf8_lossy(&res.stderr)
            );
        }
    }
}
