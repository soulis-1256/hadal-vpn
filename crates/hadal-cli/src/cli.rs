use clap::{Parser, Subcommand, ValueEnum};
use hadal_core::SplitMode;

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum CliSplitMode {
    Bypass,
    OnlyVpn,
    Off,
}

impl From<CliSplitMode> for SplitMode {
    fn from(v: CliSplitMode) -> Self {
        match v {
            CliSplitMode::Bypass => SplitMode::Bypass,
            CliSplitMode::OnlyVpn => SplitMode::OnlyVpn,
            CliSplitMode::Off => SplitMode::Off,
        }
    }
}

#[derive(Parser, Debug)]
#[command(name = "hadal-cli")]
#[command(about = "Hadal VPN — Linux Kernel WireGuard + Gaming Optimizer CLI")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Log in using a 6-character quick-pair code
    #[command(visible_alias = "login")]
    Code,
    /// View Surfshark account and subscription info
    Me,
    /// List Surfshark server clusters
    Servers {
        #[arg(short, long)]
        filter: Option<String>,
        #[arg(short, long, default_value_t = 25)]
        limit: usize,
        #[arg(long)]
        sort_load: bool,
        #[arg(long)]
        include_static: bool,
    },
    /// Generate and register a WireGuard keypair
    Keygen,
    /// Connect system-wide via hadald kernel WireGuard
    Connect {
        #[arg(short, long)]
        server: Option<String>,
        /// Pin a specific WireGuard endpoint IP/port instead of auto-probing fastest pool
        #[arg(long)]
        endpoint: Option<String>,
        /// Override WireGuard MTU (defaults to auto-detected WAN PMTU - 80)
        #[arg(long)]
        mtu: Option<u16>,
        #[arg(long)]
        no_killswitch: bool,
        #[arg(long)]
        no_ipv6_block: bool,
        /// Route ONLY traffic matching this game host's /24 subnets through VPN
        #[arg(long)]
        game_only: Option<String>,
    },
    /// Disconnect the active WireGuard tunnel
    Disconnect {
        /// Keep the nftables killswitch armed after disconnecting
        #[arg(long)]
        keep_killswitch: bool,
    },
    /// Show live daemon status, tunnel telemetry, and public IP
    Status,
    /// Toggle standalone killswitch state
    Killswitch {
        #[arg(value_parser = ["on", "off"])]
        state: String,
    },
    /// Dynamic Gaming Mode: discover lowest-ping Surfshark route for any game/region
    Gaming {
        #[arg(long, default_value = "fortnite")]
        game: String,
        #[arg(long, default_value = "eu-de")]
        region: String,
        #[arg(long)]
        host: Option<String>,
        /// Automatically connect to the lowest-latency endpoint discovered
        #[arg(long)]
        connect: bool,
        /// When connecting, route only the game's CIDRs via VPN
        #[arg(long)]
        game_only: bool,
        /// List available built-in games and regions
        #[arg(long)]
        list: bool,
        /// Skip live WireGuard end-to-end tunnel verification on candidates
        #[arg(long)]
        no_verify: bool,
    },
    /// Manage cgroupv2 L3 split tunneling
    Split {
        #[command(subcommand)]
        action: SplitAction,
    },
    /// Measure ICMP latency and optional TTL trace
    Ping {
        #[arg(default_value = "ping-de.ds.on.epicgames.com")]
        target: String,
        #[arg(short, long, default_value_t = 5)]
        count: u32,
        #[arg(long)]
        trace: bool,
    },
    /// Print systemd service & Hyprland windowrule setup commands
    InstallInfo,
}

#[derive(Subcommand, Debug)]
pub enum SplitAction {
    /// Set split-tunnel mode (bypass, only-vpn, off)
    Mode {
        #[arg(value_enum)]
        mode: CliSplitMode,
    },
    /// Launch an executable inside the active split-tunnel cgroupv2 slice
    Launch { app: String },
    /// Move already-running processes matching <app> into the split-tunnel slice
    Move { app: String },
    /// Show tracked split-tunnel applications and active cgroup slices
    Status,
}
