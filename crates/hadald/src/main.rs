use std::path::PathBuf;

use clap::Parser;
use hadal_core::{DEFAULT_SOCKET_PATH, DEFAULT_WG_IFACE};
use hadald::daemon::{run_daemon, DaemonConfig};
use hadald::net::dns::DnsMode;

#[derive(Parser)]
#[command(name = "hadald", about = "Hadal VPN privileged Linux network daemon")]
struct Args {
    /// Unix domain socket path for CLI & GUI IPC
    #[arg(long, env = "HADALD_SOCKET", default_value = DEFAULT_SOCKET_PATH)]
    socket: PathBuf,

    /// Directory for temporary runtime backups/state
    #[arg(long, env = "HADALD_STATE_DIR", default_value = "/run/hadald")]
    state_dir: PathBuf,

    /// Kernel WireGuard interface name
    #[arg(long, env = "HADALD_IFACE", default_value = DEFAULT_WG_IFACE)]
    iface: String,

    /// DNS backend: auto (systemd-resolved if present), resolved (D-Bus), or resolv-conf
    #[arg(long, env = "HADALD_DNS_MODE", value_enum, default_value_t = DnsMode::Auto)]
    dns_mode: DnsMode,

    /// Path to resolv.conf when using resolv-conf DNS mode (useful in netns tests)
    #[arg(long, env = "HADALD_RESOLV_CONF", default_value = "/etc/resolv.conf")]
    resolv_conf: PathBuf,

    /// Unix group allowed to connect to the IPC socket without root
    #[arg(long, env = "HADALD_GROUP", default_value = "network")]
    group: String,
}

#[tokio::main]
async fn main() -> hadal_core::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    run_daemon(DaemonConfig {
        socket_path: args.socket,
        state_dir: args.state_dir,
        iface: args.iface,
        dns_mode: args.dns_mode,
        resolv_conf_path: args.resolv_conf,
        socket_group: args.group,
    })
    .await
}
