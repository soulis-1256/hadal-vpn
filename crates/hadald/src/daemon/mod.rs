pub mod controller;
pub mod ipc;

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::net::UnixListener;
use tracing::{info, warn};

use hadal_core::{Result, SplitMode};

use crate::net::control::{ControlBackend, ControlPlane};
use crate::net::dns::{DnsBackend, DnsManager, DnsMode};
use crate::net::firewall::{FirewallBackend, NftablesFirewall};
use crate::net::probe::{SystemTunnelProber, TunnelProber};
use crate::net::routing::{NetlinkRouting, RoutingBackend};
use crate::net::sock_diag::{NetlinkSockDiag, SockDiagBackend};
use crate::net::wireguard::{netlink_handle, KernelWireGuard, WireGuardBackend};

pub use controller::DaemonController;
pub use ipc::{configure_socket_permissions, handle_ipc_stream};

pub struct DaemonConfig {
    pub socket_path: PathBuf,
    pub state_dir: PathBuf,
    pub iface: String,
    pub dns_mode: DnsMode,
    pub resolv_conf_path: PathBuf,
    pub socket_group: String,
}

/// Injected network & control-plane backends for `DaemonController`.
#[derive(Clone)]
pub struct DaemonBackends {
    pub wg: Arc<dyn WireGuardBackend>,
    pub firewall: Arc<dyn FirewallBackend>,
    pub routing: Arc<dyn RoutingBackend>,
    pub dns: Arc<dyn DnsBackend>,
    pub sock_diag: Arc<dyn SockDiagBackend>,
    pub control: Arc<dyn ControlBackend>,
    pub prober: Arc<dyn TunnelProber>,
}

pub async fn run_daemon(cfg: DaemonConfig) -> Result<()> {
    std::fs::create_dir_all(&cfg.state_dir)?;
    let nl = netlink_handle().await?;
    let dns = Arc::new(DnsManager::new(
        cfg.dns_mode,
        cfg.resolv_conf_path.clone(),
        &cfg.state_dir,
    ));
    let control = Arc::new(ControlPlane::start().await?);
    let backends = DaemonBackends {
        wg: Arc::new(KernelWireGuard::new(nl.clone())),
        firewall: Arc::new(NftablesFirewall),
        routing: Arc::new(NetlinkRouting::new(nl)),
        dns,
        sock_diag: Arc::new(NetlinkSockDiag),
        control,
        prober: Arc::new(SystemTunnelProber),
    };
    run_daemon_with_backends(cfg, backends).await
}

pub async fn run_daemon_with_backends(cfg: DaemonConfig, backends: DaemonBackends) -> Result<()> {
    std::fs::create_dir_all(&cfg.state_dir)?;
    if let Some(parent) = cfg.socket_path.parent() {
        std::fs::create_dir_all(parent)?;
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755));
    }
    if cfg.socket_path.exists() {
        let _ = std::fs::remove_file(&cfg.socket_path);
    }

    let listener = UnixListener::bind(&cfg.socket_path)?;
    configure_socket_permissions(&cfg.socket_path, &cfg.socket_group);

    let controller = Arc::new(DaemonController::new(cfg.iface.clone(), backends));

    info!(
        "hadald listening on {} (iface {}, dns {:?}, default split {:?})",
        cfg.socket_path.display(),
        cfg.iface,
        cfg.dns_mode,
        SplitMode::Off
    );

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

    // Handle SIGINT / SIGTERM cleanly so shutdown tears down firewall/routes safely
    let sig_tx = shutdown_tx.clone();
    tokio::spawn(async move {
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = async {
                if let Some(ref mut s) = sigterm {
                    s.recv().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {}
        }
        let _ = sig_tx.send(true);
    });

    loop {
        tokio::select! {
            accept_res = listener.accept() => {
                match accept_res {
                    Ok((stream, _)) => {
                        let ctrl = controller.clone();
                        let tx = shutdown_tx.clone();
                        tokio::spawn(async move {
                            let (reader, writer) = stream.into_split();
                            if let Err(e) = handle_ipc_stream(reader, writer, ctrl, tx).await {
                                warn!("IPC client error: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        warn!("Unix socket accept error: {e}");
                    }
                }
            }
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    info!("Shutting down hadald and clearing tunnel/firewall...");
                    let _ = controller.disconnect(false).await;
                    let _ = std::fs::remove_file(&cfg.socket_path);
                    break;
                }
            }
        }
    }

    Ok(())
}
