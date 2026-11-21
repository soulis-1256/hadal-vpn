use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::config::daemon_socket_path;
use crate::error::{Result, HadalError};
use crate::gaming::PingStats;
use crate::platform::BoxFuture;
use crate::split_tunnel::{SplitMode, SplitTunnelConfig};

pub use crate::gaming::tournament::{prepare_connect_target, scan_gaming_with_daemon};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum TunnelState {
    #[default]
    Disconnected,
    Connecting,
    Protected,
    KillswitchLocked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectSpec {
    pub cluster_id: Option<String>,
    pub domain: String,
    pub endpoint_ip: String,
    pub endpoint_port: u16,
    pub pub_key: String,
    pub priv_key: String,
    pub address: String,
    pub dns: Vec<String>,
    pub mtu: u16,
    pub killswitch: bool,
    pub ipv6_block: bool,
    pub bypass_lan: bool,
    pub split_mode: SplitMode,
    pub split_cgroup_paths: Vec<String>,
    pub game_only_cidrs: Vec<String>,
    pub location: Option<String>,
    pub country: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", content = "data", rename_all = "snake_case")]
pub enum DaemonRequest {
    Status,
    Connect(ConnectSpec),
    Disconnect {
        keep_killswitch: bool,
    },
    SetKillswitch {
        enabled: bool,
        ipv6_block: bool,
        bypass_lan: bool,
    },
    UpdateSplitTunnel(SplitTunnelConfig),
    ResetAppSockets {
        pids: Vec<u32>,
    },
    ControlHttp {
        method: String,
        url: String,
        headers: Vec<(String, String)>,
        body: Option<Vec<u8>>,
    },
    PrepareEndpoint {
        domain: String,
        discover_pmtu: bool,
    },
    ProbeWanGaming {
        target_host: String,
        domains: Vec<String>,
    },
    VerifyGamingTunnels {
        target_ip: String,
        priv_key: String,
        address: String,
        mtu: u16,
        targets: Vec<VerifyTarget>,
        #[serde(default)]
        samples: Option<u32>,
    },
    Shutdown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifyTarget {
    pub cluster_id: String,
    pub endpoint_ip: String,
    pub endpoint_port: u16,
    pub pub_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerifiedTunnelResult {
    pub cluster_id: String,
    pub endpoint_ip: String,
    pub min_ms: f64,
    pub avg_ms: f64,
    pub mdev_ms: f64,
    #[serde(default)]
    pub loss_pct: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EndpointProbeResult {
    pub domain: String,
    pub endpoint_ip: String,
    pub min_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WanGamingProbe {
    pub baseline_direct: Option<PingStats>,
    pub wan_pmtu: u16,
    pub game_cidrs: Vec<String>,
    pub endpoints: Vec<EndpointProbeResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DaemonStatus {
    pub state: TunnelState,
    pub interface: String,
    pub cluster_id: Option<String>,
    pub domain: Option<String>,
    pub endpoint: Option<String>,
    pub location: Option<String>,
    pub country: Option<String>,
    pub address: Option<String>,
    pub mtu: Option<u16>,
    pub dns: Vec<String>,
    pub killswitch: bool,
    pub ipv6_block: bool,
    pub bypass_lan: bool,
    pub split_mode: SplitMode,
    pub split_cgroup_paths: Vec<String>,
    pub game_only_cidrs: Vec<String>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub last_handshake_epoch: Option<u64>,
    pub last_error: Option<String>,
}

impl Default for DaemonStatus {
    fn default() -> Self {
        Self {
            state: TunnelState::Disconnected,
            interface: crate::config::DEFAULT_WG_IFACE.to_string(),
            cluster_id: None,
            domain: None,
            endpoint: None,
            location: None,
            country: None,
            address: None,
            mtu: None,
            dns: Vec::new(),
            killswitch: false,
            ipv6_block: true,
            bypass_lan: true,
            split_mode: SplitMode::Off,
            split_cgroup_paths: Vec::new(),
            game_only_cidrs: Vec::new(),
            rx_bytes: 0,
            tx_bytes: 0,
            last_handshake_epoch: None,
            last_error: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "status", content = "data", rename_all = "snake_case")]
pub enum DaemonResponse {
    Status(DaemonStatus),
    Http {
        status: u16,
        body: Vec<u8>,
    },
    Prepared {
        endpoint_ip: String,
        wan_pmtu: Option<u16>,
    },
    WanGamingProbed(WanGamingProbe),
    GamingTunnelsVerified(Vec<VerifiedTunnelResult>),
    Ok,
    Error {
        message: String,
    },
}

/// Transport abstraction for `hadald` newline-delimited JSON IPC.
pub trait DaemonClient: Send + Sync {
    fn send<'a>(&'a self, req: &'a DaemonRequest) -> BoxFuture<'a, Result<DaemonResponse>>;

    fn status(&self) -> BoxFuture<'_, Result<DaemonStatus>> {
        Box::pin(async move {
            match self.send(&DaemonRequest::Status).await? {
                DaemonResponse::Status(st) => Ok(st),
                other => Err(HadalError::Custom(format!(
                    "Unexpected daemon response: {other:?}"
                ))),
            }
        })
    }
}

/// Production [`DaemonClient`] communicating over a Unix domain socket.
#[derive(Debug, Clone)]
pub struct UnixDaemonClient {
    socket_path: PathBuf,
}

impl UnixDaemonClient {
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    pub fn from_env() -> Self {
        Self::new(daemon_socket_path())
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

impl DaemonClient for UnixDaemonClient {
    fn send<'a>(&'a self, req: &'a DaemonRequest) -> BoxFuture<'a, Result<DaemonResponse>> {
        Box::pin(async move {
            let stream = UnixStream::connect(&self.socket_path).await.map_err(|e| {
                HadalError::Custom(format!(
                    "Cannot reach hadald at {}: {e}. Start the daemon with `sudo systemctl start hadald` or check `hadal-cli install-info`.",
                    self.socket_path.display()
                ))
            })?;
            send_request_on_stream(stream, req).await
        })
    }
}

/// Send one [`DaemonRequest`] and parse the newline-delimited [`DaemonResponse`] over any async stream.
pub async fn send_request_on_stream<S>(stream: S, req: &DaemonRequest) -> Result<DaemonResponse>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let mut line = serde_json::to_string(req)?;
    line.push('\n');
    writer.write_all(line.as_bytes()).await?;
    writer.flush().await?;

    let mut buf_reader = BufReader::new(reader);
    let mut resp_line = String::new();
    let n = buf_reader.read_line(&mut resp_line).await?;
    if n == 0 {
        return Err(HadalError::Custom(
            "hadald closed IPC connection unexpectedly".into(),
        ));
    }
    let resp: DaemonResponse = serde_json::from_str(resp_line.trim())?;
    match resp {
        DaemonResponse::Error { message } => Err(HadalError::Custom(message)),
        other => Ok(other),
    }
}

pub async fn send_request(socket_path: &Path, req: &DaemonRequest) -> Result<DaemonResponse> {
    UnixDaemonClient::new(socket_path).send(req).await
}

pub async fn query_daemon_status(socket_path: &Path) -> Result<DaemonStatus> {
    UnixDaemonClient::new(socket_path).status().await
}
