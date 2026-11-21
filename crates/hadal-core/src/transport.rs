use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

use crate::error::{Result, HadalError};
use crate::ipc::{DaemonClient, DaemonRequest, DaemonResponse, TunnelState, UnixDaemonClient};
use crate::platform::BoxFuture;

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: reqwest::Method,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    pub timeout: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Transport seam for Surfshark HTTP API requests.
pub trait HttpTransport: Send + Sync {
    fn execute<'a>(&'a self, req: HttpRequest) -> BoxFuture<'a, Result<HttpResponse>>;
}

/// Production [`HttpTransport`] using `reqwest::Client` and optional `hadald` `ControlHttp`
/// forwarding when the daemon is in `TunnelState::KillswitchLocked`.
#[derive(Clone)]
pub struct ReqwestHttpTransport {
    http: reqwest::Client,
    daemon: Option<Arc<dyn DaemonClient>>,
}

impl ReqwestHttpTransport {
    pub fn new(daemon: Option<Arc<dyn DaemonClient>>) -> Self {
        let http = reqwest::Client::builder()
            .user_agent(concat!("hadal-vpn/", env!("CARGO_PKG_VERSION")))
            .local_address(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
            .build()
            .unwrap_or_default();
        Self { http, daemon }
    }

    pub fn direct() -> Self {
        Self::new(None)
    }

    pub fn with_socket_path(socket_path: impl Into<PathBuf>) -> Self {
        Self::new(Some(Arc::new(UnixDaemonClient::new(socket_path))))
    }

    pub fn with_daemon(daemon: Arc<dyn DaemonClient>) -> Self {
        Self::new(Some(daemon))
    }
}

impl HttpTransport for ReqwestHttpTransport {
    fn execute<'a>(&'a self, req: HttpRequest) -> BoxFuture<'a, Result<HttpResponse>> {
        Box::pin(async move {
            // When the killswitch lock is active without an active VPN tunnel, route HTTPS API
            // calls via hadald's CAP_NET_ADMIN control-plane mark so reconnection never stalls
            // and user traffic stays locked down.
            if req.url.starts_with("https://") {
                if let Some(ref daemon) = self.daemon {
                    if let Ok(st) = daemon.status().await {
                        if st.state == TunnelState::KillswitchLocked {
                            let resp = daemon
                                .send(&DaemonRequest::ControlHttp {
                                    method: req.method.as_str().to_string(),
                                    url: req.url,
                                    headers: req.headers,
                                    body: req.body,
                                })
                                .await?;
                            return match resp {
                                DaemonResponse::Http { status, body } => {
                                    Ok(HttpResponse { status, body })
                                }
                                other => Err(HadalError::Custom(format!(
                                    "Unexpected daemon control HTTP response: {other:?}"
                                ))),
                            };
                        }
                    }
                }
            }

            let mut header_map = HeaderMap::new();
            for (k, v) in &req.headers {
                if let (Ok(name), Ok(val)) = (
                    HeaderName::from_bytes(k.as_bytes()),
                    HeaderValue::from_str(v),
                ) {
                    header_map.insert(name, val);
                }
            }

            let mut builder = self.http.request(req.method, &req.url).headers(header_map);
            if let Some(timeout) = req.timeout {
                builder = builder.timeout(timeout);
            }
            if let Some(bytes) = req.body {
                builder = builder.body(bytes);
            }

            let resp = builder.send().await?;
            let status = resp.status().as_u16();
            let body = resp.bytes().await?.to_vec();
            Ok(HttpResponse { status, body })
        })
    }
}
