use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::sync::Arc;

use serde::Deserialize;
use tokio::task::JoinSet;

use crate::config::DEFAULT_WG_PORT;
use crate::error::{Result, HadalError};
use crate::gaming::probe::{pick_fastest_ipv4_with_prober, SystemNetworkProber};
use crate::gaming::traits::{DohTransport, NetworkProber};
use crate::gaming::types::strip_host_port;
use crate::platform::BoxFuture;

pub const MAX_PROBED_IPS_PER_CLUSTER: usize = 24;

const ECS_SHARD_PREFIXES: &[(&str, &str)] = &[
    ("8.8.8.8", "2.84.0.0/16"),
    ("8.8.8.8", "5.54.0.0/16"),
    ("8.8.8.8", "46.12.0.0/16"),
    ("8.8.8.8", "62.103.0.0/16"),
    ("8.8.8.8", "79.167.0.0/16"),
    ("8.8.4.4", "85.72.0.0/16"),
    ("8.8.4.4", "178.128.0.0/16"),
    ("8.8.4.4", "194.219.0.0/16"),
    ("8.8.4.4", "195.167.0.0/16"),
];

/// Production [`DohTransport`] backed by `reqwest::Client`.
#[derive(Clone)]
pub struct ReqwestDohTransport {
    http: reqwest::Client,
    allow_system_dns: bool,
}

impl ReqwestDohTransport {
    pub fn new(http: reqwest::Client, allow_system_dns: bool) -> Self {
        Self {
            http,
            allow_system_dns,
        }
    }

    pub fn default_client(allow_system_dns: bool) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(2))
            .build()?;
        Ok(Self::new(http, allow_system_dns))
    }
}

impl DohTransport for ReqwestDohTransport {
    fn get_json<'a>(&'a self, url: &'a str) -> BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move {
            let resp = self
                .http
                .get(url)
                .header("accept", "application/dns-json")
                .send()
                .await?;
            if !resp.status().is_success() {
                return Err(HadalError::Api {
                    status: resp.status().as_u16(),
                    message: format!("DoH query failed with status {}", resp.status()),
                });
            }
            Ok(resp.bytes().await?.to_vec())
        })
    }

    fn resolve_system_v4(&self, host: &str, port: u16) -> Vec<SocketAddrV4> {
        if !self.allow_system_dns {
            return Vec::new();
        }
        let Ok(addrs) = format!("{host}:{port}").to_socket_addrs() else {
            return Vec::new();
        };
        addrs
            .filter_map(|addr| match addr {
                SocketAddr::V4(v4) => Some(v4),
                SocketAddr::V6(_) => None,
            })
            .collect()
    }
}

pub fn standard_doh_urls(host: &str) -> Vec<String> {
    vec![
        format!("https://1.1.1.1/dns-query?name={host}&type=A"),
        format!("https://1.0.0.1/dns-query?name={host}&type=A"),
        format!("https://8.8.8.8/resolve?name={host}&type=A"),
        format!("https://8.8.4.4/resolve?name={host}&type=A"),
    ]
}

pub fn pooled_doh_urls(host: &str) -> Vec<String> {
    let mut urls = standard_doh_urls(host);
    for (resolver, subnet) in ECS_SHARD_PREFIXES {
        urls.push(format!(
            "https://{resolver}/resolve?name={host}&type=A&edns_client_subnet={subnet}"
        ));
    }
    urls
}

pub fn parse_doh_ipv4_response(body: &[u8], port: u16) -> Vec<SocketAddrV4> {
    #[derive(Deserialize)]
    struct DohResp {
        #[serde(default, rename = "Answer")]
        answer: Vec<DohAnswer>,
    }
    #[derive(Deserialize)]
    struct DohAnswer {
        #[serde(default, rename = "type")]
        rtype: u32,
        #[serde(default)]
        data: String,
    }

    let Ok(parsed) = serde_json::from_slice::<DohResp>(body) else {
        return Vec::new();
    };
    parsed
        .answer
        .into_iter()
        .filter(|ans| ans.rtype == 1)
        .filter_map(|ans| ans.data.trim().parse::<Ipv4Addr>().ok())
        .map(|ip| SocketAddrV4::new(ip, port))
        .collect()
}

/// Discover IPv4 addresses for `host` via direct IP-literal DoH URLs (no foreign ECS shards).
pub async fn discover_doh_ipv4s_with(
    transport: Arc<dyn DohTransport>,
    host: &str,
    port: u16,
) -> Vec<SocketAddrV4> {
    query_doh_urls(transport, host, port, standard_doh_urls(host)).await
}

/// Discover rotating backend hosting pools behind a cluster domain using ECS-sharded DoH queries.
pub async fn discover_doh_pool_ipv4s_with(
    transport: Arc<dyn DohTransport>,
    host: &str,
    port: u16,
) -> Vec<SocketAddrV4> {
    query_doh_urls(transport, host, port, pooled_doh_urls(host)).await
}

async fn query_doh_urls(
    transport: Arc<dyn DohTransport>,
    host: &str,
    port: u16,
    urls: Vec<String>,
) -> Vec<SocketAddrV4> {
    let host = host.trim();
    if host.is_empty() {
        return Vec::new();
    }
    let mut set: Vec<SocketAddrV4> = Vec::new();
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        set.push(SocketAddrV4::new(ip, port));
        return set;
    }

    for addr in transport.resolve_system_v4(host, port) {
        if !set.contains(&addr) {
            set.push(addr);
        }
    }

    let mut tasks = JoinSet::new();
    for url in urls {
        let t = transport.clone();
        tasks.spawn(async move { t.get_json(&url).await });
    }

    while let Some(joined) = tasks.join_next().await {
        if let Ok(Ok(body)) = joined {
            for sock in parse_doh_ipv4_response(&body, port) {
                if !set.contains(&sock) {
                    set.push(sock);
                }
            }
        }
    }
    set
}

/// Discover IPv4 addresses for `host` via direct IP-literal DoH URLs using a caller-provided `reqwest::Client`.
pub async fn discover_doh_ipv4s_with_http(
    http: &reqwest::Client,
    host: &str,
    port: u16,
    allow_system_dns: bool,
) -> Vec<SocketAddrV4> {
    let transport = Arc::new(ReqwestDohTransport::new(http.clone(), allow_system_dns));
    discover_doh_ipv4s_with(transport, host, port).await
}

/// Discover rotating backend hosting pools behind a Surfshark cluster domain in one parallel burst
/// by sharding Google DoH cache keys across distinct `edns_client_subnet` prefixes alongside Cloudflare.
pub async fn discover_doh_pool_ipv4s_with_http(
    http: &reqwest::Client,
    host: &str,
    port: u16,
    allow_system_dns: bool,
) -> Vec<SocketAddrV4> {
    let transport = Arc::new(ReqwestDohTransport::new(http.clone(), allow_system_dns));
    discover_doh_pool_ipv4s_with(transport, host, port).await
}

pub async fn discover_doh_ipv4s(host: &str, port: u16) -> Vec<SocketAddrV4> {
    let Ok(transport) = ReqwestDohTransport::default_client(true) else {
        return Vec::new();
    };
    discover_doh_pool_ipv4s_with(Arc::new(transport), host, port).await
}

pub async fn resolve_fastest_endpoint_ip(domain: &str) -> Result<Ipv4Addr> {
    let doh = Arc::new(ReqwestDohTransport::default_client(true)?);
    let prober = Arc::new(SystemNetworkProber);
    resolve_fastest_endpoint_ip_with(domain, doh, prober).await
}

pub async fn resolve_fastest_endpoint_ip_with(
    domain: &str,
    doh: Arc<dyn DohTransport>,
    prober: Arc<dyn NetworkProber>,
) -> Result<Ipv4Addr> {
    let host = strip_host_port(domain);
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Ok(ip);
    }
    let candidates = discover_doh_pool_ipv4s_with(doh, &host, DEFAULT_WG_PORT).await;
    if candidates.is_empty() {
        return Err(HadalError::Custom(format!(
            "Could not resolve IPv4 endpoint for {domain}"
        )));
    }
    if candidates.len() == 1 {
        return Ok(*candidates[0].ip());
    }

    let ips: Vec<Ipv4Addr> = candidates.into_iter().map(|s| *s.ip()).collect();
    let best = tokio::task::spawn_blocking(move || {
        pick_fastest_ipv4_with_prober(&ips, None, prober.as_ref())
    })
    .await
    .map_err(|e| HadalError::Custom(format!("Endpoint probe join error: {e}")))?
    .ok_or_else(|| HadalError::Custom(format!("Could not resolve IPv4 endpoint for {domain}")))?;
    Ok(best)
}
