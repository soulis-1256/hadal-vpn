use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use futures_util::future::BoxFuture;
use hadal_core::{
    cidrs_from_ipv4s, discover_doh_ipv4s_with_http, discover_doh_pool_ipv4s_with_http,
    discover_wan_pmtu_with_mark, measure_icmp_stats_with_mark, pick_fastest_ipv4_with_mark,
    EndpointProbeResult, Result, HadalError, WanGamingProbe, DEFAULT_WG_PORT,
    MAX_PROBED_IPS_PER_CLUSTER,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::Semaphore;

use super::routing::CONTROL_FWMARK;

const MAX_PROXY_HEADER_BYTES: usize = 16 * 1024;
const MAX_CONCURRENT_WAN_PROBES: usize = 24;

/// Abstraction over `hadald`'s `CONTROL_FWMARK` control-plane HTTP & WAN probing operations.
pub trait ControlBackend: Send + Sync {
    fn http_fetch<'a>(
        &'a self,
        method: &'a str,
        url: &'a str,
        headers: &'a [(String, String)],
        body: Option<Vec<u8>>,
    ) -> BoxFuture<'a, Result<(u16, Vec<u8>)>>;

    fn prepare_endpoint<'a>(
        &'a self,
        domain: &'a str,
        discover_pmtu: bool,
    ) -> BoxFuture<'a, Result<(String, Option<u16>)>>;

    fn probe_wan_gaming<'a>(
        &'a self,
        target_host: &'a str,
        domains: &'a [String],
    ) -> BoxFuture<'a, Result<WanGamingProbe>>;
}

/// Privileged control-plane transport (`SO_MARK = CONTROL_FWMARK`) used exclusively by `hadald`
/// when `KillswitchLocked` blocks general WAN traffic so users can still reconnect cleanly.
pub struct ControlPlane {
    doh_client: reqwest::Client,
    http_client: reqwest::Client,
}

impl ControlPlane {
    pub async fn start() -> Result<Self> {
        let secret_bytes: [u8; 16] = rand::random();
        let secret: String = secret_bytes.iter().map(|b| format!("{b:02x}")).collect();
        let expected_auth = Arc::new(format!(
            "Basic {}",
            BASE64_STANDARD.encode(format!("hadal:{secret}"))
        ));

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| HadalError::Custom(format!("Failed to bind control proxy: {e}")))?;
        let local_addr = listener.local_addr()?;
        let proxy_url = format!("http://hadal:{secret}@{local_addr}");

        let doh_proxy = reqwest::Proxy::all(&proxy_url)
            .map_err(|e| HadalError::Custom(format!("Control proxy URL error: {e}")))?;
        let doh_client = reqwest::Client::builder()
            .proxy(doh_proxy)
            .timeout(Duration::from_secs(4))
            .build()?;

        let http_proxy = reqwest::Proxy::all(&proxy_url)
            .map_err(|e| HadalError::Custom(format!("Control proxy URL error: {e}")))?;
        let http_client = reqwest::Client::builder()
            .proxy(http_proxy)
            .timeout(Duration::from_secs(12))
            .build()?;

        let auth_ref = expected_auth;
        let doh_ref = doh_client.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let auth = auth_ref.clone();
                let doh = doh_ref.clone();
                tokio::spawn(async move {
                    let _ = handle_proxy_client(stream, &auth, &doh).await;
                });
            }
        });

        Ok(Self {
            doh_client,
            http_client,
        })
    }

    pub async fn http_fetch(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: Option<Vec<u8>>,
    ) -> Result<(u16, Vec<u8>)> {
        let parsed = validate_control_https_url(url)?;
        let method = reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|e| HadalError::Custom(format!("Invalid HTTP method: {e}")))?;
        let mut req = self.http_client.request(method, parsed);
        for (k, v) in headers {
            req = req.header(k.as_str(), v.as_str());
        }
        if let Some(payload) = body {
            req = req.body(payload);
        }

        let resp = req.send().await?;
        let status = resp.status().as_u16();
        let bytes = resp.bytes().await?.to_vec();
        Ok((status, bytes))
    }

    pub async fn prepare_endpoint(
        &self,
        domain: &str,
        discover_pmtu: bool,
    ) -> Result<(String, Option<u16>)> {
        let host = domain.split(':').next().unwrap_or(domain).trim().to_string();
        let endpoint_ip = if let Ok(ip) = host.parse::<Ipv4Addr>() {
            ip
        } else {
            let candidates =
                discover_doh_pool_ipv4s_with_http(&self.doh_client, &host, DEFAULT_WG_PORT, false)
                    .await;
            if candidates.is_empty() {
                return Err(HadalError::Custom(format!(
                    "Could not resolve IPv4 endpoint for {domain} via DoH"
                )));
            }
            if candidates.len() == 1 {
                *candidates[0].ip()
            } else {
                let ips: Vec<Ipv4Addr> = candidates.into_iter().map(|s| *s.ip()).collect();
                tokio::task::spawn_blocking(move || {
                    pick_fastest_ipv4_with_mark(&ips, Some(CONTROL_FWMARK))
                })
                .await
                .map_err(|e| HadalError::Custom(format!("Endpoint probe join error: {e}")))?
            }
        };

        let wan_pmtu = if discover_pmtu {
            let pmtu = tokio::task::spawn_blocking(|| {
                discover_wan_pmtu_with_mark("1.1.1.1", Some(CONTROL_FWMARK))
            })
            .await
            .map_err(|e| HadalError::Custom(format!("PMTU probe join error: {e}")))?;
            Some(pmtu)
        } else {
            None
        };

        Ok((endpoint_ip.to_string(), wan_pmtu))
    }

    /// Run Gaming Mode WAN baseline, PMTU, and candidate endpoint RTT probes exclusively over the
    /// ISP interface (`SO_MARK = CONTROL_FWMARK`), bypassing any active tunnel or killswitch lock.
    pub async fn probe_wan_gaming(
        &self,
        target_host: &str,
        domains: &[String],
    ) -> Result<WanGamingProbe> {
        let host_clean = target_host
            .split(':')
            .next()
            .unwrap_or(target_host)
            .trim()
            .to_string();
        let target_ips: Vec<Ipv4Addr> = if let Ok(ip) = host_clean.parse::<Ipv4Addr>() {
            vec![ip]
        } else {
            discover_doh_ipv4s_with_http(&self.doh_client, &host_clean, 443, false)
                .await
                .into_iter()
                .map(|s| *s.ip())
                .collect()
        };

        let mut doh_tasks = Vec::with_capacity(domains.len());
        for dom in domains {
            let client = self.doh_client.clone();
            let d = dom.clone();
            doh_tasks.push(tokio::spawn(async move {
                let h = d.split(':').next().unwrap_or(&d).trim().to_string();
                let ips =
                    discover_doh_pool_ipv4s_with_http(&client, &h, DEFAULT_WG_PORT, false).await;
                (d, ips)
            }));
        }

        let target_ip_str = target_ips.first().map(|ip| ip.to_string());
        let display_target = target_host.to_string();
        let baseline_task = tokio::task::spawn_blocking(move || {
            let baseline = target_ip_str.and_then(|ip_str| {
                let mut stats = measure_icmp_stats_with_mark(&ip_str, 5, Some(CONTROL_FWMARK))?;
                stats.target = display_target;
                Some(stats)
            });
            let pmtu = discover_wan_pmtu_with_mark("1.1.1.1", Some(CONTROL_FWMARK));
            (baseline, pmtu)
        });

        let mut probe_items: Vec<(String, Ipv4Addr)> = Vec::new();
        for t in doh_tasks {
            if let Ok((dom, ips)) = t.await {
                for sock in ips.into_iter().take(MAX_PROBED_IPS_PER_CLUSTER) {
                    probe_items.push((dom.clone(), *sock.ip()));
                }
            }
        }

        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_WAN_PROBES));
        let mut probe_tasks = Vec::with_capacity(probe_items.len());
        for (dom, ip) in probe_items {
            let sem = semaphore.clone();
            probe_tasks.push(tokio::spawn(async move {
                let Ok(_permit) = sem.acquire_owned().await else {
                    return None;
                };
                tokio::task::spawn_blocking(move || {
                    let ip_str = ip.to_string();
                    let stats = measure_icmp_stats_with_mark(&ip_str, 3, Some(CONTROL_FWMARK))?;
                    Some(EndpointProbeResult {
                        domain: dom,
                        endpoint_ip: ip_str,
                        min_ms: stats.min_ms,
                    })
                })
                .await
                .ok()
                .flatten()
            }));
        }

        let mut endpoints = Vec::new();
        for t in probe_tasks {
            if let Ok(Some(item)) = t.await {
                endpoints.push(item);
            }
        }

        let (baseline_direct, wan_pmtu) = baseline_task
            .await
            .map_err(|e| HadalError::Custom(format!("WAN baseline join error: {e}")))?;

        Ok(WanGamingProbe {
            baseline_direct,
            wan_pmtu,
            game_cidrs: cidrs_from_ipv4s(&target_ips),
            endpoints,
        })
    }
}

impl ControlBackend for ControlPlane {
    fn http_fetch<'a>(
        &'a self,
        method: &'a str,
        url: &'a str,
        headers: &'a [(String, String)],
        body: Option<Vec<u8>>,
    ) -> BoxFuture<'a, Result<(u16, Vec<u8>)>> {
        Box::pin(self.http_fetch(method, url, headers, body))
    }

    fn prepare_endpoint<'a>(
        &'a self,
        domain: &'a str,
        discover_pmtu: bool,
    ) -> BoxFuture<'a, Result<(String, Option<u16>)>> {
        Box::pin(self.prepare_endpoint(domain, discover_pmtu))
    }

    fn probe_wan_gaming<'a>(
        &'a self,
        target_host: &'a str,
        domains: &'a [String],
    ) -> BoxFuture<'a, Result<WanGamingProbe>> {
        Box::pin(self.probe_wan_gaming(target_host, domains))
    }
}

/// Validate that a `ControlHttp` URL uses HTTPS on port 443.
pub fn validate_control_https_url(url: &str) -> Result<reqwest::Url> {
    let parsed = reqwest::Url::parse(url)
        .map_err(|e| HadalError::Custom(format!("Invalid control URL: {e}")))?;
    if parsed.scheme() != "https" || parsed.port_or_known_default() != Some(443) {
        return Err(HadalError::Custom(
            "ControlHttp permits only HTTPS requests on port 443".into(),
        ));
    }
    Ok(parsed)
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    !(ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_broadcast())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn set_so_mark(socket: &TcpSocket, mark: u32) -> std::io::Result<()> {
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_MARK,
            (&mark as *const u32).cast(),
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

async fn handle_proxy_client(
    stream: TcpStream,
    expected_auth: &str,
    doh_client: &reqwest::Client,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream);
    let mut lines = Vec::new();
    let mut total_bytes = 0usize;

    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            return Ok(());
        }
        total_bytes += n;
        if total_bytes > MAX_PROXY_HEADER_BYTES {
            return Ok(());
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        lines.push(trimmed.to_string());
    }

    let Some(request_line) = lines.first() else {
        return Ok(());
    };
    let mut parts = request_line.split_whitespace();
    let (Some(method), Some(authority)) = (parts.next(), parts.next()) else {
        return Ok(());
    };

    let mut client = reader.into_inner();
    if method != "CONNECT" {
        let _ = client
            .write_all(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            .await;
        return Ok(());
    }

    let auth_ok = lines[1..]
        .iter()
        .find_map(|hdr| {
            let (name, val) = hdr.split_once(':')?;
            if name.trim().eq_ignore_ascii_case("proxy-authorization") {
                Some(val.trim())
            } else {
                None
            }
        })
        .is_some_and(|val| constant_time_eq(val.as_bytes(), expected_auth.as_bytes()));

    if !auth_ok {
        let _ = client
            .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
            .await;
        return Ok(());
    }

    let Some((host, port_str)) = authority.rsplit_once(':') else {
        let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
        return Ok(());
    };
    if port_str.parse::<u16>().ok() != Some(443) {
        let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await;
        return Ok(());
    }

    let target_ip = if let Ok(ip) = host.trim_matches(['[', ']']).parse::<Ipv4Addr>() {
        ip
    } else {
        let addrs = discover_doh_ipv4s_with_http(doh_client, host, 443, false).await;
        let Some(first) = addrs.into_iter().next() else {
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
            return Ok(());
        };
        *first.ip()
    };

    if !is_public_ipv4(target_ip) {
        let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await;
        return Ok(());
    }

    let sock = TcpSocket::new_v4()?;
    set_so_mark(&sock, CONTROL_FWMARK)?;
    let mut upstream = match sock
        .connect(SocketAddr::V4(SocketAddrV4::new(target_ip, 443)))
        .await
    {
        Ok(s) => s,
        Err(_) => {
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
            return Ok(());
        }
    };

    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_control_https_443_urls_only() {
        assert!(validate_control_https_url("https://ext2.surfshark.com/v1/server/clusters").is_ok());
        assert!(validate_control_https_url("http://ext2.surfshark.com/v1").is_err());
        assert!(validate_control_https_url("https://ext2.surfshark.com:8443/v1").is_err());
        assert!(validate_control_https_url("not a url").is_err());
    }

    #[test]
    fn filters_private_and_loopback_ips() {
        assert!(!is_public_ipv4(Ipv4Addr::LOCALHOST));
        assert!(!is_public_ipv4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!is_public_ipv4(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(is_public_ipv4(Ipv4Addr::new(1, 1, 1, 1)));
    }
}
