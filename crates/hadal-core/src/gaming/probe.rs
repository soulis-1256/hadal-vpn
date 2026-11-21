use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::process::Command;
use std::sync::{Arc, Mutex};

use crate::config::DEFAULT_WG_PORT;
use crate::error::{Result, HadalError};
use crate::gaming::doh::{
    discover_doh_pool_ipv4s_with, ReqwestDohTransport, MAX_PROBED_IPS_PER_CLUSTER,
};
use crate::gaming::selection::{select_candidate_clusters, sort_gaming_candidates};
use crate::gaming::traits::{DohTransport, NetworkProber};
use crate::gaming::types::{
    build_endpoint_candidate, cidrs_from_ipv4s, recommended_wg_mtu, resolve_gaming_target,
    strip_host_port, EndpointCandidate, GamingScanReport, PingStats,
};
use crate::servers::Cluster;

const MAX_PROBE_WORKERS: usize = 16;

/// Production [`NetworkProber`] executing `ping` and system DNS lookups.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemNetworkProber;

impl NetworkProber for SystemNetworkProber {
    fn measure_icmp(
        &self,
        target: &str,
        count: u32,
        fwmark: Option<u32>,
        iface: Option<&str>,
    ) -> Option<PingStats> {
        let mut cmd = Command::new("ping");
        let count_str = count.to_string();
        cmd.args(["-4", "-n", "-c", &count_str, "-i", "0.2", "-W", "1"]);
        if let Some(mark) = fwmark {
            cmd.args(["-m", &mark.to_string()]);
        }
        if let Some(dev) = iface {
            cmd.args(["-I", dev]);
        }
        let out = cmd.arg(target).output().ok()?;
        parse_ping_output(target, &String::from_utf8_lossy(&out.stdout))
    }

    fn df_ping_ok(&self, target: &str, payload: u16, fwmark: Option<u32>) -> bool {
        let mut cmd = Command::new("ping");
        let payload_str = payload.to_string();
        cmd.args(["-4", "-n", "-M", "do", "-c", "1", "-W", "1"]);
        if let Some(mark) = fwmark {
            cmd.args(["-m", &mark.to_string()]);
        }
        cmd.args(["-s", &payload_str, target])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn resolve_ipv4s(&self, host: &str) -> Vec<Ipv4Addr> {
        let mut ips = Vec::new();
        if let Ok(addrs) = format!("{host}:443").to_socket_addrs() {
            for addr in addrs {
                if let SocketAddr::V4(v4) = addr {
                    if !ips.contains(v4.ip()) {
                        ips.push(*v4.ip());
                    }
                }
            }
        }
        ips
    }
}

/// Process `items` concurrently using a bounded pool of OS threads so probing never spawns
/// hundreds of simultaneous threads on large cluster pools.
fn map_bounded_threads<T, R, F>(items: Vec<T>, max_workers: usize, f: F) -> Vec<R>
where
    T: Send,
    R: Send,
    F: Fn(T) -> Option<R> + Sync,
{
    if items.is_empty() {
        return Vec::new();
    }
    let worker_count = max_workers.max(1).min(items.len());
    let queue = Mutex::new(items.into_iter());
    let results = Mutex::new(Vec::new());

    std::thread::scope(|scope| {
        for _ in 0..worker_count {
            scope.spawn(|| loop {
                let next = {
                    let mut guard = queue.lock().expect("probe queue lock");
                    guard.next()
                };
                let Some(item) = next else {
                    break;
                };
                if let Some(out) = f(item) {
                    results.lock().expect("probe results lock").push(out);
                }
            });
        }
    });

    results.into_inner().expect("probe results unwrap")
}

pub fn measure_icmp_stats(target: &str, count: u32) -> Option<PingStats> {
    SystemNetworkProber.measure_icmp(target, count, None, None)
}

pub fn measure_icmp_stats_with_mark(
    target: &str,
    count: u32,
    fwmark: Option<u32>,
) -> Option<PingStats> {
    SystemNetworkProber.measure_icmp(target, count, fwmark, None)
}

pub fn measure_icmp_stats_on_iface(iface: &str, target: &str, count: u32) -> Option<PingStats> {
    SystemNetworkProber.measure_icmp(target, count, None, Some(iface))
}

pub fn parse_ping_output(target: &str, stdout: &str) -> Option<PingStats> {
    let mut loss_pct = 0.0;
    for line in stdout.lines() {
        if line.contains("packet loss") {
            if let Some(pct_part) = line.split('%').next() {
                if let Some(num) = pct_part.split_whitespace().last() {
                    if let Ok(v) = num.parse::<f64>() {
                        loss_pct = v;
                    }
                }
            }
        }
        if let Some((_, stats_part)) = line.split_once(" = ") {
            let nums: Vec<&str> = stats_part.split_whitespace().next()?.split('/').collect();
            if nums.len() >= 4 {
                let min_ms = nums[0].parse().ok()?;
                let avg_ms = nums[1].parse().ok()?;
                let max_ms = nums[2].parse().ok()?;
                let mdev_ms = nums[3].parse().ok()?;
                return Some(PingStats {
                    target: target.to_string(),
                    min_ms,
                    avg_ms,
                    max_ms,
                    mdev_ms,
                    loss_pct,
                });
            }
        }
    }
    None
}

pub fn pick_fastest_ipv4_with_mark(ips: &[Ipv4Addr], fwmark: Option<u32>) -> Ipv4Addr {
    pick_fastest_ipv4_with_prober(ips, fwmark, &SystemNetworkProber)
        .unwrap_or(Ipv4Addr::UNSPECIFIED)
}

pub fn pick_fastest_ipv4_with_prober(
    ips: &[Ipv4Addr],
    fwmark: Option<u32>,
    prober: &dyn NetworkProber,
) -> Option<Ipv4Addr> {
    if ips.is_empty() {
        return None;
    }
    let measured = map_bounded_threads(ips.to_vec(), MAX_PROBE_WORKERS, |ip| {
        let stats = prober.measure_icmp(&ip.to_string(), 2, fwmark, None);
        Some((ip, stats.map(|s| s.min_ms)))
    });

    let mut best = ips[0];
    let mut best_ms = f64::INFINITY;
    for (ip, min_ms) in measured {
        if let Some(ms) = min_ms {
            if ms < best_ms {
                best_ms = ms;
                best = ip;
            }
        }
    }
    Some(best)
}

/// Probe WAN Path MTU via DF (`-M do`) ICMP binary search and derive an optimal WireGuard MTU.
pub fn discover_wan_pmtu(probe_host: &str) -> u16 {
    discover_wan_pmtu_with_prober(probe_host, None, &SystemNetworkProber)
}

pub fn discover_wan_pmtu_with_mark(probe_host: &str, fwmark: Option<u32>) -> u16 {
    discover_wan_pmtu_with_prober(probe_host, fwmark, &SystemNetworkProber)
}

pub fn discover_wan_pmtu_with_prober(
    probe_host: &str,
    fwmark: Option<u32>,
    prober: &dyn NetworkProber,
) -> u16 {
    // ICMP payload max = PMTU - 28 (20 IPv4 + 8 ICMP)
    let mut lo: u16 = 1252; // 1280 MTU
    let mut hi: u16 = 1472; // 1500 MTU
    let mut best_payload: u16 = 1464; // fallback 1492 PPPoE

    if prober.df_ping_ok(probe_host, 1472, fwmark) {
        return 1500;
    }
    if prober.df_ping_ok(probe_host, 1464, fwmark) {
        return 1492;
    }

    while lo <= hi {
        let mid = (lo + hi) / 2;
        if prober.df_ping_ok(probe_host, mid, fwmark) {
            best_payload = mid;
            lo = mid + 1;
        } else {
            hi = mid - 1;
        }
    }
    best_payload + 28
}

pub fn resolve_game_cidrs(host: &str) -> Vec<String> {
    resolve_game_cidrs_with_prober(host, &SystemNetworkProber)
}

pub fn resolve_game_cidrs_with_prober(host: &str, prober: &dyn NetworkProber) -> Vec<String> {
    cidrs_from_ipv4s(&prober.resolve_ipv4s(host))
}

/// Run Stage 1 WAN probing across candidate Surfshark clusters without pre-truncating diverse `/16`
/// candidates, allowing Stage 2 live tunnel verification to evaluate all discovered subnets first.
pub async fn probe_gaming_candidates(
    clusters: &[Cluster],
    game_id: &str,
    region_id: &str,
    custom_host: Option<&str>,
    user_coords: Option<(f64, f64)>,
) -> Result<GamingScanReport> {
    let doh = Arc::new(ReqwestDohTransport::default_client(true)?);
    let prober = Arc::new(SystemNetworkProber);
    probe_gaming_candidates_with(
        clusters,
        game_id,
        region_id,
        custom_host,
        user_coords,
        doh,
        prober,
    )
    .await
}

pub async fn probe_gaming_candidates_with(
    clusters: &[Cluster],
    game_id: &str,
    region_id: &str,
    custom_host: Option<&str>,
    user_coords: Option<(f64, f64)>,
    doh: Arc<dyn DohTransport>,
    prober: Arc<dyn NetworkProber>,
) -> Result<GamingScanReport> {
    let (target_host, target_coords) = resolve_gaming_target(game_id, region_id, custom_host)?;
    let selected = select_candidate_clusters(clusters, user_coords, target_coords, 12);

    let target_clone = target_host.clone();
    let baseline_prober = prober.clone();
    let baseline_task = tokio::task::spawn_blocking(move || {
        let baseline = baseline_prober.measure_icmp(&target_clone, 5, None, None);
        let pmtu = discover_wan_pmtu_with_prober("1.1.1.1", None, baseline_prober.as_ref());
        let cidrs = resolve_game_cidrs_with_prober(&target_clone, baseline_prober.as_ref());
        (baseline, pmtu, cidrs)
    });

    let mut doh_tasks = Vec::new();
    for cluster in &selected {
        let domain = cluster.connection_name.clone().unwrap_or_default();
        let cluster_clone = cluster.clone();
        let doh_clone = doh.clone();
        doh_tasks.push(tokio::spawn(async move {
            let host = strip_host_port(&domain);
            let ips = discover_doh_pool_ipv4s_with(doh_clone, &host, DEFAULT_WG_PORT).await;
            (cluster_clone, ips)
        }));
    }

    let (baseline_direct, wan_pmtu, game_cidrs) = baseline_task
        .await
        .map_err(|e| HadalError::Custom(format!("Baseline task failed: {e}")))?;
    let recommended_mtu = recommended_wg_mtu(wan_pmtu);

    let mut probe_items: Vec<(Cluster, Ipv4Addr)> = Vec::new();
    for task in doh_tasks {
        if let Ok((cluster, ips)) = task.await {
            for sock in ips.into_iter().take(MAX_PROBED_IPS_PER_CLUSTER) {
                probe_items.push((cluster.clone(), *sock.ip()));
            }
        }
    }

    let endpoint_prober = prober;
    let probed: Vec<EndpointCandidate> = tokio::task::spawn_blocking(move || {
        let mut list = map_bounded_threads(probe_items, MAX_PROBE_WORKERS, |(cluster, ip)| {
            let ip_str = ip.to_string();
            let stats = endpoint_prober.measure_icmp(&ip_str, 3, None, None)?;
            Some(build_endpoint_candidate(
                &cluster,
                &ip_str,
                stats.min_ms,
                target_coords,
            ))
        });
        sort_gaming_candidates(&mut list);
        list
    })
    .await
    .map_err(|e| HadalError::Custom(format!("Probe task failed: {e}")))?;

    Ok(GamingScanReport {
        game_id: game_id.to_string(),
        region_id: region_id.to_string(),
        target_host,
        baseline_direct,
        active_tunnel_ping: None,
        active_tunnel_label: None,
        wan_pmtu,
        recommended_mtu,
        candidates: probed,
        game_cidrs,
    })
}
