use std::collections::{HashMap, HashSet};

use crate::gaming::types::{is_special_cluster, is_virtual_cluster, EndpointCandidate};
use crate::servers::{Cluster, Coordinates};

/// Select the top Surfshark dynamic physical clusters geometrically closest to the user or target game region.
/// Excludes static and virtual geo-spoofed clusters so coordinates reflect physical routing paths.
pub fn select_candidate_clusters(
    clusters: &[Cluster],
    user_coords: Option<(f64, f64)>,
    target_coords: Option<(f64, f64)>,
    max_clusters: usize,
) -> Vec<Cluster> {
    let mut dynamic: Vec<Cluster> = clusters
        .iter()
        .filter(|c| {
            !is_special_cluster(c)
                && !is_virtual_cluster(c)
                && c.pub_key.as_deref().is_some_and(|k| !k.is_empty())
                && c.connection_name.as_deref().is_some_and(|s| !s.is_empty())
        })
        .cloned()
        .collect();

    // Score each cluster by combined distance from user & game target (corridor heuristic)
    // so relay cities along the line between player and game datacenter rank highest.
    dynamic.sort_by(|a, b| {
        let score = |c: &Cluster| -> f64 {
            let Some(Coordinates {
                latitude: Some(lat),
                longitude: Some(lon),
            }) = c.coordinates
            else {
                return 50_000.0;
            };
            let user_km = user_coords
                .map(|(ulat, ulon)| crate::gaming::types::haversine_km(ulat, ulon, lat, lon))
                .unwrap_or(0.0);
            let target_km = target_coords
                .map(|(tlat, tlon)| crate::gaming::types::haversine_km(lat, lon, tlat, tlon))
                .unwrap_or(0.0);
            let load_penalty = c.load.unwrap_or(30) as f64 * 4.0;
            user_km + target_km * 1.15 + load_penalty
        };
        score(a)
            .partial_cmp(&score(b))
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    dynamic.truncate(max_clusters);
    dynamic
}

/// Group endpoints within a cluster by `/16` (`prefix_octets = 2`) or `/24` (`prefix_octets = 3`)
/// as a provider-agnostic proxy for distinct upstream hosting networks.
fn cluster_subnet_key(cand: &EndpointCandidate, prefix_octets: u8) -> (String, String) {
    let net = cand
        .endpoint_ip
        .parse::<std::net::Ipv4Addr>()
        .map(|ip| {
            let o = ip.octets();
            if prefix_octets <= 2 {
                format!("{}.{}.0.0/16", o[0], o[1])
            } else {
                format!("{}.{}.{}.0/24", o[0], o[1], o[2])
            }
        })
        .unwrap_or_else(|_| cand.endpoint_ip.clone());
    (cand.cluster_id.clone(), net)
}

/// Pick up to `max_count` verification targets balancing top candidate cities and distinct `/16`
/// upstream prefixes per city so no single bad transit provider can monopolize a city's verification slot.
pub fn pick_diverse_verify_targets(
    candidates: &[EndpointCandidate],
    max_count: usize,
) -> Vec<EndpointCandidate> {
    if max_count == 0 || candidates.is_empty() {
        return Vec::new();
    }

    let mut selected_indices = Vec::with_capacity(max_count.min(candidates.len()));
    let mut seen_clusters = HashSet::new();
    let mut seen_sub16 = HashSet::new();
    let mut seen_sub24 = HashSet::new();
    let max_initial_cities = max_count.min(4);

    // Pass 1: Cover the top distinct cities first
    for (idx, cand) in candidates.iter().enumerate() {
        if selected_indices.len() >= max_initial_cities {
            break;
        }
        if seen_clusters.insert(cand.cluster_id.clone()) {
            seen_sub16.insert(cluster_subnet_key(cand, 2));
            seen_sub24.insert(cluster_subnet_key(cand, 3));
            selected_indices.push(idx);
        }
    }

    // Pass 2: Cover every distinct (cluster, /16) subnet in Stage-1 rank order
    for (idx, cand) in candidates.iter().enumerate() {
        if selected_indices.len() >= max_count {
            break;
        }
        if !selected_indices.contains(&idx) && seen_sub16.insert(cluster_subnet_key(cand, 2)) {
            seen_sub24.insert(cluster_subnet_key(cand, 3));
            selected_indices.push(idx);
        }
    }

    // Pass 3: Fall back to distinct /24 prefixes, then remaining best-ranked candidates
    for (idx, cand) in candidates.iter().enumerate() {
        if selected_indices.len() >= max_count {
            break;
        }
        if !selected_indices.contains(&idx) && seen_sub24.insert(cluster_subnet_key(cand, 3)) {
            selected_indices.push(idx);
        }
    }
    for idx in 0..candidates.len() {
        if selected_indices.len() >= max_count {
            break;
        }
        if !selected_indices.contains(&idx) {
            selected_indices.push(idx);
        }
    }

    selected_indices
        .into_iter()
        .map(|i| candidates[i].clone())
        .collect()
}

/// Sort candidates putting live E2E-verified endpoints first, ordering by zero packet loss
/// and lowest tail-adjusted RTT (`avg_ms + mdev_ms`), followed by unverified estimates.
pub fn sort_gaming_candidates(candidates: &mut [EndpointCandidate]) {
    candidates.sort_by(|a, b| match (a.verified_tunnel_ms, b.verified_tunnel_ms) {
        (Some(avg_a), Some(avg_b)) => {
            let loss_a = a.verified_loss_pct.unwrap_or(0.0);
            let loss_b = b.verified_loss_pct.unwrap_or(0.0);
            let loss_cmp = loss_a
                .partial_cmp(&loss_b)
                .unwrap_or(std::cmp::Ordering::Equal);
            if loss_cmp != std::cmp::Ordering::Equal {
                return loss_cmp;
            }
            let mdev_a = a.verified_mdev_ms.unwrap_or(0.0);
            let mdev_b = b.verified_mdev_ms.unwrap_or(0.0);
            let eff_a = avg_a + mdev_a;
            let eff_b = avg_b + mdev_b;
            eff_a
                .partial_cmp(&eff_b)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| {
                    avg_a
                        .partial_cmp(&avg_b)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .then_with(|| {
                    mdev_a
                        .partial_cmp(&mdev_b)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
        }
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => a
            .estimated_total_ms
            .partial_cmp(&b.estimated_total_ms)
            .unwrap_or(std::cmp::Ordering::Equal),
    });
}

/// Sort candidates (verified first, then estimated) and retain at most `max_per_cluster` IPs per
/// city while prioritizing distinct `/16` upstream subnets before keeping duplicates from one subnet.
pub fn finalize_gaming_candidates(
    candidates: &mut Vec<EndpointCandidate>,
    max_per_cluster: usize,
    max_total: usize,
) {
    sort_gaming_candidates(candidates);
    if max_per_cluster == 0 || max_total == 0 {
        candidates.clear();
        return;
    }

    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut seen_sub16: HashSet<(String, String)> = HashSet::new();
    let mut selected = vec![false; candidates.len()];

    // Pass 1: Keep top entry from each distinct (cluster, /16) subnet up to max_per_cluster
    for (idx, cand) in candidates.iter().enumerate() {
        let count = counts.get(&cand.cluster_id).copied().unwrap_or(0);
        if count >= max_per_cluster {
            continue;
        }
        if seen_sub16.insert(cluster_subnet_key(cand, 2)) {
            selected[idx] = true;
            counts.insert(cand.cluster_id.clone(), count + 1);
        }
    }

    // Pass 2: Fill remaining per-cluster capacity from additional IPs when fewer /16s exist
    for (idx, cand) in candidates.iter().enumerate() {
        if selected[idx] {
            continue;
        }
        let count = counts.get(&cand.cluster_id).copied().unwrap_or(0);
        if count < max_per_cluster {
            selected[idx] = true;
            counts.insert(cand.cluster_id.clone(), count + 1);
        }
    }

    let mut idx = 0;
    candidates.retain(|_| {
        let keep = selected[idx];
        idx += 1;
        keep
    });
    candidates.truncate(max_total);
}
