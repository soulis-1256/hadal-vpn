use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use crate::client::{KeyRegistrar, HadalClient};
use crate::config::{endpoint_for_domain, split_host_port_u16, DEFAULT_WG_PORT};
use crate::error::{Result, HadalError};
use crate::gaming::doh::{
    discover_doh_ipv4s_with, resolve_fastest_endpoint_ip_with, ReqwestDohTransport,
};
use crate::gaming::probe::{
    discover_wan_pmtu_with_prober, probe_gaming_candidates_with, SystemNetworkProber,
};
use crate::gaming::selection::{
    finalize_gaming_candidates, pick_diverse_verify_targets, select_candidate_clusters,
    sort_gaming_candidates,
};
use crate::gaming::traits::{DohTransport, NetworkProber};
use crate::gaming::types::{
    build_endpoint_candidate, recommended_wg_mtu, resolve_gaming_target, strip_host_port,
    EndpointCandidate, GamingScanReport,
};
use crate::ipc::{
    DaemonClient, DaemonRequest, DaemonResponse, TunnelState, UnixDaemonClient,
    VerifiedTunnelResult, VerifyTarget,
};
use crate::servers::Cluster;
use crate::wireguard::{KeyPairGenerator, OsKeyPairGenerator};

/// Resolve the endpoint IP and effective WireGuard MTU, routing DoH + ICMP/PMTU probes through
/// `hadald`'s control-plane mark whenever the daemon is currently in `KillswitchLocked`.
pub async fn prepare_connect_target(
    socket_path: &Path,
    domain: &str,
    auto_mtu: bool,
    manual_mtu: Option<u16>,
    endpoint_override: Option<&str>,
    mtu_override: Option<u16>,
) -> Result<(String, u16, u16)> {
    let daemon = UnixDaemonClient::new(socket_path);
    let doh = Arc::new(ReqwestDohTransport::default_client(true)?);
    let prober = Arc::new(SystemNetworkProber);
    prepare_connect_target_with(
        &daemon,
        doh,
        prober,
        domain,
        auto_mtu,
        manual_mtu,
        endpoint_override,
        mtu_override,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn prepare_connect_target_with(
    daemon: &dyn DaemonClient,
    doh: Arc<dyn DohTransport>,
    prober: Arc<dyn NetworkProber>,
    domain: &str,
    auto_mtu: bool,
    manual_mtu: Option<u16>,
    endpoint_override: Option<&str>,
    mtu_override: Option<u16>,
) -> Result<(String, u16, u16)> {
    let raw_target = endpoint_override
        .map(str::to_string)
        .unwrap_or_else(|| endpoint_for_domain(domain));
    let (host, port) = split_host_port_u16(&raw_target);
    let need_pmtu = mtu_override.is_none() && auto_mtu;

    let locked = daemon
        .status()
        .await
        .map(|s| s.state == TunnelState::KillswitchLocked)
        .unwrap_or(false);

    if locked {
        match daemon
            .send(&DaemonRequest::PrepareEndpoint {
                domain: host,
                discover_pmtu: need_pmtu,
            })
            .await?
        {
            DaemonResponse::Prepared {
                endpoint_ip,
                wan_pmtu,
            } => {
                let effective_mtu = resolve_effective_mtu(
                    mtu_override,
                    auto_mtu,
                    manual_mtu,
                    wan_pmtu.unwrap_or(1492),
                );
                return Ok((endpoint_ip, port, effective_mtu));
            }
            other => {
                return Err(HadalError::Custom(format!(
                    "Unexpected PrepareEndpoint response: {other:?}"
                )));
            }
        }
    }

    let endpoint_ip = resolve_fastest_endpoint_ip_with(&host, doh, prober.clone())
        .await?
        .to_string();
    let wan_pmtu = if need_pmtu {
        tokio::task::spawn_blocking(move || {
            discover_wan_pmtu_with_prober("1.1.1.1", None, prober.as_ref())
        })
        .await
        .unwrap_or(1492)
    } else {
        1492
    };
    let effective_mtu = resolve_effective_mtu(mtu_override, auto_mtu, manual_mtu, wan_pmtu);
    Ok((endpoint_ip, port, effective_mtu))
}

fn resolve_effective_mtu(
    mtu_override: Option<u16>,
    auto_mtu: bool,
    manual_mtu: Option<u16>,
    wan_pmtu: u16,
) -> u16 {
    match mtu_override {
        Some(m) => m,
        None if auto_mtu => recommended_wg_mtu(wan_pmtu),
        None => manual_mtu.unwrap_or(1412),
    }
}

/// Run a Gaming Mode scan, automatically routing WAN baseline/PMTU/endpoint probes through
/// `hadald`'s `CONTROL_FWMARK` whenever the tunnel is `Protected` or `KillswitchLocked` so
/// measurements always reflect the real ISP WAN rather than the active WireGuard tunnel.
pub async fn scan_gaming_with_daemon(
    socket_path: &Path,
    clusters: &[Cluster],
    game_id: &str,
    region_id: &str,
    custom_host: Option<&str>,
    user_coords: Option<(f64, f64)>,
    verify_client: Option<&HadalClient>,
) -> Result<GamingScanReport> {
    let daemon = UnixDaemonClient::new(socket_path);
    let doh = Arc::new(ReqwestDohTransport::default_client(true)?);
    let prober = Arc::new(SystemNetworkProber);
    let keys = OsKeyPairGenerator;
    let registrar: Option<&dyn KeyRegistrar> = verify_client.map(|c| c as &dyn KeyRegistrar);
    scan_gaming_with_deps(
        &daemon,
        doh,
        prober,
        &keys,
        registrar,
        clusters,
        game_id,
        region_id,
        custom_host,
        user_coords,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn scan_gaming_with_deps(
    daemon: &dyn DaemonClient,
    doh: Arc<dyn DohTransport>,
    prober: Arc<dyn NetworkProber>,
    keys: &dyn KeyPairGenerator,
    registrar: Option<&dyn KeyRegistrar>,
    clusters: &[Cluster],
    game_id: &str,
    region_id: &str,
    custom_host: Option<&str>,
    user_coords: Option<(f64, f64)>,
) -> Result<GamingScanReport> {
    let status = daemon.status().await.ok();
    let needs_control_wan = status.as_ref().is_some_and(|s| {
        matches!(
            s.state,
            TunnelState::Protected | TunnelState::KillswitchLocked
        )
    });

    if !needs_control_wan {
        let mut report = probe_gaming_candidates_with(
            clusters,
            game_id,
            region_id,
            custom_host,
            user_coords,
            doh.clone(),
            prober,
        )
        .await?;
        if status
            .as_ref()
            .is_some_and(|s| s.state == TunnelState::Disconnected)
        {
            if let Some(reg) = registrar {
                verify_top_candidates_with(daemon, doh, keys, reg, clusters, &mut report).await;
            }
        }
        finalize_gaming_candidates(&mut report.candidates, 3, 15);
        return Ok(report);
    }

    let (target_host, target_coords) = resolve_gaming_target(game_id, region_id, custom_host)?;
    let selected = select_candidate_clusters(clusters, user_coords, target_coords, 12);

    let mut cluster_by_domain: HashMap<String, Cluster> = HashMap::new();
    let mut domains = Vec::new();
    for c in selected {
        if let Some(ref dom) = c.connection_name {
            let host = strip_host_port(dom);
            if !host.is_empty() && !cluster_by_domain.contains_key(&host) {
                domains.push(host.clone());
                cluster_by_domain.insert(host, c);
            }
        }
    }

    let is_protected = status
        .as_ref()
        .is_some_and(|s| s.state == TunnelState::Protected);
    let active_label = status
        .as_ref()
        .filter(|s| s.state == TunnelState::Protected)
        .and_then(|s| s.location.clone().or_else(|| s.country.clone()));

    let tunnel_target = target_host.clone();
    let tunnel_prober = prober.clone();
    let tunnel_probe_task = if is_protected {
        Some(tokio::task::spawn_blocking(move || {
            tunnel_prober.measure_icmp(&tunnel_target, 4, None, None)
        }))
    } else {
        None
    };

    let resp = daemon
        .send(&DaemonRequest::ProbeWanGaming {
            target_host: target_host.clone(),
            domains,
        })
        .await
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("unknown variant") {
                HadalError::Custom(
                    "Installed hadald is older than this client; reinstall hadald and run `sudo systemctl restart hadald`."
                        .into(),
                )
            } else {
                e
            }
        })?;

    let probe = match resp {
        DaemonResponse::WanGamingProbed(p) => p,
        other => {
            return Err(HadalError::Custom(format!(
                "Unexpected ProbeWanGaming response: {other:?}"
            )));
        }
    };

    let active_tunnel_ping = match tunnel_probe_task {
        Some(handle) => handle.await.ok().flatten(),
        None => None,
    };

    let mut candidates: Vec<EndpointCandidate> = probe
        .endpoints
        .into_iter()
        .filter_map(|ep| {
            let cluster = cluster_by_domain.get(&ep.domain)?;
            Some(build_endpoint_candidate(
                cluster,
                &ep.endpoint_ip,
                ep.min_ms,
                target_coords,
            ))
        })
        .collect();

    finalize_gaming_candidates(&mut candidates, 3, 15);

    Ok(GamingScanReport {
        game_id: game_id.to_string(),
        region_id: region_id.to_string(),
        target_host,
        baseline_direct: probe.baseline_direct,
        active_tunnel_ping,
        active_tunnel_label: active_label,
        wan_pmtu: probe.wan_pmtu,
        recommended_mtu: recommended_wg_mtu(probe.wan_pmtu),
        candidates,
        game_cidrs: probe.game_cidrs,
    })
}

pub fn build_verify_targets(
    candidates: &[EndpointCandidate],
    clusters: &[Cluster],
) -> Vec<VerifyTarget> {
    candidates
        .iter()
        .filter_map(|cand| {
            let pub_key = clusters
                .iter()
                .find(|c| c.id == cand.cluster_id)
                .and_then(|c| c.pub_key.clone())
                .filter(|k| !k.is_empty())?;
            Some(VerifyTarget {
                cluster_id: cand.cluster_id.clone(),
                endpoint_ip: cand.endpoint_ip.clone(),
                endpoint_port: DEFAULT_WG_PORT,
                pub_key,
            })
        })
        .collect()
}

pub fn apply_verified_results(report: &mut GamingScanReport, results: Vec<VerifiedTunnelResult>) {
    for res in results {
        if let Some(cand) = report
            .candidates
            .iter_mut()
            .find(|c| c.cluster_id == res.cluster_id && c.endpoint_ip == res.endpoint_ip)
        {
            cand.verified_tunnel_ms = Some(res.avg_ms);
            cand.verified_mdev_ms = Some(res.mdev_ms);
            cand.verified_loss_pct = Some(res.loss_pct);
        }
    }
    sort_gaming_candidates(&mut report.candidates);
}

/// Measure real end-to-end RTT through an ephemeral `hadal-probe` WireGuard tunnel when disconnected:
/// Pass 1 sweeps up to 12 city & `/16`-subnet diverse candidates (4 samples each), then Pass 2
/// confirms the top 3 winners with 8 steady-state samples so jitter/loss decide the podium.
pub async fn verify_top_candidates_with(
    daemon: &dyn DaemonClient,
    doh: Arc<dyn DohTransport>,
    keys: &dyn KeyPairGenerator,
    registrar: &dyn KeyRegistrar,
    clusters: &[Cluster],
    report: &mut GamingScanReport,
) {
    if report.candidates.is_empty() || !registrar.has_session().await {
        return;
    }

    let diverse = pick_diverse_verify_targets(&report.candidates, 12);
    let targets = build_verify_targets(&diverse, clusters);
    if targets.is_empty() {
        return;
    }

    let host = strip_host_port(&report.target_host);
    let resolved = discover_doh_ipv4s_with(doh, &host, 443).await;
    let Some(target_ip) = resolved.first().map(|s| s.ip().to_string()) else {
        return;
    };

    let keypair = keys.generate();
    let Ok(reg) = registrar.register_public_key(&keypair.public_key).await else {
        return;
    };
    let address = reg.wireguard_address();

    if !run_verify_pass(
        daemon,
        &target_ip,
        &keypair.private_key,
        &address,
        targets,
        4,
        report,
    )
    .await
    {
        return;
    }

    // Pass 2: Confirm top 3 reachable winners with deeper steady-state sampling
    let finalist_cands: Vec<EndpointCandidate> = report
        .candidates
        .iter()
        .filter(|c| c.verified_tunnel_ms.is_some() && c.verified_loss_pct.unwrap_or(0.0) < 100.0)
        .take(3)
        .cloned()
        .collect();
    let finalist_targets = build_verify_targets(&finalist_cands, clusters);
    if !finalist_targets.is_empty() {
        let _ = run_verify_pass(
            daemon,
            &target_ip,
            &keypair.private_key,
            &address,
            finalist_targets,
            8,
            report,
        )
        .await;
    }
}

async fn run_verify_pass(
    daemon: &dyn DaemonClient,
    target_ip: &str,
    priv_key: &str,
    address: &str,
    targets: Vec<VerifyTarget>,
    samples: u32,
    report: &mut GamingScanReport,
) -> bool {
    let Ok(DaemonResponse::GamingTunnelsVerified(results)) = daemon
        .send(&DaemonRequest::VerifyGamingTunnels {
            target_ip: target_ip.to_string(),
            priv_key: priv_key.to_string(),
            address: address.to_string(),
            mtu: report.recommended_mtu,
            targets,
            samples: Some(samples),
        })
        .await
    else {
        return false;
    };
    apply_verified_results(report, results);
    true
}
