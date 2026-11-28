use hadal_core::{
    builtin_games, find_game_region, scan_gaming_with_deps, DaemonRequest, KeyRegistrar, Result,
    HadalError, DEFAULT_WG_PORT,
};

use crate::context::CliContext;
use crate::format::{format_gaming_list, format_gaming_report};
use crate::handlers::tunnel::{build_connect_spec, ConnectSpecInput};

#[allow(clippy::too_many_arguments)]
pub async fn handle_gaming(
    ctx: &CliContext,
    game: String,
    region: String,
    host: Option<String>,
    connect: bool,
    game_only: bool,
    list: bool,
    no_verify: bool,
) -> Result<()> {
    if list {
        ctx.println(format_gaming_list(&builtin_games()))?;
        return Ok(());
    }

    let target_host = host
        .clone()
        .or_else(|| find_game_region(&game, &region).map(|r| r.ping_host))
        .ok_or_else(|| HadalError::Custom(format!("Unknown region {game}/{region}")))?;

    ctx.println(format!(
        "Scanning Surfshark routes for {game}/{region} ({target_host})..."
    ))?;
    let clusters = ctx.api.get_clusters().await?;
    let registrar: Option<&dyn KeyRegistrar> = if no_verify {
        None
    } else {
        Some(ctx.api.as_ref())
    };
    let report = scan_gaming_with_deps(
        ctx.daemon.as_ref(),
        ctx.doh.clone(),
        ctx.prober.clone(),
        ctx.keys.as_ref(),
        registrar,
        &clusters,
        &game,
        &region,
        host.as_deref(),
        None,
    )
    .await?;

    ctx.println(format_gaming_report(&report))?;

    if connect {
        let best = report
            .candidates
            .first()
            .ok_or_else(|| HadalError::Custom("No reachable Surfshark candidate found".into()))?;
        let cluster = clusters
            .into_iter()
            .find(|c| c.id == best.cluster_id)
            .ok_or_else(|| HadalError::Custom("Best cluster vanished".into()))?;
        let settings = ctx.settings.load();
        let wg_key = ctx.api.ensure_wireguard_key(ctx.keys.as_ref()).await?;
        let game_cidrs = if game_only {
            report.game_cidrs.clone()
        } else {
            Vec::new()
        };
        let split_cgroup_paths = ctx
            .split
            .active_slice_cgroup_paths(settings.split_tunnel.mode);

        let spec = build_connect_spec(ConnectSpecInput {
            cluster: &cluster,
            endpoint_ip: best.endpoint_ip.clone(),
            endpoint_port: DEFAULT_WG_PORT,
            priv_key: wg_key.private_key,
            address: wg_key.address,
            mtu: report.recommended_mtu,
            killswitch: settings.killswitch,
            ipv6_block: settings.ipv6_block,
            bypass_lan: settings.bypass_lan,
            split_mode: settings.split_tunnel.mode,
            split_cgroup_paths,
            game_only_cidrs: game_cidrs,
        });
        ctx.println(format!(
            "\nConnecting to #1 candidate: {} ({}) @ {}...",
            best.location, best.domain, best.endpoint_ip
        ))?;
        ctx.daemon.send(&DaemonRequest::Connect(spec)).await?;
        ctx.println("Connected!")?;
    }

    Ok(())
}
