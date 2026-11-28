use hadal_core::{
    default_tunnel_dns, is_special_cluster, prepare_connect_target_with,
    resolve_game_cidrs_with_prober, Cluster, ConnectSpec, DaemonRequest, DaemonResponse, Result,
    HadalError, SplitMode,
};

use crate::context::CliContext;
use crate::format::{format_status, format_user_location_line};

pub struct ConnectSpecInput<'a> {
    pub cluster: &'a Cluster,
    pub endpoint_ip: String,
    pub endpoint_port: u16,
    pub priv_key: String,
    pub address: String,
    pub mtu: u16,
    pub killswitch: bool,
    pub ipv6_block: bool,
    pub bypass_lan: bool,
    pub split_mode: SplitMode,
    pub split_cgroup_paths: Vec<String>,
    pub game_only_cidrs: Vec<String>,
}

pub fn build_connect_spec(input: ConnectSpecInput<'_>) -> ConnectSpec {
    ConnectSpec {
        cluster_id: Some(input.cluster.id.clone()),
        domain: input.cluster.connection_name.clone().unwrap_or_default(),
        endpoint_ip: input.endpoint_ip,
        endpoint_port: input.endpoint_port,
        pub_key: input.cluster.pub_key.clone().unwrap_or_default(),
        priv_key: input.priv_key,
        address: input.address,
        dns: default_tunnel_dns(),
        mtu: input.mtu,
        killswitch: input.killswitch,
        ipv6_block: input.ipv6_block,
        bypass_lan: input.bypass_lan,
        split_mode: input.split_mode,
        split_cgroup_paths: input.split_cgroup_paths,
        game_only_cidrs: input.game_only_cidrs,
        location: input.cluster.location.clone(),
        country: input.cluster.country.clone(),
    }
}

pub fn find_matching_cluster(clusters: Vec<Cluster>, filter: &str) -> Option<Cluster> {
    let f_lower = filter.to_lowercase();
    let eligible: Vec<_> = clusters
        .into_iter()
        .filter(|c| c.pub_key.as_deref().is_some_and(|k| !k.is_empty()))
        .collect();

    let mut matches: Vec<_> = eligible
        .iter()
        .filter(|c| {
            c.id == filter
                || c.connection_name
                    .as_deref()
                    .is_some_and(|s| s.eq_ignore_ascii_case(filter))
                || c.location
                    .as_deref()
                    .is_some_and(|s| s.eq_ignore_ascii_case(filter))
                || c.country
                    .as_deref()
                    .is_some_and(|s| s.eq_ignore_ascii_case(filter))
        })
        .cloned()
        .collect();

    if matches.is_empty() {
        matches = eligible
            .into_iter()
            .filter(|c| {
                c.location
                    .as_deref()
                    .unwrap_or("")
                    .to_lowercase()
                    .contains(&f_lower)
                    || c.country
                        .as_deref()
                        .unwrap_or("")
                        .to_lowercase()
                        .contains(&f_lower)
                    || c.connection_name
                        .as_deref()
                        .unwrap_or("")
                        .to_lowercase()
                        .contains(&f_lower)
            })
            .collect();
    }

    matches.sort_by_key(|c| {
        let name = c.connection_name.as_deref().unwrap_or("").to_lowercase();
        let exact_prefix = name.starts_with(&format!("{f_lower}."));
        (
            u8::from(!exact_prefix),
            u8::from(is_special_cluster(c)),
            c.load.unwrap_or(999),
        )
    });
    matches.into_iter().next()
}

pub async fn handle_connect(
    ctx: &CliContext,
    server: Option<String>,
    endpoint: Option<String>,
    mtu: Option<u16>,
    no_killswitch: bool,
    no_ipv6_block: bool,
    game_only: Option<String>,
) -> Result<()> {
    let settings = ctx.settings.load();
    let clusters = ctx.api.get_clusters().await?;
    let filter = server.as_deref().unwrap_or("de-fra");
    let target = find_matching_cluster(clusters, filter)
        .ok_or_else(|| HadalError::Custom(format!("Cluster matching '{filter}' not found")))?;

    let domain = target.connection_name.clone().unwrap_or_default();
    ctx.println(format!(
        "Selected: {} ({}, {}) [load: {}%]",
        domain,
        target.location.as_deref().unwrap_or("-"),
        target.country.as_deref().unwrap_or("-"),
        target
            .load
            .map(|l| l.to_string())
            .unwrap_or_else(|| "?".into()),
    ))?;

    if endpoint.is_none() {
        ctx.println(format!(
            "Probing rotating DoH pools for fastest IP behind {domain}..."
        ))?;
    }
    let (ep_ip, ep_port, effective_mtu) = prepare_connect_target_with(
        ctx.daemon.as_ref(),
        ctx.doh.clone(),
        ctx.prober.clone(),
        &domain,
        settings.auto_mtu,
        settings.manual_mtu,
        endpoint.as_deref(),
        mtu,
    )
    .await?;

    let game_only_cidrs = if let Some(ref game_host) = game_only {
        let c = resolve_game_cidrs_with_prober(game_host, ctx.prober.as_ref());
        ctx.println(format!("Game-Only route CIDRs for {game_host}: {c:?}"))?;
        c
    } else {
        Vec::new()
    };

    let wg_key = ctx.api.ensure_wireguard_key(ctx.keys.as_ref()).await?;
    let split_cgroup_paths = ctx
        .split
        .active_slice_cgroup_paths(settings.split_tunnel.mode);

    let spec = build_connect_spec(ConnectSpecInput {
        cluster: &target,
        endpoint_ip: ep_ip.clone(),
        endpoint_port: ep_port,
        priv_key: wg_key.private_key,
        address: wg_key.address,
        mtu: effective_mtu,
        killswitch: !no_killswitch && settings.killswitch,
        ipv6_block: !no_ipv6_block && settings.ipv6_block,
        bypass_lan: settings.bypass_lan,
        split_mode: settings.split_tunnel.mode,
        split_cgroup_paths,
        game_only_cidrs,
    });

    ctx.println(format!(
        "Connecting via hadald -> {ep_ip}:{ep_port} (MTU {effective_mtu})..."
    ))?;
    let resp = ctx.daemon.send(&DaemonRequest::Connect(spec)).await?;
    if let DaemonResponse::Status(st) = resp {
        ctx.println(format!(
            "State: {:?} | Interface: {} | Killswitch: {} | IPv6 Lock: {}",
            st.state, st.interface, st.killswitch, st.ipv6_block
        ))?;
    }
    if let Ok(loc) = ctx.api.get_user_location().await {
        ctx.println(format_user_location_line("Exit IP: ", &loc, true))?;
    }
    Ok(())
}

pub async fn handle_disconnect(ctx: &CliContext, keep_killswitch: bool) -> Result<()> {
    let resp = ctx
        .daemon
        .send(&DaemonRequest::Disconnect { keep_killswitch })
        .await?;
    if let DaemonResponse::Status(st) = resp {
        ctx.println(format!(
            "State: {:?} (killswitch: {})",
            st.state, st.killswitch
        ))?;
    }
    if !keep_killswitch {
        if let Ok(loc) = ctx.api.get_user_location().await {
            ctx.println(format_user_location_line("Host IP: ", &loc, false))?;
        }
    }
    Ok(())
}

pub async fn handle_status(ctx: &CliContext) -> Result<()> {
    let st = ctx.daemon.status().await?;
    let loc = ctx.api.get_user_location().await.ok();
    ctx.println(format_status(&st, loc.as_ref()))
}

pub async fn handle_killswitch(ctx: &CliContext, state: &str) -> Result<()> {
    let enabled = state == "on";
    let settings = ctx.settings.load();
    let resp = ctx
        .daemon
        .send(&DaemonRequest::SetKillswitch {
            enabled,
            ipv6_block: settings.ipv6_block,
            bypass_lan: settings.bypass_lan,
        })
        .await?;
    if let DaemonResponse::Status(st) = resp {
        ctx.println(format!(
            "State: {:?} (killswitch={})",
            st.state, st.killswitch
        ))?;
    }
    Ok(())
}
