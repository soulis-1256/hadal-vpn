use hadal_core::{
    active_slice_for_mode, DaemonRequest, DaemonResponse, Result, SplitMode, SplitTunnelConfig,
    TunnelState, BYPASS_SLICE,
};

use crate::cli::SplitAction;
use crate::context::CliContext;
use crate::format::format_split_status;

pub async fn handle_split(ctx: &CliContext, action: SplitAction) -> Result<()> {
    let mut settings = ctx.settings.load();
    match action {
        SplitAction::Mode { mode } => {
            let m: SplitMode = mode.into();
            settings.split_tunnel.mode = m;
            settings.split_tunnel.sync_active_apps();
            let mut cfg = settings.split_tunnel.clone();
            cfg.cgroup_paths = ctx.split.active_slice_cgroup_paths(m);
            ctx.settings.save(&settings)?;
            let _ = sync_split_policy_to_daemon(ctx, cfg, &[]).await;
            ctx.println(format!("Split-tunnel mode updated to {m:?}"))?;
        }
        SplitAction::Launch { app } => {
            let mode = settings.split_tunnel.mode;
            let slice = active_slice_for_mode(mode).unwrap_or(BYPASS_SLICE);
            let pid = ctx.split.launch_in_slice(&app, slice)?;
            if !settings.split_tunnel.apps_for_mode(mode).contains(&app) {
                settings
                    .split_tunnel
                    .apps_for_mode_mut(mode)
                    .push(app.clone());
                settings.split_tunnel.sync_active_apps();
                ctx.settings.save(&settings)?;
            }
            let mut cfg = settings.split_tunnel.clone();
            cfg.cgroup_paths = ctx.split.slice_cgroup_paths(slice);
            let _ = sync_split_policy_to_daemon(ctx, cfg, &[]).await;
            ctx.println(format!(
                "Launched {app} (pid {pid}) inside cgroup slice {slice}"
            ))?;
        }
        SplitAction::Move { app } => {
            let slice = active_slice_for_mode(settings.split_tunnel.mode).unwrap_or(BYPASS_SLICE);
            let moved_pids = ctx.split.move_to_slice_pids(&app, slice)?;
            let mut cfg = settings.split_tunnel.clone();
            cfg.cgroup_paths = ctx.split.slice_cgroup_paths(slice);
            let _ = sync_split_policy_to_daemon(ctx, cfg, &moved_pids).await;
            ctx.println(format!(
                "Moved {} matching process(es) into {slice}",
                moved_pids.len()
            ))?;
        }
        SplitAction::Status => {
            let mode = settings.split_tunnel.mode;
            let exp = active_slice_for_mode(mode);
            let list = ctx
                .split
                .app_statuses(settings.split_tunnel.apps_for_mode(mode), exp);
            ctx.println(format_split_status(mode, exp, &list))?;
        }
    }
    Ok(())
}

async fn sync_split_policy_to_daemon(ctx: &CliContext, cfg: SplitTunnelConfig, moved_pids: &[u32]) {
    let Ok(DaemonResponse::Status(st)) = ctx
        .daemon
        .send(&DaemonRequest::UpdateSplitTunnel(cfg))
        .await
    else {
        return;
    };
    if !moved_pids.is_empty() && st.state == TunnelState::Protected {
        let _ = ctx
            .daemon
            .send(&DaemonRequest::ResetAppSockets {
                pids: moved_pids.to_vec(),
            })
            .await;
    }
}
