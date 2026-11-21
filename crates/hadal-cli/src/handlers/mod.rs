pub mod auth;
pub mod gaming;
pub mod network;
pub mod split;
pub mod tunnel;

use hadal_core::Result;

use crate::cli::{Cli, Commands};
use crate::context::CliContext;

pub async fn dispatch(ctx: &CliContext, cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Code => auth::handle_code(ctx).await,
        Commands::Me => auth::handle_me(ctx).await,
        Commands::Servers {
            filter,
            limit,
            sort_load,
            include_static,
        } => auth::handle_servers(ctx, filter, limit, sort_load, include_static).await,
        Commands::Keygen => auth::handle_keygen(ctx).await,
        Commands::Connect {
            server,
            endpoint,
            mtu,
            no_killswitch,
            no_ipv6_block,
            game_only,
        } => {
            tunnel::handle_connect(
                ctx,
                server,
                endpoint,
                mtu,
                no_killswitch,
                no_ipv6_block,
                game_only,
            )
            .await
        }
        Commands::Disconnect { keep_killswitch } => {
            tunnel::handle_disconnect(ctx, keep_killswitch).await
        }
        Commands::Status => tunnel::handle_status(ctx).await,
        Commands::Killswitch { state } => tunnel::handle_killswitch(ctx, &state).await,
        Commands::Gaming {
            game,
            region,
            host,
            connect,
            game_only,
            list,
            no_verify,
        } => {
            gaming::handle_gaming(ctx, game, region, host, connect, game_only, list, no_verify)
                .await
        }
        Commands::Split { action } => split::handle_split(ctx, action).await,
        Commands::Ping {
            target,
            count,
            trace,
        } => network::handle_ping(ctx, &target, count, trace),
        Commands::InstallInfo => network::handle_install_info(ctx),
    }
}
