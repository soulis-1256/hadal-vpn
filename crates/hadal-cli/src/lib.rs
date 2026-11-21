pub mod cli;
pub mod context;
pub mod format;
pub mod handlers;
pub mod traits;

use std::ffi::OsString;

use clap::Parser;
use hadal_core::Result;

pub use cli::{Cli, CliSplitMode, Commands, SplitAction};
pub use context::CliContext;
pub use handlers::tunnel::{build_connect_spec, find_matching_cluster, ConnectSpecInput};
pub use traits::{CoreSplitOps, PingTool, SplitOps, SystemPingTool, TraceHop};

pub async fn run_with(cli: Cli, ctx: &CliContext) -> Result<()> {
    handlers::dispatch(ctx, cli).await
}

pub async fn run_from<I, T>(args: I, ctx: &CliContext) -> Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = Cli::parse_from(args);
    run_with(cli, ctx).await
}
