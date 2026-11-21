use clap::Parser;
use hadal_cli::{run_with, Cli, CliContext};
use hadal_core::Result;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    let ctx = CliContext::system()?;
    run_with(cli, &ctx).await
}
