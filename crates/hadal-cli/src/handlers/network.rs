use hadal_core::Result;

use crate::context::CliContext;
use crate::format::format_install_info;
use crate::traits::TraceHop;

pub fn handle_ping(ctx: &CliContext, target: &str, count: u32, trace: bool) -> Result<()> {
    ctx.ping.run_ping(target, count)?;
    if trace {
        ctx.println(format!("\nICMP TTL trace to {target}:"))?;
        for ttl in 1..=20 {
            match ctx.ping.trace_hop(target, ttl)? {
                TraceHop::Reached(line) => {
                    ctx.println(format!("  hop {ttl:2}: {line}"))?;
                    break;
                }
                TraceHop::Exceeded(line) => {
                    ctx.println(format!("  hop {ttl:2}: {line}"))?;
                }
                TraceHop::Timeout => {
                    ctx.println(format!("  hop {ttl:2}: *"))?;
                }
            }
        }
    }
    Ok(())
}

pub fn handle_install_info(ctx: &CliContext) -> Result<()> {
    ctx.println(format_install_info())
}
