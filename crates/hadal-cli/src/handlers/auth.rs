use std::time::Duration;

use hadal_core::Result;
use hadal_core::HadalError;

use crate::context::CliContext;
use crate::format::{format_me, format_servers_table};

pub async fn handle_code(ctx: &CliContext) -> Result<()> {
    let remote = ctx.api.create_remote_login().await?;
    ctx.println(format!("\nLogin Code: {}", remote.code))?;
    ctx.println("Authorize at https://my.surfshark.com (My account -> Enter login code) — waiting...")?;

    for _ in 0..ctx.max_code_polls {
        ctx.sleeper.sleep(Duration::from_secs(3)).await;
        if let Ok(resp) = ctx.api.poll_remote_login(&remote.hash).await {
            if resp.token.is_some() {
                ctx.println("Login authorized! Session saved.")?;
                return Ok(());
            }
        }
    }
    Err(HadalError::Custom(
        "Timed out waiting for quick-pair login authorization".into(),
    ))
}

pub async fn handle_me(ctx: &CliContext) -> Result<()> {
    let me = ctx.api.get_user_me().await?;
    ctx.println(format_me(&me))
}

pub async fn handle_servers(
    ctx: &CliContext,
    filter: Option<String>,
    limit: usize,
    sort_load: bool,
    include_static: bool,
) -> Result<()> {
    let mut clusters = ctx.api.get_clusters().await?;
    if !include_static {
        clusters.retain(|c| !hadal_core::is_special_cluster(c));
    }
    if let Some(q) = filter {
        let ql = q.to_lowercase();
        clusters.retain(|c| {
            c.country
                .as_deref()
                .unwrap_or("")
                .to_lowercase()
                .contains(&ql)
                || c.location
                    .as_deref()
                    .unwrap_or("")
                    .to_lowercase()
                    .contains(&ql)
                || c.connection_name
                    .as_deref()
                    .unwrap_or("")
                    .to_lowercase()
                    .contains(&ql)
        });
    }
    if sort_load {
        clusters.sort_by_key(|c| c.load.unwrap_or(999));
    }
    ctx.println(format_servers_table(&clusters, limit))
}

pub async fn handle_keygen(ctx: &CliContext) -> Result<()> {
    let wg_key = ctx.api.rotate_wireguard_key(ctx.keys.as_ref()).await?;
    ctx.println(format!("PublicKey:  {}", wg_key.public_key))?;
    ctx.println(format!("PrivateKey: {}", wg_key.private_key))?;
    ctx.println(format!("Registered Address: {}", wg_key.address))?;
    if let Some(exp) = wg_key.expires_at {
        ctx.println(format!("ExpiresAt:  {exp}"))?;
    }
    Ok(())
}
