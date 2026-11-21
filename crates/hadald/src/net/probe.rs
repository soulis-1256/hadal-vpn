use futures_util::future::BoxFuture;
use hadal_core::{measure_icmp_stats_on_iface, PingStats};

/// Interface-bound ICMP prober abstraction for end-to-end gaming tunnel verification.
pub trait TunnelProber: Send + Sync {
    fn measure_icmp_on_iface<'a>(
        &'a self,
        iface: &'a str,
        target_ip: &'a str,
        count: u32,
    ) -> BoxFuture<'a, Option<PingStats>>;
}

/// Real ICMP prober executing `ping -I <iface>` on a blocking worker thread.
pub struct SystemTunnelProber;

impl TunnelProber for SystemTunnelProber {
    fn measure_icmp_on_iface<'a>(
        &'a self,
        iface: &'a str,
        target_ip: &'a str,
        count: u32,
    ) -> BoxFuture<'a, Option<PingStats>> {
        let iface = iface.to_string();
        let target_ip = target_ip.to_string();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                measure_icmp_stats_on_iface(&iface, &target_ip, count)
            })
            .await
            .ok()
            .flatten()
        })
    }
}
