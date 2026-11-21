use std::net::{Ipv4Addr, SocketAddrV4};

use crate::error::Result;
use crate::gaming::types::PingStats;
use crate::platform::BoxFuture;

/// Transport seam for DNS-over-HTTPS JSON queries and optional system DNS fallback.
pub trait DohTransport: Send + Sync {
    fn get_json<'a>(&'a self, url: &'a str) -> BoxFuture<'a, Result<Vec<u8>>>;
    fn resolve_system_v4(&self, host: &str, port: u16) -> Vec<SocketAddrV4>;
}

/// Socket/ICMP probing seam so PMTU discovery, endpoint RTT selection, and game CIDR lookup
/// can be deterministically unit-tested without spawning `ping`.
pub trait NetworkProber: Send + Sync {
    fn measure_icmp(
        &self,
        target: &str,
        count: u32,
        fwmark: Option<u32>,
        iface: Option<&str>,
    ) -> Option<PingStats>;

    fn df_ping_ok(&self, target: &str, payload: u16, fwmark: Option<u32>) -> bool;

    fn resolve_ipv4s(&self, host: &str) -> Vec<Ipv4Addr>;
}
