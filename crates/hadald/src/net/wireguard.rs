use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;

use futures_util::future::BoxFuture;
use futures_util::TryStreamExt;
use ipnet::IpNet;
use rtnetlink::{new_connection, Handle, LinkMessageBuilder, LinkWireguard};
use wireguard_control::{Backend, Device, DeviceUpdate, InterfaceName, Key, PeerConfigBuilder};

use hadal_core::{Result, HadalError};

pub const WG_FWMARK: u32 = 0xca7f;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WgTelemetry {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub last_handshake_epoch: Option<u64>,
}

/// Parameters required to program a kernel WireGuard interface peer.
#[derive(Debug, Clone)]
pub struct WgPeerConfig {
    pub iface: String,
    pub priv_key_b64: String,
    pub peer_pub_key_b64: String,
    pub endpoint_ip: Ipv4Addr,
    pub endpoint_port: u16,
    pub allowed_cidrs: Vec<String>,
    pub dns_ips: Vec<Ipv4Addr>,
}

/// Abstraction over kernel WireGuard interface & peer lifecycle.
pub trait WireGuardBackend: Send + Sync {
    fn ensure_interface<'a>(
        &'a self,
        iface: &'a str,
        address_cidr: &'a str,
        mtu: u16,
    ) -> BoxFuture<'a, Result<u32>>;

    fn delete_interface<'a>(&'a self, iface: &'a str) -> BoxFuture<'a, Result<()>>;

    fn get_ifindex<'a>(&'a self, iface: &'a str) -> BoxFuture<'a, Result<Option<u32>>>;

    fn apply_config(&self, cfg: &WgPeerConfig) -> Result<()>;

    fn read_telemetry(&self, iface: &str) -> Option<WgTelemetry>;
}

/// Real Linux netlink + `wireguard-control` kernel backend.
pub struct KernelWireGuard {
    handle: Handle,
}

impl KernelWireGuard {
    pub fn new(handle: Handle) -> Self {
        Self { handle }
    }

    pub fn handle(&self) -> &Handle {
        &self.handle
    }
}

impl WireGuardBackend for KernelWireGuard {
    fn ensure_interface<'a>(
        &'a self,
        iface: &'a str,
        address_cidr: &'a str,
        mtu: u16,
    ) -> BoxFuture<'a, Result<u32>> {
        Box::pin(ensure_wg_interface(&self.handle, iface, address_cidr, mtu))
    }

    fn delete_interface<'a>(&'a self, iface: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(delete_wg_interface(&self.handle, iface))
    }

    fn get_ifindex<'a>(&'a self, iface: &'a str) -> BoxFuture<'a, Result<Option<u32>>> {
        Box::pin(get_ifindex(&self.handle, iface))
    }

    fn apply_config(&self, cfg: &WgPeerConfig) -> Result<()> {
        apply_wg_config(
            &cfg.iface,
            &cfg.priv_key_b64,
            &cfg.peer_pub_key_b64,
            cfg.endpoint_ip,
            cfg.endpoint_port,
            &cfg.allowed_cidrs,
            &cfg.dns_ips,
        )
    }

    fn read_telemetry(&self, iface: &str) -> Option<WgTelemetry> {
        read_wg_telemetry(iface)
    }
}

/// Compute effective WireGuard AllowedIPs (`0.0.0.0/0` for full tunnel, or game CIDRs + DNS `/32`s).
pub fn effective_allowed_cidrs(allowed_cidrs: &[String], dns_ips: &[Ipv4Addr]) -> Vec<String> {
    if allowed_cidrs.is_empty() {
        return vec!["0.0.0.0/0".to_string()];
    }
    let mut all = allowed_cidrs.to_vec();
    for ip in dns_ips {
        let host_cidr = format!("{ip}/32");
        if !all.contains(&host_cidr) {
            all.push(host_cidr);
        }
    }
    all
}

pub async fn netlink_handle() -> Result<Handle> {
    let (connection, handle, _) = new_connection()
        .map_err(|e| HadalError::WireGuard(format!("Failed to open rtnetlink socket: {e}")))?;
    tokio::spawn(connection);
    Ok(handle)
}

pub async fn get_ifindex(handle: &Handle, iface: &str) -> Result<Option<u32>> {
    let mut links = handle.link().get().match_name(iface.to_string()).execute();
    match links.try_next().await {
        Ok(Some(msg)) => Ok(Some(msg.header.index)),
        Ok(None) => Ok(None),
        Err(rtnetlink::Error::NetlinkError(err)) if err.raw_code() == -libc::ENODEV => Ok(None),
        Err(e) => Err(HadalError::WireGuard(format!(
            "rtnetlink get link {iface}: {e}"
        ))),
    }
}

pub async fn ensure_wg_interface(
    handle: &Handle,
    iface: &str,
    address_cidr: &str,
    mtu: u16,
) -> Result<u32> {
    // Recreate cleanly if an older interface already exists
    if let Some(idx) = get_ifindex(handle, iface).await? {
        let _ = handle.link().del(idx).execute().await;
    }

    handle
        .link()
        .add(LinkWireguard::new(iface).build())
        .execute()
        .await
        .map_err(|e| {
            HadalError::WireGuard(format!("Failed to create WireGuard link {iface}: {e}"))
        })?;

    let ifindex = get_ifindex(handle, iface).await?.ok_or_else(|| {
        HadalError::WireGuard(format!("Interface {iface} missing right after creation"))
    })?;

    let net: IpNet = address_cidr.parse().map_err(|e| {
        HadalError::WireGuard(format!("Invalid WireGuard address '{address_cidr}': {e}"))
    })?;

    handle
        .address()
        .add(ifindex, net.addr(), net.prefix_len())
        .execute()
        .await
        .map_err(|e| {
            HadalError::WireGuard(format!("Failed to add address {net} to {iface}: {e}"))
        })?;

    handle
        .link()
        .set(
            LinkMessageBuilder::<LinkWireguard>::new(iface)
                .index(ifindex)
                .mtu(mtu as u32)
                .up()
                .build(),
        )
        .execute()
        .await
        .map_err(|e| {
            HadalError::WireGuard(format!("Failed to bring up {iface} (mtu {mtu}): {e}"))
        })?;

    Ok(ifindex)
}

pub async fn delete_wg_interface(handle: &Handle, iface: &str) -> Result<()> {
    if let Some(idx) = get_ifindex(handle, iface).await? {
        handle
            .link()
            .del(idx)
            .execute()
            .await
            .map_err(|e| HadalError::WireGuard(format!("Failed to delete {iface}: {e}")))?;
    }
    Ok(())
}

pub fn apply_wg_config(
    iface: &str,
    priv_key_b64: &str,
    peer_pub_key_b64: &str,
    endpoint_ip: Ipv4Addr,
    endpoint_port: u16,
    allowed_cidrs: &[String],
    dns_ips: &[Ipv4Addr],
) -> Result<()> {
    let iface_name = InterfaceName::from_str(iface)
        .map_err(|e| HadalError::WireGuard(format!("Invalid interface name '{iface}': {e}")))?;
    let priv_key = Key::from_base64(priv_key_b64.trim())
        .map_err(|e| HadalError::WireGuard(format!("Invalid private key: {e}")))?;
    let pub_key = Key::from_base64(peer_pub_key_b64.trim())
        .map_err(|e| HadalError::WireGuard(format!("Invalid peer public key: {e}")))?;

    let mut peer = PeerConfigBuilder::new(&pub_key)
        .set_endpoint(SocketAddr::new(IpAddr::V4(endpoint_ip), endpoint_port))
        .set_persistent_keepalive_interval(25)
        .replace_allowed_ips();

    for cidr in effective_allowed_cidrs(allowed_cidrs, dns_ips) {
        let net: IpNet = cidr
            .parse()
            .map_err(|e| HadalError::WireGuard(format!("Invalid AllowedIP '{cidr}': {e}")))?;
        peer = peer.add_allowed_ip(net.addr(), net.prefix_len());
    }

    DeviceUpdate::new()
        .set_private_key(priv_key)
        .set_fwmark(WG_FWMARK)
        .replace_peers()
        .add_peer(peer)
        .apply(&iface_name, Backend::Kernel)
        .map_err(|e| {
            HadalError::WireGuard(format!("Failed to apply kernel WireGuard config: {e}"))
        })?;

    Ok(())
}

pub fn read_wg_telemetry(iface: &str) -> Option<WgTelemetry> {
    let iface_name = InterfaceName::from_str(iface).ok()?;
    let dev = Device::get(&iface_name, Backend::Kernel).ok()?;
    let mut t = WgTelemetry::default();
    for peer in dev.peers {
        t.rx_bytes = t.rx_bytes.saturating_add(peer.stats.rx_bytes);
        t.tx_bytes = t.tx_bytes.saturating_add(peer.stats.tx_bytes);
        if let Some(hs) = peer.stats.last_handshake_time {
            if let Ok(dur) = hs.duration_since(std::time::UNIX_EPOCH) {
                let secs = dur.as_secs();
                if secs > 0 {
                    t.last_handshake_epoch = Some(
                        t.last_handshake_epoch
                            .map(|prev| prev.max(secs))
                            .unwrap_or(secs),
                    );
                }
            }
        }
    }
    Some(t)
}

#[cfg(test)]
mod tests {
    #[test]
    fn effective_allowed_cidrs_defaults_to_full_tunnel_or_appends_dns() {
        let one = [std::net::Ipv4Addr::new(1, 1, 1, 1)];
        assert_eq!(super::effective_allowed_cidrs(&[], &one), vec!["0.0.0.0/0"]);
        let two = [
            std::net::Ipv4Addr::new(1, 1, 1, 1),
            std::net::Ipv4Addr::new(1, 0, 0, 1),
        ];
        assert_eq!(
            super::effective_allowed_cidrs(&["3.66.0.0/16".into()], &two),
            vec!["3.66.0.0/16", "1.1.1.1/32", "1.0.0.1/32"]
        );
    }
}
