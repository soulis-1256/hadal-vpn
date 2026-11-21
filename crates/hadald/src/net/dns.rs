use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use clap::ValueEnum;
use futures_util::future::BoxFuture;
use hadal_core::{Result, HadalError};
use zbus::{proxy, Connection};

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum DnsMode {
    Auto,
    Resolved,
    ResolvConf,
}

/// Abstraction over DNS configuration and teardown for tunnel lifecycle.
pub trait DnsBackend: Send + Sync {
    fn apply_dns<'a>(&'a self, ifindex: u32, servers: &'a [Ipv4Addr]) -> BoxFuture<'a, Result<()>>;
    fn revert_dns(&self, ifindex: Option<u32>) -> BoxFuture<'_, Result<()>>;
}

/// Abstraction over `org.freedesktop.resolve1.Manager` D-Bus calls for deterministic testing.
pub trait Resolve1Client: Send + Sync {
    fn is_available(&self) -> BoxFuture<'_, bool>;
    fn set_link_dns<'a>(
        &'a self,
        ifindex: i32,
        addresses: Vec<(i32, Vec<u8>)>,
    ) -> BoxFuture<'a, std::result::Result<(), String>>;
    fn set_link_dns_ex<'a>(
        &'a self,
        ifindex: i32,
        addresses: Vec<(i32, Vec<u8>, u16, &'static str)>,
    ) -> BoxFuture<'a, std::result::Result<(), String>>;
    fn set_link_domains<'a>(
        &'a self,
        ifindex: i32,
        domains: Vec<(&'a str, bool)>,
    ) -> BoxFuture<'a, std::result::Result<(), String>>;
    fn set_link_default_route(
        &self,
        ifindex: i32,
        enable: bool,
    ) -> BoxFuture<'_, std::result::Result<(), String>>;
    fn set_link_dns_over_tls<'a>(
        &'a self,
        ifindex: i32,
        mode: &'a str,
    ) -> BoxFuture<'a, std::result::Result<(), String>>;
    fn revert_link(&self, ifindex: i32) -> BoxFuture<'_, std::result::Result<(), String>>;
    fn flush_caches(&self) -> BoxFuture<'_, std::result::Result<(), String>>;
}

#[proxy(
    interface = "org.freedesktop.resolve1.Manager",
    default_service = "org.freedesktop.resolve1",
    default_path = "/org/freedesktop/resolve1"
)]
trait Resolve1Manager {
    #[zbus(name = "SetLinkDNS")]
    fn set_link_dns(&self, ifindex: i32, addresses: Vec<(i32, Vec<u8>)>) -> zbus::Result<()>;
    #[zbus(name = "SetLinkDNSEx")]
    fn set_link_dns_ex(
        &self,
        ifindex: i32,
        addresses: Vec<(i32, Vec<u8>, u16, &str)>,
    ) -> zbus::Result<()>;
    #[zbus(name = "SetLinkDomains")]
    fn set_link_domains(&self, ifindex: i32, domains: Vec<(&str, bool)>) -> zbus::Result<()>;
    #[zbus(name = "SetLinkDefaultRoute")]
    fn set_link_default_route(&self, ifindex: i32, enable: bool) -> zbus::Result<()>;
    #[zbus(name = "SetLinkDNSOverTLS")]
    fn set_link_dns_over_tls(&self, ifindex: i32, mode: &str) -> zbus::Result<()>;
    #[zbus(name = "RevertLink")]
    fn revert_link(&self, ifindex: i32) -> zbus::Result<()>;
    #[zbus(name = "FlushCaches")]
    fn flush_caches(&self) -> zbus::Result<()>;
}

pub struct SystemdResolvedClient;

impl SystemdResolvedClient {
    async fn proxy() -> std::result::Result<Resolve1ManagerProxy<'static>, String> {
        let conn = Connection::system()
            .await
            .map_err(|e| format!("D-Bus system connection failed: {e}"))?;
        Resolve1ManagerProxy::new(&conn)
            .await
            .map_err(|e| format!("systemd-resolved proxy error: {e}"))
    }
}

impl Resolve1Client for SystemdResolvedClient {
    fn is_available(&self) -> BoxFuture<'_, bool> {
        Box::pin(async {
            let Ok(conn) = Connection::system().await else {
                return false;
            };
            let Ok(reply) = conn
                .call_method(
                    Some("org.freedesktop.DBus"),
                    "/org/freedesktop/DBus",
                    Some("org.freedesktop.DBus"),
                    "NameHasOwner",
                    &("org.freedesktop.resolve1",),
                )
                .await
            else {
                return false;
            };
            matches!(reply.body().deserialize::<bool>(), Ok(true))
        })
    }

    fn set_link_dns<'a>(
        &'a self,
        ifindex: i32,
        addresses: Vec<(i32, Vec<u8>)>,
    ) -> BoxFuture<'a, std::result::Result<(), String>> {
        Box::pin(async move {
            let proxy = Self::proxy().await?;
            proxy
                .set_link_dns(ifindex, addresses)
                .await
                .map_err(|e| e.to_string())
        })
    }

    fn set_link_dns_ex<'a>(
        &'a self,
        ifindex: i32,
        addresses: Vec<(i32, Vec<u8>, u16, &'static str)>,
    ) -> BoxFuture<'a, std::result::Result<(), String>> {
        Box::pin(async move {
            let proxy = Self::proxy().await?;
            proxy
                .set_link_dns_ex(ifindex, addresses)
                .await
                .map_err(|e| e.to_string())
        })
    }

    fn set_link_domains<'a>(
        &'a self,
        ifindex: i32,
        domains: Vec<(&'a str, bool)>,
    ) -> BoxFuture<'a, std::result::Result<(), String>> {
        Box::pin(async move {
            let proxy = Self::proxy().await?;
            proxy
                .set_link_domains(ifindex, domains)
                .await
                .map_err(|e| e.to_string())
        })
    }

    fn set_link_default_route(
        &self,
        ifindex: i32,
        enable: bool,
    ) -> BoxFuture<'_, std::result::Result<(), String>> {
        Box::pin(async move {
            let proxy = Self::proxy().await?;
            proxy
                .set_link_default_route(ifindex, enable)
                .await
                .map_err(|e| e.to_string())
        })
    }

    fn set_link_dns_over_tls<'a>(
        &'a self,
        ifindex: i32,
        mode: &'a str,
    ) -> BoxFuture<'a, std::result::Result<(), String>> {
        Box::pin(async move {
            let proxy = Self::proxy().await?;
            proxy
                .set_link_dns_over_tls(ifindex, mode)
                .await
                .map_err(|e| e.to_string())
        })
    }

    fn revert_link(&self, ifindex: i32) -> BoxFuture<'_, std::result::Result<(), String>> {
        Box::pin(async move {
            let proxy = Self::proxy().await?;
            proxy.revert_link(ifindex).await.map_err(|e| e.to_string())
        })
    }

    fn flush_caches(&self) -> BoxFuture<'_, std::result::Result<(), String>> {
        Box::pin(async move {
            let proxy = Self::proxy().await?;
            proxy.flush_caches().await.map_err(|e| e.to_string())
        })
    }
}

/// Verified DNS-over-TLS SNI hostnames for known public resolvers so plaintext UDP/TCP port-53
/// proxies inside exit nodes cannot rewrite queries into tunnel-only proxy IPs.
pub fn dot_sni_for_ip(ip: Ipv4Addr) -> Option<&'static str> {
    match ip.octets() {
        [1, 1, 1, 1] | [1, 0, 0, 1] => Some("cloudflare-dns.com"),
        [9, 9, 9, 9] | [149, 112, 112, 112] => Some("dns.quad9.net"),
        [8, 8, 8, 8] | [8, 8, 4, 4] => Some("dns.google"),
        _ => None,
    }
}

fn is_transient_link_err(msg: &str) -> bool {
    msg.contains("NoSuchLink")
        || msg.contains("unknown link")
        || (msg.contains("Link") && msg.contains("not known"))
}

pub struct DnsManager {
    mode: DnsMode,
    resolv_conf_path: PathBuf,
    backup_path: PathBuf,
    resolved: Arc<dyn Resolve1Client>,
    retry_delay: Duration,
}

impl DnsManager {
    pub fn new(mode: DnsMode, resolv_conf_path: PathBuf, state_dir: &Path) -> Self {
        Self::with_resolved_client(
            mode,
            resolv_conf_path,
            state_dir,
            Arc::new(SystemdResolvedClient),
        )
    }

    pub fn with_resolved_client(
        mode: DnsMode,
        resolv_conf_path: PathBuf,
        state_dir: &Path,
        resolved: Arc<dyn Resolve1Client>,
    ) -> Self {
        Self {
            mode,
            resolv_conf_path,
            backup_path: state_dir.join("resolv.conf.backup"),
            resolved,
            retry_delay: Duration::from_millis(50),
        }
    }

    #[cfg(test)]
    fn with_retry_delay(mut self, delay: Duration) -> Self {
        self.retry_delay = delay;
        self
    }

    pub async fn apply_dns(&self, ifindex: u32, servers: &[Ipv4Addr]) -> Result<()> {
        if servers.is_empty() {
            return Ok(());
        }
        match self.effective_mode().await {
            DnsMode::Resolved => {
                let dot_snis: Option<Vec<&'static str>> =
                    servers.iter().map(|&ip| dot_sni_for_ip(ip)).collect();

                // Netlink RTM_NEWLINK may race systemd-resolved indexing the fresh WG interface by a few ms.
                let mut last_err = None;
                for attempt in 0..4 {
                    let res = match &dot_snis {
                        Some(snis) => {
                            let ex_addrs: Vec<(i32, Vec<u8>, u16, &'static str)> = servers
                                .iter()
                                .zip(snis.iter())
                                .map(|(ip, sni)| (libc::AF_INET, ip.octets().to_vec(), 0u16, *sni))
                                .collect();
                            self.resolved.set_link_dns_ex(ifindex as i32, ex_addrs).await
                        }
                        None => {
                            let addrs: Vec<(i32, Vec<u8>)> = servers
                                .iter()
                                .map(|ip| (libc::AF_INET, ip.octets().to_vec()))
                                .collect();
                            self.resolved.set_link_dns(ifindex as i32, addrs).await
                        }
                    };
                    match res {
                        Ok(()) => {
                            last_err = None;
                            break;
                        }
                        Err(e) => {
                            let transient_link = is_transient_link_err(&e);
                            last_err = Some(e);
                            if transient_link && attempt < 3 {
                                tokio::time::sleep(self.retry_delay).await;
                                continue;
                            }
                            break;
                        }
                    }
                }
                if let Some(e) = last_err {
                    return Err(HadalError::WireGuard(format!("SetLinkDNS failed: {e}")));
                }

                // D-Bus SetLinkDomains takes (domain, routing_only=true); "." with routing_only=true becomes "~.".
                self.resolved
                    .set_link_domains(ifindex as i32, vec![(".", true)])
                    .await
                    .map_err(|e| HadalError::WireGuard(format!("SetLinkDomains failed: {e}")))?;
                self.resolved
                    .set_link_default_route(ifindex as i32, true)
                    .await
                    .map_err(|e| {
                        HadalError::WireGuard(format!("SetLinkDefaultRoute failed: {e}"))
                    })?;
                self.resolved
                    .set_link_dns_over_tls(
                        ifindex as i32,
                        if dot_snis.is_some() { "yes" } else { "no" },
                    )
                    .await
                    .map_err(|e| {
                        HadalError::WireGuard(format!("SetLinkDNSOverTLS failed: {e}"))
                    })?;
                let _ = self.resolved.flush_caches().await;
                Ok(())
            }
            DnsMode::ResolvConf | DnsMode::Auto => {
                if self.resolv_conf_path.exists() && !self.backup_path.exists() {
                    if let Some(parent) = self.backup_path.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    let _ = std::fs::copy(&self.resolv_conf_path, &self.backup_path);
                }
                if let Some(parent) = self.resolv_conf_path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let mut content = String::from("# Generated by hadald\n");
                for ip in servers {
                    content.push_str(&format!("nameserver {ip}\n"));
                }
                std::fs::write(&self.resolv_conf_path, content)?;
                Ok(())
            }
        }
    }

    pub async fn revert_dns(&self, ifindex: Option<u32>) -> Result<()> {
        match self.effective_mode().await {
            DnsMode::Resolved => {
                if let Some(idx) = ifindex {
                    let _ = self.resolved.revert_link(idx as i32).await;
                    let _ = self.resolved.flush_caches().await;
                }
                Ok(())
            }
            DnsMode::ResolvConf | DnsMode::Auto => {
                if self.backup_path.exists() {
                    let _ = std::fs::copy(&self.backup_path, &self.resolv_conf_path);
                    let _ = std::fs::remove_file(&self.backup_path);
                }
                Ok(())
            }
        }
    }

    async fn effective_mode(&self) -> DnsMode {
        match self.mode {
            DnsMode::Resolved => DnsMode::Resolved,
            DnsMode::ResolvConf => DnsMode::ResolvConf,
            DnsMode::Auto => {
                if self.resolved.is_available().await {
                    DnsMode::Resolved
                } else {
                    DnsMode::ResolvConf
                }
            }
        }
    }
}

impl DnsBackend for DnsManager {
    fn apply_dns<'a>(&'a self, ifindex: u32, servers: &'a [Ipv4Addr]) -> BoxFuture<'a, Result<()>> {
        Box::pin(self.apply_dns(ifindex, servers))
    }

    fn revert_dns(&self, ifindex: Option<u32>) -> BoxFuture<'_, Result<()>> {
        Box::pin(self.revert_dns(ifindex))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    type ExDnsAddr = (i32, Vec<u8>, u16, &'static str);
    type ExCall = (i32, Vec<ExDnsAddr>);
    type PlainCall = (i32, Vec<(i32, Vec<u8>)>);
    type DomainCall = (i32, Vec<(String, bool)>);

    #[derive(Default)]
    struct MockResolve1 {
        available: bool,
        transient_failures: AtomicUsize,
        ex_calls: Mutex<Vec<ExCall>>,
        plain_calls: Mutex<Vec<PlainCall>>,
        domains: Mutex<Vec<DomainCall>>,
        dot_modes: Mutex<Vec<(i32, String)>>,
        reverted: Mutex<Vec<i32>>,
        flushed: AtomicUsize,
    }

    impl Resolve1Client for MockResolve1 {
        fn is_available(&self) -> BoxFuture<'_, bool> {
            Box::pin(async { self.available })
        }

        fn set_link_dns<'a>(
            &'a self,
            ifindex: i32,
            addresses: Vec<(i32, Vec<u8>)>,
        ) -> BoxFuture<'a, std::result::Result<(), String>> {
            Box::pin(async move {
                self.plain_calls.lock().unwrap().push((ifindex, addresses));
                Ok(())
            })
        }

        fn set_link_dns_ex<'a>(
            &'a self,
            ifindex: i32,
            addresses: Vec<(i32, Vec<u8>, u16, &'static str)>,
        ) -> BoxFuture<'a, std::result::Result<(), String>> {
            Box::pin(async move {
                let rem = self.transient_failures.load(Ordering::SeqCst);
                if rem > 0 {
                    self.transient_failures.fetch_sub(1, Ordering::SeqCst);
                    return Err("org.freedesktop.resolve1.NoSuchLink: Link 9 not known".into());
                }
                self.ex_calls.lock().unwrap().push((ifindex, addresses));
                Ok(())
            })
        }

        fn set_link_domains<'a>(
            &'a self,
            ifindex: i32,
            domains: Vec<(&'a str, bool)>,
        ) -> BoxFuture<'a, std::result::Result<(), String>> {
            Box::pin(async move {
                self.domains.lock().unwrap().push((
                    ifindex,
                    domains.into_iter().map(|(d, r)| (d.to_string(), r)).collect(),
                ));
                Ok(())
            })
        }

        fn set_link_default_route(
            &self,
            _ifindex: i32,
            _enable: bool,
        ) -> BoxFuture<'_, std::result::Result<(), String>> {
            Box::pin(async { Ok(()) })
        }

        fn set_link_dns_over_tls<'a>(
            &'a self,
            ifindex: i32,
            mode: &'a str,
        ) -> BoxFuture<'a, std::result::Result<(), String>> {
            Box::pin(async move {
                self.dot_modes.lock().unwrap().push((ifindex, mode.to_string()));
                Ok(())
            })
        }

        fn revert_link(&self, ifindex: i32) -> BoxFuture<'_, std::result::Result<(), String>> {
            Box::pin(async move {
                self.reverted.lock().unwrap().push(ifindex);
                Ok(())
            })
        }

        fn flush_caches(&self) -> BoxFuture<'_, std::result::Result<(), String>> {
            Box::pin(async {
                self.flushed.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        }
    }

    #[tokio::test]
    async fn resolved_applies_dot_sni_retries_transient_no_such_link_and_reverts() {
        let mock = Arc::new(MockResolve1 {
            available: true,
            transient_failures: AtomicUsize::new(2),
            ..Default::default()
        });
        let tmp = std::env::temp_dir().join(format!("hadald-dns-test-{}", std::process::id()));
        let mgr = DnsManager::with_resolved_client(
            DnsMode::Auto,
            tmp.join("resolv.conf"),
            &tmp,
            mock.clone(),
        )
        .with_retry_delay(Duration::from_millis(1));

        mgr.apply_dns(9, &[Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(1, 0, 0, 1)])
            .await
            .unwrap();

        {
            let ex = mock.ex_calls.lock().unwrap();
            assert_eq!(ex.len(), 1);
            assert_eq!(ex[0].0, 9);
            assert_eq!(ex[0].1[0].3, "cloudflare-dns.com");
        }
        assert_eq!(mock.domains.lock().unwrap()[0].1, vec![(".".to_string(), true)]);
        assert_eq!(mock.dot_modes.lock().unwrap()[0], (9, "yes".to_string()));

        mgr.revert_dns(Some(9)).await.unwrap();
        assert_eq!(*mock.reverted.lock().unwrap(), vec![9]);
        assert_eq!(mock.flushed.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn resolved_falls_back_to_plain_dns_when_resolver_has_no_known_sni() {
        let mock = Arc::new(MockResolve1 {
            available: false,
            ..Default::default()
        });
        let tmp = std::env::temp_dir().join(format!("hadald-dns-plain-{}", std::process::id()));
        let mgr = DnsManager::with_resolved_client(
            DnsMode::Resolved,
            tmp.join("resolv.conf"),
            &tmp,
            mock.clone(),
        );

        mgr.apply_dns(4, &[Ipv4Addr::new(10, 64, 0, 1)])
            .await
            .unwrap();
        assert_eq!(mock.plain_calls.lock().unwrap().len(), 1);
        assert_eq!(mock.dot_modes.lock().unwrap()[0], (4, "no".to_string()));
    }

    #[tokio::test]
    async fn resolv_conf_backs_up_writes_and_restores_original_file() {
        let dir = std::env::temp_dir().join(format!("hadald-resolv-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let resolv = dir.join("resolv.conf");
        std::fs::write(&resolv, "nameserver 192.168.1.1\n").unwrap();

        let mock = Arc::new(MockResolve1::default());
        let mgr = DnsManager::with_resolved_client(DnsMode::ResolvConf, resolv.clone(), &dir, mock);
        mgr.apply_dns(1, &[Ipv4Addr::new(1, 1, 1, 1)]).await.unwrap();
        assert_eq!(
            std::fs::read_to_string(&resolv).unwrap(),
            "# Generated by hadald\nnameserver 1.1.1.1\n"
        );

        mgr.revert_dns(Some(1)).await.unwrap();
        assert_eq!(
            std::fs::read_to_string(&resolv).unwrap(),
            "nameserver 192.168.1.1\n"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
