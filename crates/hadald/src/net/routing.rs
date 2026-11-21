use std::net::Ipv4Addr;

use futures_util::future::BoxFuture;
use futures_util::TryStreamExt;
use ipnet::Ipv4Net;
use rtnetlink::packet_route::rule::{RuleAction, RuleAttribute, RuleFlags};
use rtnetlink::{Handle, IpVersion, RouteMessageBuilder};

use hadal_core::{Result, HadalError, SplitMode};

use super::wireguard::WG_FWMARK;

pub const HADAL_RT_TABLE: u32 = 51839;
pub const CONTROL_FWMARK: u32 = 0xca6d;
pub const BYPASS_FWMARK: u32 = 0xca80;
pub const ONLY_VPN_FWMARK: u32 = 0xca81;

pub const PREF_CONTROL_RULE: u32 = 5182;
pub const PREF_BYPASS_RULE: u32 = 5185;
pub const PREF_LAN_SUPPRESS_RULE: u32 = 5190;
pub const PREF_DNS_RULE: u32 = 5195;
pub const PREF_TUNNEL_RULE: u32 = 5200;

/// Desired policy-routing configuration for a WireGuard tunnel session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingConfig {
    pub ifindex: u32,
    pub split_mode: SplitMode,
    pub bypass_lan: bool,
    pub game_only_cidrs: Vec<String>,
    pub dns_ips: Vec<Ipv4Addr>,
}

/// Deterministic representation of routes & IPv4 policy rules planned for `RoutingConfig`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingPlan {
    pub routes: Vec<(Ipv4Addr, u8)>,
    pub rules: Vec<PlannedRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedRule {
    pub priority: u32,
    pub table: u32,
    pub fwmark: Option<u32>,
    pub invert: bool,
    pub dest_prefix: Option<(Ipv4Addr, u8)>,
    pub suppress_prefixlen_zero: bool,
}

/// Abstraction over policy routing table/rule setup and teardown.
pub trait RoutingBackend: Send + Sync {
    fn configure_routing<'a>(&'a self, cfg: &'a RoutingConfig) -> BoxFuture<'a, Result<()>>;
    fn teardown_routing(&self) -> BoxFuture<'_, Result<()>>;
    fn add_host_route(&self, ifindex: u32, dest: Ipv4Addr) -> BoxFuture<'_, Result<()>>;
}

/// Real Linux `rtnetlink` policy routing backend.
pub struct NetlinkRouting {
    handle: Handle,
}

impl NetlinkRouting {
    pub fn new(handle: Handle) -> Self {
        Self { handle }
    }
}

impl RoutingBackend for NetlinkRouting {
    fn configure_routing<'a>(&'a self, cfg: &'a RoutingConfig) -> BoxFuture<'a, Result<()>> {
        Box::pin(configure_routing(
            &self.handle,
            cfg.ifindex,
            cfg.split_mode,
            cfg.bypass_lan,
            &cfg.game_only_cidrs,
            &cfg.dns_ips,
        ))
    }

    fn teardown_routing(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(teardown_routing(&self.handle))
    }

    fn add_host_route(&self, ifindex: u32, dest: Ipv4Addr) -> BoxFuture<'_, Result<()>> {
        Box::pin(add_host_route(&self.handle, ifindex, dest))
    }
}

/// Build the exact routes and policy rules for a tunnel configuration without performing netlink I/O.
pub fn build_routing_plan(cfg: &RoutingConfig) -> Result<RoutingPlan> {
    let mut routes = Vec::new();
    let mut rules = Vec::new();

    // Always allow hadald's CAP_NET_ADMIN control-plane probes (fwmark 0xca6d) to bypass the tunnel via main.
    rules.push(PlannedRule {
        priority: PREF_CONTROL_RULE,
        table: 254,
        fwmark: Some(CONTROL_FWMARK),
        invert: false,
        dest_prefix: None,
        suppress_prefixlen_zero: false,
    });

    if cfg.game_only_cidrs.is_empty() {
        routes.push((Ipv4Addr::UNSPECIFIED, 0));
    } else {
        for cidr in &cfg.game_only_cidrs {
            let net: Ipv4Net = cidr
                .parse()
                .map_err(|e| HadalError::WireGuard(format!("Invalid game CIDR '{cidr}': {e}")))?;
            routes.push((net.addr(), net.prefix_len()));
        }
        for dns in &cfg.dns_ips {
            routes.push((*dns, 32));
        }
    }

    if cfg.split_mode == SplitMode::OnlyVpn && cfg.game_only_cidrs.is_empty() {
        for dns in &cfg.dns_ips {
            rules.push(PlannedRule {
                priority: PREF_DNS_RULE,
                table: HADAL_RT_TABLE,
                fwmark: None,
                invert: false,
                dest_prefix: Some((*dns, 32)),
                suppress_prefixlen_zero: false,
            });
        }
        rules.push(PlannedRule {
            priority: PREF_TUNNEL_RULE,
            table: HADAL_RT_TABLE,
            fwmark: Some(ONLY_VPN_FWMARK),
            invert: false,
            dest_prefix: None,
            suppress_prefixlen_zero: false,
        });
        return Ok(RoutingPlan { routes, rules });
    }

    if cfg.split_mode == SplitMode::Bypass {
        rules.push(PlannedRule {
            priority: PREF_BYPASS_RULE,
            table: 254,
            fwmark: Some(BYPASS_FWMARK),
            invert: false,
            dest_prefix: None,
            suppress_prefixlen_zero: false,
        });
    }

    if cfg.bypass_lan && cfg.game_only_cidrs.is_empty() {
        rules.push(PlannedRule {
            priority: PREF_LAN_SUPPRESS_RULE,
            table: 254,
            fwmark: None,
            invert: false,
            dest_prefix: None,
            suppress_prefixlen_zero: true,
        });
    }

    rules.push(PlannedRule {
        priority: PREF_TUNNEL_RULE,
        table: HADAL_RT_TABLE,
        fwmark: Some(WG_FWMARK),
        invert: true,
        dest_prefix: None,
        suppress_prefixlen_zero: false,
    });

    Ok(RoutingPlan { routes, rules })
}

pub async fn add_host_route(handle: &Handle, ifindex: u32, dest: Ipv4Addr) -> Result<()> {
    let route = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(dest, 32)
        .output_interface(ifindex)
        .table_id(254)
        .build();
    handle
        .route()
        .add(route)
        .replace()
        .execute()
        .await
        .map_err(|e| HadalError::WireGuard(format!("Failed to add probe route {dest}/32: {e}")))
}

pub async fn configure_routing(
    handle: &Handle,
    ifindex: u32,
    split_mode: SplitMode,
    bypass_lan: bool,
    game_only_cidrs: &[String],
    dns_ips: &[Ipv4Addr],
) -> Result<()> {
    let plan = build_routing_plan(&RoutingConfig {
        ifindex,
        split_mode,
        bypass_lan,
        game_only_cidrs: game_only_cidrs.to_vec(),
        dns_ips: dns_ips.to_vec(),
    })?;

    // Clean any prior hadald routing rules/routes only after plan validation succeeds
    teardown_routing(handle).await?;
    ensure_src_valid_mark();

    for (addr, prefix_len) in plan.routes {
        let route = RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(addr, prefix_len)
            .output_interface(ifindex)
            .table_id(HADAL_RT_TABLE)
            .build();
        handle
            .route()
            .add(route)
            .replace()
            .execute()
            .await
            .map_err(|e| {
                HadalError::WireGuard(format!("Failed to add VPN route {addr}/{prefix_len}: {e}"))
            })?;
    }

    for planned in plan.rules {
        let mut req = handle
            .rule()
            .add()
            .v4()
            .action(RuleAction::ToTable)
            .table_id(planned.table)
            .priority(planned.priority);
        if let Some(mark) = planned.fwmark {
            req = req.fw_mark(mark);
        }
        if let Some((addr, prefix)) = planned.dest_prefix {
            req = req.destination_prefix(addr, prefix);
        }
        if planned.suppress_prefixlen_zero {
            req.message_mut()
                .attributes
                .push(RuleAttribute::SuppressPrefixLen(0));
        }
        if planned.invert {
            req.message_mut().header.flags.insert(RuleFlags::Invert);
        }
        req.execute().await.map_err(|e| {
            HadalError::WireGuard(format!(
                "Failed to add ip rule priority {}: {e}",
                planned.priority
            ))
        })?;
    }

    Ok(())
}

pub async fn teardown_routing(handle: &Handle) -> Result<()> {
    // Delete any IPv4 rules belonging to our priority band (PREF_CONTROL_RULE..=PREF_TUNNEL_RULE) or referencing HADAL_RT_TABLE
    let mut rules = handle.rule().get(IpVersion::V4).execute();
    let mut to_del = Vec::new();
    while let Some(rule) = rules
        .try_next()
        .await
        .map_err(|e| HadalError::WireGuard(format!("Failed listing ip rules: {e}")))?
    {
        let is_ours = rule.attributes.iter().any(|attr| {
            use rtnetlink::packet_route::rule::RuleAttribute;
            match attr {
                RuleAttribute::Priority(p) => (PREF_CONTROL_RULE..=PREF_TUNNEL_RULE).contains(p),
                RuleAttribute::Table(t) => *t == HADAL_RT_TABLE,
                _ => false,
            }
        });
        if is_ours {
            to_del.push(rule);
        }
    }

    for rule in to_del {
        let _ = handle.rule().del(rule).execute().await;
    }

    // Flush table 51839 routes
    let mut routes = handle
        .route()
        .get(
            RouteMessageBuilder::<Ipv4Addr>::new()
                .table_id(HADAL_RT_TABLE)
                .build(),
        )
        .execute();
    let mut del_routes = Vec::new();
    while let Ok(Some(route)) = routes.try_next().await {
        if route.header.table == HADAL_RT_TABLE as u8
            || route.attributes.iter().any(|a| {
                use rtnetlink::packet_route::route::RouteAttribute;
                matches!(a, RouteAttribute::Table(t) if *t == HADAL_RT_TABLE)
            })
        {
            del_routes.push(route);
        }
    }
    for r in del_routes {
        let _ = handle.route().del(r).execute().await;
    }

    Ok(())
}

fn ensure_src_valid_mark() {
    // Allow incoming WireGuard & split-tunnel return packets marked in prerouting to pass strict rp_filter=1
    const PATH: &str = "/proc/sys/net/ipv4/conf/all/src_valid_mark";
    if std::fs::read_to_string(PATH).ok().as_deref().map(str::trim) != Some("1") {
        let _ = std::fs::write(PATH, b"1\n");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bypass_plan_orders_control_bypass_lan_and_tunnel_before_main() {
        const RT_RULE_PREF_MAIN: u32 = 32766;
        let plan = build_routing_plan(&RoutingConfig {
            ifindex: 7,
            split_mode: SplitMode::Bypass,
            bypass_lan: true,
            game_only_cidrs: vec![],
            dns_ips: vec![Ipv4Addr::new(1, 1, 1, 1)],
        })
        .unwrap();

        assert_eq!(plan.routes, vec![(Ipv4Addr::UNSPECIFIED, 0)]);
        let priorities: Vec<u32> = plan.rules.iter().map(|r| r.priority).collect();
        assert_eq!(
            priorities,
            vec![
                PREF_CONTROL_RULE,
                PREF_BYPASS_RULE,
                PREF_LAN_SUPPRESS_RULE,
                PREF_TUNNEL_RULE
            ]
        );
        assert!(priorities.windows(2).all(|w| w[0] < w[1]));
        assert!(*priorities.last().unwrap() < RT_RULE_PREF_MAIN);
        assert!(plan.rules.last().unwrap().invert);
    }

    #[test]
    fn only_vpn_plan_routes_only_dns_and_marked_apps_via_vpn() {
        let plan = build_routing_plan(&RoutingConfig {
            ifindex: 7,
            split_mode: SplitMode::OnlyVpn,
            bypass_lan: true,
            game_only_cidrs: vec![],
            dns_ips: vec![Ipv4Addr::new(1, 1, 1, 1)],
        })
        .unwrap();

        assert_eq!(plan.rules.len(), 3);
        assert_eq!(plan.rules[1].priority, PREF_DNS_RULE);
        assert_eq!(plan.rules[1].dest_prefix, Some((Ipv4Addr::new(1, 1, 1, 1), 32)));
        assert_eq!(plan.rules[2].priority, PREF_TUNNEL_RULE);
        assert_eq!(plan.rules[2].fwmark, Some(ONLY_VPN_FWMARK));
        assert!(!plan.rules[2].invert);
    }

    #[test]
    fn game_only_plan_populates_game_cidrs_and_rejects_bad_cidr() {
        let plan = build_routing_plan(&RoutingConfig {
            ifindex: 7,
            split_mode: SplitMode::Off,
            bypass_lan: false,
            game_only_cidrs: vec!["3.66.0.0/16".into()],
            dns_ips: vec![Ipv4Addr::new(1, 1, 1, 1)],
        })
        .unwrap();
        assert_eq!(
            plan.routes,
            vec![(Ipv4Addr::new(3, 66, 0, 0), 16), (Ipv4Addr::new(1, 1, 1, 1), 32)]
        );

        let err = build_routing_plan(&RoutingConfig {
            ifindex: 7,
            split_mode: SplitMode::Off,
            bypass_lan: false,
            game_only_cidrs: vec!["not-a-cidr".into()],
            dns_ips: vec![],
        })
        .unwrap_err();
        assert!(err.to_string().contains("Invalid game CIDR"));
    }
}
