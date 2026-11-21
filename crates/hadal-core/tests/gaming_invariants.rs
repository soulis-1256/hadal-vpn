use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::{Arc, Mutex};

use hadal_core::gaming::{
    discover_doh_ipv4s_with, discover_doh_pool_ipv4s_with, discover_wan_pmtu_with_prober,
    parse_doh_ipv4_response, pick_fastest_ipv4_with_prober, prepare_connect_target_with,
    probe_gaming_candidates_with, scan_gaming_with_deps, strip_host_port,
};
use hadal_core::{
    BoxFuture, Cluster, Coordinates, DaemonClient, DaemonRequest, DaemonResponse, DaemonStatus,
    DohTransport, EndpointCandidate, KeyPairGenerator, KeyRegistrar, NetworkProber, PingStats,
    RegisterPublicKeyResponse, Result, HadalError, TunnelState, VerifiedTunnelResult, WgKeyPair,
};

fn cluster(id: &str, location: &str, country: &str, domain: &str) -> Cluster {
    Cluster {
        id: id.into(),
        country: Some(country.into()),
        country_code: None,
        region: None,
        region_code: None,
        location: Some(location.into()),
        connection_name: Some(domain.into()),
        pub_key: Some(format!("pk-{id}")),
        tags: Vec::new(),
        load: Some(15),
        coordinates: Some(Coordinates {
            latitude: Some(50.11),
            longitude: Some(8.68),
        }),
        flag_url: None,
        cluster_type: None,
    }
}

struct FakeDoh {
    responses: HashMap<String, Vec<u8>>,
    system_addrs: HashMap<String, Vec<SocketAddrV4>>,
    queries: Mutex<Vec<String>>,
}

impl FakeDoh {
    fn new() -> Self {
        Self {
            responses: HashMap::new(),
            system_addrs: HashMap::new(),
            queries: Mutex::new(Vec::new()),
        }
    }
    fn with_json(mut self, host_substr: &str, body: &[u8]) -> Self {
        self.responses.insert(host_substr.into(), body.to_vec());
        self
    }
    fn with_system(mut self, host: &str, addrs: Vec<SocketAddrV4>) -> Self {
        self.system_addrs.insert(host.into(), addrs);
        self
    }
}

impl DohTransport for FakeDoh {
    fn get_json<'a>(&'a self, url: &'a str) -> BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move {
            self.queries.lock().unwrap().push(url.to_string());
            for (needle, body) in &self.responses {
                if url.contains(needle) {
                    return Ok(body.clone());
                }
            }
            Err(HadalError::Custom("no doh match".into()))
        })
    }

    fn resolve_system_v4(&self, host: &str, _port: u16) -> Vec<SocketAddrV4> {
        self.system_addrs.get(host).cloned().unwrap_or_default()
    }
}

struct FakeProber {
    rtts: HashMap<String, PingStats>,
    max_df_payload: u16,
    resolved: HashMap<String, Vec<Ipv4Addr>>,
    marks_seen: Mutex<Vec<Option<u32>>>,
}

impl FakeProber {
    fn new(max_df_payload: u16) -> Self {
        Self {
            rtts: HashMap::new(),
            max_df_payload,
            resolved: HashMap::new(),
            marks_seen: Mutex::new(Vec::new()),
        }
    }
    fn with_rtt(mut self, target: &str, min_ms: f64, avg_ms: f64) -> Self {
        self.rtts.insert(
            target.into(),
            PingStats {
                target: target.into(),
                min_ms,
                avg_ms,
                max_ms: avg_ms + 1.0,
                mdev_ms: 0.3,
                loss_pct: 0.0,
            },
        );
        self
    }
    fn with_resolved(mut self, host: &str, ips: Vec<Ipv4Addr>) -> Self {
        self.resolved.insert(host.into(), ips);
        self
    }
}

impl NetworkProber for FakeProber {
    fn measure_icmp(
        &self,
        target: &str,
        _count: u32,
        fwmark: Option<u32>,
        _iface: Option<&str>,
    ) -> Option<PingStats> {
        self.marks_seen.lock().unwrap().push(fwmark);
        self.rtts.get(target).cloned()
    }

    fn df_ping_ok(&self, _target: &str, payload: u16, fwmark: Option<u32>) -> bool {
        self.marks_seen.lock().unwrap().push(fwmark);
        payload <= self.max_df_payload
    }

    fn resolve_ipv4s(&self, host: &str) -> Vec<Ipv4Addr> {
        self.resolved.get(host).cloned().unwrap_or_default()
    }
}

struct FixedKeys;
impl KeyPairGenerator for FixedKeys {
    fn generate(&self) -> WgKeyPair {
        WgKeyPair {
            private_key: "priv-key".into(),
            public_key: "pub-key".into(),
        }
    }
}

struct FakeRegistrar {
    has_session: bool,
    fail_register: bool,
}

impl KeyRegistrar for FakeRegistrar {
    fn has_session(&self) -> BoxFuture<'_, bool> {
        Box::pin(async move { self.has_session })
    }
    fn register_public_key<'a>(
        &'a self,
        _pub_key: &'a str,
    ) -> BoxFuture<'a, Result<RegisterPublicKeyResponse>> {
        Box::pin(async move {
            if self.fail_register {
                return Err(HadalError::Custom("register rejected".into()));
            }
            Ok(RegisterPublicKeyResponse {
                ip: Some("10.14.0.77".into()),
                extra: serde_json::json!({}),
            })
        })
    }
}

type DaemonHandler = Box<dyn Fn(&DaemonRequest) -> Result<DaemonResponse> + Send + Sync>;

struct ScriptedDaemon {
    status: DaemonStatus,
    sent: Mutex<Vec<DaemonRequest>>,
    handler: DaemonHandler,
}

impl ScriptedDaemon {
    fn new(
        status: DaemonStatus,
        handler: impl Fn(&DaemonRequest) -> Result<DaemonResponse> + Send + Sync + 'static,
    ) -> Self {
        Self {
            status,
            sent: Mutex::new(Vec::new()),
            handler: Box::new(handler),
        }
    }
    fn sent(&self) -> Vec<DaemonRequest> {
        self.sent.lock().unwrap().clone()
    }
}

impl DaemonClient for ScriptedDaemon {
    fn send<'a>(&'a self, req: &'a DaemonRequest) -> BoxFuture<'a, Result<DaemonResponse>> {
        Box::pin(async move {
            self.sent.lock().unwrap().push(req.clone());
            if matches!(req, DaemonRequest::Status) {
                return Ok(DaemonResponse::Status(self.status.clone()));
            }
            (self.handler)(req)
        })
    }
}

#[test]
fn cluster_filtering_mtu_cidrs_and_host_port_helpers() {
    assert_eq!(strip_host_port("de-fra.prod.surfshark.com:51820"), "de-fra.prod.surfshark.com");
    assert_eq!(strip_host_port("  1.2.3.4  "), "1.2.3.4");

    assert_eq!(
        hadal_core::cidrs_from_ipv4s(&[
            Ipv4Addr::new(3, 66, 90, 1),
            Ipv4Addr::new(3, 66, 90, 25),
            Ipv4Addr::new(18, 194, 5, 8),
        ]),
        vec!["3.66.90.0/24", "18.194.5.0/24"]
    );

    assert_eq!(hadal_core::recommended_wg_mtu(1500), 1420);
    assert_eq!(hadal_core::recommended_wg_mtu(1492), 1412);
    assert_eq!(hadal_core::recommended_wg_mtu(1200), 1280);

    let (host, coords) = hadal_core::resolve_gaming_target("fortnite", "eu-de", None).unwrap();
    assert_eq!(host, "ping-de.ds.on.epicgames.com");
    assert!(coords.is_some());

    let (custom_h, _) =
        hadal_core::resolve_gaming_target("fortnite", "eu-de", Some(" 198.51.100.1 ")).unwrap();
    assert_eq!(custom_h, "198.51.100.1");
    assert!(hadal_core::resolve_gaming_target("unknown", "nope", None).is_err());

    let mut static_c = cluster(
        "de-fra-st",
        "Frankfurt",
        "Germany",
        "de-fra-st001.prod.surfshark.com",
    );
    static_c.load = Some(5);
    static_c.cluster_type = Some("static".into());
    assert!(hadal_core::is_special_cluster(&static_c));
    let mut no_coords = cluster("xx-unk", "Unknown", "Nowhere", "xx.prod.surfshark.com");
    no_coords.load = Some(10);
    no_coords.coordinates = None;
    let fra = cluster("de-fra", "Frankfurt", "Germany", "de-fra.prod.surfshark.com");
    let selected = hadal_core::gaming::select_candidate_clusters(
        &[static_c, no_coords.clone(), fra.clone()],
        Some((50.1, 8.6)),
        coords,
        2,
    );
    assert_eq!(selected.len(), 2);
    assert_eq!(selected[0].id, "de-fra");
    assert_eq!(selected[1].id, "xx-unk");

    // Cluster with empty pub_key is filtered out
    no_coords.pub_key = Some(String::new());
    let selected2 =
        hadal_core::gaming::select_candidate_clusters(&[no_coords, fra], None, coords, 5);
    assert_eq!(selected2.len(), 1);
}

#[test]
fn pmtu_binary_search_and_diversity_edge_cases() {
    let prober_1500 = FakeProber::new(1472);
    assert_eq!(discover_wan_pmtu_with_prober("1.1.1.1", None, &prober_1500), 1500);

    let prober_1492 = FakeProber::new(1464);
    assert_eq!(discover_wan_pmtu_with_prober("1.1.1.1", None, &prober_1492), 1492);

    // Non-standard MTU (e.g. LTE/tunnelled 1420 -> payload 1392)
    let prober_1420 = FakeProber::new(1392);
    assert_eq!(
        discover_wan_pmtu_with_prober("1.1.1.1", Some(0xca6d), &prober_1420),
        1420
    );
    assert!(prober_1420
        .marks_seen
        .lock()
        .unwrap()
        .iter()
        .all(|m| *m == Some(0xca6d)));

    // Diversity & finalize edge cases
    assert!(hadal_core::pick_diverse_verify_targets(&[], 5).is_empty());
    let mut one = vec![EndpointCandidate {
        cluster_id: "de-fra".into(),
        domain: "d".into(),
        endpoint_ip: "1.2.3.4".into(),
        location: "Frankfurt".into(),
        country: "DE".into(),
        load: Some(10),
        direct_rtt_ms: 10.0,
        estimated_total_ms: 12.0,
        verified_tunnel_ms: None,
        verified_mdev_ms: None,
        verified_loss_pct: None,
    }];
    assert!(hadal_core::pick_diverse_verify_targets(&one, 0).is_empty());
    hadal_core::finalize_gaming_candidates(&mut one, 0, 10);
    assert!(one.is_empty());
}

#[tokio::test]
async fn doh_discovery_and_fastest_ip_selection() {
    let parsed = parse_doh_ipv4_response(
        br#"{"Answer":[{"type":5,"data":"cname.example"},{"type":1,"data":" 138.199.19.160 "},{"type":1,"data":"bad-ip"}]}"#,
        51820,
    );
    assert_eq!(parsed, vec![SocketAddrV4::new(Ipv4Addr::new(138, 199, 19, 160), 51820)]);

    let doh = Arc::new(
        FakeDoh::new()
            .with_system("de-fra.prod.surfshark.com", vec![SocketAddrV4::new(Ipv4Addr::new(138, 199, 19, 160), 51820)])
            .with_json(
                "name=de-fra.prod.surfshark.com",
                br#"{"Answer":[{"type":1,"data":"138.199.19.160"},{"type":1,"data":"156.146.33.77"}]}"#,
            ),
    );

    let addrs = discover_doh_ipv4s_with(doh.clone(), "de-fra.prod.surfshark.com", 51820).await;
    assert_eq!(addrs.len(), 2);

    // Empty host returns empty without making DoH queries
    assert!(discover_doh_pool_ipv4s_with(doh.clone(), "   ", 51820)
        .await
        .is_empty());

    // IP literal short-circuits without hitting DoH
    let literal = discover_doh_ipv4s_with(doh.clone(), "192.0.2.5", 51820).await;
    assert_eq!(literal, vec![SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 5), 51820)]);

    let prober = Arc::new(
        FakeProber::new(1464)
            .with_rtt("138.199.19.160", 29.0, 30.0)
            .with_rtt("156.146.33.77", 14.5, 15.0),
    );
    let fastest = pick_fastest_ipv4_with_prober(
        &[
            Ipv4Addr::new(138, 199, 19, 160),
            Ipv4Addr::new(156, 146, 33, 77),
        ],
        None,
        prober.as_ref(),
    );
    assert_eq!(fastest, Some(Ipv4Addr::new(156, 146, 33, 77)));
}

#[tokio::test]
async fn prepare_connect_target_switches_between_local_and_killswitch_locked_daemon() {
    let doh = Arc::new(FakeDoh::new().with_json(
        "name=de-fra.prod.surfshark.com",
        br#"{"Answer":[{"type":1,"data":"138.199.19.160"},{"type":1,"data":"156.146.33.77"}]}"#,
    ));
    let prober = Arc::new(
        FakeProber::new(1464)
            .with_rtt("138.199.19.160", 25.0, 26.0)
            .with_rtt("156.146.33.77", 12.0, 12.5),
    );

    // Disconnected -> local DoH + fastest IP + PMTU (1492 -> WG MTU 1412)
    let disc_daemon = ScriptedDaemon::new(DaemonStatus::default(), |_| unreachable!());
    let (ip, port, mtu) = prepare_connect_target_with(
        &disc_daemon,
        doh.clone(),
        prober.clone(),
        "de-fra.prod.surfshark.com",
        true,
        None,
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!((ip.as_str(), port, mtu), ("156.146.33.77", 51820, 1412));

    // KillswitchLocked -> delegates via PrepareEndpoint and respects mtu_override
    let locked_daemon = ScriptedDaemon::new(
        DaemonStatus {
            state: TunnelState::KillswitchLocked,
            ..Default::default()
        },
        |req| match req {
            DaemonRequest::PrepareEndpoint {
                domain,
                discover_pmtu,
            } => {
                assert_eq!(domain, "de-fra.prod.surfshark.com");
                assert!(*discover_pmtu);
                Ok(DaemonResponse::Prepared {
                    endpoint_ip: "87.249.133.9".into(),
                    wan_pmtu: Some(1500),
                })
            }
            _ => unreachable!(),
        },
    );
    let (ip2, port2, mtu2) = prepare_connect_target_with(
        &locked_daemon,
        doh,
        prober,
        "de-fra.prod.surfshark.com:51820",
        true,
        Some(1380),
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!((ip2.as_str(), port2, mtu2), ("87.249.133.9", 51820, 1420));
}

#[tokio::test]
async fn gaming_tournament_two_pass_verification_and_fallback_invariants() {
    let mut vie = cluster("at-vie", "Vienna", "Austria", "at-vie.prod.surfshark.com");
    vie.load = Some(12);
    vie.coordinates = Some(Coordinates {
        latitude: Some(48.20),
        longitude: Some(16.37),
    });
    let clusters = vec![
        cluster("de-fra", "Frankfurt", "Germany", "de-fra.prod.surfshark.com"),
        vie,
    ];

    let doh = Arc::new(
        FakeDoh::new()
            .with_json(
                "name=ping-de.ds.on.epicgames.com",
                br#"{"Answer":[{"type":1,"data":"3.66.90.29"}]}"#,
            )
            .with_json(
                "name=de-fra.prod.surfshark.com",
                br#"{"Answer":[{"type":1,"data":"138.199.19.160"},{"type":1,"data":"156.146.33.77"}]}"#,
            )
            .with_json(
                "name=at-vie.prod.surfshark.com",
                br#"{"Answer":[{"type":1,"data":"87.249.133.9"}]}"#,
            ),
    );
    let prober = Arc::new(
        FakeProber::new(1472)
            .with_resolved("ping-de.ds.on.epicgames.com", vec![Ipv4Addr::new(3, 66, 90, 29)])
            .with_rtt("ping-de.ds.on.epicgames.com", 38.0, 39.0)
            .with_rtt("138.199.19.160", 19.0, 20.0)
            .with_rtt("156.146.33.77", 21.0, 21.5)
            .with_rtt("87.249.133.9", 24.0, 25.0),
    );

    // 1. Disconnected with session: Pass 1 (samples=4) + Pass 2 (samples=8) re-ranks winners!
    let daemon = ScriptedDaemon::new(DaemonStatus::default(), |req| match req {
        DaemonRequest::VerifyGamingTunnels { samples, targets, .. } => {
            if *samples == Some(4) {
                assert_eq!(targets.len(), 3);
                Ok(DaemonResponse::GamingTunnelsVerified(vec![
                    VerifiedTunnelResult {
                        cluster_id: "de-fra".into(),
                        endpoint_ip: "138.199.19.160".into(),
                        min_ms: 40.0,
                        avg_ms: 41.0,
                        mdev_ms: 4.0, // higher jitter -> 45.0 effective
                        loss_pct: 0.0,
                    },
                    VerifiedTunnelResult {
                        cluster_id: "de-fra".into(),
                        endpoint_ip: "156.146.33.77".into(),
                        min_ms: 39.5,
                        avg_ms: 40.2,
                        mdev_ms: 0.3, // lower jitter -> 40.5 effective (winner)
                        loss_pct: 0.0,
                    },
                    VerifiedTunnelResult {
                        cluster_id: "at-vie".into(),
                        endpoint_ip: "87.249.133.9".into(),
                        min_ms: 42.0,
                        avg_ms: 43.0,
                        mdev_ms: 0.5,
                        loss_pct: 50.0, // lossy
                    },
                ]))
            } else {
                assert_eq!(*samples, Some(8));
                Ok(DaemonResponse::GamingTunnelsVerified(vec![
                    VerifiedTunnelResult {
                        cluster_id: "de-fra".into(),
                        endpoint_ip: "156.146.33.77".into(),
                        min_ms: 39.0,
                        avg_ms: 39.4,
                        mdev_ms: 0.2,
                        loss_pct: 0.0,
                    },
                ]))
            }
        }
        _ => unreachable!(),
    });

    let registrar = FakeRegistrar {
        has_session: true,
        fail_register: false,
    };
    let report = scan_gaming_with_deps(
        &daemon,
        doh.clone(),
        prober.clone(),
        &FixedKeys,
        Some(&registrar),
        &clusters,
        "fortnite",
        "eu-de",
        None,
        None,
    )
    .await
    .unwrap();

    assert_eq!(report.wan_pmtu, 1500);
    assert_eq!(report.recommended_mtu, 1420);
    assert_eq!(report.game_cidrs, vec!["3.66.90.0/24"]);
    assert_eq!(report.candidates[0].endpoint_ip, "156.146.33.77");
    assert_eq!(report.candidates[0].verified_tunnel_ms, Some(39.4));
    assert_eq!(
        report.candidates.last().unwrap().endpoint_ip,
        "87.249.133.9",
        "lossy candidate must rank behind zero-loss verified endpoints"
    );
    assert_eq!(
        daemon
            .sent()
            .iter()
            .filter(|r| matches!(r, DaemonRequest::VerifyGamingTunnels { .. }))
            .count(),
        2
    );

    // 2. Fallback when Pass 1 fails -> still returns Stage 1 WAN candidates!
    let failing_reg = FakeRegistrar {
        has_session: true,
        fail_register: true,
    };
    let fallback_report = scan_gaming_with_deps(
        &daemon,
        doh.clone(),
        prober.clone(),
        &FixedKeys,
        Some(&failing_reg),
        &clusters,
        "fortnite",
        "eu-de",
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(fallback_report.candidates.len(), 3);
    assert!(fallback_report
        .candidates
        .iter()
        .all(|c| c.verified_tunnel_ms.is_none()));

    // 3. When Protected, routes WAN probes via ProbeWanGaming and records active_tunnel_ping
    let protected_daemon = ScriptedDaemon::new(
        DaemonStatus {
            state: TunnelState::Protected,
            location: Some("Vienna".into()),
            ..Default::default()
        },
        |req| match req {
            DaemonRequest::ProbeWanGaming { .. } => Ok(DaemonResponse::WanGamingProbed(
                hadal_core::WanGamingProbe {
                    baseline_direct: Some(PingStats {
                        target: "ping-de.ds.on.epicgames.com".into(),
                        min_ms: 35.0,
                        avg_ms: 36.0,
                        max_ms: 37.0,
                        mdev_ms: 0.4,
                        loss_pct: 0.0,
                    }),
                    wan_pmtu: 1492,
                    game_cidrs: vec!["3.66.90.0/24".into()],
                    endpoints: vec![hadal_core::EndpointProbeResult {
                        domain: "de-fra.prod.surfshark.com".into(),
                        endpoint_ip: "138.199.19.160".into(),
                        min_ms: 18.0,
                    }],
                },
            )),
            _ => unreachable!("VerifyGamingTunnels must NOT run while Protected"),
        },
    );
    let prot_report = scan_gaming_with_deps(
        &protected_daemon,
        doh,
        prober,
        &FixedKeys,
        Some(&registrar),
        &clusters,
        "fortnite",
        "eu-de",
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(prot_report.active_tunnel_label.as_deref(), Some("Vienna"));
    assert!(prot_report.active_tunnel_ping.is_some());
    assert_eq!(prot_report.recommended_mtu, 1412);

    // Direct probe_gaming_candidates_with smoke check
    let direct_rep = probe_gaming_candidates_with(
        &clusters,
        "fortnite",
        "eu-de",
        None,
        None,
        Arc::new(FakeDoh::new()),
        Arc::new(FakeProber::new(1464)),
    )
    .await
    .unwrap();
    assert_eq!(direct_rep.wan_pmtu, 1492);
}
