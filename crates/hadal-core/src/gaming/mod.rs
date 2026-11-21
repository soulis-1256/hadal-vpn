pub mod doh;
pub mod probe;
pub mod selection;
pub mod tournament;
pub mod traits;
pub mod types;

pub use doh::{
    discover_doh_ipv4s, discover_doh_ipv4s_with, discover_doh_ipv4s_with_http,
    discover_doh_pool_ipv4s_with, discover_doh_pool_ipv4s_with_http, parse_doh_ipv4_response,
    pooled_doh_urls, resolve_fastest_endpoint_ip, resolve_fastest_endpoint_ip_with,
    standard_doh_urls, ReqwestDohTransport, MAX_PROBED_IPS_PER_CLUSTER,
};
pub use probe::{
    discover_wan_pmtu, discover_wan_pmtu_with_mark, discover_wan_pmtu_with_prober,
    measure_icmp_stats, measure_icmp_stats_on_iface, measure_icmp_stats_with_mark,
    parse_ping_output, pick_fastest_ipv4_with_mark, pick_fastest_ipv4_with_prober,
    probe_gaming_candidates, probe_gaming_candidates_with, resolve_game_cidrs,
    resolve_game_cidrs_with_prober, SystemNetworkProber,
};
pub use selection::{
    finalize_gaming_candidates, pick_diverse_verify_targets, select_candidate_clusters,
    sort_gaming_candidates,
};
pub use tournament::{
    apply_verified_results, build_verify_targets, prepare_connect_target,
    prepare_connect_target_with, scan_gaming_with_daemon, scan_gaming_with_deps,
    verify_top_candidates_with,
};
pub use traits::{DohTransport, NetworkProber};
pub use types::{
    build_endpoint_candidate, builtin_games, cidrs_from_ipv4s, estimate_fiber_rtt_ms,
    find_game_region, haversine_km, is_special_cluster, is_virtual_cluster, recommended_wg_mtu,
    resolve_gaming_target, strip_host_port, EndpointCandidate, GameProfile, GameRegion,
    GamingScanReport, PingStats,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::servers::{Cluster, Coordinates};

    #[test]
    fn parses_linux_ping_output() {
        let sample = "\
PING ping-de.ds.on.epicgames.com (3.66.90.29) 56(84) bytes of data.
64 bytes from ec2-3-66-90-29.eu-central-1.compute.amazonaws.com (3.66.90.29): icmp_seq=1 ttl=56 time=39.2 ms

--- ping-de.ds.on.epicgames.com ping statistics ---
5 packets transmitted, 5 received, 0% packet loss, time 804ms
rtt min/avg/max/mdev = 38.895/39.552/40.119/0.400 ms
";
        let stats = parse_ping_output("ping-de.ds.on.epicgames.com", sample).unwrap();
        assert!((stats.min_ms - 38.895).abs() < 0.001);
        assert!((stats.avg_ms - 39.552).abs() < 0.001);
        assert!((stats.mdev_ms - 0.400).abs() < 0.001);
        assert!((stats.loss_pct - 0.0).abs() < 0.001);
    }

    #[test]
    fn mtu_math_fits_pppoe_and_ethernet() {
        assert_eq!(recommended_wg_mtu(1492), 1412);
        assert_eq!(recommended_wg_mtu(1500), 1420);
        assert_eq!(recommended_wg_mtu(1300), 1280);
    }

    #[test]
    fn builtin_games_registry_has_verified_regions() {
        let games = builtin_games();
        assert!(games.len() >= 6);
        assert_eq!(
            find_game_region("fortnite", "eu-de").unwrap().ping_host,
            "ping-de.ds.on.epicgames.com"
        );
        assert_eq!(
            find_game_region("apex", "eu-central-1").unwrap().ping_host,
            "dynamodb.eu-central-1.amazonaws.com"
        );
        assert_eq!(
            find_game_region("ffxiv", "eu-chaos").unwrap().ping_host,
            "neolobby06.ffxiv.com"
        );
        assert_eq!(
            find_game_region("wot", "eu1").unwrap().ping_host,
            "login.p1.worldoftanks.eu"
        );
        for g in &games {
            assert!(!g.regions.is_empty(), "game {} has no regions", g.id);
            for r in &g.regions {
                assert!(!r.ping_host.is_empty());
                assert!(find_game_region(&g.id, &r.id).is_some());
            }
        }
    }

    #[test]
    fn excludes_virtual_clusters_and_uses_realistic_fiber_rtt() {
        let vaduz = Cluster {
            id: "li-qvu".into(),
            country: Some("Liechtenstein".into()),
            country_code: Some("LI".into()),
            region: None,
            region_code: None,
            location: Some("Vaduz".into()),
            connection_name: Some("li-qvu.prod.surfshark.com".into()),
            pub_key: Some("pubkey-li".into()),
            load: Some(4),
            tags: vec!["virtual".into(), "p2p".into()],
            flag_url: None,
            cluster_type: Some("virtual".into()),
            coordinates: Some(Coordinates {
                latitude: Some(47.14),
                longitude: Some(9.52),
            }),
        };
        let vienna = Cluster {
            id: "at-vie".into(),
            country: Some("Austria".into()),
            country_code: Some("AT".into()),
            region: None,
            region_code: None,
            location: Some("Vienna".into()),
            connection_name: Some("at-vie.prod.surfshark.com".into()),
            pub_key: Some("pubkey-at".into()),
            load: Some(13),
            tags: vec!["p2p".into()],
            flag_url: None,
            cluster_type: None,
            coordinates: Some(Coordinates {
                latitude: Some(48.2085),
                longitude: Some(16.3721),
            }),
        };
        assert!(is_virtual_cluster(&vaduz));
        assert!(!is_virtual_cluster(&vienna));

        let target = find_game_region("fortnite", "eu-de").unwrap();
        let picked = select_candidate_clusters(
            &[vaduz, vienna],
            None,
            Some((target.latitude, target.longitude)),
            10,
        );
        assert_eq!(picked.len(), 1);
        assert_eq!(picked[0].id, "at-vie");

        let est = estimate_fiber_rtt_ms(48.2085, 16.3721, target.latitude, target.longitude);
        assert!(
            est > 11.0 && est < 13.5,
            "unexpected Vienna->Frankfurt est {est}"
        );

        let mut cands = vec![
            EndpointCandidate {
                cluster_id: "at-vie".into(),
                domain: "at-vie.prod.surfshark.com".into(),
                endpoint_ip: "87.249.133.9".into(),
                location: "Vienna".into(),
                country: "Austria".into(),
                load: Some(12),
                direct_rtt_ms: 28.2,
                estimated_total_ms: 40.5,
                verified_tunnel_ms: Some(41.4),
                verified_mdev_ms: Some(0.2),
                verified_loss_pct: Some(0.0),
            },
            EndpointCandidate {
                cluster_id: "de-fra".into(),
                domain: "de-fra.prod.surfshark.com".into(),
                endpoint_ip: "138.199.19.159".into(),
                location: "Frankfurt".into(),
                country: "Germany".into(),
                load: Some(18),
                direct_rtt_ms: 39.0,
                estimated_total_ms: 39.8,
                verified_tunnel_ms: Some(39.9),
                verified_mdev_ms: Some(0.3),
                verified_loss_pct: Some(0.0),
            },
            EndpointCandidate {
                cluster_id: "it-mil".into(),
                domain: "it-mil.prod.surfshark.com".into(),
                endpoint_ip: "84.17.58.192".into(),
                location: "Milan".into(),
                country: "Italy".into(),
                load: Some(13),
                direct_rtt_ms: 30.2,
                estimated_total_ms: 40.9,
                verified_tunnel_ms: None,
                verified_mdev_ms: None,
                verified_loss_pct: None,
            },
        ];
        sort_gaming_candidates(&mut cands);
        assert_eq!(cands[0].cluster_id, "de-fra");
        assert_eq!(cands[1].cluster_id, "at-vie");
        assert_eq!(cands[2].cluster_id, "it-mil");
        assert_eq!(pick_diverse_verify_targets(&cands, 2).len(), 2);
    }

    fn make_cand(
        cluster: &str,
        ip: &str,
        est: f64,
        ver_avg: Option<f64>,
        ver_mdev: Option<f64>,
        loss: Option<f64>,
    ) -> EndpointCandidate {
        EndpointCandidate {
            cluster_id: cluster.into(),
            domain: format!("{cluster}.prod.surfshark.com"),
            endpoint_ip: ip.into(),
            location: cluster.into(),
            country: "Test".into(),
            load: Some(10),
            direct_rtt_ms: est - 1.0,
            estimated_total_ms: est,
            verified_tunnel_ms: ver_avg,
            verified_mdev_ms: ver_mdev,
            verified_loss_pct: loss,
        }
    }

    #[test]
    fn picks_distinct_slash16_providers_and_penalizes_loss_and_jitter() {
        let cands = vec![
            make_cand("de-fra", "138.199.19.160", 39.4, None, None, None),
            make_cand("de-fra", "138.199.19.162", 39.5, None, None, None),
            make_cand("de-fra", "138.199.19.164", 39.6, None, None, None),
            make_cand("de-fra", "156.146.33.77", 39.7, None, None, None),
            make_cand("at-vie", "87.249.133.9", 40.5, None, None, None),
            make_cand("at-vie", "89.187.168.39", 40.6, None, None, None),
        ];

        let picked = pick_diverse_verify_targets(&cands, 4);
        let picked_ips: Vec<&str> = picked.iter().map(|c| c.endpoint_ip.as_str()).collect();
        assert_eq!(
            picked_ips,
            vec![
                "138.199.19.160",
                "87.249.133.9",
                "156.146.33.77",
                "89.187.168.39"
            ]
        );

        let mut fin = cands.clone();
        finalize_gaming_candidates(&mut fin, 2, 10);
        let fra_ips: Vec<&str> = fin
            .iter()
            .filter(|c| c.cluster_id == "de-fra")
            .map(|c| c.endpoint_ip.as_str())
            .collect();
        assert_eq!(fra_ips, vec!["138.199.19.160", "156.146.33.77"]);

        let mut rank_test = vec![
            make_cand(
                "de-fra",
                "89.117.104.35",
                39.5,
                Some(39.8),
                Some(0.2),
                Some(25.0),
            ),
            make_cand(
                "de-fra",
                "138.199.19.162",
                39.5,
                Some(40.4),
                Some(2.0),
                Some(0.0),
            ),
            make_cand(
                "de-fra",
                "156.146.33.77",
                39.7,
                Some(40.6),
                Some(0.3),
                Some(0.0),
            ),
            make_cand("at-vie", "87.249.133.9", 38.0, None, None, None),
        ];
        sort_gaming_candidates(&mut rank_test);
        let order: Vec<&str> = rank_test.iter().map(|c| c.endpoint_ip.as_str()).collect();
        assert_eq!(
            order,
            vec![
                "156.146.33.77",
                "138.199.19.162",
                "89.117.104.35",
                "87.249.133.9"
            ]
        );
    }
}
