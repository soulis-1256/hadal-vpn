use serde::{Deserialize, Serialize};

use crate::config::split_host_port_u16;
use crate::error::{Result, HadalError};
use crate::servers::{Cluster, Coordinates};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GameRegion {
    pub id: String,
    pub label: String,
    pub group: String,
    pub ping_host: String,
    pub latitude: f64,
    pub longitude: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GameProfile {
    pub id: String,
    pub name: String,
    pub regions: Vec<GameRegion>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PingStats {
    pub target: String,
    pub min_ms: f64,
    pub avg_ms: f64,
    pub max_ms: f64,
    pub mdev_ms: f64,
    pub loss_pct: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EndpointCandidate {
    pub cluster_id: String,
    pub domain: String,
    pub endpoint_ip: String,
    pub location: String,
    pub country: String,
    pub load: Option<u32>,
    pub direct_rtt_ms: f64,
    pub estimated_total_ms: f64,
    pub verified_tunnel_ms: Option<f64>,
    pub verified_mdev_ms: Option<f64>,
    #[serde(default)]
    pub verified_loss_pct: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GamingScanReport {
    pub game_id: String,
    pub region_id: String,
    pub target_host: String,
    pub baseline_direct: Option<PingStats>,
    #[serde(default)]
    pub active_tunnel_ping: Option<PingStats>,
    #[serde(default)]
    pub active_tunnel_label: Option<String>,
    pub wan_pmtu: u16,
    pub recommended_mtu: u16,
    pub candidates: Vec<EndpointCandidate>,
    pub game_cidrs: Vec<String>,
}

fn make_region(
    id: &str,
    label: &str,
    group: &str,
    ping_host: &str,
    latitude: f64,
    longitude: f64,
) -> GameRegion {
    GameRegion {
        id: id.into(),
        label: label.into(),
        group: group.into(),
        ping_host: ping_host.into(),
        latitude,
        longitude,
    }
}

/// Shared AWS GameLift/EC2 datacenter metadata for games hosted directly on verified AWS regions.
fn aws_region_entry(code: &str) -> Option<(&'static str, &'static str, f64, f64)> {
    match code {
        "eu-central-1" => Some(("Europe · Frankfurt", "Europe", 50.1109, 8.6821)),
        "eu-west-1" => Some(("Europe · Ireland (Dublin)", "Europe", 53.3498, -6.2603)),
        "eu-west-2" => Some(("Europe · United Kingdom (London)", "Europe", 51.5072, -0.1276)),
        "us-east-1" => Some(("NA-East · N. Virginia", "North America", 39.0438, -77.4874)),
        "us-east-2" => Some(("NA-East · Ohio", "North America", 40.0992, -82.806)),
        "us-west-1" => Some(("NA-West · N. California", "North America", 37.3382, -121.8863)),
        "us-west-2" => Some(("NA-West · Oregon", "North America", 45.8399, -119.7006)),
        "ca-central-1" => Some(("Canada · Montreal", "North America", 45.5017, -73.5673)),
        "sa-east-1" => Some(("Brazil · São Paulo", "South America", -23.5505, -46.6333)),
        "ap-northeast-1" => Some(("Asia · Tokyo", "Asia", 35.6762, 139.6503)),
        "ap-northeast-2" => Some(("Asia · Seoul", "Asia", 37.5665, 126.978)),
        "ap-southeast-1" => Some(("Asia · Singapore", "Asia", 1.3521, 103.8198)),
        "ap-east-1" => Some(("Asia · Hong Kong", "Asia", 22.3193, 114.1694)),
        "ap-south-1" => Some(("Asia · Mumbai", "Asia", 19.076, 72.8777)),
        "ap-southeast-2" => Some(("Oceania · Sydney", "Oceania", -33.8688, 151.2093)),
        _ => None,
    }
}

fn aws_game_profile(id: &str, name: &str, region_codes: &[&str]) -> GameProfile {
    let regions = region_codes
        .iter()
        .filter_map(|&code| {
            let (label, group, lat, lon) = aws_region_entry(code)?;
            Some(make_region(
                code,
                label,
                group,
                &format!("dynamodb.{code}.amazonaws.com"),
                lat,
                lon,
            ))
        })
        .collect();
    GameProfile {
        id: id.into(),
        name: name.into(),
        regions,
    }
}

pub fn builtin_games() -> Vec<GameProfile> {
    const FORTNITE_REGIONS: &[(&str, &str, &str, &str, f64, f64)] = &[
        (
            "eu-de",
            "Europe · Germany (Frankfurt)",
            "Europe",
            "ping-de.ds.on.epicgames.com",
            50.1109,
            8.6821,
        ),
        (
            "eu-fr",
            "Europe · France (Paris)",
            "Europe",
            "ping-fr.ds.on.epicgames.com",
            48.8566,
            2.3522,
        ),
        (
            "eu-gb",
            "Europe · United Kingdom (London)",
            "Europe",
            "ping-gb.ds.on.epicgames.com",
            51.5072,
            -0.1276,
        ),
        (
            "na-va",
            "NA-East · Virginia",
            "North America",
            "ping-va.ds.on.epicgames.com",
            39.0438,
            -77.4874,
        ),
        (
            "na-oh",
            "NA-East · Ohio",
            "North America",
            "ping-oh.ds.on.epicgames.com",
            40.0992,
            -82.806,
        ),
        (
            "na-tx",
            "NA-Central · Texas (Dallas)",
            "North America",
            "ping-tx.ds.on.epicgames.com",
            32.7767,
            -96.797,
        ),
        (
            "na-ia",
            "NA-Central · Iowa",
            "North America",
            "ping-ia.ds.on.epicgames.com",
            41.5868,
            -93.625,
        ),
        (
            "na-or",
            "NA-West · Oregon",
            "North America",
            "ping-or.ds.on.epicgames.com",
            45.8399,
            -119.7006,
        ),
        (
            "na-ncal",
            "NA-West · N. California",
            "North America",
            "ping-ncal.ds.on.epicgames.com",
            37.3382,
            -121.8863,
        ),
        (
            "na-mx",
            "Mexico",
            "North America",
            "ping-mx.ds.on.epicgames.com",
            19.4326,
            -99.1332,
        ),
        (
            "sa-br",
            "Brazil · São Paulo",
            "South America",
            "ping-sao.ds.on.epicgames.com",
            -23.5505,
            -46.6333,
        ),
        (
            "ap-tok",
            "Asia · Tokyo",
            "Asia",
            "ping-tok.ds.on.epicgames.com",
            35.6762,
            139.6503,
        ),
        (
            "oce-syd",
            "Oceania · Sydney",
            "Oceania",
            "ping-syd.ds.on.epicgames.com",
            -33.8688,
            151.2093,
        ),
        (
            "me-bah",
            "Middle East · Bahrain",
            "Middle East",
            "ping-bah.ds.on.epicgames.com",
            26.2285,
            50.586,
        ),
        (
            "me-mum",
            "Middle East · Mumbai",
            "Middle East",
            "ping-mum.ds.on.epicgames.com",
            19.076,
            72.8777,
        ),
        (
            "me-il",
            "Middle East · Israel",
            "Middle East",
            "ping-il.ds.on.epicgames.com",
            32.0853,
            34.7818,
        ),
    ];

    const FFXIV_REGIONS: &[(&str, &str, &str, &str, f64, f64)] = &[
        (
            "eu-chaos",
            "Europe · Chaos (Frankfurt)",
            "Europe",
            "neolobby06.ffxiv.com",
            50.1155,
            8.6842,
        ),
        (
            "eu-light",
            "Europe · Light (Frankfurt)",
            "Europe",
            "neolobby07.ffxiv.com",
            50.1155,
            8.6842,
        ),
        (
            "na-aether",
            "NA · Aether (San Jose)",
            "North America",
            "neolobby02.ffxiv.com",
            37.3394,
            -121.8950,
        ),
        (
            "na-primal",
            "NA · Primal (San Jose)",
            "North America",
            "neolobby04.ffxiv.com",
            37.3394,
            -121.8950,
        ),
        (
            "na-crystal",
            "NA · Crystal (San Jose)",
            "North America",
            "neolobby08.ffxiv.com",
            37.3394,
            -121.8950,
        ),
        (
            "na-dynamis",
            "NA · Dynamis (San Jose)",
            "North America",
            "neolobby11.ffxiv.com",
            37.3394,
            -121.8950,
        ),
        (
            "jp-tokyo",
            "Japan · Tokyo",
            "Asia",
            "neolobby01.ffxiv.com",
            35.6895,
            139.6917,
        ),
        (
            "oce-materia",
            "Oceania · Materia (Sydney)",
            "Oceania",
            "neolobby09.ffxiv.com",
            -33.8678,
            151.2073,
        ),
    ];

    const WOT_REGIONS: &[(&str, &str, &str, &str, f64, f64)] = &[
        (
            "eu1",
            "EU1 · Amsterdam",
            "Europe",
            "login.p1.worldoftanks.eu",
            52.3740,
            4.8897,
        ),
        (
            "eu2",
            "EU2 · Luxembourg",
            "Europe",
            "login.p2.worldoftanks.eu",
            49.5804,
            6.1117,
        ),
        (
            "eu3",
            "EU3 · Central (Luxembourg)",
            "Europe",
            "login.p3.worldoftanks.eu",
            49.5804,
            6.1117,
        ),
        (
            "eu4",
            "EU4 · Kazakhstan (Almaty)",
            "Asia",
            "login.p4.worldoftanks.eu",
            43.2525,
            76.9115,
        ),
    ];

    let to_regions = |rows: &[(&str, &str, &str, &str, f64, f64)]| -> Vec<GameRegion> {
        rows.iter()
            .map(|&(id, label, grp, host, lat, lon)| make_region(id, label, grp, host, lat, lon))
            .collect()
    };

    vec![
        GameProfile {
            id: "fortnite".into(),
            name: "Fortnite".into(),
            regions: to_regions(FORTNITE_REGIONS),
        },
        aws_game_profile(
            "apex",
            "Apex Legends",
            &[
                "eu-central-1",
                "us-east-1",
                "us-east-2",
                "us-west-2",
                "sa-east-1",
                "ap-northeast-1",
                "ap-southeast-1",
                "ap-east-1",
                "ap-southeast-2",
            ],
        ),
        aws_game_profile(
            "pubg",
            "PUBG",
            &[
                "eu-central-1",
                "eu-west-1",
                "eu-west-2",
                "us-east-1",
                "us-east-2",
                "us-west-1",
                "us-west-2",
                "ca-central-1",
                "sa-east-1",
                "ap-northeast-2",
                "ap-northeast-1",
                "ap-southeast-1",
                "ap-south-1",
                "ap-southeast-2",
            ],
        ),
        aws_game_profile(
            "dbd",
            "Dead by Daylight",
            &[
                "eu-central-1",
                "eu-west-1",
                "eu-west-2",
                "us-east-1",
                "us-east-2",
                "us-west-1",
                "us-west-2",
                "ca-central-1",
                "sa-east-1",
                "ap-northeast-2",
                "ap-northeast-1",
                "ap-southeast-1",
                "ap-east-1",
                "ap-south-1",
                "ap-southeast-2",
            ],
        ),
        GameProfile {
            id: "ffxiv".into(),
            name: "FFXIV".into(),
            regions: to_regions(FFXIV_REGIONS),
        },
        GameProfile {
            id: "wot".into(),
            name: "World of Tanks".into(),
            regions: to_regions(WOT_REGIONS),
        },
    ]
}

pub fn find_game_region(game_id: &str, region_id: &str) -> Option<GameRegion> {
    builtin_games()
        .into_iter()
        .find(|g| g.id.eq_ignore_ascii_case(game_id))
        .and_then(|g| {
            g.regions
                .into_iter()
                .find(|r| r.id.eq_ignore_ascii_case(region_id))
        })
}

/// Extract the bare host from a `host` or `host:port` string without duplicating port-splitting logic.
pub fn strip_host_port(host_or_addr: &str) -> String {
    let trimmed = host_or_addr.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    split_host_port_u16(trimmed).0
}

pub fn haversine_km(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let r = 6371.0_f64;
    let dlat = (lat2 - lat1).to_radians();
    let dlon = (lon2 - lon1).to_radians();
    let a = (dlat / 2.0).sin().powi(2)
        + lat1.to_radians().cos() * lat2.to_radians().cos() * (dlon / 2.0).sin().powi(2);
    2.0 * r * a.sqrt().atan2((1.0 - a).sqrt())
}

/// Estimate realistic second-hop optical fiber RTT (ms) from a VPN relay to a target datacenter.
/// Accounts for route curvature (~1.45x geodesic), fiber refractive index (~102 km/ms RTT),
/// and ~0.8 ms same-city IX/AWS peering overhead.
pub fn estimate_fiber_rtt_ms(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    0.8 + haversine_km(lat1, lon1, lat2, lon2) / 52.0
}

pub fn is_special_cluster(c: &Cluster) -> bool {
    let name = c.connection_name.as_deref().unwrap_or("").to_lowercase();
    let ctype = c.cluster_type.as_deref().unwrap_or("").to_lowercase();
    name.contains("-st") || ctype.contains("static") || c.tags.iter().any(|t| t == "static")
}

/// Detect virtual/geo-spoofed Surfshark clusters whose advertised city coordinates do not match
/// their physical server location (e.g. `li-qvu` Vaduz hosted in Vienna).
pub fn is_virtual_cluster(c: &Cluster) -> bool {
    let ctype = c.cluster_type.as_deref().unwrap_or("").to_lowercase();
    ctype.contains("virtual") || c.tags.iter().any(|t| t.eq_ignore_ascii_case("virtual"))
}

pub fn recommended_wg_mtu(wan_pmtu: u16) -> u16 {
    // Subtract 80 bytes (worst-case IPv6/NAT-T + WireGuard encapsulation) so frames never fragment.
    wan_pmtu.saturating_sub(80).clamp(1280, 1420)
}

/// Convert a slice of IPv4 addresses into deduplicated `/24` game-routing prefixes.
pub fn cidrs_from_ipv4s(ips: &[std::net::Ipv4Addr]) -> Vec<String> {
    let mut cidrs = Vec::new();
    for ip in ips {
        let octets = ip.octets();
        // /24 covers match instances on the same game server subnet while keeping non-game traffic off VPN
        let cidr = format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]);
        if !cidrs.contains(&cidr) {
            cidrs.push(cidr);
        }
    }
    cidrs
}

/// Resolve the target host and optional geographic coordinates for a built-in game region or custom host.
pub fn resolve_gaming_target(
    game_id: &str,
    region_id: &str,
    custom_host: Option<&str>,
) -> Result<(String, Option<(f64, f64)>)> {
    let region = find_game_region(game_id, region_id);
    let target_host = custom_host
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().to_string())
        .or_else(|| region.as_ref().map(|r| r.ping_host.clone()))
        .ok_or_else(|| HadalError::Custom(format!("Unknown game/region {game_id}/{region_id}")))?;
    let target_coords = region.as_ref().map(|r| (r.latitude, r.longitude));
    Ok((target_host, target_coords))
}

/// Construct a scored [`EndpointCandidate`] from a cluster, measured WAN RTT, and target coordinates.
pub fn build_endpoint_candidate(
    cluster: &Cluster,
    endpoint_ip: &str,
    direct_rtt_ms: f64,
    target_coords: Option<(f64, f64)>,
) -> EndpointCandidate {
    let domain = cluster.connection_name.clone().unwrap_or_default();
    let target_est_ms = if let (
        Some(Coordinates {
            latitude: Some(lat),
            longitude: Some(lon),
        }),
        Some((tlat, tlon)),
    ) = (&cluster.coordinates, target_coords)
    {
        estimate_fiber_rtt_ms(*lat, *lon, tlat, tlon)
    } else {
        6.0
    };
    EndpointCandidate {
        cluster_id: cluster.id.clone(),
        domain,
        endpoint_ip: endpoint_ip.to_string(),
        location: cluster.location.clone().unwrap_or_else(|| "Unknown".into()),
        country: cluster.country.clone().unwrap_or_else(|| "Unknown".into()),
        load: cluster.load,
        direct_rtt_ms,
        estimated_total_ms: direct_rtt_ms + target_est_ms,
        verified_tunnel_ms: None,
        verified_mdev_ms: None,
        verified_loss_pct: None,
    }
}
