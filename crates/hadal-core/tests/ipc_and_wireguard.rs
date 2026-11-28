use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use rand::rngs::StdRng;
use rand::SeedableRng;
use hadal_core::{
    normalize_wg_address, parse_rfc3339_utc_secs, send_request_on_stream, ConnectSpec,
    DaemonClient, DaemonRequest, DaemonResponse, DaemonStatus, EndpointProbeResult, PersistedWgKey,
    PingStats, RegisterPublicKeyResponse, SplitMode, SplitTunnelConfig, TunnelState,
    UnixDaemonClient, VerifiedTunnelResult, VerifyTarget, WanGamingProbe, WgKeyPair,
    WG_KEY_RENEWAL_MARGIN_SECS, WG_KEY_VALIDATE_INTERVAL_SECS,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use x25519_dalek::{PublicKey, StaticSecret};

fn temp_sock_path(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "hadal-ipc-test-{name}-{nanos}-{}.sock",
        std::process::id()
    ))
}

#[test]
fn wireguard_keypair_generation_is_valid_curve25519_and_deterministic_with_rng() {
    let mut rng1 = StdRng::seed_from_u64(42);
    let mut rng2 = StdRng::seed_from_u64(42);
    let kp1 = WgKeyPair::generate_with_rng(&mut rng1);
    let kp2 = WgKeyPair::generate_with_rng(&mut rng2);
    assert_eq!(kp1, kp2);

    let priv_bytes: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(&kp1.private_key)
        .unwrap()
        .try_into()
        .unwrap();
    let pub_bytes: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(&kp1.public_key)
        .unwrap()
        .try_into()
        .unwrap();
    let expected_pub = PublicKey::from(&StaticSecret::from(priv_bytes));
    assert_eq!(pub_bytes, *expected_pub.as_bytes());

    let random_kp = WgKeyPair::generate();
    assert_ne!(random_kp.private_key, kp1.private_key);
}

#[test]
fn normalize_wg_address_and_register_response_fallbacks() {
    assert_eq!(normalize_wg_address("10.14.0.2"), "10.14.0.2/32");
    assert_eq!(normalize_wg_address(" 10.14.0.9/24 "), "10.14.0.9/32");
    assert_eq!(normalize_wg_address("fd00::2"), "fd00::2/128");
    assert_eq!(normalize_wg_address("fd00::2/64"), "fd00::2/128");

    let primary = RegisterPublicKeyResponse {
        ip: Some("10.14.0.5".into()),
        extra: serde_json::json!({"address": "10.14.0.6"}),
    };
    assert_eq!(primary.wireguard_address(), "10.14.0.5/32");

    let via_address = RegisterPublicKeyResponse {
        ip: None,
        extra: serde_json::json!({"address": "10.14.0.7/16"}),
    };
    assert_eq!(via_address.wireguard_address(), "10.14.0.7/32");

    let via_ipv4 = RegisterPublicKeyResponse {
        ip: None,
        extra: serde_json::json!({"ipv4": "10.14.0.8"}),
    };
    assert_eq!(via_ipv4.wireguard_address(), "10.14.0.8/32");

    let default_fallback = RegisterPublicKeyResponse {
        ip: None,
        extra: serde_json::json!({}),
    };
    assert_eq!(default_fallback.wireguard_address(), "10.14.0.2/32");
    assert_eq!(default_fallback.key_id(), None);
    assert_eq!(default_fallback.expires_at(), None);

    let with_meta = RegisterPublicKeyResponse {
        ip: None,
        extra: serde_json::json!({
            "id": "01a2234e-30c9-7e6a-9664-29d720e720e6",
            "expiresAt": "2026-12-05T17:57:36+00:00",
        }),
    };
    assert_eq!(
        with_meta.key_id(),
        Some("01a2234e-30c9-7e6a-9664-29d720e720e6")
    );
    assert_eq!(with_meta.expires_at(), Some("2026-12-05T17:57:36+00:00"));
}

#[test]
fn rfc3339_timestamp_parsing_and_persisted_wg_key_validity() {
    assert_eq!(parse_rfc3339_utc_secs("1970-01-01T00:00:00Z"), Some(0));
    assert_eq!(
        parse_rfc3339_utc_secs("2026-12-05T17:57:36+00:00"),
        Some(1_796_493_456)
    );
    assert_eq!(
        parse_rfc3339_utc_secs("2026-12-05T19:57:36+02:00"),
        Some(1_796_493_456)
    );
    assert_eq!(
        parse_rfc3339_utc_secs("2026-12-05T12:57:36.987654-05:00"),
        Some(1_796_493_456)
    );
    assert!(parse_rfc3339_utc_secs("2024-02-29T00:00:00Z").is_some());
    assert!(parse_rfc3339_utc_secs("2000-02-29T00:00:00Z").is_some());
    assert_eq!(parse_rfc3339_utc_secs("2025-02-29T00:00:00Z"), None);
    assert_eq!(parse_rfc3339_utc_secs("2100-02-29T00:00:00Z"), None);
    assert_eq!(parse_rfc3339_utc_secs("not-a-timestamp"), None);

    let now = 1_795_888_656; // 2026-11-28T17:57:36Z (7 days before 2026-12-05)
    let pair = WgKeyPair {
        private_key: "priv-a".into(),
        public_key: "pub-a".into(),
    };
    let resp = RegisterPublicKeyResponse {
        ip: Some("10.14.0.2".into()),
        extra: serde_json::json!({
            "id": "key-id-1",
            "expiresAt": "2026-12-05T17:57:36+00:00"
        }),
    };
    let persisted = PersistedWgKey::from_registration(pair, &resp, Some(now));
    assert!(persisted.is_valid_at(now));
    assert!(!persisted.needs_validation_at(now));
    assert!(persisted.needs_validation_at(now + WG_KEY_VALIDATE_INTERVAL_SECS));
    assert!(!persisted.is_valid_at(1_796_493_456 - WG_KEY_RENEWAL_MARGIN_SECS));
    assert!(persisted.is_valid_at(1_796_493_456 - WG_KEY_RENEWAL_MARGIN_SECS - 1));

    // File persistence roundtrip with 0600 permissions
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("hadal-wg-key-test-{nanos}-{}", std::process::id()));
    persisted.save_to(&dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.join("wg_key.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
    assert_eq!(PersistedWgKey::load_from(&dir), Some(persisted));
    PersistedWgKey::clear_files_in(&dir);
    assert_eq!(PersistedWgKey::load_from(&dir), None);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn daemon_request_and_response_serde_roundtrip_all_variants() {
    let requests = vec![
        DaemonRequest::Status,
        DaemonRequest::Connect(ConnectSpec {
            cluster_id: Some("de-fra".into()),
            domain: "de-fra.prod.surfshark.com".into(),
            endpoint_ip: "138.199.19.160".into(),
            endpoint_port: 51820,
            pub_key: "pub".into(),
            priv_key: "priv".into(),
            address: "10.14.0.2/32".into(),
            dns: vec!["1.1.1.1".into()],
            mtu: 1412,
            killswitch: true,
            ipv6_block: true,
            bypass_lan: true,
            split_mode: SplitMode::OnlyVpn,
            split_cgroup_paths: vec!["user.slice/app-hadal_vpn.slice".into()],
            game_only_cidrs: vec!["3.66.0.0/16".into()],
            location: Some("Frankfurt".into()),
            country: Some("Germany".into()),
        }),
        DaemonRequest::Disconnect {
            keep_killswitch: true,
        },
        DaemonRequest::SetKillswitch {
            enabled: true,
            ipv6_block: false,
            bypass_lan: true,
        },
        DaemonRequest::UpdateSplitTunnel(SplitTunnelConfig::default()),
        DaemonRequest::ResetAppSockets {
            pids: vec![100, 200],
        },
        DaemonRequest::ControlHttp {
            method: "POST".into(),
            url: "https://ext2.surfshark.com/v1/auth/renew".into(),
            headers: vec![("authorization".into(), "Bearer tok".into())],
            body: Some(b"{}".to_vec()),
        },
        DaemonRequest::PrepareEndpoint {
            domain: "de-fra.prod.surfshark.com".into(),
            discover_pmtu: true,
        },
        DaemonRequest::ProbeWanGaming {
            target_host: "ping-de.ds.on.epicgames.com".into(),
            domains: vec!["de-fra.prod.surfshark.com".into()],
        },
        DaemonRequest::VerifyGamingTunnels {
            target_ip: "3.66.90.29".into(),
            priv_key: "priv".into(),
            address: "10.14.0.2/32".into(),
            mtu: 1412,
            targets: vec![VerifyTarget {
                cluster_id: "de-fra".into(),
                endpoint_ip: "138.199.19.160".into(),
                endpoint_port: 51820,
                pub_key: "pub".into(),
            }],
            samples: Some(8),
        },
        DaemonRequest::Shutdown,
    ];

    for req in requests {
        let json = serde_json::to_string(&req).unwrap();
        let back: DaemonRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, back);
    }

    let responses = vec![
        DaemonResponse::Status(DaemonStatus {
            state: TunnelState::Protected,
            ..Default::default()
        }),
        DaemonResponse::Http {
            status: 200,
            body: b"ok".to_vec(),
        },
        DaemonResponse::Prepared {
            endpoint_ip: "138.199.19.160".into(),
            wan_pmtu: Some(1492),
        },
        DaemonResponse::WanGamingProbed(WanGamingProbe {
            baseline_direct: Some(PingStats {
                target: "h".into(),
                min_ms: 10.0,
                avg_ms: 11.0,
                max_ms: 12.0,
                mdev_ms: 0.5,
                loss_pct: 0.0,
            }),
            wan_pmtu: 1492,
            game_cidrs: vec!["3.66.0.0/16".into()],
            endpoints: vec![EndpointProbeResult {
                domain: "de-fra.prod.surfshark.com".into(),
                endpoint_ip: "138.199.19.160".into(),
                min_ms: 15.0,
            }],
        }),
        DaemonResponse::GamingTunnelsVerified(vec![VerifiedTunnelResult {
            cluster_id: "de-fra".into(),
            endpoint_ip: "138.199.19.160".into(),
            min_ms: 20.0,
            avg_ms: 21.0,
            mdev_ms: 0.4,
            loss_pct: 0.0,
        }]),
        DaemonResponse::Ok,
        DaemonResponse::Error {
            message: "boom".into(),
        },
    ];

    for resp in responses {
        let json = serde_json::to_string(&resp).unwrap();
        let back: DaemonResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(resp, back);
    }
}

#[tokio::test]
async fn send_request_on_stream_handles_ok_error_eof_and_bad_json() {
    // 1. Valid request/response over duplex stream
    let (client_stream, server_stream) = tokio::io::duplex(4096);
    tokio::spawn(async move {
        let (r, mut w) = tokio::io::split(server_stream);
        let mut line = String::new();
        BufReader::new(r).read_line(&mut line).await.unwrap();
        let req: DaemonRequest = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(req, DaemonRequest::Status);
        let resp = serde_json::to_string(&DaemonResponse::Status(DaemonStatus {
            state: TunnelState::Protected,
            location: Some("Frankfurt".into()),
            ..Default::default()
        }))
        .unwrap();
        w.write_all(format!("{resp}\n").as_bytes()).await.unwrap();
    });
    let resp = send_request_on_stream(client_stream, &DaemonRequest::Status)
        .await
        .unwrap();
    assert!(matches!(
        resp,
        DaemonResponse::Status(DaemonStatus {
            state: TunnelState::Protected,
            ..
        })
    ));

    // 2. DaemonResponse::Error surfaces as HadalError::Custom
    let (c2, s2) = tokio::io::duplex(4096);
    tokio::spawn(async move {
        let (r, mut w) = tokio::io::split(s2);
        let mut line = String::new();
        let _ = BufReader::new(r).read_line(&mut line).await;
        let resp = serde_json::to_string(&DaemonResponse::Error {
            message: "invalid peer key".into(),
        })
        .unwrap();
        let _ = w.write_all(format!("{resp}\n").as_bytes()).await;
    });
    let err = send_request_on_stream(c2, &DaemonRequest::Shutdown)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("invalid peer key"));

    // 3a. Immediate closed stream fails on write with IO error
    let (c3a, s3a) = tokio::io::duplex(4096);
    drop(s3a);
    let pipe_err = send_request_on_stream(c3a, &DaemonRequest::Status)
        .await
        .unwrap_err();
    assert!(matches!(pipe_err, hadal_core::HadalError::Io(_)));

    // 3b. Server reads request then closes without responding -> unexpected EOF
    let (c3b, s3b) = tokio::io::duplex(4096);
    tokio::spawn(async move {
        let (r, _w) = tokio::io::split(s3b);
        let mut line = String::new();
        let _ = BufReader::new(r).read_line(&mut line).await;
    });
    let eof_err = send_request_on_stream(c3b, &DaemonRequest::Status)
        .await
        .unwrap_err();
    assert!(eof_err.to_string().contains("closed IPC connection"));

    // 4. Malformed JSON fails cleanly
    let (c4, mut s4) = tokio::io::duplex(4096);
    tokio::spawn(async move {
        let _ = s4.write_all(b"not-json\n").await;
    });
    assert!(send_request_on_stream(c4, &DaemonRequest::Status)
        .await
        .is_err());
}

#[tokio::test]
async fn unix_daemon_client_roundtrips_and_reports_unreachable_socket() {
    let sock = temp_sock_path("roundtrip");
    let listener = UnixListener::bind(&sock).unwrap();

    tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let (r, mut w) = stream.into_split();
            let mut line = String::new();
            BufReader::new(r).read_line(&mut line).await.unwrap();
            let req: DaemonRequest = serde_json::from_str(line.trim()).unwrap();
            assert_eq!(req, DaemonRequest::Status);
            let resp = serde_json::to_string(&DaemonResponse::Status(DaemonStatus {
                state: TunnelState::KillswitchLocked,
                killswitch: true,
                ..Default::default()
            }))
            .unwrap();
            w.write_all(format!("{resp}\n").as_bytes()).await.unwrap();
        }
    });

    let client = UnixDaemonClient::new(&sock);
    let st = client.status().await.unwrap();
    assert_eq!(st.state, TunnelState::KillswitchLocked);
    let _ = std::fs::remove_file(&sock);

    let missing = temp_sock_path("missing");
    let err = UnixDaemonClient::new(&missing).status().await.unwrap_err();
    assert!(err.to_string().contains("Cannot reach hadald"));
}
