use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use hadal_core::auth::AuthResponse;
use hadal_core::{
    daemon_socket_path, endpoint_for_domain, jwt_is_expired_at, load_settings_from,
    save_settings_to, split_host_port_u16, AppSettings, BoxFuture, Clock, DaemonClient,
    DaemonRequest, DaemonResponse, DaemonStatus, FileSessionStore, FileSettingsStore,
    FileWgKeyStore, HadalClient, HadalError, HttpRequest, HttpResponse, HttpTransport,
    KeyPairGenerator, PersistedWgKey, Result, Session, SessionStore, SettingsStore, Sleeper,
    SplitMode, SplitTunnelConfig, TunnelState, WgKeyPair, WgKeyStore, WG_KEY_RENEWAL_MARGIN_SECS,
    WG_KEY_VALIDATE_INTERVAL_SECS,
};

struct TempDir(PathBuf);

impl TempDir {
    fn new(prefix: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hadal-core-{prefix}-{nanos}-{}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn encode_jwt(payload_json: &str) -> String {
    let body = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
    format!("hdr.{body}.sig")
}

struct FixedClock(AtomicU64);

impl FixedClock {
    fn new(now: u64) -> Self {
        Self(AtomicU64::new(now))
    }
    fn set(&self, now: u64) {
        self.0.store(now, Ordering::SeqCst);
    }
}

impl Clock for FixedClock {
    fn now_unix_secs(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

struct RecordingSleeper(Mutex<Vec<Duration>>);

impl RecordingSleeper {
    fn new() -> Self {
        Self(Mutex::new(Vec::new()))
    }
    fn calls(&self) -> Vec<Duration> {
        self.0.lock().unwrap().clone()
    }
}

impl Sleeper for RecordingSleeper {
    fn sleep(&self, duration: Duration) -> BoxFuture<'_, ()> {
        self.0.lock().unwrap().push(duration);
        Box::pin(async {})
    }
}

type TransportResponder = Box<dyn Fn(&HttpRequest) -> Result<HttpResponse> + Send + Sync>;

struct MockTransport {
    requests: Mutex<Vec<HttpRequest>>,
    responder: TransportResponder,
}

impl MockTransport {
    fn new(f: impl Fn(&HttpRequest) -> Result<HttpResponse> + Send + Sync + 'static) -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
            responder: Box::new(f),
        }
    }

    fn recorded(&self) -> Vec<HttpRequest> {
        self.requests.lock().unwrap().clone()
    }
}

impl HttpTransport for MockTransport {
    fn execute<'a>(&'a self, req: HttpRequest) -> BoxFuture<'a, Result<HttpResponse>> {
        Box::pin(async move {
            self.requests.lock().unwrap().push(req.clone());
            (self.responder)(&req)
        })
    }
}

type DaemonResponder = Box<dyn Fn(&DaemonRequest) -> Result<DaemonResponse> + Send + Sync>;

struct FakeDaemon {
    status_seq: Mutex<VecDeque<DaemonStatus>>,
    sent: Mutex<Vec<DaemonRequest>>,
    responder: DaemonResponder,
}

impl FakeDaemon {
    fn with_status(
        status: DaemonStatus,
        responder: impl Fn(&DaemonRequest) -> Result<DaemonResponse> + Send + Sync + 'static,
    ) -> Self {
        Self {
            status_seq: Mutex::new(VecDeque::from([status])),
            sent: Mutex::new(Vec::new()),
            responder: Box::new(responder),
        }
    }

    fn sent_requests(&self) -> Vec<DaemonRequest> {
        self.sent.lock().unwrap().clone()
    }
}

impl DaemonClient for FakeDaemon {
    fn send<'a>(&'a self, req: &'a DaemonRequest) -> BoxFuture<'a, Result<DaemonResponse>> {
        Box::pin(async move {
            self.sent.lock().unwrap().push(req.clone());
            if matches!(req, DaemonRequest::Status) {
                let mut q = self.status_seq.lock().unwrap();
                if let Some(st) = q.front().cloned() {
                    if q.len() > 1 {
                        q.pop_front();
                    }
                    return Ok(DaemonResponse::Status(st));
                }
            }
            (self.responder)(req)
        })
    }
}

#[test]
fn session_store_roundtrip_permissions_and_corrupt_handling() {
    let dir = TempDir::new("session-store");
    let store = FileSessionStore::new(dir.path());
    assert!(store.load().is_none());

    // Corrupt JSON is ignored cleanly
    std::fs::write(dir.path().join("session.json"), "{not-json").unwrap();
    assert!(store.load().is_none());

    // Session without access token clears files instead of persisting empty session
    let session = Session {
        token: Some("tok-1".into()),
        renew_token: Some("ren-1".into()),
        token_expires_at: Some("2027-01-01T00:00:00Z".into()),
    };
    store.save(&session).unwrap();
    assert_eq!(store.load().unwrap(), session);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.path().join("session.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    store
        .save(&Session {
            token: Some("   ".into()),
            renew_token: Some("ren-1".into()),
            token_expires_at: None,
        })
        .unwrap();
    assert!(!dir.path().join("session.json").exists());
}

#[test]
fn jwt_expiry_handles_boundaries_and_malformed_tokens() {
    let tok_1000 = encode_jwt(r#"{"exp":1000}"#);
    assert!(!jwt_is_expired_at(&tok_1000, 999));
    assert!(jwt_is_expired_at(&tok_1000, 1000));
    assert!(jwt_is_expired_at(&tok_1000, 1500));

    // Unparseable or missing-exp tokens defer to API validation
    assert!(!jwt_is_expired_at(&encode_jwt(r#"{"sub":"1"}"#), 1500));
    assert!(!jwt_is_expired_at("header.!!!.sig", 1500));
    assert!(!jwt_is_expired_at("only-one-part", 1500));
}

#[tokio::test]
async fn remote_pair_and_html_error_sanitization_flow() {
    let dir = TempDir::new("auth-flow");
    let transport = Arc::new(MockTransport::new(|req| {
        if req.url.ends_with("/v1/account/users/me") {
            let has_bearer = req.headers.iter().any(|(k, _)| k == "authorization");
            if !has_bearer {
                return Ok(HttpResponse {
                    status: 403,
                    body: b"<!DOCTYPE html><html>error</html>".to_vec(),
                });
            }
            return Ok(HttpResponse {
                status: 200,
                body: br#"{"id":"u1","email":"pair@example.com","status":"active"}"#.to_vec(),
            });
        }
        if req.url.ends_with("/v1/account/authorization/create") {
            assert!(req
                .headers
                .iter()
                .all(|(k, v)| k != "x-device-version" || v != "3.14.0"));
            return Ok(HttpResponse {
                status: 200,
                body: br#"{"code":"XYZ789","hash":"pair-hash","expiresAt":999999}"#.to_vec(),
            });
        }
        if req.url.ends_with("/v1/auth/remote") {
            return Ok(HttpResponse {
                status: 200,
                body: br#"{"token":"paired-jwt","renewToken":"paired-ren"}"#.to_vec(),
            });
        }
        unreachable!("unexpected URL: {}", req.url);
    }));

    let client = HadalClient::from_session(Session::default())
        .with_config_dir(dir.path().to_path_buf())
        .with_transport(transport.clone());

    // device_id created inside temp config dir and reused
    assert!(dir.path().join("device_id").exists());
    let dev_id = client.device_id().to_string();
    let client2 = HadalClient::from_session(Session::default())
        .with_config_dir(dir.path().to_path_buf());
    assert_eq!(client2.device_id(), dev_id);

    // HTML error body is sanitized cleanly without leaking markup
    let err = client
        .get_user_me()
        .await
        .expect_err("HTML 403 should fail");
    assert!(!err.to_string().contains("<html"));
    assert!(err.to_string().contains("unexpected HTML response"));

    // Remote quick pair saves session and authorizes /users/me
    let remote = client.create_remote_login().await.unwrap();
    assert_eq!(remote.code, "XYZ789");
    let paired = client.poll_remote_login(&remote.hash).await.unwrap();
    assert_eq!(paired.token.as_deref(), Some("paired-jwt"));
    let me = client.get_user_me().await.unwrap();
    assert_eq!(me.email.as_deref(), Some("pair@example.com"));
    assert_eq!(
        Session::load_from(dir.path()).unwrap().renew_token.as_deref(),
        Some("paired-ren")
    );
    assert!(transport
        .recorded()
        .iter()
        .any(|r| r.url.ends_with("/v1/auth/remote")));
}

#[tokio::test]
async fn proactive_jwt_refresh_and_concurrent_401_coalescing() {
    let dir = TempDir::new("refresh-coalesce");
    let clock = Arc::new(FixedClock::new(1000));
    let renew_calls = Arc::new(AtomicUsize::new(0));
    let renew_calls_ref = renew_calls.clone();

    let expired_at_900 = encode_jwt(r#"{"exp":900}"#);
    let valid_at_5000 = encode_jwt(r#"{"exp":5000}"#);
    let valid_ref = valid_at_5000.clone();

    let transport = Arc::new(MockTransport::new(move |req| {
        if req.url.ends_with("/v1/auth/renew") {
            let n = renew_calls_ref.fetch_add(1, Ordering::SeqCst);
            // Verify renew sends renewToken and NOT expired access token
            let auth = req
                .headers
                .iter()
                .find(|(k, _)| k == "authorization")
                .map(|(_, v)| v.as_str())
                .unwrap_or("");
            assert_eq!(auth, format!("Bearer renew-{}", n + 1));
            return Ok(HttpResponse {
                status: 200,
                body: serde_json::to_vec(&AuthResponse {
                    token: Some(valid_ref.clone()),
                    renew_token: Some(format!("renew-{}", n + 2)),
                    token_expires_at: Some("5000".into()),
                    extra: serde_json::json!({}),
                })
                .unwrap(),
            });
        }
        if req.url.ends_with("/v1/account/users/me") {
            let auth = req
                .headers
                .iter()
                .find(|(k, _)| k == "authorization")
                .map(|(_, v)| v.as_str())
                .unwrap_or("");
            if auth == format!("Bearer {valid_ref}") {
                return Ok(HttpResponse {
                    status: 200,
                    body: br#"{"email":"fresh@example.com"}"#.to_vec(),
                });
            }
            return Ok(HttpResponse {
                status: 401,
                body: b"expired".to_vec(),
            });
        }
        unreachable!()
    }));

    let client = HadalClient::from_session(Session {
        token: Some(expired_at_900),
        renew_token: Some("renew-1".into()),
        token_expires_at: None,
    })
    .with_config_dir(dir.path().to_path_buf())
    .with_clock(clock.clone())
    .with_transport(transport);

    // Fire 4 concurrent get_user_me calls -> proactive refresh coalesces to exactly 1 /v1/auth/renew call!
    let results = tokio::join!(
        client.get_user_me(),
        client.get_user_me(),
        client.get_user_me(),
        client.get_user_me(),
    );
    for r in [results.0, results.1, results.2, results.3] {
        assert_eq!(r.unwrap().email.as_deref(), Some("fresh@example.com"));
    }
    assert_eq!(renew_calls.load(Ordering::SeqCst), 1);

    // Advance clock past 5000 and verify next call refreshes again; if renew fails, session clears
    clock.set(6000);
    let me2 = client.get_user_me().await.unwrap();
    assert_eq!(me2.email.as_deref(), Some("fresh@example.com"));
    assert_eq!(renew_calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn killswitch_locked_routes_clusters_user_location_and_renew_via_control_http() {
    let daemon = Arc::new(FakeDaemon::with_status(
        DaemonStatus {
            state: TunnelState::KillswitchLocked,
            ..Default::default()
        },
        |req| match req {
            DaemonRequest::ControlHttp { url, method, .. } => {
                if url.ends_with("/v1/server/user") && method == "GET" {
                    Ok(DaemonResponse::Http {
                        status: 200,
                        body: br#"{"ip":"203.0.113.9","secured":false,"country":"DE"}"#.to_vec(),
                    })
                } else if url.ends_with("/v5/server/clusters/all") {
                    Ok(DaemonResponse::Http {
                        status: 200,
                        body: br#"[
                            {"id":"valid","country":"Germany","pubKey":"pk-valid"},
                            {"id":"empty-pk","country":"Nowhere","pubKey":""},
                            {"id":"no-pk","country":"Missing"}
                        ]"#
                        .to_vec(),
                    })
                } else if url.ends_with("/v1/auth/renew") && method == "POST" {
                    Ok(DaemonResponse::Http {
                        status: 200,
                        body: br#"{"token":"renewed-via-control","renewToken":"ren-2"}"#.to_vec(),
                    })
                } else {
                    panic!("Unexpected ControlHttp {method} {url}");
                }
            }
            _ => Ok(DaemonResponse::Ok),
        },
    ));

    let sleeper = Arc::new(RecordingSleeper::new());
    let client = HadalClient::from_session(Session {
        token: Some("tok".into()),
        renew_token: Some("ren-1".into()),
        token_expires_at: None,
    })
    .with_daemon_client(daemon.clone())
    .with_sleeper(sleeper);

    // Regression check: get_user_location must go via ControlHttp instead of bypassing to raw WAN
    let loc = client.get_user_location().await.unwrap();
    assert_eq!(loc.ip, "203.0.113.9");

    // get_clusters filters out entries without non-empty pub_key
    let clusters = client.get_clusters().await.unwrap();
    assert_eq!(clusters.len(), 1);
    assert_eq!(clusters[0].id, "valid");

    // refresh_tokens also routes through ControlHttp when KillswitchLocked
    let refreshed = client.refresh_tokens().await.unwrap();
    assert_eq!(refreshed.token.as_deref(), Some("renewed-via-control"));

    let control_urls: Vec<String> = daemon
        .sent_requests()
        .into_iter()
        .filter_map(|r| match r {
            DaemonRequest::ControlHttp { url, .. } => Some(url),
            _ => None,
        })
        .collect();
    assert_eq!(control_urls.len(), 3);
}

#[tokio::test]
async fn get_user_location_retries_with_sleeper_and_returns_error_after_three_attempts() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let attempts_ref = attempts.clone();
    let sleeper = Arc::new(RecordingSleeper::new());
    let transport = Arc::new(MockTransport::new(move |_| {
        let n = attempts_ref.fetch_add(1, Ordering::SeqCst);
        if n < 2 {
            Ok(HttpResponse {
                status: 503,
                body: b"unavailable".to_vec(),
            })
        } else {
            Ok(HttpResponse {
                status: 200,
                body: br#"{"ip":"198.51.100.5","secured":true}"#.to_vec(),
            })
        }
    }));

    let client = HadalClient::from_session(Session::default())
        .with_transport(transport)
        .with_sleeper(sleeper.clone());
    let loc = client.get_user_location().await.unwrap();
    assert_eq!(loc.ip, "198.51.100.5");
    assert!(loc.secured);
    assert_eq!(attempts.load(Ordering::SeqCst), 3);
    assert_eq!(sleeper.calls(), vec![Duration::from_millis(500); 2]);

    // If all 3 attempts fail, returns Err cleanly
    let fail_transport = Arc::new(MockTransport::new(|_| {
        Err(HadalError::Custom("network unreachable".into()))
    }));
    let fail_sleeper = Arc::new(RecordingSleeper::new());
    let fail_client = HadalClient::from_session(Session::default())
        .with_transport(fail_transport)
        .with_sleeper(fail_sleeper.clone());
    let err = fail_client.get_user_location().await.unwrap_err();
    assert!(err.to_string().contains("network unreachable"));
    assert_eq!(fail_sleeper.calls().len(), 2);
}

#[test]
fn settings_store_migrates_legacy_split_lists_and_roundtrips() {
    let dir = TempDir::new("settings");
    let store = FileSettingsStore::new(dir.path());

    // Missing file returns secure defaults
    let def = store.load();
    assert!(def.killswitch && def.ipv6_block && def.bypass_lan && def.auto_mtu);

    // Legacy settings.json without bypass_apps/only_vpn_apps migrates `apps`
    let legacy_only_vpn = r#"{
        "killswitch": false,
        "split_tunnel": {
            "mode": "only_vpn",
            "apps": ["firefox", "obs"]
        }
    }"#;
    std::fs::write(store.path(), legacy_only_vpn).unwrap();
    let migrated = load_settings_from(dir.path());
    assert!(!migrated.killswitch);
    assert_eq!(migrated.split_tunnel.mode, SplitMode::OnlyVpn);
    assert_eq!(migrated.split_tunnel.only_vpn_apps, vec!["firefox", "obs"]);
    assert!(migrated.split_tunnel.bypass_apps.is_empty());
    assert_eq!(migrated.split_tunnel.apps, vec!["firefox", "obs"]);

    // Save & reload roundtrips custom fields
    let updated = AppSettings {
        manual_mtu: Some(1380),
        auto_mtu: false,
        game_only_routing: true,
        last_cluster_id: Some("de-fra".into()),
        split_tunnel: SplitTunnelConfig {
            mode: SplitMode::Bypass,
            apps: vec!["steam".into()],
            bypass_apps: vec!["steam".into()],
            only_vpn_apps: vec!["firefox".into()],
            cgroup_paths: vec!["user.slice/custom.slice".into()],
            game_only_cidrs: vec!["3.66.0.0/16".into()],
        },
        ..AppSettings::default()
    };
    save_settings_to(dir.path(), &updated).unwrap();
    assert_eq!(store.load(), updated);

    // Corrupt settings file falls back safely to defaults
    std::fs::write(store.path(), "not valid json").unwrap();
    assert_eq!(store.load(), AppSettings::default());
}

#[test]
fn endpoint_and_socket_path_parsing_handles_ipv6_ports_and_empty() {
    assert_eq!(endpoint_for_domain(""), "127.0.0.1:51820");
    assert_eq!(endpoint_for_domain("  [::1] "), "[::1]:51820");
    assert_eq!(endpoint_for_domain("[::1]:51900"), "[::1]:51900");
    assert_eq!(
        split_host_port_u16("de-fra.prod.surfshark.com"),
        ("de-fra.prod.surfshark.com".into(), 51820)
    );
    assert_eq!(
        split_host_port_u16("138.199.19.160:51821"),
        ("138.199.19.160".into(), 51821)
    );
    assert_eq!(split_host_port_u16("[::1]:51900"), ("[::1]".into(), 51900));
    assert!(!daemon_socket_path().as_os_str().is_empty());
}

struct SequenceKeyGen {
    seq: Mutex<VecDeque<WgKeyPair>>,
}

impl SequenceKeyGen {
    fn new(pairs: Vec<(&str, &str)>) -> Self {
        Self {
            seq: Mutex::new(
                pairs
                    .into_iter()
                    .map(|(priv_k, pub_k)| WgKeyPair {
                        private_key: priv_k.into(),
                        public_key: pub_k.into(),
                    })
                    .collect(),
            ),
        }
    }
}

impl KeyPairGenerator for SequenceKeyGen {
    fn generate(&self) -> WgKeyPair {
        self.seq
            .lock()
            .unwrap()
            .pop_front()
            .expect("exhausted test keypairs")
    }
}

#[tokio::test]
async fn ensure_wireguard_key_persists_reuses_validates_rotates_and_cleans_up_on_logout() {
    let dir = TempDir::new("wg-key-lifecycle");
    let now_start: u64 = 1_795_888_656; // 2026-11-28T17:57:36Z
    let clock = Arc::new(FixedClock::new(now_start));
    let validate_mode = Arc::new(Mutex::new("ok")); // "ok" | "404" | "500"
    let validate_mode_cb = validate_mode.clone();
    let reg_counter = Arc::new(AtomicUsize::new(0));
    let reg_counter_cb = reg_counter.clone();

    let transport = Arc::new(MockTransport::new(move |req| {
        if req.method == reqwest::Method::POST && req.url.ends_with("/v1/account/users/public-keys") {
            let n = reg_counter_cb.fetch_add(1, Ordering::SeqCst) + 1;
            let body_json: serde_json::Value =
                serde_json::from_slice(req.body.as_deref().unwrap_or(b"{}")).unwrap();
            let pub_key = body_json["pubKey"].as_str().unwrap_or("");
            let expires = if n == 1 {
                "2026-12-05T17:57:36+00:00"
            } else {
                "2026-12-12T17:57:36+00:00"
            };
            let resp = serde_json::json!({
                "id": format!("hadal-key-{n}"),
                "pubKey": pub_key,
                "expiresAt": expires,
            });
            return Ok(HttpResponse {
                status: 201,
                body: serde_json::to_vec(&resp).unwrap(),
            });
        }
        if req.method == reqwest::Method::POST
            && req.url.ends_with("/v1/account/users/public-keys/validate")
        {
            let mode = *validate_mode_cb.lock().unwrap();
            return match mode {
                "404" => Ok(HttpResponse {
                    status: 404,
                    body: b"[]".to_vec(),
                }),
                "500" => Ok(HttpResponse {
                    status: 500,
                    body: b"transient error".to_vec(),
                }),
                _ => {
                    let body_json: serde_json::Value =
                        serde_json::from_slice(req.body.as_deref().unwrap_or(b"{}")).unwrap();
                    let pub_key = body_json["pubKey"].as_str().unwrap_or("");
                    let resp = serde_json::json!({
                        "id": "hadal-key-1",
                        "pubKey": pub_key,
                        "expiresAt": "2026-12-05T17:57:36+00:00",
                    });
                    Ok(HttpResponse {
                        status: 200,
                        body: serde_json::to_vec(&resp).unwrap(),
                    })
                }
            };
        }
        if req.method == reqwest::Method::DELETE
            && req.url.contains("/v1/account/users/public-keys/")
        {
            return Ok(HttpResponse {
                status: 200,
                body: b"[]".to_vec(),
            });
        }
        Ok(HttpResponse {
            status: 404,
            body: b"{}".to_vec(),
        })
    }));

    let keygen = Arc::new(SequenceKeyGen::new(vec![
        ("priv-1", "pub-1"),
        ("priv-2", "pub-2"),
        ("priv-3", "pub-3"),
    ]));

    let client = HadalClient::from_session(Session {
        token: Some("valid-jwt".into()),
        renew_token: Some("renew-jwt".into()),
        token_expires_at: None,
    })
    .with_config_dir(dir.path().to_path_buf())
    .with_transport(transport.clone())
    .with_clock(clock.clone())
    .with_key_generator(keygen.clone());

    // 1. First call generates and registers key #1, persisting wg_key.json
    let k1 = client.ensure_wireguard_key().await.unwrap();
    assert_eq!(k1.private_key, "priv-1");
    assert_eq!(k1.public_key, "pub-1");
    assert_eq!(k1.key_id.as_deref(), Some("hadal-key-1"));
    assert_eq!(transport.recorded().len(), 1);
    assert_eq!(
        FileWgKeyStore::new(dir.path()).load().as_ref(),
        Some(&k1)
    );

    // 2. Immediate second call (e.g. gaming scan -> connect) makes ZERO HTTP requests
    let k1_again = client.ensure_wireguard_key().await.unwrap();
    assert_eq!(k1_again, k1);
    assert_eq!(transport.recorded().len(), 1);

    // 3. Separate client pointing at same config dir (CLI + GUI sharing state) reuses key with ZERO HTTP calls
    let second_client = HadalClient::from_session(Session {
        token: Some("valid-jwt".into()),
        renew_token: None,
        token_expires_at: None,
    })
    .with_config_dir(dir.path().to_path_buf())
    .with_transport(transport.clone())
    .with_clock(clock.clone())
    .with_key_generator(keygen.clone());
    assert_eq!(second_client.ensure_wireguard_key().await.unwrap(), k1);
    assert_eq!(transport.recorded().len(), 1);

    // 4. After > 1 hour, runs read-only /validate and keeps key #1 without re-registering
    clock.set(now_start + WG_KEY_VALIDATE_INTERVAL_SECS + 10);
    let k1_validated = client.ensure_wireguard_key().await.unwrap();
    assert_eq!(k1_validated.public_key, "pub-1");
    assert_eq!(reg_counter.load(Ordering::SeqCst), 1);
    assert!(transport
        .recorded()
        .last()
        .unwrap()
        .url
        .ends_with("/public-keys/validate"));

    // 5. Transient 500 from /validate keeps reusing locally valid key #1
    *validate_mode.lock().unwrap() = "500";
    clock.set(now_start + 2 * WG_KEY_VALIDATE_INTERVAL_SECS + 20);
    let k1_fallback = client.ensure_wireguard_key().await.unwrap();
    assert_eq!(k1_fallback.public_key, "pub-1");
    assert_eq!(reg_counter.load(Ordering::SeqCst), 1);

    // 6. Server 404 from /validate (early revocation) self-heals by registering key #2
    *validate_mode.lock().unwrap() = "404";
    clock.set(now_start + 3 * WG_KEY_VALIDATE_INTERVAL_SECS + 30);
    let k2 = client.ensure_wireguard_key().await.unwrap();
    assert_eq!(k2.private_key, "priv-2");
    assert_eq!(k2.public_key, "pub-2");
    assert_eq!(k2.key_id.as_deref(), Some("hadal-key-2"));
    assert_eq!(reg_counter.load(Ordering::SeqCst), 2);

    // 7. Near expiry (< 12h remaining before 2026-12-12T17:57:36Z) deletes key #2 and rotates to key #3
    let k2_exp = k2.effective_expires_at_epoch().unwrap();
    clock.set(k2_exp - WG_KEY_RENEWAL_MARGIN_SECS + 60);
    let k3 = client.ensure_wireguard_key().await.unwrap();
    assert_eq!(k3.private_key, "priv-3");
    assert_eq!(k3.key_id.as_deref(), Some("hadal-key-3"));
    assert!(transport.recorded().iter().any(|r| {
        r.method == reqwest::Method::DELETE
            && r.url.ends_with("/v1/account/users/public-keys/hadal-key-2")
    }));

    // 8. Logout deletes Hadal's own key #3 and removes both wg_key.json and session.json
    client.logout().await;
    assert!(PersistedWgKey::load_from(dir.path()).is_none());
    assert!(Session::load_from(dir.path()).is_none());
    assert!(transport.recorded().iter().any(|r| {
        r.method == reqwest::Method::DELETE
            && r.url.ends_with("/v1/account/users/public-keys/hadal-key-3")
    }));
}

#[tokio::test]
async fn register_public_key_handles_409_conflict_via_validate() {
    let dir = TempDir::new("wg-key-409");
    let transport = Arc::new(MockTransport::new(move |req| {
        if req.url.ends_with("/v1/account/users/public-keys") {
            return Ok(HttpResponse {
                status: 409,
                body: b"{\"message\":\"Conflict\"}".to_vec(),
            });
        }
        if req.url.ends_with("/v1/account/users/public-keys/validate") {
            return Ok(HttpResponse {
                status: 200,
                body: br#"{"id":"existing-409-id","pubKey":"pub-dup","expiresAt":"2026-12-05T17:57:36+00:00"}"#.to_vec(),
            });
        }
        Ok(HttpResponse {
            status: 404,
            body: b"{}".to_vec(),
        })
    }));

    let client = HadalClient::from_session(Session {
        token: Some("valid-jwt".into()),
        renew_token: None,
        token_expires_at: None,
    })
    .with_config_dir(dir.path().to_path_buf())
    .with_transport(transport);

    let resp = client.register_public_key("pub-dup").await.unwrap();
    assert_eq!(resp.key_id(), Some("existing-409-id"));
    assert_eq!(resp.expires_at(), Some("2026-12-05T17:57:36+00:00"));
}
