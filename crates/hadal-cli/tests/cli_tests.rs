use std::collections::{HashMap, VecDeque};
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Parser;
use hadal_cli::{
    build_connect_spec, find_matching_cluster, format, run_with, Cli, CliContext, CliSplitMode,
    Commands, ConnectSpecInput, PingTool, SplitAction, SplitOps, TraceHop,
};
use hadal_core::auth::{AuthResponse, RemoteCodeResponse, UserMe};
use hadal_core::{
    AppSettings, BoxFuture, Cluster, Coordinates, DaemonClient, DaemonRequest, DaemonResponse,
    DaemonStatus, DohTransport, KeyPairGenerator, NetworkProber, PingStats,
    RegisterPublicKeyResponse, Result, SettingsStore, HadalApi, HadalError, Sleeper,
    SplitAppStatus, SplitMode, TunnelState, UserLocation, WgKeyPair, BYPASS_SLICE, VPN_SLICE,
};

struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

impl Write for SharedBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct FakeApi {
    clusters: Mutex<Vec<Cluster>>,
    user_me: UserMe,
    location: std::result::Result<UserLocation, String>,
    poll_results: Mutex<VecDeque<Result<AuthResponse>>>,
    registered_pubkeys: Mutex<Vec<String>>,
}

impl FakeApi {
    fn new(clusters: Vec<Cluster>) -> Self {
        Self {
            clusters: Mutex::new(clusters),
            user_me: UserMe {
                id: Some("u1".into()),
                email: Some("cli@example.com".into()),
                status: Some("active".into()),
                expires_at: None,
                extra: Default::default(),
            },
            location: Ok(UserLocation {
                ip: "198.51.100.77".into(),
                isp: Some("Surfshark".into()),
                country_code: Some("DE".into()),
                country: Some("Germany".into()),
                region: None,
                city: Some("Frankfurt".into()),
                secured: true,
            }),
            poll_results: Mutex::new(VecDeque::new()),
            registered_pubkeys: Mutex::new(Vec::new()),
        }
    }
}

impl hadal_core::KeyRegistrar for FakeApi {
    fn has_session(&self) -> BoxFuture<'_, bool> {
        Box::pin(async { true })
    }
    fn register_public_key<'a>(
        &'a self,
        pub_key: &'a str,
    ) -> BoxFuture<'a, Result<RegisterPublicKeyResponse>> {
        Box::pin(async move {
            self.registered_pubkeys
                .lock()
                .unwrap()
                .push(pub_key.to_string());
            Ok(RegisterPublicKeyResponse {
                ip: Some("10.14.0.42".into()),
                extra: Default::default(),
            })
        })
    }
}

impl HadalApi for FakeApi {
    fn create_remote_login(&self) -> BoxFuture<'_, Result<RemoteCodeResponse>> {
        Box::pin(async move {
            Ok(RemoteCodeResponse {
                code: "PAIR42".into(),
                hash: "h-42".into(),
                expires_at: Some(999999),
            })
        })
    }

    fn poll_remote_login<'a>(&'a self, _hash: &'a str) -> BoxFuture<'a, Result<AuthResponse>> {
        Box::pin(async move {
            self.poll_results
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Err(HadalError::Custom("pending".into())))
        })
    }

    fn get_user_me(&self) -> BoxFuture<'_, Result<UserMe>> {
        Box::pin(async move { Ok(self.user_me.clone()) })
    }

    fn get_clusters(&self) -> BoxFuture<'_, Result<Vec<Cluster>>> {
        Box::pin(async move { Ok(self.clusters.lock().unwrap().clone()) })
    }

    fn get_user_location(&self) -> BoxFuture<'_, Result<UserLocation>> {
        Box::pin(async move {
            self.location
                .clone()
                .map_err(HadalError::Custom)
        })
    }
}

type DaemonCallback = Box<dyn Fn(&DaemonRequest) -> Result<DaemonResponse> + Send + Sync>;

struct FakeDaemon {
    requests: Mutex<Vec<DaemonRequest>>,
    handler: Mutex<DaemonCallback>,
}

impl FakeDaemon {
    fn new(
        handler: impl Fn(&DaemonRequest) -> Result<DaemonResponse> + Send + Sync + 'static,
    ) -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
            handler: Mutex::new(Box::new(handler)),
        }
    }

    fn requests(&self) -> Vec<DaemonRequest> {
        self.requests.lock().unwrap().clone()
    }
}

impl DaemonClient for FakeDaemon {
    fn send<'a>(&'a self, req: &'a DaemonRequest) -> BoxFuture<'a, Result<DaemonResponse>> {
        Box::pin(async move {
            self.requests.lock().unwrap().push(req.clone());
            let h = self.handler.lock().unwrap();
            h(req)
        })
    }
}

struct MemSettings(Mutex<AppSettings>);

impl MemSettings {
    fn new(s: AppSettings) -> Self {
        Self(Mutex::new(s))
    }
    fn get(&self) -> AppSettings {
        self.0.lock().unwrap().clone()
    }
}

impl SettingsStore for MemSettings {
    fn load(&self) -> AppSettings {
        self.0.lock().unwrap().clone()
    }
    fn save(&self, settings: &AppSettings) -> Result<()> {
        *self.0.lock().unwrap() = settings.clone();
        Ok(())
    }
}

struct FakeSplitOps {
    moved_pids: Vec<u32>,
    statuses: Vec<SplitAppStatus>,
    launches: Mutex<Vec<(String, String)>>,
}

impl SplitOps for FakeSplitOps {
    fn active_slice_cgroup_paths(&self, mode: SplitMode) -> Vec<String> {
        match mode {
            SplitMode::Bypass => vec![format!("user.slice/{BYPASS_SLICE}")],
            SplitMode::OnlyVpn => vec![format!("user.slice/{VPN_SLICE}")],
            SplitMode::Off => Vec::new(),
        }
    }
    fn slice_cgroup_paths(&self, slice_name: &str) -> Vec<String> {
        vec![format!("user.slice/{slice_name}")]
    }
    fn launch_in_slice(&self, app: &str, slice_name: &str) -> Result<u32> {
        self.launches
            .lock()
            .unwrap()
            .push((app.to_string(), slice_name.to_string()));
        Ok(4444)
    }
    fn move_to_slice_pids(&self, _app: &str, _slice_name: &str) -> Result<Vec<u32>> {
        Ok(self.moved_pids.clone())
    }
    fn app_statuses(&self, _apps: &[String], _expected_slice: Option<&str>) -> Vec<SplitAppStatus> {
        self.statuses.clone()
    }
}

struct FakeDoh;
impl DohTransport for FakeDoh {
    fn get_json<'a>(&'a self, url: &'a str) -> BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move {
            if url.contains("ping-de.ds.on.epicgames.com") {
                return Ok(br#"{"Answer":[{"type":1,"data":"3.66.90.29"}]}"#.to_vec());
            }
            if url.contains("de-fra.prod.surfshark.com") {
                return Ok(
                    br#"{"Answer":[{"type":1,"data":"138.199.19.160"},{"type":1,"data":"156.146.33.77"}]}"#
                        .to_vec(),
                );
            }
            Ok(br#"{"Answer":[]}"#.to_vec())
        })
    }
    fn resolve_system_v4(&self, _host: &str, _port: u16) -> Vec<SocketAddrV4> {
        Vec::new()
    }
}

struct FakeProber;
impl NetworkProber for FakeProber {
    fn measure_icmp(
        &self,
        target: &str,
        _count: u32,
        _fwmark: Option<u32>,
        _iface: Option<&str>,
    ) -> Option<PingStats> {
        let min = match target {
            "156.146.33.77" => 11.2,
            "138.199.19.160" => 22.0,
            _ => 38.5,
        };
        Some(PingStats {
            target: target.into(),
            min_ms: min,
            avg_ms: min + 0.5,
            max_ms: min + 1.0,
            mdev_ms: 0.2,
            loss_pct: 0.0,
        })
    }
    fn df_ping_ok(&self, _target: &str, payload: u16, _fwmark: Option<u32>) -> bool {
        payload <= 1464
    }
    fn resolve_ipv4s(&self, _host: &str) -> Vec<Ipv4Addr> {
        vec![Ipv4Addr::new(3, 66, 90, 29)]
    }
}

struct FixedKeys;
impl KeyPairGenerator for FixedKeys {
    fn generate(&self) -> WgKeyPair {
        WgKeyPair {
            private_key: "priv-cli-key".into(),
            public_key: "pub-cli-key".into(),
        }
    }
}

struct FakePingTool {
    hops: HashMap<u8, TraceHop>,
}
impl PingTool for FakePingTool {
    fn run_ping(&self, _target: &str, _count: u32) -> Result<()> {
        Ok(())
    }
    fn trace_hop(&self, _target: &str, ttl: u8) -> Result<TraceHop> {
        Ok(self.hops.get(&ttl).cloned().unwrap_or(TraceHop::Timeout))
    }
}

struct NoopSleeper;
impl Sleeper for NoopSleeper {
    fn sleep(&self, _duration: Duration) -> BoxFuture<'_, ()> {
        Box::pin(async {})
    }
}

fn sample_clusters() -> Vec<Cluster> {
    vec![
        Cluster {
            id: "de-fra-st".into(),
            country: Some("Germany".into()),
            country_code: Some("DE".into()),
            region: None,
            region_code: None,
            location: Some("Frankfurt Static".into()),
            connection_name: Some("de-fra-st001.prod.surfshark.com".into()),
            pub_key: Some("pk-fra-st".into()),
            tags: vec!["static".into()],
            load: Some(2),
            coordinates: Some(Coordinates {
                latitude: Some(50.11),
                longitude: Some(8.68),
            }),
            flag_url: None,
            cluster_type: Some("static".into()),
        },
        Cluster {
            id: "de-fra".into(),
            country: Some("Germany".into()),
            country_code: Some("DE".into()),
            region: None,
            region_code: None,
            location: Some("Frankfurt".into()),
            connection_name: Some("de-fra.prod.surfshark.com".into()),
            pub_key: Some("pk-fra".into()),
            tags: vec!["p2p".into()],
            load: Some(25),
            coordinates: Some(Coordinates {
                latitude: Some(50.11),
                longitude: Some(8.68),
            }),
            flag_url: None,
            cluster_type: None,
        },
        Cluster {
            id: "at-vie".into(),
            country: Some("Austria".into()),
            country_code: Some("AT".into()),
            region: None,
            region_code: None,
            location: Some("Vienna".into()),
            connection_name: Some("at-vie.prod.surfshark.com".into()),
            pub_key: Some("pk-vie".into()),
            tags: vec!["p2p".into()],
            load: Some(8),
            coordinates: Some(Coordinates {
                latitude: Some(48.20),
                longitude: Some(16.37),
            }),
            flag_url: None,
            cluster_type: None,
        },
    ]
}

fn build_test_ctx(
    api: Arc<dyn HadalApi>,
    daemon: Arc<dyn DaemonClient>,
    settings: Arc<dyn SettingsStore>,
    split: Arc<dyn SplitOps>,
    ping: Arc<dyn PingTool>,
) -> (CliContext, Arc<Mutex<Vec<u8>>>) {
    let buf = Arc::new(Mutex::new(Vec::new()));
    let ctx = CliContext {
        api,
        daemon,
        settings,
        split,
        doh: Arc::new(FakeDoh),
        prober: Arc::new(FakeProber),
        keys: Arc::new(FixedKeys),
        ping,
        sleeper: Arc::new(NoopSleeper),
        stdout: Arc::new(Mutex::new(SharedBuffer(buf.clone()))),
        max_code_polls: 3,
    };
    (ctx, buf)
}

fn output_str(buf: &Arc<Mutex<Vec<u8>>>) -> String {
    String::from_utf8(buf.lock().unwrap().clone()).unwrap()
}

#[test]
fn cli_parses_all_subcommands_and_rejects_invalid_values() {
    let cli = Cli::try_parse_from([
        "hadal-cli",
        "connect",
        "--server",
        "de-fra",
        "--mtu",
        "1380",
        "--no-killswitch",
        "--game-only",
        "ping-de.ds.on.epicgames.com",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Commands::Connect {
            server: Some(_),
            mtu: Some(1380),
            no_killswitch: true,
            game_only: Some(_),
            ..
        }
    ));

    let split_cli = Cli::try_parse_from(["hadal-cli", "split", "mode", "only-vpn"]).unwrap();
    assert!(matches!(
        split_cli.command,
        Commands::Split {
            action: SplitAction::Mode {
                mode: CliSplitMode::OnlyVpn
            }
        }
    ));

    assert!(Cli::try_parse_from(["hadal-cli", "killswitch", "maybe"]).is_err());
    assert!(Cli::try_parse_from(["hadal-cli", "split", "mode", "invalid"]).is_err());
}

#[test]
fn cluster_matching_prefers_dynamic_over_static_and_builds_spec() {
    let matched = find_matching_cluster(sample_clusters(), "de-fra").unwrap();
    assert_eq!(matched.id, "de-fra");

    let spec = build_connect_spec(ConnectSpecInput {
        cluster: &matched,
        endpoint_ip: "156.146.33.77".into(),
        endpoint_port: 51820,
        priv_key: "priv".into(),
        address: "10.14.0.42/32".into(),
        mtu: 1412,
        killswitch: true,
        ipv6_block: true,
        bypass_lan: true,
        split_mode: SplitMode::Bypass,
        split_cgroup_paths: vec!["user.slice/app-hadal_bypass.slice".into()],
        game_only_cidrs: vec!["3.66.90.0/24".into()],
    });
    assert_eq!(spec.cluster_id.as_deref(), Some("de-fra"));
    assert_eq!(spec.pub_key, "pk-fra");
    assert_eq!(spec.dns, vec!["1.1.1.1", "1.0.0.1"]);
    assert_eq!(spec.game_only_cidrs, vec!["3.66.90.0/24"]);
}

#[tokio::test]
async fn cli_auth_servers_keygen_and_quick_pair_commands() {
    let api = Arc::new(FakeApi::new(sample_clusters()));
    api.poll_results.lock().unwrap().push_back(Ok(AuthResponse {
        token: None,
        token_expires_at: None,
        renew_token: None,
        extra: Default::default(),
    }));
    api.poll_results.lock().unwrap().push_back(Ok(AuthResponse {
        token: Some("ok-jwt".into()),
        token_expires_at: None,
        renew_token: Some("ok-ren".into()),
        extra: Default::default(),
    }));

    let daemon = Arc::new(FakeDaemon::new(|_| Ok(DaemonResponse::Status(DaemonStatus::default()))));
    let settings = Arc::new(MemSettings::new(AppSettings::default()));
    let split = Arc::new(FakeSplitOps {
        moved_pids: vec![],
        statuses: vec![],
        launches: Mutex::new(vec![]),
    });
    let ping = Arc::new(FakePingTool {
        hops: HashMap::new(),
    });

    let (ctx, buf) = build_test_ctx(api.clone(), daemon, settings, split, ping);

    run_with(Cli::parse_from(["hadal-cli", "code"]), &ctx)
        .await
        .unwrap();
    // `login` acts as a backward-compatible alias for quick-pair `code`
    api.poll_results.lock().unwrap().push_back(Ok(AuthResponse {
        token: Some("ok-jwt-2".into()),
        token_expires_at: None,
        renew_token: Some("ok-ren-2".into()),
        extra: Default::default(),
    }));
    run_with(Cli::parse_from(["hadal-cli", "login"]), &ctx)
        .await
        .unwrap();
    run_with(Cli::parse_from(["hadal-cli", "me"]), &ctx)
        .await
        .unwrap();
    run_with(
        Cli::parse_from(["hadal-cli", "servers", "--sort-load"]),
        &ctx,
    )
    .await
    .unwrap();
    run_with(Cli::parse_from(["hadal-cli", "keygen"]), &ctx)
        .await
        .unwrap();

    let out = output_str(&buf);
    assert!(out.contains("Login Code: PAIR42"));
    assert!(out.contains("Login authorized! Session saved."));
    assert!(out.contains("User: cli@example.com"));
    assert!(out.contains("Vienna"));
    assert!(!out.contains("Frankfurt Static")); // static excluded unless --include-static
    assert!(out.contains("Registered Address: 10.14.0.42/32"));

    // Quick pair timeout after max_code_polls
    let timeout_err = run_with(Cli::parse_from(["hadal-cli", "code"]), &ctx)
        .await
        .unwrap_err();
    assert!(timeout_err.to_string().contains("Timed out"));
}

#[tokio::test]
async fn cli_connect_status_killswitch_disconnect_and_ipc_error_handling() {
    let api = Arc::new(FakeApi::new(sample_clusters()));
    let daemon = Arc::new(FakeDaemon::new(|req| match req {
        DaemonRequest::Status => Ok(DaemonResponse::Status(DaemonStatus {
            state: TunnelState::Disconnected,
            interface: "hadal-wg".into(),
            ..Default::default()
        })),
        DaemonRequest::Connect(spec) => {
            assert_eq!(spec.endpoint_ip, "156.146.33.77");
            assert_eq!(spec.mtu, 1412);
            assert!(!spec.killswitch); // --no-killswitch passed
            assert_eq!(spec.game_only_cidrs, vec!["3.66.90.0/24"]);
            Ok(DaemonResponse::Status(DaemonStatus {
                state: TunnelState::Protected,
                interface: "hadal-wg".into(),
                endpoint: Some("156.146.33.77:51820".into()),
                location: Some("Frankfurt".into()),
                country: Some("Germany".into()),
                address: Some("10.14.0.42/32".into()),
                mtu: Some(1412),
                rx_bytes: 123,
                tx_bytes: 456,
                ..Default::default()
            }))
        }
        DaemonRequest::SetKillswitch { enabled, .. } => Ok(DaemonResponse::Status(DaemonStatus {
            state: if *enabled {
                TunnelState::KillswitchLocked
            } else {
                TunnelState::Disconnected
            },
            killswitch: *enabled,
            ..Default::default()
        })),
        DaemonRequest::Disconnect { keep_killswitch } => {
            Ok(DaemonResponse::Status(DaemonStatus {
                state: if *keep_killswitch {
                    TunnelState::KillswitchLocked
                } else {
                    TunnelState::Disconnected
                },
                killswitch: *keep_killswitch,
                ..Default::default()
            }))
        }
        other => unreachable!("unexpected {other:?}"),
    }));
    let settings = Arc::new(MemSettings::new(AppSettings::default()));
    let split = Arc::new(FakeSplitOps {
        moved_pids: vec![],
        statuses: vec![],
        launches: Mutex::new(vec![]),
    });
    let ping = Arc::new(FakePingTool {
        hops: HashMap::new(),
    });

    let (ctx, buf) = build_test_ctx(api.clone(), daemon.clone(), settings, split, ping);

    run_with(
        Cli::parse_from([
            "hadal-cli",
            "connect",
            "--server",
            "de-fra",
            "--no-killswitch",
            "--game-only",
            "ping-de.ds.on.epicgames.com",
        ]),
        &ctx,
    )
    .await
    .unwrap();
    run_with(Cli::parse_from(["hadal-cli", "status"]), &ctx)
        .await
        .unwrap();
    run_with(Cli::parse_from(["hadal-cli", "killswitch", "on"]), &ctx)
        .await
        .unwrap();
    run_with(
        Cli::parse_from(["hadal-cli", "disconnect", "--keep-killswitch"]),
        &ctx,
    )
    .await
    .unwrap();

    let out = output_str(&buf);
    assert!(out.contains("State: Protected | Interface: hadal-wg"));
    assert!(out.contains("Exit IP: 198.51.100.77"));
    assert!(out.contains("State: KillswitchLocked (killswitch=true)"));

    // Propagates daemon IPC error cleanly
    let broken_daemon = Arc::new(FakeDaemon::new(|_| {
        Err(HadalError::Custom("Cannot reach hadald at /run/hadald/hadald.sock".into()))
    }));
    let (err_ctx, _) = build_test_ctx(
        api,
        broken_daemon,
        Arc::new(MemSettings::new(AppSettings::default())),
        Arc::new(FakeSplitOps {
            moved_pids: vec![],
            statuses: vec![],
            launches: Mutex::new(vec![]),
        }),
        Arc::new(FakePingTool {
            hops: HashMap::new(),
        }),
    );
    let err = run_with(Cli::parse_from(["hadal-cli", "status"]), &err_ctx)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("Cannot reach hadald"));
}

#[tokio::test]
async fn cli_gaming_split_move_reset_sockets_and_ping_trace() {
    let api = Arc::new(FakeApi::new(sample_clusters()));
    let daemon = Arc::new(FakeDaemon::new(|req| match req {
        DaemonRequest::Status => Ok(DaemonResponse::Status(DaemonStatus {
            state: TunnelState::Disconnected,
            ..Default::default()
        })),
        DaemonRequest::UpdateSplitTunnel(_) => Ok(DaemonResponse::Status(DaemonStatus {
            state: TunnelState::Protected,
            ..Default::default()
        })),
        DaemonRequest::ResetAppSockets { .. } => Ok(DaemonResponse::Ok),
        DaemonRequest::Connect(_) => Ok(DaemonResponse::Status(DaemonStatus {
            state: TunnelState::Protected,
            ..Default::default()
        })),
        _ => Ok(DaemonResponse::Ok),
    }));
    let settings = Arc::new(MemSettings::new(AppSettings::default()));
    let split = Arc::new(FakeSplitOps {
        moved_pids: vec![501, 502],
        statuses: vec![SplitAppStatus {
            name: "steam".into(),
            display_name: "Steam".into(),
            running: true,
            in_split_slice: true,
            slice: Some(BYPASS_SLICE.into()),
            pids: vec![501],
        }],
        launches: Mutex::new(vec![]),
    });
    let ping = Arc::new(FakePingTool {
        hops: HashMap::from([
            (1, TraceHop::Exceeded("10.0.0.1 time exceeded".into())),
            (2, TraceHop::Timeout),
            (3, TraceHop::Reached("64 bytes from 3.66.90.29".into())),
        ]),
    });

    let (ctx, buf) = build_test_ctx(
        api,
        daemon.clone(),
        settings.clone(),
        split.clone(),
        ping,
    );

    // gaming --list & gaming --no-verify --connect --game-only
    run_with(Cli::parse_from(["hadal-cli", "gaming", "--list"]), &ctx)
        .await
        .unwrap();
    run_with(
        Cli::parse_from([
            "hadal-cli",
            "gaming",
            "--no-verify",
            "--connect",
            "--game-only",
        ]),
        &ctx,
    )
    .await
    .unwrap();

    // split mode, launch, move (must trigger ResetAppSockets when Protected!), status
    run_with(
        Cli::parse_from(["hadal-cli", "split", "mode", "only-vpn"]),
        &ctx,
    )
    .await
    .unwrap();
    assert_eq!(settings.get().split_tunnel.mode, SplitMode::OnlyVpn);

    run_with(
        Cli::parse_from(["hadal-cli", "split", "launch", "zen-browser"]),
        &ctx,
    )
    .await
    .unwrap();
    assert!(settings
        .get()
        .split_tunnel
        .only_vpn_apps
        .contains(&"zen-browser".to_string()));

    run_with(
        Cli::parse_from(["hadal-cli", "split", "move", "steam"]),
        &ctx,
    )
    .await
    .unwrap();
    assert!(daemon.requests().iter().any(|r| matches!(
        r,
        DaemonRequest::ResetAppSockets { pids } if pids == &vec![501, 502]
    )));

    run_with(Cli::parse_from(["hadal-cli", "split", "status"]), &ctx)
        .await
        .unwrap();
    run_with(
        Cli::parse_from(["hadal-cli", "ping", "3.66.90.29", "--trace"]),
        &ctx,
    )
    .await
    .unwrap();
    run_with(Cli::parse_from(["hadal-cli", "install-info"]), &ctx)
        .await
        .unwrap();

    let out = output_str(&buf);
    assert!(out.contains("Game: Fortnite (fortnite)"));
    assert!(out.contains("Connected!"));
    assert!(out.contains("Launched zen-browser (pid 4444)"));
    assert!(out.contains("Moved 2 matching process(es)"));
    assert!(out.contains("hop  1: 10.0.0.1 time exceeded"));
    assert!(out.contains("hop  2: *"));
    assert!(out.contains("hop  3: 64 bytes from 3.66.90.29"));
    assert!(out.contains("./scripts/install.sh --reconnect"));

    // Sanity check pure formatting helper
    let empty_table = format::format_servers_table(&[], 10);
    assert!(empty_table.contains("LOCATION"));
}
