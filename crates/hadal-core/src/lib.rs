pub mod auth;
pub mod client;
pub mod config;
pub mod error;
pub mod gaming;
pub mod ipc;
pub mod platform;
pub mod servers;
pub mod split_tunnel;
pub mod transport;
pub mod wireguard;

pub use auth::{jwt_is_expired, jwt_is_expired_at, FileSessionStore, Session, SessionStore};
pub use client::{
    HttpRequest, HttpResponse, HttpTransport, KeyRegistrar, ReqwestHttpTransport, HadalApi,
    HadalClient,
};
pub use config::{
    daemon_socket_path, default_tunnel_dns, endpoint_for_domain, load_settings, load_settings_from,
    save_settings, save_settings_to, settings_path, settings_path_in, hadal_config_dir,
    split_host_port_u16, AppSettings, FileSettingsStore, SettingsStore, DEFAULT_SOCKET_PATH,
    DEFAULT_WG_IFACE, DEFAULT_WG_PORT,
};
pub use error::{Result, HadalError};
pub use gaming::{
    build_endpoint_candidate, builtin_games, cidrs_from_ipv4s, discover_doh_ipv4s,
    discover_doh_ipv4s_with, discover_doh_ipv4s_with_http, discover_doh_pool_ipv4s_with,
    discover_doh_pool_ipv4s_with_http, discover_wan_pmtu, discover_wan_pmtu_with_mark,
    discover_wan_pmtu_with_prober, estimate_fiber_rtt_ms, finalize_gaming_candidates,
    find_game_region, is_special_cluster, is_virtual_cluster, measure_icmp_stats,
    measure_icmp_stats_on_iface, measure_icmp_stats_with_mark, parse_ping_output,
    pick_diverse_verify_targets, pick_fastest_ipv4_with_mark, pick_fastest_ipv4_with_prober,
    prepare_connect_target_with, probe_gaming_candidates, probe_gaming_candidates_with,
    recommended_wg_mtu, resolve_fastest_endpoint_ip, resolve_fastest_endpoint_ip_with,
    resolve_game_cidrs, resolve_game_cidrs_with_prober, resolve_gaming_target,
    scan_gaming_with_deps, strip_host_port, DohTransport, EndpointCandidate, GameProfile,
    GameRegion, GamingScanReport, NetworkProber, PingStats, ReqwestDohTransport,
    SystemNetworkProber, MAX_PROBED_IPS_PER_CLUSTER,
};
pub use ipc::{
    prepare_connect_target, query_daemon_status, scan_gaming_with_daemon, send_request,
    send_request_on_stream, ConnectSpec, DaemonClient, DaemonRequest, DaemonResponse, DaemonStatus,
    EndpointProbeResult, TunnelState, UnixDaemonClient, VerifiedTunnelResult, VerifyTarget,
    WanGamingProbe,
};
pub use platform::{BoxFuture, Clock, Sleeper, SystemClock, TokioSleeper};
pub use servers::{Cluster, Coordinates, UserLocation};
pub use split_tunnel::{
    active_slice_for_mode, app_statuses, discover_desktop_apps, ensure_user_slice_dir,
    find_app_pids, launch_app_in_slice, move_app_to_slice, reconcile_split_slices,
    resolve_user_slice_cgroup_path, AppCatalog, CgroupManager, DesktopAppEntry, PolicyStore,
    ProcessInspector, ProcessSnapshot, SettingsPolicyStore, SplitAppStatus, SplitMode,
    SplitTunnelConfig, SplitTunnelManager, SysinfoProcessInspector, SystemdCgroupManager,
    XdgAppCatalog, BYPASS_SLICE, DEFAULT_SLICE, VPN_SLICE,
};
pub use wireguard::{
    normalize_wg_address, parse_rfc3339_utc_secs, FileWgKeyStore, KeyPairGenerator,
    OsKeyPairGenerator, PersistedWgKey, RegisterPublicKeyResponse, WgKeyPair, WgKeyStore,
    WG_KEY_FALLBACK_TTL_SECS, WG_KEY_FILENAME, WG_KEY_RENEWAL_MARGIN_SECS,
    WG_KEY_VALIDATE_INTERVAL_SECS,
};
