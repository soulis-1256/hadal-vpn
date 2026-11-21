export type TunnelState =
  | "disconnected"
  | "connecting"
  | "protected"
  | "killswitch_locked";

export type SplitMode = "bypass" | "only_vpn" | "off";
export type ActiveSplitMode = Exclude<SplitMode, "off">;

export type RouteId =
  | "home"
  | "locations"
  | "gaming"
  | "settings"
  | "settings/split"
  | "settings/split/apps"
  | "settings/about";
export type RouteKind = "home" | "sheet" | "full";
export type SubPageAnim = "none" | "in" | "back";
export type SlideDir = "forward" | "backward" | "fade";
export type TransitionPhase = "idle" | "exiting" | "entering";

export interface SplitTunnelConfig {
  mode: SplitMode;
  apps: string[];
  bypass_apps: string[];
  only_vpn_apps: string[];
  cgroup_paths: string[];
  game_only_cidrs: string[];
}

export interface AppSettings {
  killswitch: boolean;
  ipv6_block: boolean;
  bypass_lan: boolean;
  auto_mtu: boolean;
  manual_mtu: number | null;
  split_tunnel: SplitTunnelConfig;
  favorite_game: string;
  favorite_game_region: string;
  game_only_routing: boolean;
  last_cluster_id: string | null;
}

export interface DaemonStatus {
  state: TunnelState;
  interface: string;
  cluster_id: string | null;
  domain: string | null;
  endpoint: string | null;
  location: string | null;
  country: string | null;
  address: string | null;
  mtu: number | null;
  dns: string[];
  killswitch: boolean;
  ipv6_block: boolean;
  bypass_lan: boolean;
  split_mode: SplitMode;
  split_cgroup_paths: string[];
  game_only_cidrs: string[];
  rx_bytes: number;
  tx_bytes: number;
  last_handshake_epoch: number | null;
  last_error: string | null;
}

export interface DaemonEnvelope {
  reachable: boolean;
  status: DaemonStatus;
  error: string | null;
}

export interface Coordinates {
  latitude: number | null;
  longitude: number | null;
}

export interface Cluster {
  id: string;
  country: string | null;
  countryCode: string | null;
  region: string | null;
  regionCode: string | null;
  location: string | null;
  connectionName: string | null;
  pubKey: string | null;
  tags: string[];
  load: number | null;
  coordinates?: Coordinates | null;
  flagUrl: string | null;
  type: string | null;
}

export interface UserLocation {
  ip: string;
  isp: string | null;
  countryCode: string | null;
  country: string | null;
  region: string | null;
  city: string | null;
  secured: boolean;
}

export interface UserMe {
  id: string | null;
  email: string | null;
  status: string | null;
  expires_at: string | null;
}

export interface AuthResponse {
  token?: string | null;
  tokenExpiresAt?: string | null;
  renewToken?: string | null;
}

export interface RemoteCodeResponse {
  code: string;
  hash: string;
  expiresAt: number | null;
}

export interface GameRegion {
  id: string;
  label: string;
  group: string;
  ping_host: string;
  latitude: number;
  longitude: number;
}

export interface GameProfile {
  id: string;
  name: string;
  regions: GameRegion[];
}

export interface PingStats {
  target: string;
  min_ms: number;
  avg_ms: number;
  max_ms: number;
  mdev_ms: number;
  loss_pct: number;
}

export interface EndpointCandidate {
  cluster_id: string;
  domain: string;
  endpoint_ip: string;
  location: string;
  country: string;
  load: number | null;
  direct_rtt_ms: number;
  estimated_total_ms: number;
  verified_tunnel_ms: number | null;
  verified_mdev_ms: number | null;
  verified_loss_pct?: number | null;
}

export interface GamingScanReport {
  game_id: string;
  region_id: string;
  target_host: string;
  baseline_direct: PingStats | null;
  active_tunnel_ping?: PingStats | null;
  active_tunnel_label?: string | null;
  wan_pmtu: number;
  recommended_mtu: number;
  candidates: EndpointCandidate[];
  game_cidrs: string[];
}

export interface DesktopAppEntry {
  id: string;
  name: string;
  exec: string;
  bin: string;
  wm_class?: string | null;
  running: boolean;
}

export interface SplitAppStatus {
  name: string;
  display_name: string;
  running: boolean;
  in_split_slice: boolean;
  slice: string | null;
  pids: number[];
}

export type SplitAppStatusMap = Record<ActiveSplitMode, SplitAppStatus[]>;
