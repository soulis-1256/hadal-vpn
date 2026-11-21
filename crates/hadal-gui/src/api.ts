import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { openUrl } from "@tauri-apps/plugin-opener";
import type {
  AppSettings,
  AuthResponse,
  Cluster,
  DaemonEnvelope,
  DaemonStatus,
  DesktopAppEntry,
  GameProfile,
  GamingScanReport,
  RemoteCodeResponse,
  SplitAppStatus,
  SplitMode,
  UserLocation,
  UserMe,
} from "./types";

export interface ConnectClusterOptions {
  clusterId: string;
  endpointOverride?: string | null;
  mtuOverride?: number | null;
  gameOnlyCidrs?: string[] | null;
}

/** Injectable transport boundary decoupling UI state and views from global Tauri IPC. */
export interface VpnApi {
  isLoggedIn: () => Promise<boolean>;
  createRemoteLogin: () => Promise<RemoteCodeResponse>;
  pollRemoteLogin: (hash: string) => Promise<AuthResponse>;
  getUserMe: () => Promise<UserMe>;
  logout: () => Promise<void>;

  getServers: (forceRefresh?: boolean) => Promise<Cluster[]>;
  getUserLocation: () => Promise<UserLocation>;

  getDaemonStatus: () => Promise<DaemonEnvelope>;
  connectCluster: (opts: ConnectClusterOptions) => Promise<DaemonStatus>;
  disconnectTunnel: (keepKillswitch?: boolean) => Promise<DaemonStatus>;
  setKillswitch: (
    enabled: boolean,
    ipv6Block: boolean,
    bypassLan: boolean,
  ) => Promise<DaemonStatus>;

  getSettings: () => Promise<AppSettings>;
  saveSettings: (settings: AppSettings) => Promise<AppSettings>;

  getBuiltinGames: () => Promise<GameProfile[]>;
  scanGaming: (
    gameId: string,
    regionId: string,
    customHost?: string | null,
  ) => Promise<GamingScanReport>;
  connectGamingBest: (
    gameId: string,
    regionId: string,
    customHost: string | null,
    gameOnly: boolean,
  ) => Promise<GamingScanReport>;

  discoverSplitApps: () => Promise<DesktopAppEntry[]>;
  getSplitAppStatuses: (apps: string[], mode: SplitMode) => Promise<SplitAppStatus[]>;
  splitLaunchApp: (command: string, mode: SplitMode) => Promise<number>;

  hideWindow: () => Promise<void>;
  quitApp: () => Promise<void>;
  openExternal: (url: string) => Promise<void>;
  listenDaemonStatus: (cb: (env: DaemonEnvelope) => void) => Promise<UnlistenFn>;
}

/** Default production VpnApi backed by Tauri IPC commands and events. */
export function createTauriApi(): VpnApi {
  return {
    isLoggedIn: () => invoke<boolean>("is_logged_in"),
    createRemoteLogin: () => invoke<RemoteCodeResponse>("create_remote_login"),
    pollRemoteLogin: (hash) => invoke<AuthResponse>("poll_remote_login", { hash }),
    getUserMe: () => invoke<UserMe>("get_user_me"),
    logout: () => invoke<void>("logout"),

    getServers: (forceRefresh = false) => invoke<Cluster[]>("get_servers", { forceRefresh }),
    getUserLocation: () => invoke<UserLocation>("get_user_location"),

    getDaemonStatus: () => invoke<DaemonEnvelope>("get_daemon_status"),
    connectCluster: (opts) =>
      invoke<DaemonStatus>("connect_cluster", {
        clusterId: opts.clusterId,
        endpointOverride: opts.endpointOverride ?? null,
        mtuOverride: opts.mtuOverride ?? null,
        gameOnlyCidrs: opts.gameOnlyCidrs ?? null,
      }),
    disconnectTunnel: (keepKillswitch = false) =>
      invoke<DaemonStatus>("disconnect_tunnel", { keepKillswitch }),
    setKillswitch: (enabled, ipv6Block, bypassLan) =>
      invoke<DaemonStatus>("set_killswitch", { enabled, ipv6Block, bypassLan }),

    getSettings: () => invoke<AppSettings>("get_settings"),
    saveSettings: (settings) => invoke<AppSettings>("save_settings_cmd", { settings }),

    getBuiltinGames: () => invoke<GameProfile[]>("get_builtin_games"),
    scanGaming: (gameId, regionId, customHost) =>
      invoke<GamingScanReport>("scan_gaming", {
        gameId,
        regionId,
        customHost: customHost ?? null,
      }),
    connectGamingBest: (gameId, regionId, customHost, gameOnly) =>
      invoke<GamingScanReport>("connect_gaming_best", {
        gameId,
        regionId,
        customHost,
        gameOnly,
      }),

    discoverSplitApps: () => invoke<DesktopAppEntry[]>("discover_split_apps"),
    getSplitAppStatuses: (apps, mode) =>
      invoke<SplitAppStatus[]>("get_split_app_statuses", { apps, mode }),
    splitLaunchApp: (command, mode) =>
      invoke<number>("split_launch_app", { command, mode }),

    hideWindow: () => invoke<void>("hide_window"),
    quitApp: () => invoke<void>("quit_app"),
    openExternal: (url) => openUrl(url),
    listenDaemonStatus: (cb) => listen<DaemonEnvelope>("daemon-status", (ev) => cb(ev.payload)),
  };
}

export const api: VpnApi = createTauriApi();
