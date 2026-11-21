import "@testing-library/jest-dom/vitest";
import { vi } from "vitest";
import type { VpnApi } from "../../src/api";
import type {
  AppSettings,
  Cluster,
  DaemonEnvelope,
  DaemonStatus,
  DesktopAppEntry,
  GameProfile,
  GamingScanReport,
  SplitAppStatus,
  UserLocation,
  UserMe,
} from "../../src/types";

export function makeSettings(overrides: Partial<AppSettings> = {}): AppSettings {
  return {
    killswitch: true,
    ipv6_block: true,
    bypass_lan: true,
    auto_mtu: true,
    manual_mtu: null,
    split_tunnel: {
      mode: "bypass",
      apps: ["steam", "discord"],
      bypass_apps: ["steam", "discord"],
      only_vpn_apps: ["firefox"],
      cgroup_paths: [],
      game_only_cidrs: [],
      ...overrides.split_tunnel,
    },
    favorite_game: "fortnite",
    favorite_game_region: "eu-de",
    game_only_routing: false,
    last_cluster_id: null,
    ...overrides,
  };
}

export function makeDaemonStatus(overrides: Partial<DaemonStatus> = {}): DaemonStatus {
  return {
    state: "disconnected",
    interface: "hadal-wg",
    cluster_id: null,
    domain: null,
    endpoint: null,
    location: null,
    country: null,
    address: null,
    mtu: null,
    dns: [],
    killswitch: true,
    ipv6_block: true,
    bypass_lan: true,
    split_mode: "bypass",
    split_cgroup_paths: [],
    game_only_cidrs: [],
    rx_bytes: 0,
    tx_bytes: 0,
    last_handshake_epoch: null,
    last_error: null,
    ...overrides,
  };
}

export function makeEnvelope(
  statusOverrides: Partial<DaemonStatus> = {},
  reachable = true,
  error: string | null = null,
): DaemonEnvelope {
  return {
    reachable,
    status: makeDaemonStatus(statusOverrides),
    error,
  };
}

export const SAMPLE_CLUSTERS: Cluster[] = [
  {
    id: "de-fra",
    country: "Germany",
    countryCode: "DE",
    region: "Europe",
    regionCode: "EU",
    location: "Frankfurt",
    connectionName: "de-fra.prod.surfshark.com",
    pubKey: "pk-fra",
    tags: ["p2p"],
    load: 18,
    coordinates: { latitude: 50.11, longitude: 8.68 },
    flagUrl: null,
    type: "generic",
  },
  {
    id: "at-vie",
    country: "Austria",
    countryCode: "AT",
    region: "Europe",
    regionCode: "EU",
    location: "Vienna",
    connectionName: "at-vie.prod.surfshark.com",
    pubKey: "pk-vie",
    tags: ["p2p"],
    load: 9,
    coordinates: { latitude: 48.2, longitude: 16.37 },
    flagUrl: null,
    type: "generic",
  },
  {
    id: "us-nyc-st",
    country: "United States",
    countryCode: "US",
    region: "Americas",
    regionCode: "NA",
    location: "New York",
    connectionName: "us-nyc-st001.prod.surfshark.com",
    pubKey: "pk-nyc-st",
    tags: ["static"],
    load: 45,
    coordinates: { latitude: 40.71, longitude: -74.0 },
    flagUrl: null,
    type: "static",
  },
];

export const SAMPLE_GAMES: GameProfile[] = [
  {
    id: "fortnite",
    name: "Fortnite",
    regions: [
      {
        id: "eu-de",
        label: "Europe · Germany (Frankfurt)",
        group: "Europe",
        ping_host: "ping-de.ds.on.epicgames.com",
        latitude: 50.11,
        longitude: 8.68,
      },
      {
        id: "na-va",
        label: "NA-East · Virginia",
        group: "North America",
        ping_host: "ping-va.ds.on.epicgames.com",
        latitude: 39.04,
        longitude: -77.48,
      },
    ],
  },
  {
    id: "valorant",
    name: "Valorant",
    regions: [
      {
        id: "eu-fr",
        label: "Europe · Paris",
        group: "Europe",
        ping_host: "dynamodb.eu-west-3.amazonaws.com",
        latitude: 48.85,
        longitude: 2.35,
      },
    ],
  },
];

export const SAMPLE_DESKTOP_APPS: DesktopAppEntry[] = [
  {
    id: "steam",
    name: "Steam",
    exec: "/usr/bin/steam",
    bin: "steam",
    wm_class: "steam",
    running: true,
  },
  {
    id: "obs",
    name: "OBS Studio",
    exec: "/usr/bin/obs",
    bin: "obs",
    wm_class: "obs",
    running: true,
  },
  {
    id: "vlc",
    name: "VLC Media Player",
    exec: "/usr/bin/vlc",
    bin: "vlc",
    wm_class: "vlc",
    running: false,
  },
];

export const SAMPLE_LOCATION: UserLocation = {
  ip: "198.51.100.42",
  isp: "Test ISP",
  countryCode: "DE",
  country: "Germany",
  region: "Hesse",
  city: "Frankfurt",
  secured: false,
};

export const SAMPLE_USER_ME: UserMe = {
  id: "user-1",
  email: "tester@example.com",
  status: "active",
  expires_at: "2027-01-01T00:00:00Z",
};

export const SAMPLE_GAMING_REPORT: GamingScanReport = {
  game_id: "fortnite",
  region_id: "eu-de",
  target_host: "ping-de.ds.on.epicgames.com",
  baseline_direct: {
    target: "ping-de.ds.on.epicgames.com",
    min_ms: 38.0,
    avg_ms: 39.2,
    max_ms: 41.0,
    mdev_ms: 0.45,
    loss_pct: 0,
  },
  active_tunnel_ping: null,
  active_tunnel_label: null,
  wan_pmtu: 1492,
  recommended_mtu: 1412,
  candidates: [
    {
      cluster_id: "de-fra",
      domain: "de-fra.prod.surfshark.com",
      endpoint_ip: "138.199.19.160",
      location: "Frankfurt",
      country: "Germany",
      load: 18,
      direct_rtt_ms: 21.4,
      estimated_total_ms: 22.2,
      verified_tunnel_ms: 24.5,
      verified_mdev_ms: 0.3,
      verified_loss_pct: 0,
    },
    {
      cluster_id: "at-vie",
      domain: "at-vie.prod.surfshark.com",
      endpoint_ip: "87.249.133.9",
      location: "Vienna",
      country: "Austria",
      load: 9,
      direct_rtt_ms: 26.0,
      estimated_total_ms: 38.3,
      verified_tunnel_ms: 40.2,
      verified_mdev_ms: 1.2,
      verified_loss_pct: 12,
    },
  ],
  game_cidrs: ["3.66.0.0/16"],
};

export interface FakeApiController {
  api: VpnApi;
  emitDaemonStatus: (env: DaemonEnvelope) => void;
  mocks: {
    isLoggedIn: ReturnType<typeof vi.fn<VpnApi["isLoggedIn"]>>;
    createRemoteLogin: ReturnType<typeof vi.fn<VpnApi["createRemoteLogin"]>>;
    pollRemoteLogin: ReturnType<typeof vi.fn<VpnApi["pollRemoteLogin"]>>;
    getUserMe: ReturnType<typeof vi.fn<VpnApi["getUserMe"]>>;
    logout: ReturnType<typeof vi.fn<VpnApi["logout"]>>;
    getServers: ReturnType<typeof vi.fn<VpnApi["getServers"]>>;
    getUserLocation: ReturnType<typeof vi.fn<VpnApi["getUserLocation"]>>;
    getDaemonStatus: ReturnType<typeof vi.fn<VpnApi["getDaemonStatus"]>>;
    connectCluster: ReturnType<typeof vi.fn<VpnApi["connectCluster"]>>;
    disconnectTunnel: ReturnType<typeof vi.fn<VpnApi["disconnectTunnel"]>>;
    setKillswitch: ReturnType<typeof vi.fn<VpnApi["setKillswitch"]>>;
    getSettings: ReturnType<typeof vi.fn<VpnApi["getSettings"]>>;
    saveSettings: ReturnType<typeof vi.fn<VpnApi["saveSettings"]>>;
    getBuiltinGames: ReturnType<typeof vi.fn<VpnApi["getBuiltinGames"]>>;
    scanGaming: ReturnType<typeof vi.fn<VpnApi["scanGaming"]>>;
    connectGamingBest: ReturnType<typeof vi.fn<VpnApi["connectGamingBest"]>>;
    discoverSplitApps: ReturnType<typeof vi.fn<VpnApi["discoverSplitApps"]>>;
    getSplitAppStatuses: ReturnType<typeof vi.fn<VpnApi["getSplitAppStatuses"]>>;
    splitLaunchApp: ReturnType<typeof vi.fn<VpnApi["splitLaunchApp"]>>;
    hideWindow: ReturnType<typeof vi.fn<VpnApi["hideWindow"]>>;
    quitApp: ReturnType<typeof vi.fn<VpnApi["quitApp"]>>;
    openExternal: ReturnType<typeof vi.fn<VpnApi["openExternal"]>>;
    listenDaemonStatus: ReturnType<typeof vi.fn<VpnApi["listenDaemonStatus"]>>;
  };
}

export function createFakeVpnApi(
  opts: {
    loggedIn?: boolean;
    settings?: AppSettings;
    envelope?: DaemonEnvelope;
    clusters?: Cluster[];
    games?: GameProfile[];
    location?: UserLocation;
    userMe?: UserMe;
  } = {},
): FakeApiController {
  let currentSettings = opts.settings ?? makeSettings();
  let currentEnv = opts.envelope ?? makeEnvelope();
  const listeners = new Set<(env: DaemonEnvelope) => void>();

  const defaultSplitStatuses = (apps: string[]): SplitAppStatus[] =>
    apps.map((name) => ({
      name,
      display_name: name[0].toUpperCase() + name.slice(1),
      running: name === "steam",
      in_split_slice: name === "steam",
      slice: name === "steam" ? "app-hadal_bypass.slice" : null,
      pids: name === "steam" ? [4242] : [],
    }));

  const mocks: FakeApiController["mocks"] = {
    isLoggedIn: vi.fn<VpnApi["isLoggedIn"]>(async () => opts.loggedIn ?? true),
    createRemoteLogin: vi.fn<VpnApi["createRemoteLogin"]>(async () => ({
      code: "ABCD12",
      hash: "pair-hash",
      expiresAt: Math.floor(Date.now() / 1000) + 300,
    })),
    pollRemoteLogin: vi.fn<VpnApi["pollRemoteLogin"]>(async () => ({})),
    getUserMe: vi.fn<VpnApi["getUserMe"]>(async () => opts.userMe ?? SAMPLE_USER_ME),
    logout: vi.fn<VpnApi["logout"]>(async () => {}),
    getServers: vi.fn<VpnApi["getServers"]>(async () => opts.clusters ?? SAMPLE_CLUSTERS),
    getUserLocation: vi.fn<VpnApi["getUserLocation"]>(async () => opts.location ?? SAMPLE_LOCATION),
    getDaemonStatus: vi.fn<VpnApi["getDaemonStatus"]>(async () => currentEnv),
    connectCluster: vi.fn<VpnApi["connectCluster"]>(async ({ clusterId }) => {
      const cluster = (opts.clusters ?? SAMPLE_CLUSTERS).find((c) => c.id === clusterId);
      currentEnv = makeEnvelope({
        state: "protected",
        cluster_id: clusterId,
        domain: cluster?.connectionName ?? null,
        endpoint: "138.199.19.160:51820",
        location: cluster?.location ?? "Frankfurt",
        country: cluster?.country ?? "Germany",
        address: "10.14.0.2/32",
        mtu: 1412,
        rx_bytes: 2048,
        tx_bytes: 1024,
        last_handshake_epoch: Math.floor(Date.now() / 1000) - 5,
      });
      return currentEnv.status;
    }),
    disconnectTunnel: vi.fn<VpnApi["disconnectTunnel"]>(async (keepKillswitch = false) => {
      currentEnv = makeEnvelope({
        state: keepKillswitch ? "killswitch_locked" : "disconnected",
        killswitch: keepKillswitch,
      });
      return currentEnv.status;
    }),
    setKillswitch: vi.fn<VpnApi["setKillswitch"]>(async (enabled, ipv6Block, bypassLan) => {
      currentEnv = makeEnvelope({
        state: enabled ? "killswitch_locked" : "disconnected",
        killswitch: enabled,
        ipv6_block: ipv6Block,
        bypass_lan: bypassLan,
      });
      return currentEnv.status;
    }),
    getSettings: vi.fn<VpnApi["getSettings"]>(async () => currentSettings),
    saveSettings: vi.fn<VpnApi["saveSettings"]>(async (next) => {
      currentSettings = next;
      return next;
    }),
    getBuiltinGames: vi.fn<VpnApi["getBuiltinGames"]>(async () => opts.games ?? SAMPLE_GAMES),
    scanGaming: vi.fn<VpnApi["scanGaming"]>(async () => SAMPLE_GAMING_REPORT),
    connectGamingBest: vi.fn<VpnApi["connectGamingBest"]>(async () => {
      currentEnv = makeEnvelope({
        state: "protected",
        cluster_id: "de-fra",
        location: "Frankfurt",
        country: "Germany",
        mtu: 1412,
      });
      return SAMPLE_GAMING_REPORT;
    }),
    discoverSplitApps: vi.fn<VpnApi["discoverSplitApps"]>(async () => SAMPLE_DESKTOP_APPS),
    getSplitAppStatuses: vi.fn<VpnApi["getSplitAppStatuses"]>(async (apps) =>
      defaultSplitStatuses(apps),
    ),
    splitLaunchApp: vi.fn<VpnApi["splitLaunchApp"]>(async () => 9999),
    hideWindow: vi.fn<VpnApi["hideWindow"]>(async () => {}),
    quitApp: vi.fn<VpnApi["quitApp"]>(async () => {}),
    openExternal: vi.fn<VpnApi["openExternal"]>(async () => {}),
    listenDaemonStatus: vi.fn<VpnApi["listenDaemonStatus"]>(async (cb) => {
      listeners.add(cb);
      return () => {
        listeners.delete(cb);
      };
    }),
  };

  return {
    api: mocks,
    emitDaemonStatus: (env: DaemonEnvelope) => {
      currentEnv = env;
      for (const cb of listeners) cb(env);
    },
    mocks,
  };
}

export function stubReducedMotion(matches: boolean): () => void {
  const prev = window.matchMedia;
  Object.defineProperty(window, "matchMedia", {
    configurable: true,
    writable: true,
    value: vi.fn((query: string) => ({
      matches: query.includes("prefers-reduced-motion") ? matches : false,
      media: query,
      onchange: null,
      addListener: vi.fn(),
      removeListener: vi.fn(),
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      dispatchEvent: vi.fn(),
    })),
  });
  return () => {
    Object.defineProperty(window, "matchMedia", {
      configurable: true,
      writable: true,
      value: prev,
    });
  };
}
