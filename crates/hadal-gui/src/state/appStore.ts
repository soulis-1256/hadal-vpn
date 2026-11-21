import { createMemo, createSignal, onCleanup, onMount } from "solid-js";
import type { VpnApi } from "../api";
import type { FocusRequest } from "../globe/OrbitGlobe";
import type {
  ActiveSplitMode,
  AppSettings,
  Cluster,
  DaemonEnvelope,
  DaemonStatus,
  EndpointCandidate,
  GameProfile,
  GamingScanReport,
  RouteId,
  RouteKind,
  SplitAppStatusMap,
  SplitTunnelConfig,
  SubPageAnim,
  UserLocation,
  UserMe,
} from "../types";

export interface RouteEntry {
  id: RouteId;
  kind: RouteKind;
}

const ROUTE_KIND: Record<RouteId, RouteKind> = {
  home: "home",
  locations: "sheet",
  gaming: "full",
  settings: "full",
  "settings/split": "full",
  "settings/split/apps": "full",
  "settings/about": "full",
};

export const DEFAULT_SETTINGS: AppSettings = {
  killswitch: true,
  ipv6_block: true,
  bypass_lan: true,
  auto_mtu: true,
  manual_mtu: null,
  split_tunnel: {
    mode: "bypass",
    apps: ["steam", "discord"],
    bypass_apps: ["steam", "discord"],
    only_vpn_apps: [],
    cgroup_paths: [],
    game_only_cidrs: [],
  },
  favorite_game: "fortnite",
  favorite_game_region: "eu-de",
  game_only_routing: false,
  last_cluster_id: null,
};

export const DEFAULT_ENVELOPE: DaemonEnvelope = {
  reachable: false,
  status: {
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
    killswitch: false,
    ipv6_block: true,
    bypass_lan: true,
    split_mode: "off",
    split_cgroup_paths: [],
    game_only_cidrs: [],
    rx_bytes: 0,
    tx_bytes: 0,
    last_handshake_epoch: null,
    last_error: null,
  },
  error: null,
};

const EMPTY_SPLIT_STATUSES: SplitAppStatusMap = {
  bypass: [],
  only_vpn: [],
};

export function appsForSplitMode(st: SplitTunnelConfig, mode: ActiveSplitMode): string[] {
  const list = mode === "only_vpn" ? st.only_vpn_apps : st.bypass_apps;
  if (list) return list;
  return st.mode === mode ? st.apps : [];
}

export function badgeLabelFor(env: DaemonEnvelope): string {
  const st = env.status;
  switch (st.state) {
    case "protected":
      return st.location ?? st.country ?? "Protected";
    case "connecting":
      return "Connecting";
    case "killswitch_locked":
      return "Locked";
    default:
      return env.reachable ? "ISP" : "Offline";
  }
}

/** Reactive application store parameterized by an injected VpnApi transport. */
export function createAppStore(api: VpnApi) {
  let disposed = false;
  let unlistenFn: (() => void) | undefined;
  let launchRefreshTimer: number | undefined;
  let focusSeq = 0;

  const [loggedIn, setLoggedIn] = createSignal<boolean | null>(null);
  const [routeStack, setRouteStack] = createSignal<RouteEntry[]>([{ id: "home", kind: "home" }]);
  const [subAnim, setSubAnim] = createSignal<SubPageAnim>("none");

  const [daemon, setDaemon] = createSignal<DaemonEnvelope>(DEFAULT_ENVELOPE);
  const [settings, setSettings] = createSignal<AppSettings>(DEFAULT_SETTINGS);
  const [clusters, setClusters] = createSignal<Cluster[]>([]);
  const [games, setGames] = createSignal<GameProfile[]>([]);
  const [userLocation, setUserLocation] = createSignal<UserLocation | null>(null);
  const [userMe, setUserMe] = createSignal<UserMe | null>(null);
  const [appStatusesByMode, setAppStatusesByMode] =
    createSignal<SplitAppStatusMap>(EMPTY_SPLIT_STATUSES);

  const [tunnelBusy, setTunnelBusy] = createSignal(false);
  const [connectingClusterId, setConnectingClusterId] = createSignal<string | null>(null);
  const [scanningGaming, setScanningGaming] = createSignal(false);
  const [connectingGaming, setConnectingGaming] = createSignal(false);
  const [gamingReport, setGamingReport] = createSignal<GamingScanReport | null>(null);
  const [noticeError, setNoticeError] = createSignal<string | null>(null);
  const [hoveredClusterId, setHoveredClusterId] = createSignal<string | null>(null);
  const [focusRequest, setFocusRequest] = createSignal<FocusRequest | null>(null);

  const topRoute = createMemo(() => routeStack()[routeStack().length - 1]);
  const badgeLabel = createMemo(() => badgeLabelFor(daemon()));

  const selectedCluster = createMemo<Cluster | null>(() => {
    const list = clusters();
    if (list.length === 0) return null;
    const statusId = daemon().status.cluster_id;
    if (statusId) {
      const active = list.find((c) => c.id === statusId);
      if (active) return active;
    }
    const lastId = settings().last_cluster_id;
    if (lastId) {
      const saved = list.find((c) => c.id === lastId);
      if (saved) return saved;
    }
    return [...list].sort((a, b) => (a.load ?? 999) - (b.load ?? 999))[0] ?? list[0];
  });

  function focusCluster(clusterId: string) {
    focusSeq += 1;
    setFocusRequest({ clusterId, seq: focusSeq });
  }

  function openRoute(id: RouteId) {
    const kind = ROUTE_KIND[id];
    const stack = routeStack();
    const prev = stack[stack.length - 1];
    if (prev.id === id) return;

    setHoveredClusterId(null);
    setSubAnim(prev.kind === "full" && kind === "full" ? "in" : "none");
    setRouteStack([...stack, { id, kind }]);
    if (id === "settings" || id === "settings/split") {
      void refreshAppStatuses();
    }
  }

  function popRoute() {
    const stack = routeStack();
    if (stack.length <= 1) return;
    const prev = stack[stack.length - 1];
    const nextStack = stack.slice(0, -1);
    const nextTop = nextStack[nextStack.length - 1];
    setHoveredClusterId(null);
    setSubAnim(prev.kind === "full" && nextTop.kind === "full" ? "back" : "none");
    setRouteStack(nextStack);
  }

  function closeSheets() {
    setHoveredClusterId(null);
    setRouteStack((stack) => {
      const next = [...stack];
      while (next.length > 1 && next[next.length - 1].kind === "sheet") {
        next.pop();
      }
      return next;
    });
  }

  function popToHome() {
    setHoveredClusterId(null);
    setSubAnim("none");
    setRouteStack([{ id: "home", kind: "home" }]);
  }

  function applyConnectedStatus(status: DaemonStatus) {
    setDaemon({ reachable: true, status, error: null });
  }

  async function refreshDaemon() {
    try {
      setDaemon(await api.getDaemonStatus());
    } catch {
      // keep existing daemon state on transient IPC errors
    }
  }

  async function refreshLocation() {
    try {
      setUserLocation(await api.getUserLocation());
    } catch {
      // blocked by killswitch or offline
    }
  }

  async function refreshModeAppStatuses(mode: ActiveSplitMode) {
    const apps = appsForSplitMode(settings().split_tunnel, mode);
    if (apps.length === 0) {
      setAppStatusesByMode((prev) => ({ ...prev, [mode]: [] }));
      return;
    }
    try {
      const statuses = await api.getSplitAppStatuses(apps, mode);
      setAppStatusesByMode((prev) => ({ ...prev, [mode]: statuses }));
    } catch {
      // ignore transient split status poll error
    }
  }

  async function refreshAppStatuses(modeOverride?: ActiveSplitMode) {
    if (modeOverride) {
      await refreshModeAppStatuses(modeOverride);
      return;
    }
    await Promise.all([
      refreshModeAppStatuses("bypass"),
      refreshModeAppStatuses("only_vpn"),
    ]);
  }

  async function bootstrapAuthedData() {
    const [srvs, me] = await Promise.allSettled([
      api.getServers(false),
      api.getUserMe(),
    ]);
    if (srvs.status === "fulfilled") setClusters(srvs.value);
    if (me.status === "fulfilled") setUserMe(me.value);
    await Promise.all([refreshDaemon(), refreshLocation(), refreshAppStatuses()]);
  }

  async function reportTunnelError(err: unknown) {
    await refreshDaemon();
    if (topRoute().id !== "home" || !daemon().status.last_error) {
      setNoticeError(String(err));
    }
  }

  async function updateSettings(patch: Partial<AppSettings>) {
    const next: AppSettings = { ...settings(), ...patch };
    setSettings(next);
    try {
      const saved = await api.saveSettings(next);
      setSettings(saved);
      if (patch.split_tunnel && saved.split_tunnel.mode !== "off") {
        await refreshAppStatuses(saved.split_tunnel.mode);
      }
    } catch (e) {
      setNoticeError(String(e));
    }
  }

  async function connectCluster(
    clusterId: string,
    opts?: { endpointOverride?: string; mtuOverride?: number; gameOnlyCidrs?: string[] },
  ) {
    setNoticeError(null);
    setTunnelBusy(true);
    setConnectingClusterId(clusterId);
    focusCluster(clusterId);
    try {
      const status = await api.connectCluster({
        clusterId,
        endpointOverride: opts?.endpointOverride ?? null,
        mtuOverride: opts?.mtuOverride ?? null,
        gameOnlyCidrs: opts?.gameOnlyCidrs ?? null,
      });
      applyConnectedStatus(status);
      setSettings((s) => ({ ...s, last_cluster_id: clusterId }));
      void refreshLocation();
      popToHome();
    } catch (e) {
      await reportTunnelError(e);
    } finally {
      setTunnelBusy(false);
      setConnectingClusterId(null);
    }
  }

  async function quickConnect() {
    const target = selectedCluster();
    if (!target) {
      setNoticeError("Server list empty. Open locations and sync clusters.");
      return;
    }
    await connectCluster(target.id);
  }

  async function selectClusterFromGlobe(clusterId: string) {
    const target = clusters().find((c) => c.id === clusterId);
    if (!target) return;
    focusCluster(clusterId);
    setSettings((s) => ({ ...s, last_cluster_id: clusterId }));

    const st = daemon().status;
    if (st.state === "protected" && st.cluster_id !== clusterId) {
      await connectCluster(clusterId);
    }
  }

  async function disconnect(keepKillswitch: boolean) {
    setNoticeError(null);
    setTunnelBusy(true);
    try {
      const status = await api.disconnectTunnel(keepKillswitch);
      applyConnectedStatus(status);
      setSettings((s) => ({ ...s, killswitch: keepKillswitch }));
      void refreshLocation();
    } catch (e) {
      await reportTunnelError(e);
    } finally {
      setTunnelBusy(false);
    }
  }

  async function toggleKillswitch(enabled: boolean) {
    setNoticeError(null);
    const prev = settings();
    setSettings({ ...prev, killswitch: enabled });
    try {
      const status = await api.setKillswitch(enabled, prev.ipv6_block, prev.bypass_lan);
      applyConnectedStatus(status);
    } catch (e) {
      setSettings(prev);
      setNoticeError(String(e));
    }
  }

  async function scanGaming(gameId: string, regionId: string, customHost: string | null) {
    setNoticeError(null);
    setScanningGaming(true);
    try {
      setGamingReport(await api.scanGaming(gameId, regionId, customHost));
    } catch (e) {
      setNoticeError(String(e));
    } finally {
      setScanningGaming(false);
    }
  }

  async function connectGamingBest(
    gameId: string,
    regionId: string,
    customHost: string | null,
    gameOnly: boolean,
  ) {
    setNoticeError(null);
    setConnectingGaming(true);
    try {
      const report = await api.connectGamingBest(gameId, regionId, customHost, gameOnly);
      setGamingReport(report);
      const bestCluster = report.candidates[0]?.cluster_id;
      if (bestCluster) {
        setSettings((s) => ({ ...s, last_cluster_id: bestCluster }));
        focusCluster(bestCluster);
      }
      await refreshDaemon();
      void refreshLocation();
      popToHome();
    } catch (e) {
      await reportTunnelError(e);
    } finally {
      setConnectingGaming(false);
    }
  }

  async function connectCandidate(cand: EndpointCandidate, report: GamingScanReport) {
    const cidrs = settings().game_only_routing ? report.game_cidrs : [];
    await connectCluster(cand.cluster_id, {
      endpointOverride: `${cand.endpoint_ip}:51820`,
      mtuOverride: report.recommended_mtu,
      gameOnlyCidrs: cidrs,
    });
  }

  async function refreshServers() {
    try {
      setClusters(await api.getServers(true));
    } catch (e) {
      setNoticeError(String(e));
    }
  }

  async function launchSplitApp(command: string) {
    const mode = settings().split_tunnel.mode;
    try {
      await api.splitLaunchApp(command, mode);
      if (mode !== "off") {
        if (launchRefreshTimer !== undefined) {
          window.clearTimeout(launchRefreshTimer);
        }
        launchRefreshTimer = window.setTimeout(() => {
          launchRefreshTimer = undefined;
          if (!disposed) void refreshAppStatuses(mode);
        }, 450);
      }
    } catch (e) {
      setNoticeError(String(e));
    }
  }

  async function signOut() {
    await api.logout();
    setLoggedIn(false);
    setClusters([]);
    setUserMe(null);
    setUserLocation(null);
    setGamingReport(null);
    setAppStatusesByMode(EMPTY_SPLIT_STATUSES);
    setNoticeError(null);
    popToHome();
  }

  function mountLifecycle() {
    const onKeyDown = (ev: KeyboardEvent) => {
      if (ev.key === "Escape" && !ev.defaultPrevented) {
        if (routeStack().length > 1) {
          ev.preventDefault();
          popRoute();
          return;
        }
        void api.hideWindow();
      }
    };
    window.addEventListener("keydown", onKeyDown);

    onCleanup(() => {
      disposed = true;
      window.removeEventListener("keydown", onKeyDown);
      if (launchRefreshTimer !== undefined) {
        window.clearTimeout(launchRefreshTimer);
        launchRefreshTimer = undefined;
      }
      unlistenFn?.();
    });

    onMount(async () => {
      let prevState = daemon().status.state;
      try {
        const unlisten = await api.listenDaemonStatus((env) => {
          setDaemon(env);
          if (env.status.state !== prevState) {
            prevState = env.status.state;
            void refreshLocation();
          }
          const r = topRoute().id;
          if (r === "settings" || r === "settings/split") {
            void refreshAppStatuses();
          }
        });
        if (disposed) {
          unlisten();
          return;
        }
        unlistenFn = unlisten;
      } catch {
        // ignore listener failure in headless/non-Tauri runs
      }

      try {
        const [isAuth, loadedSettings, loadedGames] = await Promise.all([
          api.isLoggedIn(),
          api.getSettings(),
          api.getBuiltinGames(),
        ]);
        if (disposed) return;
        setSettings(loadedSettings);
        setGames(loadedGames);
        setLoggedIn(isAuth);
        await refreshDaemon();
        if (isAuth && !disposed) {
          await bootstrapAuthedData();
        }
      } catch (e) {
        if (disposed) return;
        setNoticeError(String(e));
        setLoggedIn(false);
      }
    });
  }

  return {
    loggedIn,
    setLoggedIn,
    routeStack,
    topRoute,
    subAnim,
    daemon,
    settings,
    clusters,
    selectedCluster,
    games,
    userLocation,
    userMe,
    appStatusesByMode,
    tunnelBusy,
    connectingClusterId,
    scanningGaming,
    connectingGaming,
    gamingReport,
    noticeError,
    setNoticeError,
    hoveredClusterId,
    setHoveredClusterId,
    focusRequest,
    focusCluster,
    badgeLabel,
    openRoute,
    popRoute,
    closeSheets,
    popToHome,
    refreshDaemon,
    bootstrapAuthedData,
    updateSettings,
    connectCluster,
    quickConnect,
    selectClusterFromGlobe,
    disconnect,
    toggleKillswitch,
    scanGaming,
    connectGamingBest,
    connectCandidate,
    refreshServers,
    launchSplitApp,
    signOut,
    hideWindow: () => void api.hideWindow(),
    quitApp: () => void api.quitApp(),
    mountLifecycle,
  };
}
