import { createMemo, Match, onCleanup, Show, Switch } from "solid-js";
import { api, type VpnApi } from "./api";
import { AboutView } from "./components/AboutView";
import { AddAppView } from "./components/AddAppView";
import { AuthView } from "./components/AuthView";
import { GamingView } from "./components/GamingView";
import { HomeLayer } from "./components/HomeLayer";
import { LocationsSheet } from "./components/LocationsSheet";
import { MinimizeButton } from "./components/MinimizeButton";
import { NoticeBanner } from "./components/NoticeBanner";
import { SettingsView } from "./components/SettingsView";
import { SplitTunnelView } from "./components/SplitTunnelView";
import { buildTieredGlobeData } from "./globe/clusterPins";
import { OrbitGlobe, type GlobeVisualState } from "./globe/OrbitGlobe";
import { createAppStore } from "./state/appStore";

interface AppProps {
  api?: VpnApi;
}

export function App(props: AppProps) {
  const client = props.api ?? api;
  const store = createAppStore(client);
  store.mountLifecycle();

  const visualDeviceState = createMemo(() => {
    switch (store.daemon().status.state) {
      case "protected":
        return "protected";
      case "connecting":
        return "connecting";
      case "killswitch_locked":
        return "locked";
      default:
        return "idle";
    }
  });

  const globeVisualState = createMemo<GlobeVisualState>(() => {
    const st = store.daemon().status.state;
    if (st === "protected") return "protected";
    if (st === "connecting") return "connecting";
    return "idle";
  });

  const tieredGlobeData = createMemo(() =>
    buildTieredGlobeData(
      store.clusters(),
      store.daemon().status.cluster_id,
      store.selectedCluster()?.id ?? null,
      store.gamingReport(),
    ),
  );

  const fullAnimClass = () => {
    const a = store.subAnim();
    if (a === "in") return "anim-in";
    if (a === "back") return "anim-back";
    return "";
  };

  let spotRaf = 0;
  let pendingSpotEv: PointerEvent | null = null;

  onCleanup(() => {
    if (spotRaf && typeof window.cancelAnimationFrame === "function") {
      window.cancelAnimationFrame(spotRaf);
    }
    pendingSpotEv = null;
  });

  function applyPointerSpot(ev: PointerEvent) {
    const target = ev.target as HTMLElement | null;
    const spot = target?.closest<HTMLElement>("[data-spot]");
    if (!spot || !spot.isConnected) return;
    const rect = spot.getBoundingClientRect();
    spot.style.setProperty("--mx", `${ev.clientX - rect.left}px`);
    spot.style.setProperty("--my", `${ev.clientY - rect.top}px`);
  }

  function handlePointerMove(ev: PointerEvent) {
    if (typeof window.requestAnimationFrame !== "function") {
      applyPointerSpot(ev);
      return;
    }
    pendingSpotEv = ev;
    if (spotRaf) return;
    spotRaf = window.requestAnimationFrame(() => {
      spotRaf = 0;
      const latest = pendingSpotEv;
      pendingSpotEv = null;
      if (latest) applyPointerSpot(latest);
    });
  }

  return (
    <Show
      when={store.loggedIn() !== null}
      fallback={
        <div
          class="device"
          data-state="idle"
          style={{
            display: "flex",
            "flex-direction": "column",
            "align-items": "center",
            "justify-content": "center",
            gap: "12px",
          }}
        >
          <div style={{ position: "absolute", top: "9px", right: "14px" }}>
            <MinimizeButton onClick={store.hideWindow} />
          </div>
          <div class="wm">
            H<span>A</span>DAL
          </div>
          <div class="mono" style={{ "font-size": "11px", color: "var(--mute)" }}>
            Connecting to daemon…
          </div>
        </div>
      }
    >
      <Show
        when={store.loggedIn()}
        fallback={
          <div onPointerMove={handlePointerMove} style={{ width: "100%", height: "100%" }}>
            <AuthView
              api={client}
              onMinimize={store.hideWindow}
              onAuthenticated={() => {
                store.setLoggedIn(true);
                void store.bootstrapAuthedData();
              }}
            />
          </div>
        }
      >
        <div
          class="device"
          data-state={visualDeviceState()}
          data-mode={store.topRoute().kind}
          onPointerMove={handlePointerMove}
        >
          <OrbitGlobe
            tieredData={tieredGlobeData()}
            activeClusterId={store.daemon().status.cluster_id}
            selectedClusterId={store.selectedCluster()?.id ?? null}
            hoveredClusterId={store.hoveredClusterId()}
            tunnelState={globeVisualState()}
            scanning={store.scanningGaming()}
            homeActive={store.topRoute().kind === "home"}
            obscured={store.topRoute().kind === "full"}
            focusRequest={store.focusRequest()}
            onSelectCluster={(id) => void store.selectClusterFromGlobe(id)}
          />

          <HomeLayer
            daemon={store.daemon()}
            selectedCluster={store.selectedCluster()}
            userLocation={store.userLocation()}
            gamingReport={store.gamingReport()}
            tunnelBusy={store.tunnelBusy()}
            killswitchEnabled={store.settings().killswitch}
            hidden={store.topRoute().kind !== "home"}
            onOpenRoute={store.openRoute}
            onMinimize={store.hideWindow}
            onQuickConnect={() => void store.quickConnect()}
            onDisconnect={(keepKs) => void store.disconnect(keepKs)}
            onRetryDaemon={() => void store.refreshDaemon()}
          />

          <div
            class="backdrop"
            classList={{ open: store.topRoute().kind === "sheet" }}
            onClick={() => store.closeSheets()}
          />

          <LocationsSheet
            open={store.topRoute().id === "locations"}
            clusters={store.clusters()}
            activeClusterId={store.daemon().status.cluster_id}
            selectedClusterId={store.selectedCluster()?.id ?? null}
            connectingClusterId={store.connectingClusterId()}
            gamingReport={store.gamingReport()}
            tunnelBusy={store.tunnelBusy()}
            onClose={() => store.closeSheets()}
            onConnect={(id) => void store.connectCluster(id)}
            onRefresh={store.refreshServers}
            onHoverCluster={store.setHoveredClusterId}
          />

          <div
            class="full-layer"
            classList={{ open: store.topRoute().kind === "full" }}
            aria-hidden={store.topRoute().kind !== "full"}
          >
            <Switch>
              <Match when={store.topRoute().id === "gaming"}>
                <GamingView
                  games={store.games()}
                  favoriteGame={store.settings().favorite_game}
                  favoriteRegion={store.settings().favorite_game_region}
                  gameOnlyRouting={store.settings().game_only_routing}
                  scanning={store.scanningGaming()}
                  connectingBest={store.connectingGaming()}
                  report={store.gamingReport()}
                  animClass={fullAnimClass()}
                  onBack={store.popRoute}
                  onMinimize={store.hideWindow}
                  onUpdateGameSettings={(game, region, gameOnly) =>
                    void store.updateSettings({
                      favorite_game: game,
                      favorite_game_region: region,
                      game_only_routing: gameOnly,
                    })
                  }
                  onScan={(g, r, h) => void store.scanGaming(g, r, h)}
                  onConnectBest={(g, r, h, go) => void store.connectGamingBest(g, r, h, go)}
                  onConnectCandidate={(cand, report) => void store.connectCandidate(cand, report)}
                  onHoverCluster={store.setHoveredClusterId}
                />
              </Match>

              <Match when={store.topRoute().id === "settings"}>
                <SettingsView
                  daemon={store.daemon()}
                  settings={store.settings()}
                  userMe={store.userMe()}
                  animClass={fullAnimClass()}
                  onBack={store.popRoute}
                  onMinimize={store.hideWindow}
                  onOpenSplit={() => store.openRoute("settings/split")}
                  onOpenAbout={() => store.openRoute("settings/about")}
                  onUpdateSettings={(patch) => void store.updateSettings(patch)}
                  onToggleKillswitch={(enabled) => void store.toggleKillswitch(enabled)}
                  onSignOut={() => void store.signOut()}
                  onQuit={store.quitApp}
                />
              </Match>

              <Match when={store.topRoute().id === "settings/about"}>
                <AboutView
                  animClass={fullAnimClass()}
                  onBack={store.popRoute}
                  onMinimize={store.hideWindow}
                  onOpenExternal={(url) => void client.openExternal(url)}
                />
              </Match>

              <Match when={store.topRoute().id === "settings/split"}>
                <SplitTunnelView
                  splitTunnel={store.settings().split_tunnel}
                  appStatusesByMode={store.appStatusesByMode()}
                  animClass={fullAnimClass()}
                  onBack={store.popRoute}
                  onMinimize={store.hideWindow}
                  onOpenAddApps={() => store.openRoute("settings/split/apps")}
                  onUpdateSplitTunnel={(next) => void store.updateSettings({ split_tunnel: next })}
                  onLaunchApp={(cmd) => void store.launchSplitApp(cmd)}
                />
              </Match>

              <Match when={store.topRoute().id === "settings/split/apps"}>
                <AddAppView
                  splitTunnel={store.settings().split_tunnel}
                  animClass={fullAnimClass()}
                  onBack={store.popRoute}
                  onMinimize={store.hideWindow}
                  onDiscoverApps={() => client.discoverSplitApps()}
                  onUpdateSplitTunnel={(next) => void store.updateSettings({ split_tunnel: next })}
                />
              </Match>
            </Switch>
          </div>

          <Show when={store.noticeError()}>
            {(msg) => <NoticeBanner message={msg()} onDismiss={() => store.setNoticeError(null)} />}
          </Show>
        </div>
      </Show>
    </Show>
  );
}
