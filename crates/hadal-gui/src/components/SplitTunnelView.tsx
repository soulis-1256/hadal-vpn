import Plus from "lucide-solid/icons/plus";
import X from "lucide-solid/icons/x";
import { createMemo, For, onCleanup, onMount, Show } from "solid-js";
import { appsForSplitMode } from "../state/appStore";
import type {
  ActiveSplitMode,
  SplitAppStatus,
  SplitAppStatusMap,
  SplitMode,
  SplitTunnelConfig,
} from "../types";
import { attachMiddleClickScroll, type MiddleClickScrollHandle } from "../utils/middleClickScroll";
import { FullPageHeader } from "./FullPageHeader";
import { SegmentedTabs, type SegmentedTabOption } from "./SegmentedTabs";

const SPLIT_TABS: readonly SegmentedTabOption<SplitMode>[] = [
  { value: "off", label: "Off" },
  { value: "bypass", label: "Bypass VPN" },
  { value: "only_vpn", label: "Route via VPN" },
];

interface SplitTunnelViewProps {
  splitTunnel: SplitTunnelConfig;
  appStatusesByMode: SplitAppStatusMap;
  animClass: string;
  onBack: () => void;
  onMinimize?: () => void;
  onOpenAddApps: () => void;
  onUpdateSplitTunnel: (next: SplitTunnelConfig) => void;
  onLaunchApp: (command: string) => void;
}

export function SplitTunnelView(props: SplitTunnelViewProps) {
  let bodyRef: HTMLDivElement | undefined;
  let middleScroll: MiddleClickScrollHandle | undefined;

  onMount(() => {
    if (bodyRef) middleScroll = attachMiddleClickScroll(bodyRef);
  });
  onCleanup(() => {
    middleScroll?.cleanup();
  });
  function commit(mode: SplitMode, apps: string[]) {
    const prevBypass = appsForSplitMode(props.splitTunnel, "bypass");
    const prevOnlyVpn = appsForSplitMode(props.splitTunnel, "only_vpn");
    const nextBypass = mode === "bypass" ? apps : prevBypass;
    const nextOnlyVpn = mode === "only_vpn" ? apps : prevOnlyVpn;
    props.onUpdateSplitTunnel({
      ...props.splitTunnel,
      mode,
      apps: mode === "off" ? [] : apps,
      bypass_apps: nextBypass,
      only_vpn_apps: nextOnlyVpn,
    });
  }

  function handleModeChange(nextMode: SplitMode) {
    if (nextMode === "off") {
      commit("off", []);
      return;
    }
    commit(nextMode, appsForSplitMode(props.splitTunnel, nextMode));
  }

  function removeApp(mode: ActiveSplitMode, appName: string) {
    const next = appsForSplitMode(props.splitTunnel, mode).filter((a) => a !== appName);
    commit(mode, next);
  }

  function statusEntriesFor(mode: ActiveSplitMode): SplitAppStatus[] {
    const configured = appsForSplitMode(props.splitTunnel, mode);
    const live = props.appStatusesByMode[mode] ?? [];
    const byName = new Map(live.map((s) => [s.name, s]));
    return configured.map(
      (name) =>
        byName.get(name) ?? {
          name,
          display_name: name,
          running: false,
          in_split_slice: false,
          slice: null,
          pids: [],
        },
    );
  }

  function statusLabel(app: SplitAppStatus, mode: ActiveSplitMode): string {
    if (app.in_split_slice) {
      const pidText = `${app.pids.length} ${app.pids.length === 1 ? "PID" : "PIDs"}`;
      return mode === "only_vpn"
        ? `Routed via VPN (${pidText})`
        : `Bypassing VPN (${pidText})`;
    }
    if (app.running) return "Running outside split slice";
    return "Not running";
  }

  function dotState(app: SplitAppStatus): "active" | "running" | "idle" {
    if (app.in_split_slice) return "active";
    if (app.running) return "running";
    return "idle";
  }

  return (
    <div style={{ display: "flex", "flex-direction": "column", height: "100%" }}>
      <FullPageHeader
        kicker="Settings / Traffic"
        title="Split tunneling"
        onBack={props.onBack}
        onMinimize={props.onMinimize}
      />

      <div ref={bodyRef} class={`full-body ${props.animClass}`}>
        <div class="sec-lbl">Policy Mode</div>

        <SegmentedTabs
          options={SPLIT_TABS}
          value={props.splitTunnel.mode}
          onChange={handleModeChange}
          ariaLabel="Split tunneling mode"
          exitMs={80}
          enterMs={120}
        >
          {(renderedMode) => {
            const activeMode = createMemo<ActiveSplitMode | null>(() => {
              const m = renderedMode();
              return m === "off" ? null : m;
            });
            const entries = createMemo(() => {
              const m = activeMode();
              return m ? statusEntriesFor(m) : [];
            });
            const heading = () =>
              activeMode() === "bypass"
                ? `Apps bypassing VPN (${entries().length})`
                : `Apps via VPN (${entries().length})`;

            return (
              <Show
                when={activeMode()}
                fallback={
                  <div class="empty-card list-fade">
                    All applications route through the active WireGuard tunnel.
                  </div>
                }
              >
                {(mode) => (
                  <div class="list-fade">
                    <div class="sec-lbl">{heading()}</div>

                    <Show
                      when={entries().length > 0}
                      fallback={
                        <div class="empty-card" style={{ "margin-bottom": "8px" }}>
                          No applications assigned to this policy yet.
                        </div>
                      }
                    >
                      <div class="menu-grp">
                        <For each={entries()}>
                          {(app) => (
                            <div class="menu-row static">
                              <span class="split-dot" data-state={dotState(app)} />
                              <div class="m">
                                <b>{app.display_name}</b>
                                <small>{statusLabel(app, mode())}</small>
                              </div>
                              <Show when={!app.running}>
                                <button
                                  type="button"
                                  class="mini-pill-btn"
                                  data-spot=""
                                  onClick={() => props.onLaunchApp(app.name)}
                                >
                                  Launch
                                </button>
                              </Show>
                              <button
                                type="button"
                                class="icon-lg"
                                data-spot=""
                                style={{
                                  width: "34px",
                                  height: "34px",
                                  "border-radius": "10px",
                                }}
                                aria-label={`Remove ${app.display_name}`}
                                onClick={() => removeApp(mode(), app.name)}
                              >
                                <X size={14} strokeWidth={2} />
                              </button>
                            </div>
                          )}
                        </For>
                      </div>
                    </Show>

                    <button
                      type="button"
                      class="add-full"
                      data-spot=""
                      onClick={props.onOpenAddApps}
                    >
                      <Plus size={16} strokeWidth={2.2} />
                      <span>Add Application</span>
                    </button>
                  </div>
                )}
              </Show>
            );
          }}
        </SegmentedTabs>
      </div>
    </div>
  );
}
