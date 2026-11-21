import SplitIcon from "lucide-solid/icons/git-branch";
import { createEffect, createMemo, createSignal, For, onCleanup, onMount, Show } from "solid-js";
import type { EndpointCandidate, GameProfile, GamingScanReport } from "../types";
import { attachMiddleClickScroll, type MiddleClickScrollHandle } from "../utils/middleClickScroll";
import { FullPageHeader } from "./FullPageHeader";
import { Select, type SelectOption } from "./Select";
import { Toggle } from "./Toggle";

interface GamingViewProps {
  games: GameProfile[];
  favoriteGame: string;
  favoriteRegion: string;
  gameOnlyRouting: boolean;
  scanning: boolean;
  connectingBest: boolean;
  report: GamingScanReport | null;
  animClass: string;
  onBack: () => void;
  onMinimize?: () => void;
  onUpdateGameSettings: (game: string, region: string, gameOnly: boolean) => void;
  onScan: (gameId: string, regionId: string, customHost: string | null) => void;
  onConnectBest: (
    gameId: string,
    regionId: string,
    customHost: string | null,
    gameOnly: boolean,
  ) => void;
  onConnectCandidate: (cand: EndpointCandidate, report: GamingScanReport) => void;
  onHoverCluster: (clusterId: string | null) => void;
}

export function GamingView(props: GamingViewProps) {
  const [selectedGame, setSelectedGame] = createSignal(props.favoriteGame || "fortnite");
  const [selectedRegion, setSelectedRegion] = createSignal(props.favoriteRegion || "eu-de");
  const [customHost, setCustomHost] = createSignal("");
  let bodyRef: HTMLDivElement | undefined;
  let middleScroll: MiddleClickScrollHandle | undefined;

  onMount(() => {
    if (bodyRef) middleScroll = attachMiddleClickScroll(bodyRef);
  });
  onCleanup(() => {
    middleScroll?.cleanup();
  });

  createEffect(() => {
    setSelectedGame(props.favoriteGame || "fortnite");
    setSelectedRegion(props.favoriteRegion || "eu-de");
  });

  const activeGame = createMemo(
    () => props.games.find((g) => g.id === selectedGame()) ?? props.games[0],
  );

  const activeRegion = createMemo(() => {
    const game = activeGame();
    if (!game) return undefined;
    return game.regions.find((r) => r.id === selectedRegion()) ?? game.regions[0];
  });

  const gameOptions = createMemo<SelectOption[]>(() =>
    props.games.map((g) => ({ value: g.id, label: g.name })),
  );

  const regionOptions = createMemo<SelectOption[]>(() =>
    (activeGame()?.regions ?? []).map((r) => ({
      value: r.id,
      label: r.label,
      group: r.group,
    })),
  );

  const targetHostDisplay = createMemo(() => {
    const custom = customHost().trim();
    if (custom.length > 0) return custom;
    return activeRegion()?.ping_host ?? "ping-de.ds.on.epicgames.com";
  });

  const showingEstimatesOnly = createMemo(() => {
    const r = props.report;
    if (!r || props.scanning || r.candidates.length === 0) return false;
    return r.candidates.every((c) => c.verified_tunnel_ms === null);
  });

  function handleGameChange(gameId: string) {
    setSelectedGame(gameId);
    const nextGame = props.games.find((g) => g.id === gameId);
    const nextRegion =
      nextGame?.regions.find((r) => r.id === selectedRegion())?.id ??
      nextGame?.regions[0]?.id ??
      selectedRegion();
    setSelectedRegion(nextRegion);
    props.onUpdateGameSettings(gameId, nextRegion, props.gameOnlyRouting);
  }

  function handleRegionChange(regionId: string) {
    setSelectedRegion(regionId);
    props.onUpdateGameSettings(selectedGame(), regionId, props.gameOnlyRouting);
  }

  return (
    <div style={{ display: "flex", "flex-direction": "column", height: "100%" }}>
      <FullPageHeader
        kicker="Route Tournament"
        title="Gaming Boost"
        onBack={props.onBack}
        onMinimize={props.onMinimize}
      />

      <div ref={bodyRef} class={`full-body ${props.animClass}`}>
        <div class="select-row-scope">
          <Select
            value={selectedGame()}
            options={gameOptions()}
            placeholder="Game"
            onChange={handleGameChange}
          />
          <Select
            value={activeRegion()?.id ?? selectedRegion()}
            options={regionOptions()}
            placeholder="Game Region"
            onChange={handleRegionChange}
          />
        </div>

        <input
          type="text"
          class="txt-in"
          placeholder="Custom server host or IP (optional)"
          value={customHost()}
          onInput={(e) => setCustomHost(e.currentTarget.value)}
        />

        <div class="menu-grp" style={{ "margin-bottom": "10px" }}>
          <div style={{ display: "flex", "align-items": "center" }}>
            <div
              class="ico-wrap"
              style={{
                width: "34px",
                height: "34px",
                "border-radius": "10px",
                display: "grid",
                "place-items": "center",
                background: "rgba(255,255,255,0.06)",
                color: "var(--ok)",
                "margin-left": "13px",
                flex: "none",
              }}
            >
              <SplitIcon size={15} strokeWidth={2} />
            </div>
            <div style={{ flex: 1, "min-width": 0 }}>
              <Toggle
                title="Game-Only Split"
                description="Tunnel only game CIDRs; keep desktop direct"
                checked={props.gameOnlyRouting}
                onChange={(next) =>
                  props.onUpdateGameSettings(selectedGame(), selectedRegion(), next)
                }
              />
            </div>
          </div>
        </div>

        <div class="dual">
          <button
            type="button"
            class="btn-surf"
            data-spot=""
            disabled={props.scanning || props.connectingBest}
            onClick={() =>
              props.onScan(
                selectedGame(),
                activeRegion()?.id ?? selectedRegion(),
                customHost().trim() || null,
              )
            }
          >
            {props.scanning ? "Scanning…" : "Scan"}
          </button>

          <button
            type="button"
            class="btn-pri"
            data-spot=""
            disabled={props.scanning || props.connectingBest}
            onClick={() =>
              props.onConnectBest(
                selectedGame(),
                activeRegion()?.id ?? selectedRegion(),
                customHost().trim() || null,
                props.gameOnlyRouting,
              )
            }
          >
            {props.connectingBest ? "Connecting…" : "Connect Best"}
          </button>
        </div>

        <Show when={props.scanning}>
          <div class="scan-track">
            <div class="scan-bar" />
          </div>
          <div class="empty-card">
            Probing <span class="mono" style={{ color: "var(--ink)" }}>{targetHostDisplay()}</span> across{" "}
            {activeGame()?.name ?? "game"} relays…
          </div>
        </Show>

        <Show when={!props.scanning && !props.report}>
          <div class="empty-card">
            Target: <span class="mono" style={{ color: "var(--ink)" }}>{targetHostDisplay()}</span>
            <div style={{ "margin-top": "4px" }}>Press Scan to benchmark endpoints</div>
          </div>
        </Show>

        <Show when={!props.scanning && props.report}>
          {(report) => (
            <div class="list-fade">
              <div class="sec-head">
                <b>{report().target_host}</b>
                <small>
                  PMTU {report().wan_pmtu} → {report().recommended_mtu}
                </small>
              </div>

              <div class="stat-frame">
                <Show
                  when={report().baseline_direct}
                  fallback={
                    <div class="stat-note">Direct ICMP baseline unavailable on WAN</div>
                  }
                >
                  {(b) => (
                    <div class="stat3">
                      <div>
                        <small>Direct Avg</small>
                        <b>{b().avg_ms.toFixed(1)} ms</b>
                      </div>
                      <div>
                        <small>Min / Max</small>
                        <b>
                          {b().min_ms.toFixed(0)} / {b().max_ms.toFixed(0)}
                        </b>
                      </div>
                      <div>
                        <small>Jitter</small>
                        <b>±{b().mdev_ms.toFixed(2)} ms</b>
                      </div>
                    </div>
                  )}
                </Show>

                <Show when={report().active_tunnel_ping}>
                  {(tp) => {
                    const baseAvg = report().baseline_direct?.avg_ms;
                    const delta = baseAvg !== undefined ? tp().avg_ms - baseAvg : null;
                    return (
                      <div class="tun-live">
                        <span>
                          {report().active_tunnel_label ?? "Active Tunnel"} (live)
                        </span>
                        <b>
                          {tp().avg_ms.toFixed(1)} ms
                          <Show when={delta !== null}>
                            <span>
                              ({delta! >= 0 ? "+" : ""}
                              {delta!.toFixed(1)} ms)
                            </span>
                          </Show>
                        </b>
                      </div>
                    );
                  }}
                </Show>
              </div>

              <Show when={showingEstimatesOnly()}>
                <div class="wan-hint">
                  Showing WAN hop estimates — disconnect active tunnel to run live E2E probes
                </div>
              </Show>

              <For each={report().candidates}>
                {(cand, idx) => {
                  const hasVerified = () => cand.verified_tunnel_ms !== null;
                  const rttMs = () => cand.verified_tunnel_ms ?? cand.estimated_total_ms;
                  const loss = () => cand.verified_loss_pct ?? 0;
                  const hasLoss = () => loss() > 0;
                  return (
                    <button
                      type="button"
                      class="cand"
                      data-spot=""
                      data-best={idx() === 0 ? "true" : "false"}
                      onMouseEnter={() => props.onHoverCluster(cand.cluster_id)}
                      onMouseLeave={() => props.onHoverCluster(null)}
                      onClick={() => props.onConnectCandidate(cand, report())}
                    >
                      <span class="rk">#{idx() + 1}</span>
                      <div class="m">
                        <b>
                          {cand.location}, {cand.country}
                        </b>
                        <small>
                          {cand.endpoint_ip}
                          {cand.load !== null ? ` · ${cand.load}% load` : ""}
                        </small>
                      </div>
                      <div class="ms">
                        <span
                          style={{
                            color: hasLoss() ? "#ffb547" : idx() === 0 ? "#3ee6d0" : "var(--ink)",
                          }}
                        >
                          {hasVerified() ? "" : "~"}
                          {rttMs().toFixed(1)} ms
                        </span>
                        <small
                          style={{
                            color: hasLoss() ? "#ffb547" : hasVerified() ? "#3ee6d0" : "#8fb3ff",
                          }}
                        >
                          {hasVerified()
                            ? `${hasLoss() ? `${loss()}% loss · ` : ""}verified`
                            : `est · hop ${cand.direct_rtt_ms.toFixed(1)} ms`}
                        </small>
                      </div>
                    </button>
                  );
                }}
              </For>
            </div>
          )}
        </Show>
      </div>
    </div>
  );
}
