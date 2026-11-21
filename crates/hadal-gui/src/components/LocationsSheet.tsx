import Check from "lucide-solid/icons/check";
import ChevronDown from "lucide-solid/icons/chevron-down";
import RefreshCw from "lucide-solid/icons/refresh-cw";
import X from "lucide-solid/icons/x";
import { createEffect, createMemo, createSignal, For, onCleanup, onMount, Show } from "solid-js";
import { isStaticCluster } from "../globe/clusterPins";
import type { Cluster, GamingScanReport } from "../types";
import { attachMiddleClickScroll, type MiddleClickScrollHandle } from "../utils/middleClickScroll";
import { SearchInput } from "./SearchInput";
import { SegmentedTabs, type SegmentedTabOption } from "./SegmentedTabs";

type NodeFilter = "all" | "low" | "static";

interface LocationsSheetProps {
  open: boolean;
  clusters: Cluster[];
  activeClusterId: string | null;
  selectedClusterId: string | null;
  connectingClusterId: string | null;
  gamingReport: GamingScanReport | null;
  tunnelBusy: boolean;
  onClose: () => void;
  onConnect: (clusterId: string) => void;
  onRefresh: () => Promise<void>;
  onHoverCluster?: (clusterId: string | null) => void;
}

interface CountryGroup {
  country: string;
  countryCode: string;
  items: Cluster[];
  bestLoad: number;
}

interface IndexedCluster {
  cluster: Cluster;
  isStatic: boolean;
  haystack: string;
  country: string;
  countryCode: string;
}

interface CountryGroupRowProps {
  group: CountryGroup;
  open: boolean;
  activeClusterId: string | null;
  selectedClusterId: string | null;
  connectingClusterId: string | null;
  tunnelBusy: boolean;
  pingLookup: () => Map<string, number>;
  onToggle: (country: string) => void;
  onConnect: (clusterId: string) => void;
}

/** Country accordion row that mounts city buttons only while expanded (or closing). */
function CountryGroupRow(props: CountryGroupRowProps) {
  const [keepMounted, setKeepMounted] = createSignal(false);
  let unmountTimer: number | undefined;

  createEffect(() => {
    if (unmountTimer !== undefined) {
      window.clearTimeout(unmountTimer);
      unmountTimer = undefined;
    }
    if (props.open) {
      setKeepMounted(true);
    } else if (keepMounted()) {
      unmountTimer = window.setTimeout(() => {
        unmountTimer = undefined;
        setKeepMounted(false);
      }, 280);
    }
  });

  onCleanup(() => {
    if (unmountTimer !== undefined) {
      window.clearTimeout(unmountTimer);
    }
  });

  const showCities = () => props.open || keepMounted();

  return (
    <div class="acc-grp" data-open={props.open ? "true" : "false"}>
      <button
        type="button"
        class="acc-head"
        aria-expanded={props.open ? "true" : "false"}
        onClick={() => props.onToggle(props.group.country)}
      >
        <span class="cc-pill">{props.group.countryCode}</span>
        <b>{props.group.country}</b>
        <span class="meta">
          {props.group.items.length} ·{" "}
          {props.group.bestLoad < 999 ? `${props.group.bestLoad}%` : "--"}
        </span>
        <span class="chev">
          <ChevronDown size={15} strokeWidth={2.1} />
        </span>
      </button>

      <div class="acc-cities-wrap">
        <div class="acc-cities">
          <Show when={showCities()}>
            <For each={props.group.items}>
              {(c) => {
                const isActive = () => props.activeClusterId === c.id;
                const isSelected = () => !isActive() && props.selectedClusterId === c.id;
                const isConnecting = () => props.connectingClusterId === c.id;
                const ping = () => props.pingLookup().get(c.id);
                return (
                  <button
                    type="button"
                    class="city-row"
                    data-cluster-id={c.id}
                    data-on={isActive() ? "true" : "false"}
                    data-selected={isSelected() ? "true" : "false"}
                    disabled={props.tunnelBusy && !isConnecting()}
                    onClick={() => props.onConnect(c.id)}
                  >
                    <div class="m">
                      <b>
                        <span>{c.location ?? c.id}</span>
                        <Show when={isStaticCluster(c)}>
                          <span class="tag-s">STATIC</span>
                        </Show>
                      </b>
                      <small>
                        {c.connectionName ?? c.id}
                        {c.load !== null ? ` · ${c.load}% load` : ""}
                      </small>
                    </div>
                    <span class="p">
                      <Show
                        when={!isActive()}
                        fallback={<Check size={14} strokeWidth={2.4} />}
                      >
                        {isConnecting()
                          ? "…"
                          : ping() !== undefined
                            ? `${ping()}ms`
                            : c.load !== null
                              ? `${c.load}%`
                              : "Connect"}
                      </Show>
                    </span>
                  </button>
                );
              }}
            </For>
          </Show>
        </div>
      </div>
    </div>
  );
}

export function LocationsSheet(props: LocationsSheetProps) {
  const [query, setQuery] = createSignal("");
  const [filter, setFilter] = createSignal<NodeFilter>("all");
  const [openCountries, setOpenCountries] = createSignal<Record<string, boolean>>({});
  const [instantAcc, setInstantAcc] = createSignal(false);
  const [syncing, setSyncing] = createSignal(false);

  let bodyRef: HTMLDivElement | undefined;
  let middleScroll: MiddleClickScrollHandle | undefined;
  let wasOpen = false;

  onMount(() => {
    if (bodyRef) middleScroll = attachMiddleClickScroll(bodyRef);
  });
  onCleanup(() => {
    middleScroll?.cleanup();
  });

  // On open, instantly snap accordion state & internal scrollTop BEFORE the sheet glides up,
  // avoiding simultaneous layout reflow or mid-slide scroll jumps.
  createEffect(() => {
    const isOpen = props.open;
    if (!isOpen) middleScroll?.stop();
    const justOpened = isOpen && !wasOpen;
    wasOpen = isOpen;
    if (!justOpened) return;

    const targetId = props.activeClusterId ?? props.selectedClusterId;
    const target = targetId ? props.clusters.find((c) => c.id === targetId) : undefined;
    if (!target || !targetId) return;

    const country = target.country ?? target.countryCode ?? "Unknown";
    setInstantAcc(true);
    if (filter() === "static" && !isStaticCluster(target)) {
      setFilter("all");
    }
    setOpenCountries((prev) => ({ ...prev, [country]: true }));

    const centerTargetRow = () => {
      const body = bodyRef;
      const row = body?.querySelector<HTMLElement>(
        `[data-cluster-id="${CSS.escape(targetId)}"]`,
      );
      if (body && row) {
        const rowRect = row.getBoundingClientRect();
        const bodyRect = body.getBoundingClientRect();
        if (bodyRect.height > 0 && rowRect.height > 0) {
          const targetTop =
            body.scrollTop +
            (rowRect.top - bodyRect.top) -
            (bodyRect.height / 2 - rowRect.height / 2);
          body.scrollTop = Math.max(0, targetTop);
        }
      }
      if (typeof window.requestAnimationFrame === "function") {
        window.requestAnimationFrame(() => setInstantAcc(false));
      } else {
        setInstantAcc(false);
      }
    };

    if (typeof window.requestAnimationFrame === "function") {
      window.requestAnimationFrame(centerTargetRow);
    } else {
      centerTargetRow();
    }
  });

  const filterTabs = createMemo<readonly SegmentedTabOption<NodeFilter>[]>(() => [
    { value: "all", label: `All (${props.clusters.length})` },
    { value: "low", label: "Low Load" },
    { value: "static", label: "Static IP" },
  ]);

  const pingLookup = createMemo(() => {
    const map = new Map<string, number>();
    const report = props.gamingReport;
    if (!report) return map;
    for (const c of report.candidates) {
      map.set(c.cluster_id, Math.round(c.verified_tunnel_ms ?? c.estimated_total_ms));
    }
    return map;
  });

  const indexedClusters = createMemo<IndexedCluster[]>(() =>
    props.clusters.map((cluster) => ({
      cluster,
      isStatic: isStaticCluster(cluster),
      country: cluster.country ?? cluster.countryCode ?? "Unknown",
      countryCode: cluster.countryCode ?? "--",
      haystack: `${cluster.country ?? ""} ${cluster.location ?? ""} ${cluster.countryCode ?? ""} ${cluster.connectionName ?? ""}`.toLowerCase(),
    })),
  );

  function buildGroups(mode: NodeFilter): CountryGroup[] {
    const q = query().trim().toLowerCase();
    const map = new Map<string, CountryGroup>();

    for (const entry of indexedClusters()) {
      if (mode === "static" && !entry.isStatic) continue;
      if (q && !entry.haystack.includes(q)) continue;

      let g = map.get(entry.country);
      if (!g) {
        g = {
          country: entry.country,
          countryCode: entry.countryCode,
          items: [],
          bestLoad: entry.cluster.load ?? 999,
        };
        map.set(entry.country, g);
      }
      g.items.push(entry.cluster);
      if ((entry.cluster.load ?? 999) < g.bestLoad) {
        g.bestLoad = entry.cluster.load ?? 999;
      }
    }

    const groups = Array.from(map.values());
    if (mode === "low") {
      groups.sort((a, b) => a.bestLoad - b.bestLoad || a.country.localeCompare(b.country));
      for (const g of groups) {
        g.items.sort((a, b) => (a.load ?? 999) - (b.load ?? 999));
      }
    } else {
      groups.sort((a, b) => a.country.localeCompare(b.country));
    }
    return groups;
  }

  async function handleRefresh() {
    if (syncing()) return;
    setSyncing(true);
    try {
      await props.onRefresh();
    } finally {
      window.setTimeout(() => setSyncing(false), 450);
    }
  }

  function toggleCountry(country: string) {
    if (query().trim().length > 0) return;
    setOpenCountries((prev) => ({ ...prev, [country]: !prev[country] }));
  }

  return (
    <section
      class="sheet-layer"
      classList={{ open: props.open }}
      data-instant-acc={instantAcc() ? "true" : "false"}
      aria-hidden={!props.open}
      aria-label="Locations"
    >
      <div class="sheet-handle" onClick={props.onClose}>
        <i />
      </div>

      <div class="sheet-hdr">
        <div class="stitle">
          <small>Exit Nodes</small>
          <b>Select location</b>
        </div>
        <button
          type="button"
          class="icon-lg close"
          data-spot=""
          aria-label="Close locations"
          onClick={props.onClose}
        >
          <X size={16} strokeWidth={2.2} />
        </button>
      </div>

      <div class="sheet-pinned">
        <div class="search-row">
          <SearchInput
            value={query()}
            placeholder="Search country or city…"
            onInput={setQuery}
          />
          <button
            type="button"
            class="sync-btn"
            classList={{ spinning: syncing() }}
            data-spot=""
            title="Sync clusters"
            aria-label="Refresh Nodes"
            onClick={() => void handleRefresh()}
          >
            <RefreshCw size={16} strokeWidth={2} />
          </button>
        </div>
      </div>

      <div class="sheet-body" ref={bodyRef}>
        <SegmentedTabs
          options={filterTabs()}
          value={filter()}
          onChange={setFilter}
          ariaLabel="Cluster filter"
          exitMs={70}
          enterMs={110}
        >
          {(renderedMode) => {
            const groups = createMemo(() => buildGroups(renderedMode()));
            const hasQuery = () => query().trim().length > 0;
            return (
              <Show
                when={groups().length > 0}
                fallback={<div class="empty-card">No matching locations</div>}
              >
                <div class="list-fade">
                  <For each={groups()}>
                    {(g) => (
                      <CountryGroupRow
                        group={g}
                        open={hasQuery() || !!openCountries()[g.country]}
                        activeClusterId={props.activeClusterId}
                        selectedClusterId={props.selectedClusterId}
                        connectingClusterId={props.connectingClusterId}
                        tunnelBusy={props.tunnelBusy}
                        pingLookup={pingLookup}
                        onToggle={toggleCountry}
                        onConnect={props.onConnect}
                      />
                    )}
                  </For>
                </div>
              </Show>
            );
          }}
        </SegmentedTabs>
      </div>
    </section>
  );
}
