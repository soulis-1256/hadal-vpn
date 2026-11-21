import Plus from "lucide-solid/icons/plus";
import RefreshCw from "lucide-solid/icons/refresh-cw";
import { createMemo, createSignal, For, onCleanup, onMount, Show } from "solid-js";
import { appsForSplitMode } from "../state/appStore";
import type { ActiveSplitMode, DesktopAppEntry, SplitTunnelConfig } from "../types";
import { attachMiddleClickScroll, type MiddleClickScrollHandle } from "../utils/middleClickScroll";
import { FullPageHeader } from "./FullPageHeader";
import { SearchInput } from "./SearchInput";
import { Toggle } from "./Toggle";

interface AddAppViewProps {
  splitTunnel: SplitTunnelConfig;
  animClass: string;
  onBack: () => void;
  onMinimize?: () => void;
  onDiscoverApps: () => Promise<DesktopAppEntry[]>;
  onUpdateSplitTunnel: (next: SplitTunnelConfig) => void;
}

export function AddAppView(props: AddAppViewProps) {
  const [query, setQuery] = createSignal("");
  const [apps, setApps] = createSignal<DesktopAppEntry[]>([]);
  const [loading, setLoading] = createSignal(false);
  let bodyRef: HTMLDivElement | undefined;
  let middleScroll: MiddleClickScrollHandle | undefined;

  const targetMode = createMemo<ActiveSplitMode>(() =>
    props.splitTunnel.mode === "only_vpn" ? "only_vpn" : "bypass",
  );

  const selectedApps = createMemo(() => appsForSplitMode(props.splitTunnel, targetMode()));

  async function loadApps() {
    if (loading()) return;
    setLoading(true);
    try {
      setApps(await props.onDiscoverApps());
    } finally {
      setLoading(false);
    }
  }

  onMount(() => {
    if (bodyRef) middleScroll = attachMiddleClickScroll(bodyRef);
    void loadApps();
  });
  onCleanup(() => {
    middleScroll?.cleanup();
  });

  function isSelected(entry: DesktopAppEntry): boolean {
    const list = selectedApps();
    return list.includes(entry.id) || list.includes(entry.bin);
  }

  function setAppEnabled(idOrBin: string, enabled: boolean, aliases: string[] = []) {
    const mode = targetMode();
    const current = appsForSplitMode(props.splitTunnel, mode);
    const cleaned = current.filter((x) => x !== idOrBin && !aliases.includes(x));
    const nextApps = enabled ? [...cleaned, idOrBin] : cleaned;

    const prevBypass = appsForSplitMode(props.splitTunnel, "bypass");
    const prevOnlyVpn = appsForSplitMode(props.splitTunnel, "only_vpn");
    props.onUpdateSplitTunnel({
      ...props.splitTunnel,
      mode,
      apps: nextApps,
      bypass_apps: mode === "bypass" ? nextApps : prevBypass,
      only_vpn_apps: mode === "only_vpn" ? nextApps : prevOnlyVpn,
    });
  }

  const filteredApps = createMemo(() => {
    const q = query().trim().toLowerCase();
    if (!q) return apps();
    return apps().filter(
      (a) =>
        a.name.toLowerCase().includes(q) ||
        a.id.toLowerCase().includes(q) ||
        a.bin.toLowerCase().includes(q),
    );
  });

  const runningApps = createMemo(() => filteredApps().filter((a) => a.running));
  const installedApps = createMemo(() => filteredApps().filter((a) => !a.running));

  const customCommandCandidate = createMemo(() => {
    const q = query().trim();
    if (!q) return null;
    const lower = q.toLowerCase();
    const alreadyListed = apps().some(
      (a) => a.id.toLowerCase() === lower || a.bin.toLowerCase() === lower,
    );
    const alreadySelected = selectedApps().some((x) => x.toLowerCase() === lower);
    if (alreadyListed || alreadySelected) return null;
    return q;
  });

  return (
    <div style={{ display: "flex", "flex-direction": "column", height: "100%" }}>
      <FullPageHeader
        kicker="Split Tunneling"
        title="Add application"
        onBack={props.onBack}
        onMinimize={props.onMinimize}
      />

      <div ref={bodyRef} class={`full-body ${props.animClass}`}>
        <div class="search-row">
          <SearchInput
            value={query()}
            placeholder="Search installed apps or command…"
            onInput={setQuery}
          />
          <button
            type="button"
            class="sync-btn"
            classList={{ spinning: loading() }}
            data-spot=""
            aria-label="Rescan applications"
            onClick={() => void loadApps()}
          >
            <RefreshCw size={16} strokeWidth={2} />
          </button>
        </div>

        <Show when={customCommandCandidate()}>
          {(cmd) => (
            <button
              type="button"
              class="add-full"
              data-spot=""
              style={{ "margin-top": 0, "margin-bottom": "12px" }}
              onClick={() => {
                setAppEnabled(cmd(), true);
                setQuery("");
                props.onBack();
              }}
            >
              <Plus size={15} strokeWidth={2.2} />
              <span>Add custom command &ldquo;{cmd()}&rdquo;</span>
            </button>
          )}
        </Show>

        <Show when={loading() && apps().length === 0}>
          <div class="empty-card">Scanning desktop applications…</div>
        </Show>

        <Show when={!loading() && filteredApps().length === 0 && !customCommandCandidate()}>
          <div class="empty-card">No matching desktop applications found</div>
        </Show>

        <Show when={runningApps().length > 0}>
          <div class="sec-lbl">Running Now ({runningApps().length})</div>
          <div class="menu-grp">
            <For each={runningApps()}>
              {(app) => (
                <Toggle
                  title={app.name}
                  description={`${app.bin} · active process`}
                  checked={isSelected(app)}
                  onChange={(enabled) => setAppEnabled(app.id, enabled, [app.bin])}
                />
              )}
            </For>
          </div>
        </Show>

        <Show when={installedApps().length > 0}>
          <div class="sec-lbl">Installed Applications ({installedApps().length})</div>
          <div class="menu-grp">
            <For each={installedApps()}>
              {(app) => (
                <Toggle
                  title={app.name}
                  description={app.bin}
                  checked={isSelected(app)}
                  onChange={(enabled) => setAppEnabled(app.id, enabled, [app.bin])}
                />
              )}
            </For>
          </div>
        </Show>
      </div>
    </div>
  );
}
