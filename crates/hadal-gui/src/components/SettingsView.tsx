import ChevronRight from "lucide-solid/icons/chevron-right";
import SplitIcon from "lucide-solid/icons/git-branch";
import Info from "lucide-solid/icons/info";
import { onCleanup, onMount, Show } from "solid-js";
import pkg from "../../package.json";
import { appsForSplitMode } from "../state/appStore";
import type { AppSettings, DaemonEnvelope, UserMe } from "../types";
import { attachMiddleClickScroll, type MiddleClickScrollHandle } from "../utils/middleClickScroll";
import { FullPageHeader } from "./FullPageHeader";
import { Toggle } from "./Toggle";

interface SettingsViewProps {
  daemon: DaemonEnvelope;
  settings: AppSettings;
  userMe: UserMe | null;
  animClass: string;
  onBack: () => void;
  onMinimize?: () => void;
  onOpenSplit: () => void;
  onOpenAbout: () => void;
  onUpdateSettings: (patch: Partial<AppSettings>) => void;
  onToggleKillswitch: (enabled: boolean) => void;
  onSignOut: () => void;
  onQuit: () => void;
}

export function SettingsView(props: SettingsViewProps) {
  let bodyRef: HTMLDivElement | undefined;
  let middleScroll: MiddleClickScrollHandle | undefined;

  onMount(() => {
    if (bodyRef) middleScroll = attachMiddleClickScroll(bodyRef);
  });
  onCleanup(() => {
    middleScroll?.cleanup();
  });

  const splitSummary = () => {
    const st = props.settings.split_tunnel;
    if (st.mode === "off") return "Disabled — all apps use tunnel";
    const count = appsForSplitMode(st, st.mode).length;
    const label = st.mode === "bypass" ? "Bypass VPN" : "Route via VPN";
    return `${label} · ${count} ${count === 1 ? "app" : "apps"}`;
  };

  return (
    <div style={{ display: "flex", "flex-direction": "column", height: "100%" }}>
      <FullPageHeader
        kicker="Control & Account"
        title="Settings"
        onBack={props.onBack}
        onMinimize={props.onMinimize}
      />

      <div ref={bodyRef} class={`full-body settings-body ${props.animClass}`}>
        <div class="sec-lbl">Protection &amp; Network</div>
        <div class="menu-grp">
          <Toggle
            title="Killswitch + DNS Lock"
            description="Block all non-VPN traffic & lock DNS"
            checked={props.daemon.status.killswitch || props.settings.killswitch}
            tone="err"
            onChange={props.onToggleKillswitch}
          />
          <Toggle
            title="Block IPv6 Traffic"
            description="Prevent dual-stack leaks outside WireGuard"
            checked={props.settings.ipv6_block}
            onChange={(v) => props.onUpdateSettings({ ipv6_block: v })}
          />
          <Toggle
            title="Bypass Local Network"
            description="Keep LAN subnets direct outside VPN"
            checked={props.settings.bypass_lan}
            onChange={(v) => props.onUpdateSettings({ bypass_lan: v })}
          />
          <Toggle
            title="Auto PMTU"
            description="Probe upstream WAN MTU automatically"
            checked={props.settings.auto_mtu}
            onChange={(v) => props.onUpdateSettings({ auto_mtu: v })}
          />
          <Show when={!props.settings.auto_mtu}>
            <div class="switch-row">
              <label class="switch-text" for="manual-mtu-input">
                <span class="switch-title">Manual MTU</span>
                <span class="switch-desc">WireGuard payload cap (1280–1440)</span>
              </label>
              <input
                id="manual-mtu-input"
                type="number"
                class="num-in"
                aria-label="Manual MTU"
                min={1280}
                max={1440}
                value={props.settings.manual_mtu ?? 1420}
                onChange={(e) => {
                  const raw = Number(e.currentTarget.value);
                  const mtu = Number.isFinite(raw) ? Math.max(1280, Math.min(1440, raw)) : 1420;
                  props.onUpdateSettings({ manual_mtu: mtu });
                }}
              />
            </div>
          </Show>
        </div>

        <div class="sec-lbl">Applications</div>
        <div class="menu-grp">
          <button
            type="button"
            class="menu-row"
            data-spot=""
            onClick={props.onOpenSplit}
          >
            <div class="ico-wrap">
              <SplitIcon size={15} strokeWidth={2} />
            </div>
            <div class="m">
              <b>Split Tunneling</b>
              <small>{splitSummary()}</small>
            </div>
            <span style={{ color: "var(--mute)", display: "inline-flex" }}>
              <ChevronRight size={16} strokeWidth={2} />
            </span>
          </button>
        </div>

        <div class="sec-lbl">Account</div>
        <div class="acct-card">
          <div class="acct-email">{props.userMe?.email ?? "Authenticated session"}</div>

          <div class="acct-btns">
            <button
              type="button"
              class="btn-surf"
              data-spot=""
              onClick={props.onSignOut}
            >
              Sign Out
            </button>
            <button
              type="button"
              class="btn-danger-soft"
              data-spot=""
              onClick={props.onQuit}
            >
              Quit App
            </button>
          </div>
        </div>

        <div class="menu-grp" style={{ "margin-top": "10px", "margin-bottom": 0 }}>
          <button
            type="button"
            class="menu-row"
            data-spot=""
            onClick={props.onOpenAbout}
          >
            <div class="ico-wrap">
              <Info size={15} strokeWidth={2} />
            </div>
            <div class="m">
              <b>About &amp; Licenses</b>
              <small>v{pkg.version} · GPL-3.0-or-later</small>
            </div>
            <span style={{ color: "var(--mute)", display: "inline-flex" }}>
              <ChevronRight size={16} strokeWidth={2} />
            </span>
          </button>
        </div>
      </div>
    </div>
  );
}
