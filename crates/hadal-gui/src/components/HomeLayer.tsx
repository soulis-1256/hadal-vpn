import ChevronUp from "lucide-solid/icons/chevron-up";
import SettingsIcon from "lucide-solid/icons/settings";
import Zap from "lucide-solid/icons/zap";
import { createMemo, Show } from "solid-js";
import type {
  Cluster,
  DaemonEnvelope,
  GamingScanReport,
  RouteId,
  UserLocation,
} from "../types";
import { MinimizeButton } from "./MinimizeButton";

interface HomeLayerProps {
  daemon: DaemonEnvelope;
  selectedCluster: Cluster | null;
  userLocation: UserLocation | null;
  gamingReport: GamingScanReport | null;
  tunnelBusy: boolean;
  killswitchEnabled: boolean;
  hidden?: boolean;
  onOpenRoute: (route: RouteId) => void;
  onMinimize: () => void;
  onQuickConnect: () => void;
  onDisconnect: (keepKillswitch: boolean) => void;
  onRetryDaemon: () => void;
}

export function HomeLayer(props: HomeLayerProps) {
  const status = () => props.daemon.status;

  const isProtected = () => status().state === "protected";
  const isConnecting = () => status().state === "connecting";
  const isLocked = () => status().state === "killswitch_locked";

  const offlineHint = () => {
    const raw = props.daemon.error ?? "";
    if (!raw || raw.startsWith("Cannot reach hadald") || raw.includes("No such file")) {
      return "Run: sudo systemctl start hadald";
    }
    if (raw.toLowerCase().includes("permission denied")) {
      return "Socket permission denied (group network)";
    }
    return raw;
  };

  const statusTag = () => {
    if (!props.daemon.reachable) return "OFFLINE";
    if (isProtected()) return "VPN";
    if (isConnecting()) return "SYNC";
    if (isLocked()) return "LOCKED";
    return "ISP";
  };

  const ipDisplay = () => {
    if (isProtected()) {
      const addr = status().address?.split("/")[0];
      return addr ?? props.userLocation?.ip ?? "Secured";
    }
    if (isLocked()) return "0.0.0.0";
    return props.userLocation?.ip ?? "Locating…";
  };

  const primaryTitle = () => {
    if (isProtected() || isConnecting()) {
      const loc = status().location ?? props.selectedCluster?.location;
      const ctry = status().country ?? props.selectedCluster?.country;
      if (loc && ctry) return `${loc}, ${ctry}`;
      if (loc) return loc;
    }
    const sel = props.selectedCluster;
    if (sel?.location && sel.country) return `${sel.location}, ${sel.country}`;
    if (sel?.location) return sel.location;
    if (sel?.country) return sel.country;
    return props.daemon.reachable ? "Select location" : "No cluster loaded";
  };

  const matchedPingMs = createMemo(() => {
    const sel = props.selectedCluster;
    const report = props.gamingReport;
    if (!sel || !report) return null;
    const cand = report.candidates.find((c) => c.cluster_id === sel.id);
    if (!cand) return null;
    return Math.round(cand.verified_tunnel_ms ?? cand.estimated_total_ms);
  });

  const metaLine = () => {
    const st = status();
    const sel = props.selectedCluster;
    const parts: string[] = [];
    const rawName = (isProtected() || isConnecting() ? st.domain : null) ?? sel?.connectionName;
    if (rawName) {
      parts.push(rawName.replace(/\.prod\.surfshark\.com$/i, ""));
    }
    const ping = matchedPingMs();
    if (ping !== null) parts.push(`${ping}ms`);
    if (sel?.load !== null && sel?.load !== undefined) parts.push(`${sel.load}% load`);
    if (isProtected() && st.mtu) parts.push(`MTU ${st.mtu}`);
    if (parts.length === 0) {
      return props.daemon.reachable ? "Tap to browse locations" : "Daemon disconnected";
    }
    return parts.join(" · ");
  };

  const ctaLabel = () => {
    if (isProtected()) return "Disconnect";
    if (isLocked()) return "Unlock Killswitch";
    if (isConnecting() || props.tunnelBusy) return "Connecting…";
    return "Connect";
  };

  function handlePrimaryAction() {
    if (isProtected()) {
      props.onDisconnect(props.killswitchEnabled);
      return;
    }
    if (isLocked()) {
      props.onDisconnect(false);
      return;
    }
    props.onQuickConnect();
  }

  return (
    <div class="home-layer" aria-hidden={props.hidden ? "true" : undefined}>
      <header class="top-bar">
        <div class="brand-grp">
          <div class="wm">
            H<span>A</span>DAL
          </div>
          <div class="top-status">
            <i class="st-dot" />
            <b>{ipDisplay()}</b>
            <span> · {statusTag()}</span>
          </div>
        </div>

        <div class="hdr-actions">
          <button
            type="button"
            class="hdr-icon settings"
            data-spot=""
            aria-label="Settings"
            title="Settings"
            onClick={() => props.onOpenRoute("settings")}
          >
            <SettingsIcon size={16} strokeWidth={2} />
          </button>
          <MinimizeButton onClick={props.onMinimize} />
        </div>
      </header>

      <div class="space-hud">
        <Show when={!props.daemon.reachable}>
          <div class="offline-pill" role="status">
            <div>
              <strong>hadald daemon offline</strong>
              <span>{offlineHint()}</span>
            </div>
            <button
              type="button"
              class="mini-pill-btn"
              data-spot=""
              onClick={props.onRetryDaemon}
            >
              Retry Connection
            </button>
          </div>
        </Show>

        <Show when={props.daemon.reachable && status().last_error}>
          {(err) => (
            <div class="alert-box" role="alert">
              <span class="alert-msg">{err()}</span>
            </div>
          )}
        </Show>
      </div>

      <div class="atlas-dock">
        <button
          type="button"
          class="loc-card"
          data-spot=""
          aria-label="Select location"
          onClick={() => props.onOpenRoute("locations")}
        >
          <span class="cc-pill">{props.selectedCluster?.countryCode ?? "--"}</span>
          <div class="m">
            <b>{primaryTitle()}</b>
            <small>{metaLine()}</small>
          </div>
          <span class="chev">
            <ChevronUp size={16} strokeWidth={2.2} />
          </span>
        </button>

        <div class="split-actions">
          <button
            type="button"
            class="cta connect"
            data-spot=""
            disabled={(props.tunnelBusy || !props.daemon.reachable) && !isLocked()}
            onClick={handlePrimaryAction}
          >
            {ctaLabel()}
          </button>

          <button
            type="button"
            class="boost-tile"
            data-spot=""
            onClick={() => props.onOpenRoute("gaming")}
          >
            <Zap size={15} strokeWidth={2.2} />
            <span>Gaming</span>
          </button>
        </div>
      </div>
    </div>
  );
}
