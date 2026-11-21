import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen } from "@solidjs/testing-library";
import { createSignal } from "solid-js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AddAppView } from "../src/components/AddAppView";
import { SegmentedTabs } from "../src/components/SegmentedTabs";
import { SplitTunnelView } from "../src/components/SplitTunnelView";
import type {
  ActiveSplitMode,
  SplitAppStatusMap,
  SplitTunnelConfig,
} from "../src/types";
import { SAMPLE_DESKTOP_APPS, stubReducedMotion } from "./helpers/fakeApi";

describe("SegmentedTabs, SplitTunnelView & AddAppView ordering & isolation", () => {
  let restoreMotion: (() => void) | undefined;

  beforeEach(() => {
    vi.useFakeTimers();
    restoreMotion = stubReducedMotion(false);
  });

  afterEach(() => {
    cleanup();
    restoreMotion?.();
    vi.useRealTimers();
  });

  it("keeps outgoing split-tunnel pane content pinned during exit until animationend fires", async () => {
    const initialConfig: SplitTunnelConfig = {
      mode: "bypass",
      apps: ["steam", "discord"],
      bypass_apps: ["steam", "discord"],
      only_vpn_apps: ["firefox"],
      cgroup_paths: [],
      game_only_cidrs: [],
    };
    const statusMap: SplitAppStatusMap = {
      bypass: [
        {
          name: "steam",
          display_name: "Steam",
          running: true,
          in_split_slice: true,
          slice: "app-hadal_bypass.slice",
          pids: [1101],
        },
        {
          name: "discord",
          display_name: "Discord",
          running: false,
          in_split_slice: false,
          slice: null,
          pids: [],
        },
      ],
      only_vpn: [
        {
          name: "firefox",
          display_name: "Firefox",
          running: true,
          in_split_slice: true,
          slice: "app-hadal_vpn.slice",
          pids: [2202],
        },
      ],
    };

    const onUpdateSplitTunnel = vi.fn();
    const onLaunchApp = vi.fn();

    render(() => {
      const [cfg, setCfg] = createSignal<SplitTunnelConfig>(initialConfig);
      return (
        <SplitTunnelView
          splitTunnel={cfg()}
          appStatusesByMode={statusMap}
          animClass=""
          onBack={vi.fn()}
          onOpenAddApps={vi.fn()}
          onUpdateSplitTunnel={(next) => {
            onUpdateSplitTunnel(next);
            setCfg(next);
          }}
          onLaunchApp={onLaunchApp}
        />
      );
    });

    const bypassTab = screen.getByRole("tab", { name: "Bypass VPN" });
    const onlyVpnTab = screen.getByRole("tab", { name: "Route via VPN" });
    const panel = screen.getByRole("tabpanel");
    const tablist = screen.getByRole("tablist");

    expect(bypassTab).toHaveAttribute("aria-selected", "true");
    expect(panel).toHaveAttribute("data-phase", "idle");
    expect(panel).toHaveAttribute("data-rendered-mode", "bypass");
    expect(screen.getByText("Steam")).toBeInTheDocument();
    expect(screen.getByText("Bypassing VPN (1 PID)")).toBeInTheDocument();
    expect(screen.getByText("Apps bypassing VPN (2)")).toBeInTheDocument();
    expect(screen.queryByText("Firefox")).not.toBeInTheDocument();

    await fireEvent.click(onlyVpnTab);

    expect(onlyVpnTab).toHaveAttribute("aria-selected", "true");
    expect(bypassTab).toHaveAttribute("aria-selected", "false");
    expect(tablist.style.getPropertyValue("--seg-index")).toBe("2");
    expect(panel).toHaveAttribute("data-phase", "exiting");
    expect(panel).toHaveAttribute("data-dir", "forward");
    expect(panel).toHaveAttribute("data-rendered-mode", "bypass");

    // Outgoing content must still be rendered halfway through exit (50ms < 80ms)
    expect(screen.getByText("Steam")).toBeInTheDocument();
    expect(screen.queryByText("Firefox")).not.toBeInTheDocument();

    vi.advanceTimersByTime(40);
    expect(panel).toHaveAttribute("data-phase", "exiting");
    expect(screen.getByText("Steam")).toBeInTheDocument();

    // Exit animation completes -> content swaps cleanly and enters
    await fireEvent.animationEnd(panel);
    expect(panel).toHaveAttribute("data-phase", "entering");
    expect(panel).toHaveAttribute("data-rendered-mode", "only_vpn");
    expect(screen.getByText("Firefox")).toBeInTheDocument();
    expect(screen.getByText("Routed via VPN (1 PID)")).toBeInTheDocument();
    expect(screen.getByText("Apps via VPN (1)")).toBeInTheDocument();
    expect(screen.queryByText("Steam")).not.toBeInTheDocument();

    await fireEvent.animationEnd(panel);
    expect(panel).toHaveAttribute("data-phase", "idle");

    // Switching back sets backward direction and holds "only_vpn" until timer fallback completes
    await fireEvent.click(bypassTab);
    expect(panel).toHaveAttribute("data-phase", "exiting");
    expect(panel).toHaveAttribute("data-dir", "backward");
    expect(panel).toHaveAttribute("data-rendered-mode", "only_vpn");

    vi.advanceTimersByTime(80);
    expect(panel).toHaveAttribute("data-phase", "entering");
    expect(panel).toHaveAttribute("data-rendered-mode", "bypass");
    expect(screen.getByText("Steam")).toBeInTheDocument();

    vi.advanceTimersByTime(120);
    expect(panel).toHaveAttribute("data-phase", "idle");
  });

  it("cancels outgoing exit cleanly if user clicks back to original tab mid-exit", async () => {
    const onChange = vi.fn();
    render(() => {
      const [tab, setTab] = createSignal<ActiveSplitMode>("bypass");
      return (
        <SegmentedTabs
          options={[
            { value: "bypass", label: "Bypass VPN" },
            { value: "only_vpn", label: "Route via VPN" },
          ]}
          value={tab()}
          onChange={(next) => {
            onChange(next);
            setTab(next);
          }}
        >
          {(rendered) => <div data-testid="pane-body">{rendered()}</div>}
        </SegmentedTabs>
      );
    });

    const bypassTab = screen.getByRole("tab", { name: "Bypass VPN" });
    const onlyVpnTab = screen.getByRole("tab", { name: "Route via VPN" });
    const panel = screen.getByRole("tabpanel");

    await fireEvent.click(onlyVpnTab);
    expect(panel).toHaveAttribute("data-phase", "exiting");
    expect(screen.getByTestId("pane-body")).toHaveTextContent("bypass");

    vi.advanceTimersByTime(40);
    await fireEvent.click(bypassTab);
    expect(bypassTab).toHaveAttribute("aria-selected", "true");
    expect(screen.getByTestId("pane-body")).toHaveTextContent("bypass");
    expect(panel).toHaveAttribute("data-phase", "entering");

    vi.advanceTimersByTime(200);
    expect(panel).toHaveAttribute("data-phase", "idle");
    expect(screen.getByTestId("pane-body")).toHaveTextContent("bypass");
    expect(onChange).toHaveBeenCalledTimes(2);
  });

  it("swaps immediately when prefers-reduced-motion is reduce", async () => {
    restoreMotion?.();
    restoreMotion = stubReducedMotion(true);

    render(() => {
      const [tab, setTab] = createSignal<ActiveSplitMode>("bypass");
      return (
        <SegmentedTabs
          options={[
            { value: "bypass", label: "Bypass VPN" },
            { value: "only_vpn", label: "Route via VPN" },
          ]}
          value={tab()}
          onChange={setTab}
        >
          {(rendered) => <div data-testid="pane-body">{rendered()}</div>}
        </SegmentedTabs>
      );
    });

    await fireEvent.click(screen.getByRole("tab", { name: "Route via VPN" }));
    const panel = screen.getByRole("tabpanel");
    expect(panel).toHaveAttribute("data-phase", "idle");
    expect(panel).toHaveAttribute("data-rendered-mode", "only_vpn");
    expect(screen.getByTestId("pane-body")).toHaveTextContent("only_vpn");
  });

  it("isolates bypass_apps and only_vpn_apps when adding, launching, and removing apps", async () => {
    const initialConfig: SplitTunnelConfig = {
      mode: "only_vpn",
      apps: ["firefox"],
      bypass_apps: ["steam"],
      only_vpn_apps: ["firefox"],
      cgroup_paths: [],
      game_only_cidrs: [],
    };
    const onUpdate = vi.fn();
    const onLaunch = vi.fn();
    const onOpenAddApps = vi.fn();

    render(() => {
      const [cfg, setCfg] = createSignal<SplitTunnelConfig>(initialConfig);
      return (
        <div>
          <SplitTunnelView
            splitTunnel={cfg()}
            appStatusesByMode={{
              bypass: [],
              only_vpn: [
                {
                  name: "firefox",
                  display_name: "Firefox",
                  running: false,
                  in_split_slice: false,
                  slice: null,
                  pids: [],
                },
              ],
            }}
            animClass=""
            onBack={vi.fn()}
            onOpenAddApps={onOpenAddApps}
            onUpdateSplitTunnel={(next) => {
              onUpdate(next);
              setCfg(next);
            }}
            onLaunchApp={onLaunch}
          />
          <AddAppView
            splitTunnel={cfg()}
            animClass=""
            onBack={vi.fn()}
            onDiscoverApps={async () => SAMPLE_DESKTOP_APPS}
            onUpdateSplitTunnel={(next) => {
              onUpdate(next);
              setCfg(next);
            }}
          />
        </div>
      );
    });

    await fireEvent.click(screen.getByRole("button", { name: "Launch" }));
    expect(onLaunch).toHaveBeenCalledWith("firefox");

    await fireEvent.click(screen.getByRole("button", { name: /Add Application/i }));
    expect(onOpenAddApps).toHaveBeenCalledTimes(1);

    const vlcSwitch = await screen.findByRole("switch", { name: "VLC Media Player" });
    await fireEvent.click(vlcSwitch);

    const lastCall = onUpdate.mock.calls.at(-1)?.[0] as SplitTunnelConfig;
    expect(lastCall.only_vpn_apps).toEqual(["firefox", "vlc"]);
    expect(lastCall.bypass_apps).toEqual(["steam"]);

    await fireEvent.click(screen.getByRole("button", { name: "Remove Firefox" }));
    const afterRemove = onUpdate.mock.calls.at(-1)?.[0] as SplitTunnelConfig;
    expect(afterRemove.only_vpn_apps).toEqual(["vlc"]);
    expect(afterRemove.bypass_apps).toEqual(["steam"]);
  });

  it("synthesizes fallback rows for configured apps while live statuses are still loading", async () => {
    const cfg: SplitTunnelConfig = {
      mode: "bypass",
      apps: ["steam"],
      bypass_apps: ["steam"],
      only_vpn_apps: ["firefox"],
      cgroup_paths: [],
      game_only_cidrs: [],
    };
    render(() => {
      const [splitTunnel, setSplitTunnel] = createSignal(cfg);
      return (
        <SplitTunnelView
          splitTunnel={splitTunnel()}
          appStatusesByMode={{ bypass: [], only_vpn: [] }}
          animClass=""
          onBack={vi.fn()}
          onOpenAddApps={vi.fn()}
          onUpdateSplitTunnel={setSplitTunnel}
          onLaunchApp={vi.fn()}
        />
      );
    });

    expect(screen.getByText("steam")).toBeInTheDocument();

    await fireEvent.click(screen.getByRole("tab", { name: "Route via VPN" }));
    vi.advanceTimersByTime(80);
    expect(screen.getByText("firefox")).toBeInTheDocument();
  });
});
