import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@solidjs/testing-library";
import { createSignal } from "solid-js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "../src/App";
import { LocationsSheet } from "../src/components/LocationsSheet";
import { buildTieredGlobeData } from "../src/globe/clusterPins";
import { OrbitGlobe } from "../src/globe/OrbitGlobe";
import type { Cluster } from "../src/types";
import { attachMiddleClickScroll } from "../src/utils/middleClickScroll";
import {
  createFakeVpnApi,
  makeEnvelope,
  makeSettings,
  SAMPLE_CLUSTERS,
} from "./helpers/fakeApi";

describe("Hadal VPN Spatial Atlas App & Views integration", () => {
  let restoreGetContext: (() => void) | undefined;

  beforeEach(() => {
    const spy = vi
      .spyOn(HTMLCanvasElement.prototype, "getContext")
      .mockImplementation(() => null);
    restoreGetContext = () => spy.mockRestore();
  });

  afterEach(() => {
    cleanup();
    restoreGetContext?.();
    vi.useRealTimers();
  });

  it("renders AuthView when logged out and authenticates via Quick Pair", async () => {
    vi.useFakeTimers();
    const fake = createFakeVpnApi({ loggedIn: false });
    fake.mocks.pollRemoteLogin
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({ token: "pair-jwt", renewToken: "pair-ren" });

    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", {
      value: { writeText },
      configurable: true,
    });

    render(() => <App api={fake.api} />);

    await screen.findByText("ABCD12");
    await fireEvent.click(screen.getByRole("button", { name: "Open Web" }));
    expect(fake.mocks.openExternal).toHaveBeenCalledWith("https://my.surfshark.com");
    await fireEvent.click(screen.getByRole("button", { name: "Copy pairing code" }));
    expect(writeText).toHaveBeenCalledWith("ABCD12");
    await screen.findByRole("button", { name: "Pairing code copied" });
    expect(screen.getByRole("button", { name: "New code" })).toBeInTheDocument();

    await vi.advanceTimersByTimeAsync(3000);
    expect(fake.mocks.pollRemoteLogin).toHaveBeenCalledWith("pair-hash");
    expect(screen.queryByRole("button", { name: "Connect" })).not.toBeInTheDocument();

    await vi.advanceTimersByTimeAsync(3000);
    await screen.findByRole("button", { name: "Connect" });
  });

  it("renders offline daemon notice with Retry Connection recovery", async () => {
    const fake = createFakeVpnApi({
      loggedIn: true,
      envelope: makeEnvelope({ state: "disconnected" }, false, "daemon unreachable"),
    });

    render(() => <App api={fake.api} />);

    await screen.findByText("hadald daemon offline");
    const connectBtn = screen.getByRole("button", { name: "Connect" });
    expect(connectBtn).toBeDisabled();

    fake.mocks.getDaemonStatus.mockResolvedValueOnce(makeEnvelope({ state: "disconnected" }, true));
    await fireEvent.click(screen.getByRole("button", { name: "Retry Connection" }));

    await waitFor(() =>
      expect(screen.queryByText("hadald daemon offline")).not.toBeInTheDocument(),
    );
    expect(screen.getByRole("button", { name: "Connect" })).toBeEnabled();
  });

  it("opens Locations sheet, filters & toggles country accordions, and connects back to Home", async () => {
    const fake = createFakeVpnApi({ loggedIn: true });
    render(() => <App api={fake.api} />);

    // Wait for bootstrapAuthedData() clusters to populate dock card (lowest load = Vienna, Austria)
    await screen.findByText("Vienna, Austria");
    await fireEvent.click(screen.getByRole("button", { name: "Select location" }));

    expect(screen.getByText("Exit Nodes")).toBeInTheDocument();

    // Currently selected cluster's country (Austria) auto-expands on open and highlights Vienna
    const austriaHead = screen.getByRole("button", { name: /Austria/i });
    expect(austriaHead).toHaveAttribute("aria-expanded", "true");
    await fireEvent.click(austriaHead);
    expect(austriaHead).toHaveAttribute("aria-expanded", "false");

    // Other country accordions remain collapsible/expandable individually
    const germanyHead = screen.getByRole("button", { name: /Germany/i });
    expect(germanyHead).toHaveAttribute("aria-expanded", "false");
    await fireEvent.click(germanyHead);
    expect(germanyHead).toHaveAttribute("aria-expanded", "true");
    await fireEvent.click(germanyHead);
    expect(germanyHead).toHaveAttribute("aria-expanded", "false");

    // Static IP filter finds New York
    await fireEvent.click(screen.getByRole("tab", { name: "Static IP" }));
    const usHead = await screen.findByRole("button", { name: /United States/i });
    await fireEvent.click(usHead);
    await fireEvent.click(screen.getByRole("button", { name: /New York/i }));

    await waitFor(() =>
      expect(fake.mocks.connectCluster).toHaveBeenCalledWith({
        clusterId: "us-nyc-st",
        endpointOverride: null,
        mtuOverride: null,
        gameOnlyCidrs: null,
      }),
    );

    // Popped cleanly back to Home protected state
    await screen.findByRole("button", { name: "Disconnect" });
  });

  it("scans Gaming endpoints with grouped dropdowns and connects candidate with game-only CIDRs", async () => {
    const fake = createFakeVpnApi({
      loggedIn: true,
      settings: makeSettings({ game_only_routing: true }),
    });
    render(() => <App api={fake.api} />);

    await screen.findByRole("button", { name: "Gaming" });
    await fireEvent.click(screen.getByRole("button", { name: "Gaming" }));

    expect(screen.getByText("Gaming Boost")).toBeInTheDocument();
    await fireEvent.input(screen.getByPlaceholderText(/Custom server host/i), {
      target: { value: "custom.match.gg" },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Scan" }));

    await waitFor(() =>
      expect(fake.mocks.scanGaming).toHaveBeenCalledWith(
        "fortnite",
        "eu-de",
        "custom.match.gg",
      ),
    );
    await screen.findByText(/Frankfurt, Germany/i);
    await screen.findByText(/12% loss/i);

    await fireEvent.click(screen.getByRole("button", { name: /Frankfurt, Germany/i }));
    await waitFor(() =>
      expect(fake.mocks.connectCluster).toHaveBeenCalledWith({
        clusterId: "de-fra",
        endpointOverride: "138.199.19.160:51820",
        mtuOverride: 1412,
        gameOnlyCidrs: ["3.66.0.0/16"],
      }),
    );
    await screen.findByRole("button", { name: "Disconnect" });
  });

  it("navigates Settings -> Split Tunneling -> Add Application, handles Killswitch rollback, and signs out", async () => {
    const fake = createFakeVpnApi({
      loggedIn: true,
      envelope: makeEnvelope({ state: "disconnected", killswitch: false }),
      settings: makeSettings({ killswitch: false, auto_mtu: false, manual_mtu: 1400 }),
      clusters: SAMPLE_CLUSTERS,
    });
    fake.mocks.setKillswitch.mockRejectedValueOnce(new Error("nftables failed"));

    render(() => <App api={fake.api} />);

    await screen.findByText("Vienna, Austria");
    await fireEvent.click(screen.getByRole("button", { name: "Settings" }));

    // Account card renders email + actions without avatar/status bloat
    await screen.findByText("tester@example.com");
    expect(screen.queryByText(/hadald online/i)).not.toBeInTheDocument();
    expect(document.querySelector(".acct-av")).toBeNull();
    expect(screen.getByLabelText("Manual MTU")).toHaveValue(1400);

    // Killswitch rollback check
    const ksSwitch = screen.getByRole("switch", { name: "Killswitch + DNS Lock" });
    await fireEvent.click(ksSwitch);
    await screen.findByText(/nftables failed/i);
    expect(ksSwitch).toHaveAttribute("aria-checked", "false");

    // Push Split Tunneling -> Add Application -> test search clear X button -> Add custom command
    await fireEvent.click(screen.getByRole("button", { name: /Split Tunneling/i }));
    await screen.findByText("Split tunneling");
    await fireEvent.click(screen.getByRole("button", { name: /Add Application/i }));
    await screen.findByText("Add application");

    const addSearch = screen.getByPlaceholderText(/Search installed apps/i);
    await fireEvent.input(addSearch, { target: { value: "temporary" } });
    await fireEvent.click(screen.getByRole("button", { name: "Clear search" }));
    expect(addSearch).toHaveValue("");

    await fireEvent.input(addSearch, {
      target: { value: "cs2-launcher" },
    });
    await fireEvent.click(
      screen.getByRole("button", { name: /Add custom command.*cs2-launcher/i }),
    );
    await waitFor(() =>
      expect(fake.mocks.saveSettings).toHaveBeenCalledWith(
        expect.objectContaining({
          split_tunnel: expect.objectContaining({
            bypass_apps: expect.arrayContaining(["cs2-launcher"]),
          }),
        }),
      ),
    );

    // Back from split tunnel -> Settings -> About & Licenses -> back -> Sign Out
    await fireEvent.click(screen.getByRole("button", { name: "Back" }));
    await screen.findByText("tester@example.com");
    await fireEvent.click(screen.getByRole("button", { name: /About & Licenses/i }));
    await screen.findByText("Hadal VPN v0.2.1");
    expect(screen.getByText("GPL-3.0-or-later")).toBeInTheDocument();
    await fireEvent.click(screen.getByRole("button", { name: "View GNU GPL-3.0 License" }));
    expect(fake.mocks.openExternal).toHaveBeenCalledWith(
      "https://www.gnu.org/licenses/gpl-3.0.html",
    );
    await fireEvent.click(screen.getByRole("button", { name: "Back" }));
    await screen.findByText("tester@example.com");
    await fireEvent.click(screen.getByRole("button", { name: "Sign Out" }));
    await screen.findByRole("button", { name: "Open Web" });
  });

  it("shows Unlock Killswitch CTA when daemon state is killswitch_locked", async () => {
    const fake = createFakeVpnApi({
      loggedIn: true,
      envelope: makeEnvelope({ state: "killswitch_locked", killswitch: true }),
    });

    render(() => <App api={fake.api} />);

    const unlockBtn = await screen.findByRole("button", { name: "Unlock Killswitch" });
    expect(unlockBtn).toBeEnabled();
    await fireEvent.click(unlockBtn);

    await waitFor(() => expect(fake.mocks.disconnectTunnel).toHaveBeenCalledWith(false));
    await screen.findByRole("button", { name: "Connect" });
  });

  it("layers Escape cleanly: closes Select drawer -> pops full/sheet routes -> hides only on Home", async () => {
    const fake = createFakeVpnApi({ loggedIn: true });
    const { container } = render(() => <App api={fake.api} />);

    await screen.findByText("Vienna, Austria");
    await fireEvent.click(screen.getByRole("button", { name: "Gaming" }));

    // Open Region Select drawer inside Gaming (2nd select-trigger)
    const triggers = container.querySelectorAll(".select-trigger");
    const regionTrigger = triggers[1] as HTMLButtonElement;
    await fireEvent.click(regionTrigger);
    expect(regionTrigger).toHaveAttribute("aria-expanded", "true");

    // 1st Escape closes drawer only
    await fireEvent.keyDown(window, { key: "Escape" });
    expect(regionTrigger).toHaveAttribute("aria-expanded", "false");
    expect(screen.getByText("Gaming Boost")).toBeInTheDocument();
    expect(fake.mocks.hideWindow).not.toHaveBeenCalled();

    // 2nd Escape pops Gaming -> Home without hiding window
    await fireEvent.keyDown(window, { key: "Escape" });
    expect(fake.mocks.hideWindow).not.toHaveBeenCalled();

    // Open Locations sheet then close it with Escape
    await fireEvent.click(screen.getByRole("button", { name: "Select location" }));
    expect(screen.getByText("Exit Nodes")).toBeInTheDocument();
    await fireEvent.keyDown(window, { key: "Escape" });
    expect(fake.mocks.hideWindow).not.toHaveBeenCalled();

    // Final Escape on root Home hides window
    await fireEvent.keyDown(window, { key: "Escape" });
    expect(fake.mocks.hideWindow).toHaveBeenCalledTimes(1);
  });

  it("hides window from header Minimize button and clears Location search via X button", async () => {
    const fake = createFakeVpnApi({ loggedIn: true });
    render(() => <App api={fake.api} />);

    await screen.findByText("Vienna, Austria");

    // Settings icon-only button has accessible label without visible text label
    const settingsBtn = screen.getByRole("button", { name: "Settings" });
    expect(settingsBtn).toHaveTextContent("");

    await fireEvent.click(screen.getByRole("button", { name: "Minimize to tray" }));
    expect(fake.mocks.hideWindow).toHaveBeenCalledTimes(1);

    await fireEvent.click(screen.getByRole("button", { name: "Select location" }));
    const locSearch = screen.getByPlaceholderText(/Search country or city/i);
    expect(screen.queryByRole("button", { name: "Clear search" })).not.toBeInTheDocument();

    await fireEvent.input(locSearch, { target: { value: "Germany" } });
    expect(screen.queryByRole("button", { name: /Austria/i })).not.toBeInTheDocument();

    const clearBtn = screen.getByRole("button", { name: "Clear search" });
    await fireEvent.click(clearBtn);
    expect(locSearch).toHaveValue("");
    expect(screen.getByRole("button", { name: /Austria/i })).toBeInTheDocument();
  });

  it("exposes Minimize to tray button on AuthView and all full-screen views", async () => {
    const loggedOutFake = createFakeVpnApi({ loggedIn: false });
    const firstRender = render(() => <App api={loggedOutFake.api} />);

    await screen.findByRole("button", { name: "Open Web" });
    await fireEvent.click(screen.getByRole("button", { name: "Minimize to tray" }));
    expect(loggedOutFake.mocks.hideWindow).toHaveBeenCalledTimes(1);
    firstRender.unmount();

    const fake = createFakeVpnApi({ loggedIn: true });
    render(() => <App api={fake.api} />);
    await screen.findByText("Vienna, Austria");

    await fireEvent.click(screen.getByRole("button", { name: "Gaming" }));
    await screen.findByText("Gaming Boost");
    await fireEvent.click(screen.getByRole("button", { name: "Minimize to tray" }));
    expect(fake.mocks.hideWindow).toHaveBeenCalledTimes(1);

    await fireEvent.click(screen.getByRole("button", { name: "Back" }));
    await fireEvent.click(screen.getByRole("button", { name: "Settings" }));
    await screen.findByText("tester@example.com");
    await fireEvent.click(screen.getByRole("button", { name: "Minimize to tray" }));
    expect(fake.mocks.hideWindow).toHaveBeenCalledTimes(2);

    await fireEvent.click(screen.getByRole("button", { name: /Split Tunneling/i }));
    await screen.findByText("Split tunneling");
    await fireEvent.click(screen.getByRole("button", { name: "Minimize to tray" }));
    expect(fake.mocks.hideWindow).toHaveBeenCalledTimes(3);

    await fireEvent.click(screen.getByRole("button", { name: /Add Application/i }));
    await screen.findByText("Add application");
    await fireEvent.click(screen.getByRole("button", { name: "Minimize to tray" }));
    expect(fake.mocks.hideWindow).toHaveBeenCalledTimes(4);
  });

  it("supports middle-click wheel scrolling on scrollable list containers", () => {
    const box = document.createElement("div");
    Object.defineProperty(box, "scrollHeight", { value: 900, configurable: true });
    Object.defineProperty(box, "clientHeight", { value: 300, configurable: true });
    box.scrollTop = 40;
    document.body.appendChild(box);

    const rafCallbacks: FrameRequestCallback[] = [];
    const rafSpy = vi
      .spyOn(window, "requestAnimationFrame")
      .mockImplementation((cb) => {
        rafCallbacks.push(cb);
        return rafCallbacks.length;
      });
    const cancelSpy = vi.spyOn(window, "cancelAnimationFrame").mockImplementation(() => {});

    const handle = attachMiddleClickScroll(box);

    // Middle-click release starts toggle autoscroll and attaches origin marker
    fireEvent.pointerDown(box, { button: 1, clientX: 100, clientY: 100 });
    fireEvent.pointerUp(window, { button: 1, clientX: 100, clientY: 100 });
    expect(document.querySelector(".autoscroll-anchor")).not.toBeNull();

    // Move downward beyond deadzone and tick animation frames
    fireEvent.pointerMove(window, { clientX: 100, clientY: 180 });
    const now = performance.now();
    rafCallbacks.shift()?.(now);
    rafCallbacks.shift()?.(now + 40);
    expect(box.scrollTop).toBeGreaterThan(40);

    // Escape closes autoscroll cleanly and removes origin marker
    fireEvent.keyDown(window, { key: "Escape" });
    expect(document.querySelector(".autoscroll-anchor")).toBeNull();

    handle.cleanup();
    box.remove();
    rafSpy.mockRestore();
    cancelSpy.mockRestore();
  });

  it("lazily mounts city rows only for expanded or searched countries in LocationsSheet", async () => {
    const manyClusters: Cluster[] = [];
    for (let c = 0; c < 40; c++) {
      for (let city = 0; city < 4; city++) {
        manyClusters.push({
          id: `c${c}-city${city}`,
          country: `Country ${String(c).padStart(2, "0")}`,
          countryCode: `C${c}`,
          region: "Europe",
          regionCode: "EU",
          location: `City ${c}-${city}`,
          connectionName: `c${c}-${city}.hadal.test`,
          pubKey: null,
          load: 10 + city,
          tags: [],
          coordinates: { longitude: 10 + c, latitude: 40 },
          flagUrl: null,
          type: "generic",
        });
      }
    }

    const [open, setOpen] = createSignal(false);
    const { container } = render(() => (
      <LocationsSheet
        open={open()}
        clusters={manyClusters}
        activeClusterId="c0-city0"
        selectedClusterId="c0-city0"
        connectingClusterId={null}
        gamingReport={null}
        tunnelBusy={false}
        onClose={() => setOpen(false)}
        onConnect={() => {}}
        onRefresh={async () => {}}
      />
    ));

    // Before opening, all 40 countries are collapsed -> zero city buttons in DOM
    expect(container.querySelectorAll(".acc-head")).toHaveLength(40);
    expect(container.querySelectorAll(".city-row")).toHaveLength(0);
    expect(container.querySelectorAll(".acc-head[data-spot], .city-row[data-spot]")).toHaveLength(0);

    // Opening auto-expands only active country (Country 00 -> 4 cities, not 160)
    setOpen(true);
    await waitFor(() => expect(container.querySelectorAll(".city-row")).toHaveLength(4));

    // Expanding a second country mounts only its 4 cities (total 8)
    await fireEvent.click(screen.getByRole("button", { name: /Country 12/i }));
    expect(container.querySelectorAll(".city-row")).toHaveLength(8);
  });

  it("pauses OrbitGlobe rAF loop when obscured or after LocationsSheet fades out", () => {
    const stub2dCtx = {
      setTransform: vi.fn(),
      clearRect: vi.fn(),
      fillRect: vi.fn(),
      beginPath: vi.fn(),
      arc: vi.fn(),
      fill: vi.fn(),
      stroke: vi.fn(),
      strokeText: vi.fn(),
      fillText: vi.fn(),
      measureText: vi.fn(() => ({ width: 24 })),
      createRadialGradient: vi.fn(() => ({ addColorStop: vi.fn() })),
    };

    const ctxSpy = vi
      .spyOn(HTMLCanvasElement.prototype, "getContext")
      .mockImplementation((kind: string) =>
        kind === "2d" ? (stub2dCtx as unknown as CanvasRenderingContext2D) : null,
      );

    let nextId = 1;
    const queue = new Map<number, FrameRequestCallback>();
    const rafSpy = vi
      .spyOn(window, "requestAnimationFrame")
      .mockImplementation((cb) => {
        const id = nextId++;
        queue.set(id, cb);
        return id;
      });
    const cancelSpy = vi
      .spyOn(window, "cancelAnimationFrame")
      .mockImplementation((id) => {
        queue.delete(id);
      });

    try {
      const tiered = buildTieredGlobeData(SAMPLE_CLUSTERS, "at-vie", "at-vie", null);
      const [homeActive, setHomeActive] = createSignal(true);
      const [obscured, setObscured] = createSignal(false);

      render(() => (
        <OrbitGlobe
          tieredData={tiered}
          activeClusterId="at-vie"
          selectedClusterId="at-vie"
          hoveredClusterId={null}
          tunnelState="protected"
          scanning={false}
          homeActive={homeActive()}
          obscured={obscured()}
          focusRequest={null}
          onSelectCluster={() => {}}
        />
      ));

      const flushOneFrame = (ts: number) => {
        const first = queue.entries().next();
        if (first.done) return false;
        const [id, cb] = first.value;
        queue.delete(id);
        cb(ts);
        return true;
      };

      // Active Home keeps scheduling animation frames
      expect(queue.size).toBe(1);
      expect(flushOneFrame(1000)).toBe(true);
      expect(queue.size).toBe(1);

      // Opening LocationsSheet (homeActive = false) drains HUD fade then stops rAF
      setHomeActive(false);
      let steps = 0;
      let ts = 1020;
      while (queue.size > 0 && steps < 10) {
        flushOneFrame(ts);
        ts += 20;
        steps += 1;
      }
      expect(queue.size).toBe(0);
      expect(steps).toBeLessThan(10);

      // Returning home resumes rAF; opening opaque full-layer cancels rAF immediately
      setHomeActive(true);
      expect(queue.size).toBe(1);
      setObscured(true);
      expect(queue.size).toBe(0);

      // Closing full-layer resumes rAF cleanly
      setObscured(false);
      expect(queue.size).toBe(1);
    } finally {
      rafSpy.mockRestore();
      cancelSpy.mockRestore();
      ctxSpy.mockRestore();
    }
  });
});
