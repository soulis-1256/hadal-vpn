import { describe, expect, it } from "vitest";
import { buildGlobePins, buildTieredGlobeData } from "../src/globe/clusterPins";
import {
  clampLat,
  computeCameraTransform,
  GLOBE_FOCUS_CY,
  GLOBE_FOCUS_ZOOM,
  GLOBE_W,
  projectSurfacePoint,
  wrapLon,
} from "../src/globe/globeMath";
import {
  createLabelLayoutState,
  rectsOverlap,
  solveAndStepLabels,
  type InViewPin,
  type Rect,
} from "../src/globe/labelLayout";
import type { Cluster, GamingScanReport } from "../src/types";

function makeCluster(overrides: Partial<Cluster> & { id: string }): Cluster {
  return {
    country: "Germany",
    countryCode: "DE",
    region: "Europe",
    regionCode: "EU",
    location: "Frankfurt",
    connectionName: `${overrides.id}.prod`,
    pubKey: `pk-${overrides.id}`,
    tags: [],
    load: 20,
    coordinates: { latitude: 50.11, longitude: 8.68 },
    flagUrl: null,
    type: "generic",
    ...overrides,
  };
}

describe("globeMath, tiered clusterPins, and fixed-anchor labelLayout invariants", () => {
  it("projects any focused surface coordinate dead-center (180, ~230) at 3.8x zoom", () => {
    const cities = [
      { lat: 37.98, lon: 23.73 },
      { lat: 50.11, lon: 8.68 },
      { lat: 40.71, lon: -74.0 },
      { lat: 35.68, lon: 139.7 },
      { lat: -33.86, lon: 151.2 },
    ];

    for (const c of cities) {
      const cam = computeCameraTransform(clampLat(c.lat), wrapLon(c.lon), GLOBE_FOCUS_ZOOM);
      const pt = projectSurfacePoint(c.lat, c.lon, cam);
      expect(pt.visible).toBe(true);
      expect(pt.facing).toBeGreaterThan(0.95);
      expect(Math.abs(pt.x - GLOBE_W / 2)).toBeLessThan(0.2);
      expect(Math.abs(pt.y - GLOBE_FOCUS_CY)).toBeLessThan(0.35);
    }
  });

  it("wraps longitudes to [-180, 180) and clamps latitudes to [-72, 72]", () => {
    expect(wrapLon(190)).toBe(-170);
    expect(wrapLon(-190)).toBe(170);
    expect(wrapLon(540)).toBe(-180);
    expect(clampLat(89)).toBe(72);
    expect(clampLat(-89)).toBe(-72);
  });

  it("deduplicates same-city clusters into one pin and merges gaming ping metrics", () => {
    const base = makeCluster({ id: "de-fra-01", load: 42 });
    const sibling = makeCluster({
      id: "de-fra-02",
      load: 15,
      tags: ["static"],
      type: "static",
    });
    const noCoords = makeCluster({
      id: "xx-null",
      location: "Unknown",
      coordinates: { latitude: null, longitude: null },
    });

    const report: GamingScanReport = {
      game_id: "fortnite",
      region_id: "eu-de",
      target_host: "ping-de.ds.on.epicgames.com",
      baseline_direct: null,
      wan_pmtu: 1492,
      recommended_mtu: 1412,
      game_cidrs: [],
      candidates: [
        {
          cluster_id: "de-fra-01",
          domain: "de-fra-01.prod",
          endpoint_ip: "1.2.3.4",
          location: "Frankfurt",
          country: "Germany",
          load: 42,
          direct_rtt_ms: 21,
          estimated_total_ms: 22.8,
          verified_tunnel_ms: 24.4,
          verified_mdev_ms: 0.4,
        },
      ],
    };

    const pins = buildGlobePins([base, sibling, noCoords], "de-fra-01", null, report);
    expect(pins).toHaveLength(1);
    expect(pins[0].clusterId).toBe("de-fra-01");
    expect(pins[0].clusterIds).toEqual(["de-fra-01", "de-fra-02"]);
    expect(pins[0].hasStatic).toBe(true);
    expect(pins[0].pingMs).toBe(24);
  });

  it("builds 3-tier Continent -> Country -> City pins with single-city leaf shortcuts", () => {
    const clusters: Cluster[] = [
      makeCluster({
        id: "de-fra",
        country: "Germany",
        countryCode: "DE",
        location: "Frankfurt",
        coordinates: { latitude: 50.11, longitude: 8.68 },
      }),
      makeCluster({
        id: "de-ber",
        country: "Germany",
        countryCode: "DE",
        location: "Berlin",
        coordinates: { latitude: 52.52, longitude: 13.4 },
      }),
      makeCluster({
        id: "at-vie",
        country: "Austria",
        countryCode: "AT",
        location: "Vienna",
        coordinates: { latitude: 48.2, longitude: 16.37 },
      }),
      makeCluster({
        id: "us-nyc",
        country: "United States",
        countryCode: "US",
        region: "Americas",
        regionCode: "NA",
        location: "New York",
        coordinates: { latitude: 40.71, longitude: -74.0 },
      }),
      makeCluster({
        id: "us-chi",
        country: "United States",
        countryCode: "US",
        region: "Americas",
        regionCode: "NA",
        location: "Chicago",
        coordinates: { latitude: 41.87, longitude: -87.62 },
      }),
      makeCluster({
        id: "us-lax",
        country: "United States",
        countryCode: "US",
        region: "Americas",
        regionCode: "NA",
        location: "Los Angeles",
        coordinates: { latitude: 34.05, longitude: -118.24 },
      }),
    ];

    const tiered = buildTieredGlobeData(clusters, "at-vie", null, null);
    expect(tiered.continents.map((c) => c.label)).toEqual(["Europe", "North America"]);
    expect(tiered.continents.every((c) => !c.isLeaf)).toBe(true);

    const de = tiered.countries.find((c) => c.countryCode === "DE")!;
    const at = tiered.countries.find((c) => c.countryCode === "AT")!;
    const us = tiered.countries.find((c) => c.countryCode === "US")!;
    expect(de.label).toBe("Germany");
    expect(de.isLeaf).toBe(false);
    expect(de.childCount).toBe(2);

    // Single-city country keeps its country label at Tier 2 and connects directly on click.
    expect(at.label).toBe("Austria");
    expect(at.isLeaf).toBe(true);
    expect(at.childCount).toBe(1);

    // Multi-city country medoid anchors inside the US (Chicago), not on a coastline edge.
    expect(us.label).toBe("United States");
    expect(us.isLeaf).toBe(false);
    expect(us.city).toBe("Chicago");
    expect(us.focusZoom).toBeGreaterThanOrEqual(3.0);
    expect(tiered.cities).toHaveLength(6);
  });

  it("keeps fixed-anchor labels pan-locked without flipping across dots", () => {
    const state = createLabelLayoutState();
    const dummyPin = (key: string, city: string, lat: number, lon: number) => ({
      key,
      tier: "city" as const,
      continentId: "EU" as const,
      clusterId: key,
      clusterIds: [key],
      label: city,
      city,
      country: "Test",
      countryCode: "TS",
      connectionName: key,
      load: 20,
      lat,
      lon,
      childCount: 1,
      focusZoom: 3.8,
      isLeaf: true,
      isCountryHub: true,
      importance: 100,
      hasStatic: false,
      pingMs: 12,
      ranked: false,
      pref: 0,
    });

    const p1 = dummyPin("de::fra", "Frankfurt", 50.11, 8.68);
    const p2 = dummyPin("ch::zur", "Zurich", 47.37, 8.54);
    const iv1: InViewPin = { key: p1.key, pin: p1, idx: 0, x: 170, y: 200, pref: 0 };
    const iv2: InViewPin = { key: p2.key, pin: p2, idx: 1, x: 172, y: 214, pref: 0 };

    // 1. Zoomed out (1.0x) with minLabelZoom 1.35 and no hover -> zero labels shown
    const zoomedOutIdle = solveAndStepLabels(state, {
      isHome: true,
      appR: 150,
      zoom: 1.0,
      homeHudAlpha: 1,
      inViewPins: [iv1, iv2],
      projMap: new Map([[p1.key, iv1], [p2.key, iv2]]),
      obstacles: [[iv1.x - 4, iv1.y - 4, 8, 8], [iv2.x - 4, iv2.y - 4, 8, 8]],
      wantHoverPin: null,
      cityFontSize: 11.5,
      padX: 4,
      padY: 2,
      lineHeight: 14,
      measureCityWidth: (city) => city.length * 7,
      dt: 0.05,
    });
    expect(zoomedOutIdle.drawables).toHaveLength(0);

    // 2. Zoomed out with hover -> reveals hovered label inside safe screen rect
    const zoomedOutHover = solveAndStepLabels(state, {
      isHome: true,
      appR: 150,
      zoom: 1.0,
      homeHudAlpha: 1,
      inViewPins: [iv1, iv2],
      projMap: new Map([[p1.key, iv1], [p2.key, iv2]]),
      obstacles: [[iv1.x - 4, iv1.y - 4, 8, 8], [iv2.x - 4, iv2.y - 4, 8, 8]],
      wantHoverPin: iv1,
      cityFontSize: 11.5,
      padX: 4,
      padY: 2,
      lineHeight: 14,
      measureCityWidth: (city) => city.length * 7,
      dt: 0.05,
    });
    expect(zoomedOutHover.drawables).toHaveLength(1);
    expect(zoomedOutHover.drawables[0].city).toBe("Frankfurt");
    expect(zoomedOutHover.labelHits).toHaveLength(1);

    // 3. Zoomed in (3.0x) -> places both labels strictly locked to pan offset (1:1 delta)
    const iv2Spaced: InViewPin = { ...iv2, y: 234 };
    const obs: Rect[] = [[170 - 4, 200 - 4, 8, 8], [172 - 4, 234 - 4, 8, 8]];
    const solved1 = solveAndStepLabels(state, {
      isHome: true,
      appR: 300,
      zoom: 3.0,
      homeHudAlpha: 1,
      inViewPins: [iv1, iv2Spaced],
      projMap: new Map([[p1.key, iv1], [p2.key, iv2Spaced]]),
      obstacles: obs,
      wantHoverPin: null,
      cityFontSize: 11.5,
      padX: 4,
      padY: 2,
      lineHeight: 14,
      measureCityWidth: (city) => city.length * 7,
      dt: 0.05,
    });
    expect(solved1.drawables).toHaveLength(2);
    const fra1 = solved1.drawables.find((d) => d.city === "Frankfurt")!;
    const zur1 = solved1.drawables.find((d) => d.city === "Zurich")!;
    expect(
      rectsOverlap([fra1.tx, fra1.ty, 60, 14], [zur1.tx, zur1.ty, 42, 14]),
    ).toBe(false);

    const pan1 = { ...iv1, x: 176, y: 205 };
    const pan2 = { ...iv2Spaced, x: 178, y: 239 };
    const solved2 = solveAndStepLabels(state, {
      isHome: true,
      appR: 300,
      zoom: 3.0,
      homeHudAlpha: 1,
      inViewPins: [pan1, pan2],
      projMap: new Map([[p1.key, pan1], [p2.key, pan2]]),
      obstacles: [[176 - 4, 205 - 4, 8, 8], [178 - 4, 239 - 4, 8, 8]],
      wantHoverPin: null,
      cityFontSize: 11.5,
      padX: 4,
      padY: 2,
      lineHeight: 14,
      measureCityWidth: (city) => city.length * 7,
      dt: 0.05,
    });
    const fra2 = solved2.drawables.find((d) => d.city === "Frankfurt")!;
    const zur2 = solved2.drawables.find((d) => d.city === "Zurich")!;
    // Pan delta (+6, +5) shifts labels by the exact same (+6, +5) pixels with zero lag/swing.
    expect(fra2.tx - fra1.tx).toBeCloseTo(6, 5);
    expect(fra2.ty - fra1.ty).toBeCloseTo(5, 5);
    expect(zur2.tx - zur1.tx).toBeCloseTo(6, 5);
    expect(zur2.ty - zur1.ty).toBeCloseTo(5, 5);
  });

  it("keeps visible labels on dense 25-pin regions with adjacent 10px twin cities without global collapse", () => {
    const state = createLabelLayoutState();
    const mkPin = (key: string, city: string, idx: number, x: number, y: number): InViewPin => ({
      key,
      pin: {
        key,
        tier: "city",
        continentId: "EU",
        clusterId: key,
        clusterIds: [key],
        label: city,
        city,
        country: "EU",
        countryCode: "EU",
        connectionName: key,
        load: 15 + (idx % 30),
        lat: 48,
        lon: 16,
        childCount: 1,
        focusZoom: 3.8,
        isLeaf: true,
        isCountryHub: idx % 3 === 0,
        importance: 100 - idx,
        hasStatic: false,
        pingMs: null,
        ranked: false,
        pref: idx % 4,
      },
      idx,
      x,
      y,
      pref: idx % 4,
    });

    const pins: InViewPin[] = [
      mkPin("at::vienna", "Vienna", 0, 180, 230),
      mkPin("sk::bratislava", "Bratislava", 1, 189, 231),
    ];
    for (let r = 0; r < 5; r++) {
      for (let c = 0; c < 5; c++) {
        if (r === 2 && c === 2) continue;
        const idx = pins.length;
        pins.push(mkPin(`eu::c${idx}`, `City${idx}`, idx, 60 + c * 64, 85 + r * 66));
      }
    }

    const obstacles: Rect[] = pins.map((p) => [p.x - 4, p.y - 4, 8, 8]);
    const projMap = new Map(pins.map((p) => [p.key, p]));

    const res = solveAndStepLabels(state, {
      isHome: true,
      appR: 420,
      zoom: 7.5,
      homeHudAlpha: 1,
      inViewPins: pins,
      projMap,
      obstacles,
      wantHoverPin: null,
      activePinKey: "at::vienna",
      cityFontSize: 11.5,
      padX: 4,
      padY: 2,
      lineHeight: 14,
      measureCityWidth: (city) => city.length * 7,
      dt: 0.25,
    });

    expect(res.drawables.length).toBeGreaterThanOrEqual(16);
    expect(res.drawables.some((d) => d.city === "Vienna")).toBe(true);
  });
});
