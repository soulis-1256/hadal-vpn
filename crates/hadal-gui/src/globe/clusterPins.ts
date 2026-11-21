import type { Cluster, GamingScanReport } from "../types";

export type ContinentId = "NA" | "SA" | "EU" | "AF" | "AS" | "OC";
export type GlobeTier = "continent" | "country" | "city";

export interface GlobePin {
  key: string;
  tier: GlobeTier;
  continentId: ContinentId;
  clusterId: string;
  clusterIds: string[];
  label: string;
  city: string;
  country: string;
  countryCode: string;
  connectionName: string;
  load: number;
  lat: number;
  lon: number;
  childCount: number;
  /** Zoom level recommended when clicking this non-leaf pin to expand its next tier. */
  focusZoom: number;
  /** True for individual cities and single-city countries that connect/select directly on click. */
  isLeaf: boolean;
  /** True for the primary representative hub within a country (used for stable priority ordering). */
  isCountryHub: boolean;
  /** Static geographic importance weight (higher = more prominent, independent of live load). */
  importance: number;
  hasStatic: boolean;
  pingMs: number | null;
  ranked: boolean;
  pref: number;
}

export interface TieredGlobeData {
  continents: GlobePin[];
  countries: GlobePin[];
  cities: GlobePin[];
}

interface ContinentMeta {
  id: ContinentId;
  name: string;
  lat: number;
  lon: number;
  focusZoom: number;
}

const CONTINENT_META: Record<ContinentId, ContinentMeta> = {
  NA: { id: "NA", name: "North America", lat: 40.5, lon: -96.5, focusZoom: 1.95 },
  SA: { id: "SA", name: "South America", lat: -14.5, lon: -58.0, focusZoom: 2.0 },
  EU: { id: "EU", name: "Europe", lat: 49.5, lon: 13.0, focusZoom: 2.08 },
  AF: { id: "AF", name: "Africa", lat: 7.5, lon: 21.5, focusZoom: 2.0 },
  AS: { id: "AS", name: "Asia", lat: 31.0, lon: 94.0, focusZoom: 1.9 },
  OC: { id: "OC", name: "Oceania", lat: -25.5, lon: 134.5, focusZoom: 2.15 },
};

const CONTINENT_ORDER: readonly ContinentId[] = ["EU", "NA", "AS", "SA", "AF", "OC"];

const COUNTRY_TO_CONTINENT: Record<string, ContinentId> = {
  // Europe
  AD: "EU", AL: "EU", AT: "EU", AX: "EU", BA: "EU", BE: "EU", BG: "EU", BY: "EU",
  CH: "EU", CY: "EU", CZ: "EU", DE: "EU", DK: "EU", EE: "EU", ES: "EU", FI: "EU",
  FO: "EU", FR: "EU", GB: "EU", GG: "EU", GI: "EU", GR: "EU", HR: "EU", HU: "EU",
  IE: "EU", IM: "EU", IS: "EU", IT: "EU", JE: "EU", LI: "EU", LT: "EU", LU: "EU",
  LV: "EU", MC: "EU", MD: "EU", ME: "EU", MK: "EU", MT: "EU", NL: "EU", NO: "EU",
  PL: "EU", PT: "EU", RO: "EU", RS: "EU", RU: "EU", SE: "EU", SI: "EU", SK: "EU",
  SM: "EU", UA: "EU", UK: "EU", VA: "EU", XK: "EU",
  // North & Central America + Caribbean
  AG: "NA", AI: "NA", AW: "NA", BB: "NA", BM: "NA", BS: "NA", BZ: "NA", CA: "NA",
  CR: "NA", CU: "NA", CW: "NA", DM: "NA", DO: "NA", GD: "NA", GL: "NA", GT: "NA",
  HN: "NA", HT: "NA", JM: "NA", KN: "NA", KY: "NA", LC: "NA", MX: "NA", NI: "NA",
  PA: "NA", PR: "NA", SV: "NA", TC: "NA", TT: "NA", US: "NA", VC: "NA", VG: "NA",
  // South America
  AR: "SA", BO: "SA", BR: "SA", CL: "SA", CO: "SA", EC: "SA", FK: "SA", GF: "SA",
  GY: "SA", PE: "SA", PY: "SA", SR: "SA", UY: "SA", VE: "SA",
  // Africa
  AO: "AF", BF: "AF", BI: "AF", BJ: "AF", BW: "AF", CD: "AF", CF: "AF", CG: "AF",
  CI: "AF", CM: "AF", CV: "AF", DJ: "AF", DZ: "AF", EG: "AF", EH: "AF", ER: "AF",
  ET: "AF", GA: "AF", GH: "AF", GM: "AF", GN: "AF", GQ: "AF", GW: "AF", KE: "AF",
  KM: "AF", LR: "AF", LS: "AF", LY: "AF", MA: "AF", MG: "AF", ML: "AF", MR: "AF",
  MU: "AF", MW: "AF", MZ: "AF", NA: "AF", NE: "AF", NG: "AF", RE: "AF", RW: "AF",
  SC: "AF", SD: "AF", SL: "AF", SN: "AF", SO: "AF", SS: "AF", ST: "AF", SZ: "AF",
  TD: "AF", TG: "AF", TN: "AF", TZ: "AF", UG: "AF", ZA: "AF", ZM: "AF", ZW: "AF",
  // Asia & Middle East
  AE: "AS", AF: "AS", AM: "AS", AZ: "AS", BD: "AS", BH: "AS", BN: "AS", BT: "AS",
  CN: "AS", GE: "AS", HK: "AS", ID: "AS", IL: "AS", IN: "AS", IQ: "AS", IR: "AS",
  JO: "AS", JP: "AS", KG: "AS", KH: "AS", KP: "AS", KR: "AS", KW: "AS", KZ: "AS",
  LA: "AS", LB: "AS", LK: "AS", MM: "AS", MN: "AS", MO: "AS", MV: "AS", MY: "AS",
  NP: "AS", OM: "AS", PH: "AS", PK: "AS", PS: "AS", QA: "AS", SA: "AS", SG: "AS",
  SY: "AS", TH: "AS", TJ: "AS", TL: "AS", TM: "AS", TR: "AS", TW: "AS", UZ: "AS",
  VN: "AS", YE: "AS",
  // Oceania
  AU: "OC", FJ: "OC", FM: "OC", GU: "OC", KI: "OC", MH: "OC", NC: "OC", NR: "OC",
  NZ: "OC", PG: "OC", PW: "OC", SB: "OC", TO: "OC", TV: "OC", VU: "OC", WS: "OC",
};

function stableHash(input: string): number {
  let h = 2166136261;
  for (let i = 0; i < input.length; i++) {
    h ^= input.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

export function isStaticCluster(cluster: Cluster): boolean {
  return cluster.type === "static" || cluster.tags.some((t) => t.toLowerCase() === "static");
}

export function classifyContinent(
  countryCode: string | null | undefined,
  lat: number,
  lon: number,
): ContinentId {
  const cc = (countryCode ?? "").trim().toUpperCase();
  const mapped = COUNTRY_TO_CONTINENT[cc];
  if (mapped) return mapped;

  // Geographic fallback when a country code is missing or new.
  if (lon <= -30) {
    return lat >= 12 ? "NA" : "SA";
  }
  if (lon >= 112 && lat <= -8) {
    return "OC";
  }
  if (lat >= 35 && lon >= -25 && lon <= 50) {
    return "EU";
  }
  if (lat < 35 && lon >= -20 && lon <= 52) {
    return "AF";
  }
  return "AS";
}

function greatCircleDeg(lat1: number, lon1: number, lat2: number, lon2: number): number {
  const r = Math.PI / 180;
  const dLat = (lat2 - lat1) * r;
  const dLon = (lon2 - lon1) * r;
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(lat1 * r) * Math.cos(lat2 * r) * Math.sin(dLon / 2) ** 2;
  return (2 * Math.atan2(Math.sqrt(a), Math.sqrt(Math.max(0, 1 - a)))) / r;
}

function pickMedoidCity(cities: GlobePin[]): GlobePin {
  if (cities.length === 1) return cities[0];
  let best = cities[0];
  let bestSum = Number.POSITIVE_INFINITY;
  for (const cand of cities) {
    let sum = 0;
    for (const other of cities) {
      sum += greatCircleDeg(cand.lat, cand.lon, other.lat, other.lon);
    }
    // Slight static preference for cities with more clusters when geographic centrality ties.
    const score = sum - Math.min(2, cand.clusterIds.length * 0.15);
    if (
      score < bestSum - 1e-6 ||
      (Math.abs(score - bestSum) <= 1e-6 && cand.key < best.key)
    ) {
      bestSum = score;
      best = cand;
    }
  }
  return best;
}

function computeCountryCityFocusZoom(cities: GlobePin[], center: GlobePin): number {
  if (cities.length <= 1) return 3.8;
  let maxDist = 0;
  for (const c of cities) {
    const d = greatCircleDeg(center.lat, center.lon, c.lat, c.lon);
    if (d > maxDist) maxDist = d;
  }
  // Wide countries (e.g. US ~25deg radius) frame around 3.05x; compact countries zoom deeper (~3.85x).
  if (maxDist >= 18) return 3.05;
  if (maxDist >= 10) return 3.35;
  if (maxDist >= 5) return 3.65;
  return 3.9;
}

/**
 * Deduplicate real VPN clusters into unique geographic city pins so dense multi-cluster
 * metro locations never render overlapping dots on the 3D globe.
 */
export function buildGlobePins(
  clusters: Cluster[],
  activeClusterId: string | null,
  selectedClusterId: string | null,
  gamingReport: GamingScanReport | null,
): GlobePin[] {
  return buildTieredGlobeData(clusters, activeClusterId, selectedClusterId, gamingReport).cities;
}

/**
 * Build the 3-tier globe hierarchy (`continents` -> `countries` -> `cities`) cleanly from real
 * Surfshark clusters so zoomed views smoothly drill down without server-load jitter.
 */
export function buildTieredGlobeData(
  clusters: Cluster[],
  activeClusterId: string | null,
  selectedClusterId: string | null,
  gamingReport: GamingScanReport | null,
): TieredGlobeData {
  const pingByCluster = new Map<string, { ms: number; ranked: boolean }>();
  if (gamingReport) {
    for (const cand of gamingReport.candidates) {
      const ms = cand.verified_tunnel_ms ?? cand.estimated_total_ms;
      pingByCluster.set(cand.cluster_id, { ms: Math.round(ms), ranked: true });
    }
  }

  interface Bucket {
    key: string;
    members: Cluster[];
  }
  const buckets = new Map<string, Bucket>();

  for (const cluster of clusters) {
    const lat = cluster.coordinates?.latitude;
    const lon = cluster.coordinates?.longitude;
    if (
      typeof lat !== "number" ||
      !Number.isFinite(lat) ||
      typeof lon !== "number" ||
      !Number.isFinite(lon)
    ) {
      continue;
    }
    const cityNorm = (cluster.location ?? "").trim().toLowerCase() || cluster.id.toLowerCase();
    const ccNorm = (cluster.countryCode ?? "--").toLowerCase();
    const key = `${ccNorm}::${cityNorm}`;
    let bucket = buckets.get(key);
    if (!bucket) {
      bucket = { key, members: [] };
      buckets.set(key, bucket);
    }
    bucket.members.push(cluster);
  }

  const cities: GlobePin[] = [];
  for (const bucket of buckets.values()) {
    let rep = bucket.members[0];
    let bestScore = Number.POSITIVE_INFINITY;
    let hasStatic = false;
    let bestPing: number | null = null;
    let ranked = false;
    const clusterIds: string[] = [];

    for (const m of bucket.members) {
      clusterIds.push(m.id);
      if (isStaticCluster(m)) hasStatic = true;
      const gInfo = pingByCluster.get(m.id);
      if (gInfo) {
        ranked = true;
        if (bestPing === null || gInfo.ms < bestPing) bestPing = gInfo.ms;
      }

      let score = m.load ?? 999;
      if (m.id === activeClusterId) score = -10_000;
      else if (m.id === selectedClusterId) score = -5_000;
      else if (gInfo) score = -1_000 + gInfo.ms;

      if (score < bestScore) {
        bestScore = score;
        rep = m;
      }
    }

    const repLat = rep.coordinates!.latitude!;
    const repLon = rep.coordinates!.longitude!;
    const country = rep.country ?? rep.countryCode ?? "Unknown";
    const countryCode = rep.countryCode ?? "--";
    const city = rep.location ?? rep.country ?? rep.id;
    const continentId = classifyContinent(rep.countryCode, repLat, repLon);

    cities.push({
      key: bucket.key,
      tier: "city",
      continentId,
      clusterId: rep.id,
      clusterIds,
      label: city,
      city,
      country,
      countryCode,
      connectionName: rep.connectionName ?? rep.id,
      load: rep.load ?? 0,
      lat: repLat,
      lon: repLon,
      childCount: 1,
      focusZoom: 3.8,
      isLeaf: true,
      isCountryHub: false,
      importance: clusterIds.length * 10,
      hasStatic,
      pingMs: bestPing,
      ranked,
      pref: stableHash(bucket.key) % 4,
    });
  }

  // Group cities by country for Tier 2 and assign static country-hub markers.
  const byCountry = new Map<string, GlobePin[]>();
  for (const pin of cities) {
    const cKey = (pin.countryCode !== "--" ? pin.countryCode : pin.country).toUpperCase();
    let list = byCountry.get(cKey);
    if (!list) {
      list = [];
      byCountry.set(cKey, list);
    }
    list.push(pin);
  }

  const countries: GlobePin[] = [];
  for (const [cKey, group] of byCountry) {
    const hub = pickMedoidCity(group);
    hub.isCountryHub = true;
    hub.importance += 100;

    // Representative cluster prefers active -> selected -> gaming -> hub/lowest load.
    let repPin = hub;
    let bestRepScore = Number.POSITIVE_INFINITY;
    const allClusterIds: string[] = [];
    let bestPing: number | null = null;
    let hasStatic = false;
    let ranked = false;
    let minLoad = 999;

    for (const p of group) {
      allClusterIds.push(...p.clusterIds);
      if (p.hasStatic) hasStatic = true;
      if (p.ranked) ranked = true;
      if (p.pingMs !== null && (bestPing === null || p.pingMs < bestPing)) {
        bestPing = p.pingMs;
      }
      if (p.load < minLoad) minLoad = p.load;

      let s = p === hub ? -100 : p.load;
      if (activeClusterId && p.clusterIds.includes(activeClusterId)) s = -10_000;
      else if (selectedClusterId && p.clusterIds.includes(selectedClusterId)) s = -5_000;
      else if (p.pingMs !== null) s = -1_000 + p.pingMs;

      if (s < bestRepScore) {
        bestRepScore = s;
        repPin = p;
      }
    }

    const isLeaf = group.length === 1;
    countries.push({
      key: `ctry::${cKey}`,
      tier: "country",
      continentId: hub.continentId,
      clusterId: repPin.clusterId,
      clusterIds: allClusterIds,
      label: hub.country,
      city: hub.city,
      country: hub.country,
      countryCode: hub.countryCode,
      connectionName: repPin.connectionName,
      load: minLoad === 999 ? 0 : minLoad,
      lat: hub.lat,
      lon: hub.lon,
      childCount: group.length,
      focusZoom: isLeaf ? 3.8 : computeCountryCityFocusZoom(group, hub),
      isLeaf,
      isCountryHub: true,
      importance: 200 + group.length * 15,
      hasStatic,
      pingMs: bestPing,
      ranked,
      pref: stableHash(`ctry::${cKey}`) % 4,
    });
  }

  // Group countries by continent for Tier 1 overview.
  const byContinent = new Map<ContinentId, GlobePin[]>();
  for (const cPin of countries) {
    let list = byContinent.get(cPin.continentId);
    if (!list) {
      list = [];
      byContinent.set(cPin.continentId, list);
    }
    list.push(cPin);
  }

  const continents: GlobePin[] = [];
  for (const contId of CONTINENT_ORDER) {
    const group = byContinent.get(contId);
    if (!group || group.length === 0) continue;
    const meta = CONTINENT_META[contId];
    const allClusterIds: string[] = [];
    let bestPing: number | null = null;
    let hasStatic = false;
    let ranked = false;
    let minLoad = 999;
    let repCountry = group[0];

    for (const cPin of group) {
      allClusterIds.push(...cPin.clusterIds);
      if (cPin.hasStatic) hasStatic = true;
      if (cPin.ranked) ranked = true;
      if (cPin.pingMs !== null && (bestPing === null || cPin.pingMs < bestPing)) {
        bestPing = cPin.pingMs;
      }
      if (cPin.load < minLoad) minLoad = cPin.load;
      if (
        (activeClusterId && cPin.clusterIds.includes(activeClusterId)) ||
        (selectedClusterId &&
          cPin.clusterIds.includes(selectedClusterId) &&
          !(activeClusterId && repCountry.clusterIds.includes(activeClusterId)))
      ) {
        repCountry = cPin;
      }
    }

    continents.push({
      key: `cont::${contId}`,
      tier: "continent",
      continentId: contId,
      clusterId: repCountry.clusterId,
      clusterIds: allClusterIds,
      label: meta.name,
      city: meta.name,
      country: meta.name,
      countryCode: contId,
      connectionName: repCountry.connectionName,
      load: minLoad === 999 ? 0 : minLoad,
      lat: meta.lat,
      lon: meta.lon,
      childCount: group.length,
      focusZoom: meta.focusZoom,
      isLeaf: false,
      isCountryHub: true,
      importance: 1000 + group.length,
      hasStatic,
      pingMs: bestPing,
      ranked,
      pref: 0,
    });
  }

  return { continents, countries, cities };
}
