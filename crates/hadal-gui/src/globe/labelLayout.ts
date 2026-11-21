import { GLOBE_W } from "./globeMath";
import type { GlobePin } from "./clusterPins";

export type Rect = [number, number, number, number];

export interface InViewPin {
  key: string;
  pin: GlobePin;
  idx: number;
  x: number;
  y: number;
  pref: number;
  /** Cosine of angle toward camera in [0, 1]; defaults to 1.0 when omitted in unit tests. */
  facing?: number;
}

export interface LabelAnimEntry {
  alpha: number;
  hov: number;
  w: number;
  h: number;
  fs: number;
  text: string;
  idx: number;
}

export interface LabelHitRect {
  idx: number;
  x: number;
  y: number;
  w: number;
  h: number;
}

export interface DrawableLabel {
  key: string;
  city: string;
  tx: number;
  ty: number;
  fs: number;
  alpha: number;
  hov: number;
}

export interface LabelLayoutState {
  visibleKeys: Set<string>;
  widthCache: Map<string, number>;
  anim: Record<string, LabelAnimEntry>;
}

interface PlacedLabel {
  pin: InViewPin;
  box: Rect;
  hoverOnly: boolean;
}

export interface LayoutSolveParams {
  isHome: boolean;
  appR: number;
  zoom: number;
  homeHudAlpha: number;
  inViewPins: InViewPin[];
  projMap: ReadonlyMap<string, InViewPin>;
  obstacles: Rect[];
  wantHoverPin: InViewPin | null;
  activePinKey?: string | null;
  cityFontSize: number;
  padX: number;
  padY: number;
  lineHeight: number;
  measureCityWidth: (city: string, fontSize: number) => number;
  dt: number;
  /** Minimum zoom required before auto-labeling all eligible tier pins (defaults to 0 when passed explicitly). */
  minLabelZoom?: number;
}

export interface LayoutStepResult {
  drawables: DrawableLabel[];
  labelHits: LabelHitRect[];
}

export function rectsOverlap(r1: Rect, r2: Rect, gapX = 0, gapY = gapX): boolean {
  return !(
    r1[0] + r1[2] + gapX < r2[0] ||
    r2[0] + r2[2] + gapX < r1[0] ||
    r1[1] + r1[3] + gapY < r2[1] ||
    r2[1] + r2[3] + gapY < r1[1]
  );
}

export function createLabelLayoutState(): LabelLayoutState {
  return {
    visibleKeys: new Set<string>(),
    widthCache: new Map<string, number>(),
    anim: {},
  };
}

function measureCached(
  state: LabelLayoutState,
  text: string,
  fs: number,
  measureFn: (t: string, fs: number) => number,
): number {
  const key = `${fs.toFixed(2)}::${text}`;
  const hit = state.widthCache.get(key);
  if (hit !== undefined) return hit;
  const w = measureFn(text, fs);
  if (state.widthCache.size > 400) state.widthCache.clear();
  state.widthCache.set(key, w);
  return w;
}

function fixedBoxForPin(
  pin: InViewPin,
  bw: number,
  bh: number,
  offsetY: number,
  clampHover: boolean,
): Rect {
  let bx = pin.x - bw / 2;
  let by = pin.y + offsetY;
  if (clampHover) {
    bx = Math.max(8, Math.min(GLOBE_W - 8 - bw, bx));
    if (by + bh > 392) {
      by = Math.max(66, pin.y - offsetY - bh);
    }
    by = Math.max(66, Math.min(392 - bh, by));
  }
  return [bx, by, bw, bh];
}

function pinPriorityTier(
  pin: InViewPin,
  hoverKey: string | null,
  activePinKey: string | null,
): number {
  if (pin.key === hoverKey || pin.key === activePinKey) return 0;
  if (pin.pin.ranked) return 1;
  if (pin.pin.tier === "continent" || pin.pin.isCountryHub) return 2;
  return 3;
}

/**
 * Fixed-anchor, pan-locked map label placement with spatial hysteresis.
 *
 * Unlike 8-direction slot flipping, every label stays pixel-locked centered below its pin
 * dot so panning and zooming never swing text across dots or coastlines. Overlaps are resolved
 * deterministically by static importance tiers + fade hysteresis (`visibleKeys`).
 */
export function solveAndStepLabels(
  state: LabelLayoutState,
  params: LayoutSolveParams,
): LayoutStepResult {
  const {
    isHome,
    appR,
    zoom,
    homeHudAlpha,
    inViewPins,
    obstacles,
    wantHoverPin,
    activePinKey = null,
    cityFontSize,
    padX,
    padY,
    lineHeight,
    measureCityWidth,
    dt,
    minLabelZoom = 1.35,
  } = params;

  const solvedMap = new Map<string, PlacedLabel>();
  const hoverKey = wantHoverPin?.key ?? null;
  const labelOffset = 7;

  // Build key-aligned dot boxes around visible pins (excluding each pin's own dot during checks).
  const obstacleCenters = obstacles.map((o) => [o[0] + o[2] / 2, o[1] + o[3] / 2, o] as const);

  if (isHome && appR > 62 && zoom > minLabelZoom && inViewPins.length > 0 && homeHudAlpha > 0.01) {
    interface Candidate {
      pin: InViewPin;
      box: Rect;
      tier: number;
      wasVisible: boolean;
      facing: number;
    }

    const candidates: Candidate[] = [];
    for (const pin of inViewPins) {
      const facing = pin.facing ?? 1;
      const isPriority = pin.key === hoverKey || pin.key === activePinKey;
      if (!isPriority && facing < 0.14) continue;

      const text = pin.pin.label || pin.pin.city;
      const bw = measureCached(state, text, cityFontSize, measureCityWidth) + padX * 2;
      const bh = lineHeight + padY * 2;
      const offsetY = isPriority ? labelOffset + 2 : labelOffset;
      const box = fixedBoxForPin(pin, bw, bh, offsetY, false);

      if (!isPriority) {
        if (box[0] < -20 || box[0] + box[2] > GLOBE_W + 20 || box[1] < 38 || box[1] + box[3] > 416) {
          continue;
        }
      }

      candidates.push({
        pin,
        box,
        tier: pinPriorityTier(pin, hoverKey, activePinKey),
        wasVisible: state.visibleKeys.has(pin.key),
        facing,
      });
    }

    // Strictly deterministic sort: priority tier -> hysteresis (already visible wins ties)
    // -> static importance (cluster count / country hub) -> stable lexical key.
    candidates.sort((a, b) => {
      if (a.tier !== b.tier) return a.tier - b.tier;
      if (a.wasVisible !== b.wasVisible) return a.wasVisible ? -1 : 1;
      if (a.pin.pin.importance !== b.pin.pin.importance) {
        return b.pin.pin.importance - a.pin.pin.importance;
      }
      return a.pin.key < b.pin.key ? -1 : a.pin.key > b.pin.key ? 1 : 0;
    });

    const placedBoxes: Rect[] = [];
    const nextVisible = new Set<string>();

    for (const cand of candidates) {
      const { pin, box, tier, wasVisible } = cand;
      const isPriority = tier === 0;

      // Hysteresis: hidden labels need generous extra room to enter, visible ones stay stable.
      const labelGapX = isPriority ? 0 : wasVisible ? 3 : 11;
      const labelGapY = isPriority ? 0 : wasVisible ? 2 : 7;

      const collidesWithLabel = placedBoxes.some((b) =>
        rectsOverlap(box, b, labelGapX, labelGapY),
      );
      if (collidesWithLabel && !isPriority) continue;

      if (tier >= 2) {
        const dotGap = wasVisible ? 0 : 2;
        const hitsOtherDot = obstacleCenters.some(([cx, cy, oBox]) => {
          if (Math.hypot(cx - pin.x, cy - pin.y) < 1.5) return false;
          return rectsOverlap(box, oBox, dotGap, dotGap);
        });
        if (hitsOtherDot) continue;
      }

      placedBoxes.push(box);
      nextVisible.add(pin.key);
      solvedMap.set(pin.key, { pin, box, hoverOnly: false });
    }

    state.visibleKeys = nextVisible;
  } else {
    state.visibleKeys.clear();
  }

  // Always allow hovered pin's label cleanly inside safe bounds (even when zoomed out).
  if (wantHoverPin && homeHudAlpha > 0.01 && !solvedMap.has(wantHoverPin.key)) {
    const text = wantHoverPin.pin.label || wantHoverPin.pin.city;
    const bw = measureCached(state, text, cityFontSize, measureCityWidth) + padX * 2;
    const bh = lineHeight + padY * 2;
    const box = fixedBoxForPin(wantHoverPin, bw, bh, labelOffset + 2, true);
    solvedMap.set(wantHoverPin.key, {
      pin: wantHoverPin,
      box,
      hoverOnly: true,
    });
  }

  for (const [key, item] of solvedMap) {
    const { pin, box, hoverOnly } = item;
    const isH = key === hoverKey;
    const text = pin.pin.label || pin.pin.city;
    let la = state.anim[key];
    if (!la) {
      la = {
        alpha: 0,
        hov: isH ? 1 : 0,
        w: box[2],
        h: box[3],
        fs: cityFontSize,
        text,
        idx: pin.idx,
      };
      state.anim[key] = la;
    } else {
      la.w = box[2];
      la.h = box[3];
      la.fs = cityFontSize;
      la.text = text;
      la.idx = pin.idx;
      la.hov += ((isH ? 1 : 0) - la.hov) * (1 - Math.exp(-12 * dt));
    }

    const bx = box[0];
    const by = box[1];
    const facing = pin.facing ?? 1;
    const limbF = hoverOnly || isH ? 1 : Math.max(0, Math.min(1, (facing - 0.14) / 0.14));
    const topF = Math.max(0, Math.min(1, (by - 48) / 14));
    const botF = Math.max(0, Math.min(1, (408 - (by + la.h)) / 16));
    const leftF = Math.max(0, Math.min(1, (bx - 4) / 14));
    const rightF = Math.max(0, Math.min(1, (GLOBE_W - 4 - (bx + la.w)) / 14));
    const edgeF = hoverOnly || isH ? 1 : Math.min(limbF, topF, botF, leftF, rightF);

    const targetA = homeHudAlpha * edgeF;
    const rate = targetA > la.alpha ? 8.5 : 10.5;
    la.alpha += (targetA - la.alpha) * (1 - Math.exp(-rate * dt));
  }

  // Smoothly fade out labels leaving the active set, tracking last projected screen coordinates cleanly.
  const leavingPos = new Map<string, [number, number]>();
  for (const key of Object.keys(state.anim)) {
    if (solvedMap.has(key)) continue;
    const la = state.anim[key];
    const pm = params.projMap.get(key);
    if (pm) {
      leavingPos.set(key, [pm.x - la.w / 2, pm.y + labelOffset]);
    }
    la.alpha *= Math.exp(-11 * dt);
    if (la.alpha <= 0.015 || !pm) {
      delete state.anim[key];
    }
  }

  const drawables: DrawableLabel[] = [];
  const labelHits: LabelHitRect[] = [];

  const entries = Object.entries(state.anim)
    .filter(([, la]) => la.alpha > 0.015)
    .sort(([, a], [, b]) => a.hov - b.hov);

  for (const [key, la] of entries) {
    const solved = solvedMap.get(key);
    const lp = leavingPos.get(key);
    const bx = solved ? solved.box[0] : lp ? lp[0] : 0;
    const by = solved ? solved.box[1] : lp ? lp[1] : 0;
    const tx = bx + padX;
    const ty = by + la.h / 2 + 0.5;

    if (isHome && la.alpha > 0.25) {
      labelHits.push({ idx: la.idx, x: bx - 4, y: by - 4, w: la.w + 8, h: la.h + 8 });
    }

    drawables.push({
      key,
      city: la.text,
      tx,
      ty,
      fs: la.fs,
      alpha: la.alpha,
      hov: la.hov,
    });
  }

  return { drawables, labelHits };
}
