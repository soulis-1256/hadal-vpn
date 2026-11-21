import { createEffect, onCleanup, onMount } from "solid-js";
import type { GlobePin, GlobeTier, TieredGlobeData } from "./clusterPins";
import {
  clampLat,
  computeCameraTransform,
  GLOBE_FOCUS_ZOOM,
  GLOBE_H,
  GLOBE_MAX_ZOOM,
  GLOBE_MIN_ZOOM,
  GLOBE_POSE_CY,
  GLOBE_W,
  projectSurfacePoint,
  wrapLon,
} from "./globeMath";
import {
  createLabelLayoutState,
  solveAndStepLabels,
  type InViewPin,
  type LabelHitRect,
  type Rect,
} from "./labelLayout";
import { MullvadGlobeGL } from "./MullvadGlobeGL";

export type GlobeVisualState = "idle" | "connecting" | "protected";

export interface FocusRequest {
  clusterId: string;
  seq: number;
}

interface OrbitGlobeProps {
  tieredData: TieredGlobeData;
  activeClusterId: string | null;
  selectedClusterId: string | null;
  hoveredClusterId: string | null;
  tunnelState: GlobeVisualState;
  scanning: boolean;
  homeActive: boolean;
  obscured?: boolean;
  focusRequest: FocusRequest | null;
  onSelectCluster: (clusterId: string) => void;
}

interface Star {
  x: number;
  y: number;
  r: number;
  phase: number;
}

const STARS: Star[] = Array.from({ length: 85 }, () => ({
  x: Math.random() * GLOBE_W,
  y: Math.random() * GLOBE_H,
  r: Math.random() * 1.25 + 0.25,
  phase: Math.random() * 6,
}));

function accentColorForState(state: GlobeVisualState): string {
  if (state === "protected") return "#3ee6d0";
  if (state === "connecting") return "#8fb3ff";
  return "#ffb547";
}

function resolveTierWithHysteresis(z: number, cur: GlobeTier): GlobeTier {
  if (cur === "continent") {
    if (z >= 2.85) return "city";
    if (z >= 1.55) return "country";
    return "continent";
  }
  if (cur === "country") {
    if (z <= 1.38) return "continent";
    if (z >= 2.85) return "city";
    return "country";
  }
  if (z <= 1.38) return "continent";
  if (z <= 2.55) return "country";
  return "city";
}

export function OrbitGlobe(props: OrbitGlobeProps) {
  let skyCanvas!: HTMLCanvasElement;
  let glCanvas!: HTMLCanvasElement;
  let hudCanvas!: HTMLCanvasElement;

  let lon0 = 18;
  let lat0 = 40;
  let tLon = 18;
  let tLat = 40;
  let zoom = 1.0;
  let tZoom = 1.0;
  let vLon = 0;
  let vLat = 0;
  let dragging = false;
  let hoverPinIdx: number | null = null;
  let activeTier: GlobeTier = "continent";
  let wasHome = props.homeActive;
  let homeReturnAt = performance.now();
  let homeHudAlpha = props.homeActive ? 1 : 0;
  let lastFocusSeq = -1;
  let didInitialFrame = false;

  interface ProjectedPinHit {
    idx: number;
    x: number;
    y: number;
    pin: GlobePin;
    isActiveBeacon: boolean;
  }
  let projectedPins: ProjectedPinHit[] = [];
  let labelHits: LabelHitRect[] = [];
  const labelState = createLabelLayoutState();
  let wakeLoop: (() => void) | null = null;
  let stopLoop: (() => void) | null = null;

  function focusPin(pin: GlobePin, zoomMin = GLOBE_FOCUS_ZOOM) {
    vLon = 0;
    vLat = 0;
    hoverPinIdx = null;
    tLon = pin.lon;
    tLat = clampLat(pin.lat);
    tZoom = Math.max(tZoom, zoomMin);
  }

  // Initial overview framing once clusters arrive + explicit focus requests from clicks/selections.
  createEffect(() => {
    const req = props.focusRequest;
    const cities = props.tieredData.cities;
    if (!didInitialFrame && cities.length > 0) {
      const targetId = props.activeClusterId ?? props.selectedClusterId;
      const initPin =
        (targetId ? cities.find((p) => p.clusterIds.includes(targetId)) : undefined) ?? cities[0];
      if (initPin) {
        lon0 = tLon = initPin.lon;
        lat0 = tLat = clampLat(initPin.lat);
        didInitialFrame = true;
      }
    }
    if (req && req.seq !== lastFocusSeq) {
      lastFocusSeq = req.seq;
      const targetPin = cities.find((p) => p.clusterIds.includes(req.clusterId));
      if (targetPin) {
        focusPin(targetPin, GLOBE_FOCUS_ZOOM);
      }
    }
  });

  onMount(() => {
    const dpr = Math.min(2, Math.max(1, window.devicePixelRatio || 1));
    for (const c of [skyCanvas, glCanvas, hudCanvas]) {
      c.width = Math.round(GLOBE_W * dpr);
      c.height = Math.round(GLOBE_H * dpr);
    }

    const skyCtx = skyCanvas.getContext?.("2d") ?? null;
    const hudCtx = hudCanvas.getContext?.("2d") ?? null;
    const glGlobe = new MullvadGlobeGL(glCanvas);

    // Prevent browser autoscroll circle on middle-click pan across Linux WebKit2GTK / Chromium.
    const preventMiddleScroll = (ev: MouseEvent) => {
      if (ev.button === 1) ev.preventDefault();
    };
    const preventAuxClick = (ev: MouseEvent) => {
      if (ev.button === 1) ev.preventDefault();
    };
    hudCanvas.addEventListener("mousedown", preventMiddleScroll);
    hudCanvas.addEventListener("auxclick", preventAuxClick);

    let armed = false;
    let downBtn = -1;
    let downX = 0;
    let downY = 0;
    let lastX = 0;
    let lastY = 0;
    let lastMoveTime = performance.now();

    const hitTestPoint = (px: number, py: number, maxDist: number): number | null => {
      let best: number | null = null;
      let bestD = maxDist;
      for (const p of projectedPins) {
        const d = Math.hypot(p.x - px, p.y - py);
        if (d < bestD) {
          bestD = d;
          best = p.idx;
        }
      }
      if (best === null) {
        for (let k = labelHits.length - 1; k >= 0; k--) {
          const lh = labelHits[k];
          if (px >= lh.x && px <= lh.x + lh.w && py >= lh.y && py <= lh.y + lh.h) {
            best = lh.idx;
            break;
          }
        }
      }
      return best;
    };

    const onPointerDown = (e: PointerEvent) => {
      if (!props.homeActive || (e.button !== 0 && e.button !== 1)) return;
      if (e.button === 1) e.preventDefault();
      armed = true;
      dragging = e.button === 1;
      downBtn = e.button;
      downX = e.clientX;
      downY = e.clientY;
      lastX = e.clientX;
      lastY = e.clientY;
      vLon = 0;
      vLat = 0;
      lastMoveTime = performance.now();
      if (dragging) {
        try {
          hudCanvas.setPointerCapture(e.pointerId);
        } catch {
          // Ignore in synthetic pointer environments.
        }
        hudCanvas.style.cursor = "grabbing";
      }
      wakeLoop?.();
    };

    const onPointerMove = (e: PointerEvent) => {
      const rect = hudCanvas.getBoundingClientRect();
      const px = e.clientX - rect.left;
      const py = e.clientY - rect.top;

      if (armed) {
        if (!dragging) {
          if (Math.hypot(e.clientX - downX, e.clientY - downY) < 5) return;
          dragging = true;
          lastX = e.clientX;
          lastY = e.clientY;
          lastMoveTime = performance.now();
          try {
            hudCanvas.setPointerCapture(e.pointerId);
          } catch {
            // Ignore
          }
          hudCanvas.style.cursor = "grabbing";
        }
        const now = performance.now();
        const dt = Math.max(0.004, (now - lastMoveTime) / 1000);
        lastMoveTime = now;
        const dx = e.clientX - lastX;
        const dy = e.clientY - lastY;
        lastX = e.clientX;
        lastY = e.clientY;

        const sens = 0.38 / zoom;
        const dLon = -dx * sens;
        const dLat = dy * sens;
        tLon = wrapLon(tLon + dLon);
        tLat = clampLat(tLat + dLat);

        const instVLon = Math.max(-420, Math.min(420, dLon / dt));
        const instVLat = Math.max(-320, Math.min(320, dLat / dt));
        vLon = vLon * 0.45 + instVLon * 0.55;
        vLat = vLat * 0.45 + instVLat * 0.55;
        wakeLoop?.();
        return;
      }

      if (props.homeActive && e.target === hudCanvas) {
        hoverPinIdx = hitTestPoint(px, py, 14);
        hudCanvas.style.cursor = hoverPinIdx !== null ? "pointer" : "grab";
        wakeLoop?.();
      } else {
        hoverPinIdx = null;
      }
    };

    const onPointerEnd = (e: PointerEvent) => {
      if (!armed && !dragging) return;
      const wasDragging = dragging;
      armed = false;
      dragging = false;

      if (wasDragging) {
        if (performance.now() - lastMoveTime > 80) {
          vLon = 0;
          vLat = 0;
        } else {
          wakeLoop?.();
        }
      } else if (e.type === "pointerup" && downBtn === 0) {
        const rect = hudCanvas.getBoundingClientRect();
        const px = e.clientX - rect.left;
        const py = e.clientY - rect.top;
        const hit = hoverPinIdx ?? hitTestPoint(px, py, 16);
        if (hit !== null) {
          const item = projectedPins.find((p) => p.idx === hit);
          if (item) {
            if (item.isActiveBeacon && activeTier === "continent") {
              focusPin(item.pin, GLOBE_FOCUS_ZOOM);
            } else if (!item.pin.isLeaf) {
              focusPin(item.pin, item.pin.focusZoom);
            } else {
              focusPin(item.pin, GLOBE_FOCUS_ZOOM);
              props.onSelectCluster(item.pin.clusterId);
            }
          }
        }
      }
      hudCanvas.style.cursor = hoverPinIdx !== null ? "pointer" : "grab";
    };

    const onWheel = (e: WheelEvent) => {
      if (!props.homeActive) return;
      e.preventDefault();
      tZoom = Math.max(
        GLOBE_MIN_ZOOM,
        Math.min(GLOBE_MAX_ZOOM, tZoom * Math.exp(-e.deltaY * 0.002)),
      );
      wakeLoop?.();
    };

    const onPointerLeave = () => {
      hoverPinIdx = null;
    };

    hudCanvas.addEventListener("pointerdown", onPointerDown);
    window.addEventListener("pointermove", onPointerMove);
    hudCanvas.addEventListener("pointerup", onPointerEnd);
    hudCanvas.addEventListener("pointercancel", onPointerEnd);
    hudCanvas.addEventListener("pointerleave", onPointerLeave);
    hudCanvas.addEventListener("wheel", onWheel, { passive: false });

    let rafId = 0;
    let lastT = performance.now();
    let mounted = true;

    const canAnimateNow = () => {
      if (!mounted || props.obscured) return false;
      if (typeof document !== "undefined" && document.hidden) return false;
      return true;
    };

    const stopTick = () => {
      if (rafId) {
        window.cancelAnimationFrame(rafId);
        rafId = 0;
      }
    };

    const shouldContinueAfterDraw = () => {
      if (!canAnimateNow()) return false;
      if (props.homeActive || props.scanning || dragging || armed) return true;
      const zoomSettled = Math.abs(tZoom - zoom) < 0.002;
      const lonSettled = Math.abs(wrapLon(tLon - lon0)) < 0.02;
      const latSettled = Math.abs(tLat - lat0) < 0.02;
      const velSettled = Math.abs(vLon) < 0.1 && Math.abs(vLat) < 0.1;
      return !(zoomSettled && lonSettled && latSettled && velSettled && homeHudAlpha <= 0.005);
    };

    const scheduleTick = () => {
      if (rafId || !canAnimateNow() || !skyCtx || !hudCtx) return;
      if (typeof window.requestAnimationFrame !== "function") return;
      lastT = performance.now();
      rafId = window.requestAnimationFrame(tick);
    };

    const tick = (now: number) => {
      rafId = 0;
      if (!canAnimateNow()) return;
      const dt = Math.min(0.05, Math.max(0.001, (now - lastT) / 1000));
      lastT = now;

      const kZoom = 1 - Math.exp(-8.5 * dt);
      zoom += (tZoom - zoom) * kZoom;

      const nextTier = resolveTierWithHysteresis(zoom, activeTier);
      if (nextTier !== activeTier) {
        activeTier = nextTier;
        hoverPinIdx = null;
        labelState.visibleKeys.clear();
      }

      const isHome = props.homeActive;
      if (isHome && !wasHome) {
        homeReturnAt = now;
        homeHudAlpha = 0;
      }
      wasHome = isHome;
      if (isHome) {
        if (now - homeReturnAt >= 120) {
          homeHudAlpha = Math.min(1, homeHudAlpha + (1 - homeHudAlpha) * (1 - Math.exp(-5.5 * dt)));
        }
      } else {
        homeHudAlpha = Math.max(0, homeHudAlpha * (1 - Math.exp(-10 * dt)));
        if (homeHudAlpha <= 0.005) homeHudAlpha = 0;
      }

      if (!dragging && (Math.abs(vLon) > 0.08 || Math.abs(vLat) > 0.08)) {
        tLon = wrapLon(tLon + vLon * dt);
        tLat = clampLat(tLat + vLat * dt);
        const damp = Math.pow(0.025, dt);
        vLon *= damp;
        vLat *= damp;
      } else if (!dragging) {
        vLon = 0;
        vLat = 0;
      }

      const dLon = wrapLon(tLon - lon0);
      const kOrb = dragging ? 1 - Math.exp(-32 * dt) : 1 - Math.exp(-7.5 * dt);
      lon0 = wrapLon(lon0 + dLon * kOrb);
      lat0 += (tLat - lat0) * kOrb;

      const cam = computeCameraTransform(lat0, lon0, zoom, GLOBE_POSE_CY);
      const isProtected = props.tunnelState === "protected";
      const accentCol = accentColorForState(props.tunnelState);

      if (skyCtx) {
        skyCtx.setTransform(dpr, 0, 0, dpr, 0, 0);
        skyCtx.clearRect(0, 0, GLOBE_W, GLOBE_H);
        for (const st of STARS) {
          const sx = (((st.x - lon0 * 0.35) % GLOBE_W) + GLOBE_W) % GLOBE_W;
          skyCtx.fillStyle = `rgba(195,212,255,${0.2 + 0.32 * Math.sin(now / 900 + st.phase)})`;
          skyCtx.fillRect(sx, st.y, st.r, st.r);
        }

        const halo = skyCtx.createRadialGradient(
          cam.cx,
          cam.cy,
          cam.appR * 0.85,
          cam.cx,
          cam.cy,
          cam.appR * 1.22,
        );
        halo.addColorStop(0, isProtected ? "rgba(62,230,208,0.22)" : "rgba(95,140,255,0.2)");
        halo.addColorStop(1, "rgba(90,140,255,0)");
        skyCtx.fillStyle = halo;
        skyCtx.beginPath();
        skyCtx.arc(cam.cx, cam.cy, cam.appR * 1.22, 0, Math.PI * 2);
        skyCtx.fill();

        const glDrawn = glGlobe.draw(cam.proj, cam.view, cam.centerView, isProtected);
        if (!glDrawn) {
          const disc = skyCtx.createRadialGradient(
            cam.cx - cam.appR * 0.3,
            cam.cy - cam.appR * 0.35,
            cam.appR * 0.1,
            cam.cx,
            cam.cy,
            cam.appR,
          );
          disc.addColorStop(0, "#172855");
          disc.addColorStop(1, "#071026");
          skyCtx.fillStyle = disc;
          skyCtx.beginPath();
          skyCtx.arc(cam.cx, cam.cy, cam.appR, 0, Math.PI * 2);
          skyCtx.fill();
        }
      }

      if (hudCtx) {
        hudCtx.setTransform(dpr, 0, 0, dpr, 0, 0);
        hudCtx.clearRect(0, 0, GLOBE_W, GLOBE_H);

        // Limb highlight ring
        hudCtx.strokeStyle = isProtected ? "rgba(62,230,208,0.28)" : "rgba(145,175,255,0.22)";
        hudCtx.lineWidth = 1;
        hudCtx.beginPath();
        hudCtx.arc(cam.cx, cam.cy, cam.appR, 0, Math.PI * 2);
        hudCtx.stroke();

        const nextProjected: ProjectedPinHit[] = [];
        const inViewPins: InViewPin[] = [];
        const obstacles: Rect[] = [];
        const projMap = new Map<string, InViewPin>();
        const pinScale = 0.85 + Math.min(1.8, zoom) * 0.25;
        const focusClusterId = props.activeClusterId ?? props.selectedClusterId;
        const extHoverId = props.hoveredClusterId;

        const { continents, countries, cities } = props.tieredData;
        const activeCityPin = focusClusterId
          ? cities.find((c) => c.clusterIds.includes(focusClusterId)) ?? null
          : null;

        // Determine current tier pins and active beacon overlay in Tier 1.
        const tierList =
          activeTier === "continent"
            ? continents
            : activeTier === "country"
              ? countries
              : cities;

        interface RenderEntry {
          pin: GlobePin;
          isActiveBeacon: boolean;
        }
        const renderEntries: RenderEntry[] = tierList.map((pin) => ({
          pin,
          isActiveBeacon: false,
        }));

        let activeCityScreen: { x: number; y: number } | null = null;
        if (activeTier === "continent" && activeCityPin) {
          const apt = projectSurfacePoint(activeCityPin.lat, activeCityPin.lon, cam);
          if (apt.visible) {
            activeCityScreen = { x: apt.x, y: apt.y };
            renderEntries.push({
              pin: { ...activeCityPin, key: `active::${activeCityPin.key}` },
              isActiveBeacon: true,
            });
          }
        }

        let hoveredInView: InViewPin | null = null;
        let activePinKey: string | null = null;

        for (let i = 0; i < renderEntries.length; i++) {
          const { pin, isActiveBeacon } = renderEntries[i];
          const pt = projectSurfacePoint(pin.lat, pin.lon, cam);
          if (!pt.visible) continue;

          const iv: InViewPin = {
            key: pin.key,
            pin,
            idx: i,
            x: pt.x,
            y: pt.y,
            pref: pin.pref,
            facing: pt.facing,
          };
          projMap.set(pin.key, iv);

          const isSel =
            isActiveBeacon ||
            (activeTier !== "continent" &&
              (focusClusterId ? pin.clusterIds.includes(focusClusterId) : false));
          if (isSel) activePinKey = pin.key;

          const isHoverByRow = extHoverId ? pin.clusterIds.includes(extHoverId) : false;
          const isHover = isHome && (hoverPinIdx === i || isHoverByRow);
          const isProbe = !isHome && (props.scanning || pin.ranked);

          obstacles.push([pt.x - 4, pt.y - 4, 8, 8]);

          if (isSel || isProbe) {
            const spd =
              props.tunnelState === "connecting" || props.scanning ? 450 : 850;
            const pulse = (now / spd + i * 0.18) % 1;
            const rCore = 4.3 * pinScale;
            const ringCount = isSel && isProtected ? 2 : 1;

            hudCtx.fillStyle = accentCol;
            hudCtx.globalAlpha = 0.22;
            hudCtx.beginPath();
            hudCtx.arc(pt.x, pt.y, rCore * 2.8, 0, Math.PI * 2);
            hudCtx.fill();

            for (let r = 0; r < ringCount; r++) {
              const pr = (pulse + r * 0.5) % 1;
              hudCtx.strokeStyle = accentCol;
              hudCtx.globalAlpha = (1 - pr) * 0.9;
              hudCtx.lineWidth = 1.4;
              hudCtx.beginPath();
              hudCtx.arc(pt.x, pt.y, rCore + pr * 16 * pinScale, 0, Math.PI * 2);
              hudCtx.stroke();
            }

            hudCtx.globalAlpha = 1;
            hudCtx.fillStyle = accentCol;
            hudCtx.shadowColor = accentCol;
            hudCtx.shadowBlur = 12;
            hudCtx.beginPath();
            hudCtx.arc(pt.x, pt.y, rCore, 0, Math.PI * 2);
            hudCtx.fill();
            hudCtx.shadowBlur = 0;
            hudCtx.strokeStyle = isHover ? "#3ee6d0" : "#ffffff";
            hudCtx.lineWidth = 1.5;
            hudCtx.stroke();
          } else {
            // Avoid overlapping a continent dot right on top of the active beacon in Tier 1.
            const nearActiveBeacon =
              activeTier === "continent" &&
              activeCityScreen !== null &&
              Math.hypot(pt.x - activeCityScreen.x, pt.y - activeCityScreen.y) < 16;

            if (!nearActiveBeacon) {
              const rBase =
                pin.tier === "continent"
                  ? 3.1
                  : pin.tier === "country"
                    ? 2.45 * pinScale
                    : 2.1 * pinScale;

              // Subtle outer ring on expandable Tier 2 countries with multiple cities.
              if (pin.tier === "country" && !pin.isLeaf) {
                hudCtx.strokeStyle = isHover
                  ? "rgba(62,230,208,0.85)"
                  : "rgba(180,204,255,0.45)";
                hudCtx.lineWidth = 1.1;
                hudCtx.beginPath();
                hudCtx.arc(pt.x, pt.y, rBase + 2.5, 0, Math.PI * 2);
                hudCtx.stroke();
              } else if (isHover) {
                hudCtx.strokeStyle = "#3ee6d0";
                hudCtx.globalAlpha = 0.72;
                hudCtx.lineWidth = 1.3;
                hudCtx.beginPath();
                hudCtx.arc(pt.x, pt.y, rBase + 3.2, 0, Math.PI * 2);
                hudCtx.stroke();
                hudCtx.globalAlpha = 1;
              }

              hudCtx.fillStyle = isHover ? "#3ee6d0" : "#eef3ff";
              hudCtx.shadowColor = isHover ? "#3ee6d0" : "#9fb6ff";
              hudCtx.shadowBlur = isHover ? 8 : 4;
              hudCtx.beginPath();
              hudCtx.arc(pt.x, pt.y, rBase, 0, Math.PI * 2);
              hudCtx.fill();
              hudCtx.shadowBlur = 0;
            }
          }

          if (isHome) {
            if (pt.x >= 10 && pt.x <= GLOBE_W - 10 && pt.y >= 58 && pt.y <= 396) {
              nextProjected.push({ idx: i, x: pt.x, y: pt.y, pin, isActiveBeacon });
            }
            // In Tier 1 overview, only continent labels appear persistently; active beacon labels on hover.
            const autoLabelAllowed = !isActiveBeacon || isHover;
            if (autoLabelAllowed && pt.x >= -40 && pt.x <= GLOBE_W + 40 && pt.y >= 20 && pt.y <= 430) {
              inViewPins.push(iv);
            }
            if (isHover) hoveredInView = iv;
          }
        }
        projectedPins = nextProjected;

        const cityFs = activeTier === "continent" ? 12 : 11.5;
        const lineHeight = Math.ceil(cityFs * 1.2);
        const layout = solveAndStepLabels(labelState, {
          isHome,
          appR: cam.appR,
          zoom,
          homeHudAlpha,
          inViewPins,
          projMap,
          obstacles,
          wantHoverPin: !dragging && isHome && homeHudAlpha > 0.05 ? hoveredInView : null,
          activePinKey,
          cityFontSize: cityFs,
          padX: 4,
          padY: 2,
          lineHeight,
          minLabelZoom: 0,
          measureCityWidth: (city, fs) => {
            hudCtx.font = `600 ${fs}px "Chakra Petch", sans-serif`;
            return hudCtx.measureText(city).width;
          },
          dt,
        });
        labelHits = layout.labelHits;

        hudCtx.textBaseline = "middle";
        hudCtx.lineJoin = "round";
        for (const d of layout.drawables) {
          const ha = d.hov;
          hudCtx.font = `600 ${d.fs}px "Chakra Petch", sans-serif`;

          hudCtx.globalAlpha = d.alpha * 0.88;
          hudCtx.lineWidth = 3;
          hudCtx.strokeStyle = "rgba(4,7,16,0.92)";
          hudCtx.strokeText(d.city, d.tx, d.ty);

          const r = Math.round(241 + (62 - 241) * ha);
          const g = Math.round(245 + (230 - 245) * ha);
          const b = Math.round(255 + (208 - 255) * ha);
          hudCtx.globalAlpha = d.alpha;
          hudCtx.fillStyle = `rgb(${r},${g},${b})`;
          hudCtx.fillText(d.city, d.tx, d.ty);
        }
        hudCtx.globalAlpha = 1;
        hudCtx.textBaseline = "alphabetic";
      }

      if (shouldContinueAfterDraw()) {
        rafId = window.requestAnimationFrame(tick);
      }
    };

    wakeLoop = scheduleTick;
    stopLoop = stopTick;

    const onVisibilityChange = () => {
      if (typeof document !== "undefined" && document.hidden) {
        stopTick();
      } else {
        scheduleTick();
      }
    };
    if (typeof document !== "undefined") {
      document.addEventListener("visibilitychange", onVisibilityChange);
    }

    scheduleTick();

    onCleanup(() => {
      mounted = false;
      wakeLoop = null;
      stopLoop = null;
      stopTick();
      if (typeof document !== "undefined") {
        document.removeEventListener("visibilitychange", onVisibilityChange);
      }
      hudCanvas.removeEventListener("mousedown", preventMiddleScroll);
      hudCanvas.removeEventListener("auxclick", preventAuxClick);
      hudCanvas.removeEventListener("pointerdown", onPointerDown);
      window.removeEventListener("pointermove", onPointerMove);
      hudCanvas.removeEventListener("pointerup", onPointerEnd);
      hudCanvas.removeEventListener("pointercancel", onPointerEnd);
      hudCanvas.removeEventListener("pointerleave", onPointerLeave);
      hudCanvas.removeEventListener("wheel", onWheel);
      glGlobe.dispose();
    });
  });

  // Wake or pause the rAF loop when view visibility, scanner state, or globe targets change.
  createEffect(() => {
    const obscured = !!props.obscured;
    void props.homeActive;
    void props.tunnelState;
    void props.scanning;
    void props.activeClusterId;
    void props.selectedClusterId;
    void props.hoveredClusterId;
    void props.tieredData;
    void props.focusRequest;
    if (obscured || (typeof document !== "undefined" && document.hidden)) {
      stopLoop?.();
    } else {
      wakeLoop?.();
    }
  });

  return (
    <div class="globe-stage" aria-hidden="true">
      <canvas ref={skyCanvas} class="sky" />
      <canvas ref={glCanvas} class="globe-gl" />
      <canvas ref={hudCanvas} class="hud" />
    </div>
  );
}
