export interface MiddleClickScrollHandle {
  stop: () => void;
  cleanup: () => void;
}

const DEADZONE_PX = 8;
const DRAG_THRESHOLD_PX = 5;

/**
 * Enable desktop middle-click (mouse wheel click) scrolling on an overflow-y element.
 *
 * Supports both holding the middle mouse button while dragging (with pointer capture
 * so motion outside the compact 360x540 window still scrolls smoothly) and clicking the
 * middle button once to toggle velocity-based autoscroll until the next click, wheel,
 * or Escape key.
 */
export function attachMiddleClickScroll(el: HTMLElement): MiddleClickScrollHandle {
  let active = false;
  let held = false;
  let draggedWhileHeld = false;
  let capturedPointerId: number | null = null;
  let originX = 0;
  let originY = 0;
  let curY = 0;
  let rafId = 0;
  let lastT = 0;
  let marker: HTMLDivElement | null = null;

  const removeMarker = () => {
    if (marker) {
      marker.remove();
      marker = null;
    }
  };

  const showMarker = (x: number, y: number) => {
    removeMarker();
    if (typeof document === "undefined" || !document.body) return;
    const node = document.createElement("div");
    node.className = "autoscroll-anchor";
    node.style.left = `${x}px`;
    node.style.top = `${y}px`;
    node.setAttribute("aria-hidden", "true");
    document.body.appendChild(node);
    marker = node;
  };

  const releaseCapture = () => {
    if (capturedPointerId !== null) {
      try {
        if (el.hasPointerCapture?.(capturedPointerId)) {
          el.releasePointerCapture(capturedPointerId);
        }
      } catch {
        // Ignore in synthetic environments.
      }
      capturedPointerId = null;
    }
  };

  const step = (now: number) => {
    if (!active) return;
    const dt = Math.min(0.05, Math.max(0.001, (now - lastT) / 1000));
    lastT = now;

    const dy = curY - originY;
    const absDy = Math.abs(dy);
    if (absDy > DEADZONE_PX) {
      const eff = absDy - DEADZONE_PX;
      const speed = eff * 3.8 + 0.045 * eff * eff;
      el.scrollTop += Math.sign(dy) * speed * dt;
    }

    rafId = window.requestAnimationFrame(step);
  };

  const stop = () => {
    if (!active && !held) return;
    active = false;
    held = false;
    draggedWhileHeld = false;
    if (rafId) {
      window.cancelAnimationFrame(rafId);
      rafId = 0;
    }
    releaseCapture();
    removeMarker();
    el.style.cursor = "";
  };

  const onMouseDown = (ev: MouseEvent) => {
    if (ev.button === 1 && el.scrollHeight > el.clientHeight + 1) {
      ev.preventDefault();
    }
  };

  const onAuxClick = (ev: MouseEvent) => {
    if (ev.button === 1) {
      ev.preventDefault();
    }
  };

  const onPointerDown = (ev: PointerEvent) => {
    if (ev.button !== 1) {
      if (active) {
        ev.preventDefault();
        ev.stopPropagation();
        stop();
      }
      return;
    }

    if (active && !held) {
      ev.preventDefault();
      ev.stopPropagation();
      stop();
      return;
    }

    if (el.scrollHeight <= el.clientHeight + 1) return;

    ev.preventDefault();
    active = true;
    held = true;
    draggedWhileHeld = false;
    originX = ev.clientX;
    originY = ev.clientY;
    curY = ev.clientY;
    lastT = performance.now();
    el.style.cursor = "ns-resize";
    showMarker(originX, originY);

    try {
      el.setPointerCapture?.(ev.pointerId);
      capturedPointerId = ev.pointerId;
    } catch {
      capturedPointerId = null;
    }

    if (!rafId && typeof window.requestAnimationFrame === "function") {
      rafId = window.requestAnimationFrame(step);
    }
  };

  const onWindowPointerMove = (ev: PointerEvent) => {
    if (!active) return;
    curY = ev.clientY;
    if (held && Math.hypot(ev.clientX - originX, ev.clientY - originY) > DRAG_THRESHOLD_PX) {
      draggedWhileHeld = true;
    }
  };

  const onWindowPointerUp = (ev: PointerEvent) => {
    if (!active || !held) return;
    if (ev.button !== 1) return;
    held = false;
    releaseCapture();
    if (draggedWhileHeld) {
      stop();
    }
  };

  const onWindowKeyDown = (ev: KeyboardEvent) => {
    if (!active) return;
    if (ev.key === "Escape") {
      ev.preventDefault();
      ev.stopPropagation();
      stop();
    }
  };

  const onWheel = () => {
    if (active && !held) stop();
  };

  el.addEventListener("mousedown", onMouseDown);
  el.addEventListener("auxclick", onAuxClick);
  el.addEventListener("pointerdown", onPointerDown);
  el.addEventListener("wheel", onWheel, { passive: true });
  window.addEventListener("pointermove", onWindowPointerMove);
  window.addEventListener("pointerup", onWindowPointerUp);
  window.addEventListener("pointercancel", stop);
  window.addEventListener("keydown", onWindowKeyDown, true);

  return {
    stop,
    cleanup: () => {
      stop();
      el.removeEventListener("mousedown", onMouseDown);
      el.removeEventListener("auxclick", onAuxClick);
      el.removeEventListener("pointerdown", onPointerDown);
      el.removeEventListener("wheel", onWheel);
      window.removeEventListener("pointermove", onWindowPointerMove);
      window.removeEventListener("pointerup", onWindowPointerUp);
      window.removeEventListener("pointercancel", stop);
      window.removeEventListener("keydown", onWindowKeyDown, true);
    },
  };
}
