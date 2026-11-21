import {
  batch,
  createEffect,
  createMemo,
  createSignal,
  For,
  onCleanup,
  untrack,
  type Accessor,
  type JSX,
} from "solid-js";
import type { TransitionPhase } from "../types";

export interface SegmentedTabOption<T extends string> {
  value: T;
  label: string;
}

interface SegmentedTabsProps<T extends string> {
  options: readonly SegmentedTabOption<T>[];
  value: T;
  onChange: (next: T) => void;
  children: (renderedTab: Accessor<T>) => JSX.Element;
  exitMs?: number;
  enterMs?: number;
  ariaLabel?: string;
}

function prefersReducedMotion(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof window.matchMedia === "function" &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches
  );
}

/**
 * Synchronized segmented control and animated tab pane.
 *
 * Updates the active tab indicator immediately on click while holding the pane's
 * rendered mode on the outgoing tab until the exit animation completes, preventing
 * content from snapping ahead of the transition.
 */
export function SegmentedTabs<T extends string>(props: SegmentedTabsProps<T>) {
  const [targetValue, setTargetValue] = createSignal<T>(props.value);
  const [renderedValue, setRenderedValue] = createSignal<T>(props.value);
  const [phase, setPhase] = createSignal<TransitionPhase>("idle");
  const [dir, setDir] = createSignal<"forward" | "backward">("forward");

  let paneRef: HTMLDivElement | undefined;
  let exitTimer: number | undefined;
  let enterTimer: number | undefined;

  const exitDuration = () => props.exitMs ?? 100;
  const enterDuration = () => props.enterMs ?? 140;

  function clearTimers() {
    if (exitTimer !== undefined) {
      window.clearTimeout(exitTimer);
      exitTimer = undefined;
    }
    if (enterTimer !== undefined) {
      window.clearTimeout(enterTimer);
      enterTimer = undefined;
    }
  }

  onCleanup(clearTimers);

  // Sync only when props.value changes externally (e.g., async settings load),
  // leaving local user-initiated transitions untouched.
  let prevExternal = props.value;
  createEffect(() => {
    const external = props.value;
    if (external === prevExternal) return;
    prevExternal = external;
    if (external !== untrack(targetValue)) {
      clearTimers();
      setTargetValue(() => external);
      setRenderedValue(() => external);
      setPhase("idle");
    }
  });

  const activeIndex = createMemo(() => {
    const idx = props.options.findIndex((o) => o.value === targetValue());
    return idx >= 0 ? idx : 0;
  });

  function finishEnter() {
    if (enterTimer !== undefined) {
      window.clearTimeout(enterTimer);
      enterTimer = undefined;
    }
    if (phase() === "entering") {
      setPhase("idle");
    }
  }

  function commitSwap() {
    if (exitTimer !== undefined) {
      window.clearTimeout(exitTimer);
      exitTimer = undefined;
    }
    if (phase() !== "exiting") return;

    const next = targetValue();
    setRenderedValue(() => next);
    if (prefersReducedMotion()) {
      setPhase("idle");
      return;
    }
    setPhase("entering");
    enterTimer = window.setTimeout(finishEnter, enterDuration());
  }

  function handleAnimationEnd(ev: AnimationEvent) {
    if (ev.target !== paneRef) return;
    if (phase() === "exiting") {
      commitSwap();
    } else if (phase() === "entering") {
      finishEnter();
    }
  }

  function selectTab(next: T) {
    if (next === targetValue()) return;
    clearTimers();

    const currentRenderedIdx = Math.max(
      0,
      props.options.findIndex((o) => o.value === renderedValue()),
    );
    const nextIdx = Math.max(
      0,
      props.options.findIndex((o) => o.value === next),
    );

    batch(() => {
      setDir(nextIdx >= currentRenderedIdx ? "forward" : "backward");
      setTargetValue(() => next);

      if (prefersReducedMotion()) {
        setRenderedValue(() => next);
        setPhase("idle");
      } else if (renderedValue() === next) {
        setPhase("entering");
        enterTimer = window.setTimeout(finishEnter, enterDuration());
      } else {
        setPhase("exiting");
        exitTimer = window.setTimeout(commitSwap, exitDuration());
      }

      props.onChange(next);
    });
  }

  return (
    <div class="segmented-stack">
      <div
        class="segmented"
        role="tablist"
        aria-label={props.ariaLabel}
        style={{
          "--seg-count": String(props.options.length),
          "--seg-index": String(activeIndex()),
        }}
      >
        <div class="seg-thumb" />
        <For each={props.options}>
          {(opt) => {
            const isSelected = () => targetValue() === opt.value;
            return (
              <button
                type="button"
                role="tab"
                class="seg-btn"
                aria-selected={isSelected() ? "true" : "false"}
                data-active={isSelected() ? "true" : "false"}
                onClick={() => selectTab(opt.value)}
              >
                {opt.label}
              </button>
            );
          }}
        </For>
      </div>

      <div
        ref={paneRef}
        role="tabpanel"
        class="segmented-pane"
        data-phase={phase()}
        data-dir={dir()}
        data-rendered-mode={renderedValue()}
        onAnimationEnd={handleAnimationEnd}
      >
        {props.children(renderedValue)}
      </div>
    </div>
  );
}
