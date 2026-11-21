import Check from "lucide-solid/icons/check";
import ChevronDown from "lucide-solid/icons/chevron-down";
import { createEffect, createSignal, For, onCleanup, Show } from "solid-js";

export interface SelectOption {
  value: string;
  label: string;
  group?: string;
}

interface SelectProps {
  value: string;
  options: SelectOption[];
  placeholder?: string;
  onChange: (value: string) => void;
}

export function Select(props: SelectProps) {
  const [open, setOpen] = createSignal(false);
  let containerRef: HTMLDivElement | undefined;

  const selectedLabel = () =>
    props.options.find((o) => o.value === props.value)?.label ??
    props.placeholder ??
    props.value;

  const groups = () => {
    const map = new Map<string, SelectOption[]>();
    for (const opt of props.options) {
      const g = opt.group ?? "";
      const list = map.get(g) ?? [];
      list.push(opt);
      map.set(g, list);
    }
    return Array.from(map.entries());
  };

  createEffect(() => {
    if (!open()) return;
    const onPointerDown = (e: PointerEvent) => {
      if (containerRef && !containerRef.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        e.stopPropagation();
        setOpen(false);
      }
    };
    window.addEventListener("pointerdown", onPointerDown);
    window.addEventListener("keydown", onKeyDown, true);
    onCleanup(() => {
      window.removeEventListener("pointerdown", onPointerDown);
      window.removeEventListener("keydown", onKeyDown, true);
    });
  });

  return (
    <div class="studio-select" ref={containerRef}>
      <button
        type="button"
        class="select-trigger"
        data-spot=""
        aria-expanded={open() ? "true" : "false"}
        onClick={() => setOpen((prev) => !prev)}
      >
        <span class="select-trigger-label">{selectedLabel()}</span>
        <ChevronDown class="select-chev" size={14} strokeWidth={1.9} />
      </button>

      <div class="select-drawer" data-open={open() ? "true" : "false"}>
        <div class="select-drawer-clip">
          <div class="select-panel">
            <For each={groups()}>
              {([groupName, items]) => (
                <>
                  <Show when={groupName.length > 0}>
                    <div class="select-group">{groupName}</div>
                  </Show>
                  <For each={items}>
                    {(opt) => {
                      const selected = () => opt.value === props.value;
                      return (
                        <button
                          type="button"
                          class="select-opt"
                          data-selected={selected() ? "true" : "false"}
                          onClick={() => {
                            props.onChange(opt.value);
                            setOpen(false);
                          }}
                        >
                          <span class="select-opt-label">{opt.label}</span>
                          <Show when={selected()}>
                            <Check size={13} strokeWidth={2.2} />
                          </Show>
                        </button>
                      );
                    }}
                  </For>
                </>
              )}
            </For>
          </div>
        </div>
      </div>
    </div>
  );
}
