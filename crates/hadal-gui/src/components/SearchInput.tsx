import Search from "lucide-solid/icons/search";
import X from "lucide-solid/icons/x";
import { Show } from "solid-js";

interface SearchInputProps {
  value: string;
  placeholder: string;
  ariaLabel?: string;
  onInput: (value: string) => void;
}

export function SearchInput(props: SearchInputProps) {
  let inputRef: HTMLInputElement | undefined;

  return (
    <div
      class="srch"
      onClick={(e) => {
        if (e.target !== inputRef && !(e.target as HTMLElement | null)?.closest(".srch-clear")) {
          inputRef?.focus();
        }
      }}
    >
      <Search size={15} strokeWidth={2} />
      <input
        ref={inputRef}
        type="text"
        placeholder={props.placeholder}
        aria-label={props.ariaLabel ?? props.placeholder}
        value={props.value}
        onInput={(e) => props.onInput(e.currentTarget.value)}
      />
      <Show when={props.value.length > 0}>
        <button
          type="button"
          class="srch-clear"
          aria-label="Clear search"
          onClick={() => {
            props.onInput("");
            inputRef?.focus();
          }}
        >
          <X size={13} strokeWidth={2.2} />
        </button>
      </Show>
    </div>
  );
}
