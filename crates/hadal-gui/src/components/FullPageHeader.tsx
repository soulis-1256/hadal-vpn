import ArrowLeft from "lucide-solid/icons/arrow-left";
import { Show } from "solid-js";
import { MinimizeButton } from "./MinimizeButton";

interface FullPageHeaderProps {
  kicker: string;
  title: string;
  onBack: () => void;
  onMinimize?: () => void;
}

export function FullPageHeader(props: FullPageHeaderProps) {
  return (
    <header class="full-hdr">
      <button
        type="button"
        class="icon-lg back"
        data-spot=""
        aria-label="Back"
        onClick={props.onBack}
      >
        <ArrowLeft size={16} strokeWidth={2.2} />
      </button>
      <div class="stitle">
        <small>{props.kicker}</small>
        <b>{props.title}</b>
      </div>
      <Show when={props.onMinimize}>
        {(onMinimize) => <MinimizeButton variant="panel" onClick={onMinimize()} />}
      </Show>
    </header>
  );
}
