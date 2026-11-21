import Minus from "lucide-solid/icons/minus";

interface MinimizeButtonProps {
  onClick: () => void;
  variant?: "hdr" | "panel";
}

export function MinimizeButton(props: MinimizeButtonProps) {
  const className = () =>
    props.variant === "panel" ? "icon-lg minimize" : "hdr-icon minimize";

  return (
    <button
      type="button"
      class={className()}
      data-spot=""
      aria-label="Minimize to tray"
      title="Minimize to tray"
      onClick={props.onClick}
    >
      <Minus size={16} strokeWidth={2.2} />
    </button>
  );
}
