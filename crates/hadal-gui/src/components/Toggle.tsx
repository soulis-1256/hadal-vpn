interface ToggleProps {
  title: string;
  description?: string;
  checked: boolean;
  disabled?: boolean;
  tone?: "fg" | "ok" | "err";
  onChange: (next: boolean) => void;
}

export function Toggle(props: ToggleProps) {
  return (
    <div class="switch-row">
      <div class="switch-text">
        <span class="switch-title">{props.title}</span>
        {props.description && <span class="switch-desc">{props.description}</span>}
      </div>
      <button
        type="button"
        role="switch"
        aria-label={props.title}
        aria-checked={props.checked}
        class="toggle"
        data-checked={props.checked ? "true" : "false"}
        data-tone={props.tone ?? "fg"}
        disabled={props.disabled}
        onClick={() => props.onChange(!props.checked)}
      />
    </div>
  );
}
