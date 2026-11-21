import X from "lucide-solid/icons/x";

interface NoticeBannerProps {
  message: string;
  onDismiss: () => void;
}

export function NoticeBanner(props: NoticeBannerProps) {
  return (
    <div class="alert-box alert-banner" role="alert">
      <span class="alert-msg">{props.message}</span>
      <button
        type="button"
        class="icon-btn alert-close"
        aria-label="Dismiss error"
        onClick={props.onDismiss}
      >
        <X size={12} strokeWidth={2} />
      </button>
    </div>
  );
}
