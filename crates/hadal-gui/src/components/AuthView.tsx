import Check from "lucide-solid/icons/check";
import Copy from "lucide-solid/icons/copy";
import RefreshCw from "lucide-solid/icons/refresh-cw";
import { createSignal, onCleanup, onMount, Show } from "solid-js";
import type { VpnApi } from "../api";
import { MinimizeButton } from "./MinimizeButton";

const PERMANENT_PAIR_ERR = /expired|410|unauthorized|forbidden|invalid/i;

interface AuthViewProps {
  api: VpnApi;
  onAuthenticated: () => void;
  onMinimize?: () => void;
}

export function AuthView(props: AuthViewProps) {
  const [pairCode, setPairCode] = createSignal<string | null>(null);
  const [busy, setBusy] = createSignal(false);
  const [copied, setCopied] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);

  let unmounted = false;
  let pollTimer: number | undefined;
  let copiedTimer: number | undefined;
  const clearPoll = () => {
    if (pollTimer !== undefined) {
      window.clearInterval(pollTimer);
      pollTimer = undefined;
    }
  };
  onCleanup(() => {
    unmounted = true;
    clearPoll();
    if (copiedTimer !== undefined) {
      window.clearTimeout(copiedTimer);
      copiedTimer = undefined;
    }
  });

  onMount(() => {
    void startPairFlow();
  });

  async function copyPairCode() {
    const code = pairCode();
    if (!code) return;
    let ok = false;
    if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
      try {
        await navigator.clipboard.writeText(code);
        ok = true;
      } catch {
        // Fallback below when async clipboard permission is unavailable
      }
    }
    if (!ok && typeof document !== "undefined") {
      try {
        const ta = document.createElement("textarea");
        ta.value = code;
        ta.setAttribute("readonly", "");
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        ok = document.execCommand("copy");
        ta.remove();
      } catch {
        ok = false;
      }
    }
    if (!ok) {
      setError("Clipboard unavailable — copy the pairing code manually.");
      return;
    }
    setCopied(true);
    if (copiedTimer !== undefined) window.clearTimeout(copiedTimer);
    copiedTimer = window.setTimeout(() => {
      copiedTimer = undefined;
      setCopied(false);
    }, 1800);
  }

  async function startPairFlow() {
    clearPoll();
    setError(null);
    setCopied(false);
    setBusy(true);
    try {
      const resp = await props.api.createRemoteLogin();
      if (unmounted) return;
      setPairCode(resp.code);
      const hash = resp.hash;
      const expiresAt = resp.expiresAt;
      pollTimer = window.setInterval(async () => {
        if (unmounted) return;
        if (expiresAt && Date.now() / 1000 > expiresAt) {
          clearPoll();
          setError("Pairing code expired. Request a new code.");
          return;
        }
        try {
          const auth = await props.api.pollRemoteLogin(hash);
          if (unmounted) return;
          if (auth.token) {
            clearPoll();
            props.onAuthenticated();
          }
        } catch (err) {
          if (unmounted) return;
          const msg = String(err);
          if (PERMANENT_PAIR_ERR.test(msg)) {
            clearPoll();
            setError(msg);
          }
        }
      }, 3000);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div class="auth-shell">
      <div class="auth-top">
        <div class="auth-brand">
          <div class="auth-title">
            H<span>A</span>DAL
          </div>
        </div>
        <Show when={props.onMinimize}>
          {(onMinimize) => <MinimizeButton onClick={onMinimize()} />}
        </Show>
      </div>

      <div class="auth-center">
        <Show when={error()}>
          {(msg) => (
            <div class="alert-box" role="alert" style={{ "margin-bottom": "10px" }}>
              <span class="alert-msg">{msg()}</span>
            </div>
          )}
        </Show>

        <div class="auth-card">
          <div class="pair-box">
            <div class="pair-head">
              <span class="field-label">Login Code</span>
              <button
                type="button"
                class="pair-refresh"
                aria-label="New code"
                disabled={busy()}
                onClick={() => void startPairFlow()}
              >
                <RefreshCw size={11} strokeWidth={2.2} />
                <span>{busy() ? "Wait…" : "New"}</span>
              </button>
            </div>
            <div class="pair-code">{pairCode() ?? "------"}</div>
            <div class="pair-meta">My account → Enter login code</div>
          </div>

          <div class="dual" style={{ "margin-bottom": 0 }}>
            <button
              type="button"
              class="btn-surf"
              data-spot=""
              onClick={() => void props.api.openExternal("https://my.surfshark.com")}
            >
              Open Web
            </button>
            <button
              type="button"
              class="btn-pri"
              data-spot=""
              disabled={!pairCode()}
              aria-label={copied() ? "Pairing code copied" : "Copy pairing code"}
              onClick={() => void copyPairCode()}
            >
              <Show when={copied()} fallback={<Copy size={15} strokeWidth={2.2} />}>
                <Check size={15} strokeWidth={2.4} />
              </Show>
              <span>{copied() ? "Copied!" : "Copy Code"}</span>
            </button>
          </div>
        </div>
      </div>

      <div class="auth-footer">
        <span>Unofficial client · Not affiliated with Surfshark B.V.</span>
      </div>
    </div>
  );
}
