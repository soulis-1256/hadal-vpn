import { onCleanup, onMount, Show } from "solid-js";
import pkg from "../../package.json";
import { attachMiddleClickScroll, type MiddleClickScrollHandle } from "../utils/middleClickScroll";
import { FullPageHeader } from "./FullPageHeader";

const GPL_V3_URL = "https://www.gnu.org/licenses/gpl-3.0.html";

interface AboutViewProps {
  animClass: string;
  onBack: () => void;
  onMinimize?: () => void;
  onOpenExternal?: (url: string) => void;
}

export function AboutView(props: AboutViewProps) {
  let bodyRef: HTMLDivElement | undefined;
  let middleScroll: MiddleClickScrollHandle | undefined;

  onMount(() => {
    if (bodyRef) middleScroll = attachMiddleClickScroll(bodyRef);
  });
  onCleanup(() => {
    middleScroll?.cleanup();
  });

  return (
    <div style={{ display: "flex", "flex-direction": "column", height: "100%" }}>
      <FullPageHeader
        kicker="Settings / Legal"
        title="About & Licenses"
        onBack={props.onBack}
        onMinimize={props.onMinimize}
      />

      <div ref={bodyRef} class={`full-body ${props.animClass}`}>
        <div class="sec-lbl">Application</div>
        <div class="legal-card" style={{ "margin-bottom": "12px" }}>
          <div class="legal-head">
            <b>Hadal VPN v{pkg.version}</b>
            <span>GPL-3.0-or-later</span>
          </div>
          <p class="legal-copy">
            Copyright &copy; 2026 soulis-1256. Provided with ABSOLUTELY NO WARRANTY; you may
            copy, modify, and redistribute this software under the GNU GPL v3 or later.
          </p>
          <p class="legal-copy" style={{ "margin-top": "6px" }}>
            Independent open-source client for Surfshark accounts; not affiliated with, endorsed
            by, or sponsored by Surfshark B.V.
          </p>
          <Show when={props.onOpenExternal}>
            {(openExternal) => (
              <button
                type="button"
                class="legal-link"
                data-spot=""
                onClick={() => openExternal()(GPL_V3_URL)}
              >
                View GNU GPL-3.0 License
              </button>
            )}
          </Show>
        </div>

        <div class="sec-lbl">Third-Party Notices</div>
        <div class="legal-card">
          <p class="legal-copy">
            <b>3D Globe &amp; Meshes:</b> Adapted from Mullvad VPN (Copyright &copy; Mullvad VPN
            AB, GPL-3.0-or-later; mesh buffers via globe-mesh-builder).
          </p>
          <p class="legal-copy">
            <b>Map Geometry:</b> Natural Earth coastline &amp; land datasets (CC0 / Public Domain).
          </p>
          <p class="legal-copy">
            <b>Fonts &amp; Icons:</b> Chakra Petch &amp; IBM Plex Mono (OFL-1.1); Lucide icons
            (ISC).
          </p>
        </div>
      </div>
    </div>
  );
}
