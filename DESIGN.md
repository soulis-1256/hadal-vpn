# Hadal VPN Design System (`DESIGN.md`)

> **Aesthetic:** Aerospace Spatial Atlas — deep-space obsidian surfaces, a live offline WebGL2 3D globe (`OrbitGlobe` + `MullvadGlobeGL`), stepped translucent HUD overlays, and high-contrast state signals on a `360 × 540` opaque borderless tray popover.  
> Built with **SolidJS + modular CSS + `lucide-solid`** (zero native `<select>` popups, zero external tile/network map dependencies).

---

## 1. Palette (`crates/hadal-gui/src/styles/tokens.css`)

### Surfaces & Hairlines

Because Hyprland maps the popover with `opaque = true` and `no_blur = true`, depth is established through deep radial canvas values, stepped card surfaces (`--surf`, `--surf-hi`, `--surf-deep`), and `1px` inset specular rim highlights (`--rim`, `--rim-hi`):

| Token | Value | Role |
|---|---|---|
| `--ink` | `#f1f5ff` | Primary headings, active tabs, values |
| `--mute` | `#8994b2` | Secondary metadata, descriptions, inactive options |
| `--dim` | `#586380` | Placeholders, footer labels, idle split-dot |
| `--surf` | `rgba(255, 255, 255, 0.055)` | Elevated cards, group panels, triggers |
| `--surf-hi` | `rgba(255, 255, 255, 0.1)` | Hover surfaces & secondary action buttons |
| `--surf-deep` | `rgba(4, 7, 16, 0.58)` | Recessed inputs, segmented tracks, Quick Pair box |
| `--rim` | `inset 0 1px 0 rgba(255, 255, 255, 0.075)` | Subtle top-rim highlight on cards/buttons |
| `--rim-hi` | `inset 0 1px 0 rgba(255, 255, 255, 0.14)` | Stronger rim on dock cards, auth card, sliding thumb |

### State Signals & Accents

| Token | Value | Role |
|---|---|---|
| `--sc` | `#ffb547` (default / `idle`) | Idle accent, wordmark highlight, `Connect` CTA, selected-but-disconnected marker |
| `--sc` (`connecting`) | `#8fb3ff` (`--link`) | Connecting pulse, `SYNC` dot, link text |
| `--sc` (`protected`) / `--ok` | `#3ee6d0` | Protected tunnel signal, `#1` gaming rank badge, verified RTT, active toggle & split dot, `Gaming` tile |
| `--sc` (`locked`) / `--err` | `#ff5c7a` | `killswitch_locked` state, `Disconnect`/`Unlock Killswitch` CTA, killswitch toggle, `Quit App`, alerts |

---

## 2. Typography & Spatial Atlas Layout (`360 × 540`)

* **Display & UI Sans (`--f-disp`, `--f-ui`):** `"Chakra Petch", sans-serif` (self-hosted `@fontsource/chakra-petch`, `OFL-1.1`).
* **Technical Mono (`--f-mono`):** `"IBM Plex Mono", monospace` (self-hosted `@fontsource/ibm-plex-mono`, `OFL-1.1`) with `font-variant-numeric: tabular-nums` — IPs, RTT (`ms`), jitter (`±`), PMTU/MTU, node loads, country codes, and Quick Pair codes.
* **Layered Spatial Architecture (`App.tsx`, `layout.css`):**
  1. **`OrbitGlobe` (`z-index: 0`):** 3-canvas stage (`sky`, `globe-gl` WebGL2 mesh using `public/geo/*.gl`, `hud` interactive pins/labels) with 3-tier zoom hysteresis (`continent` → `country` → `city`) and priority label collision solver (`labelLayout.ts`).
  2. **`HomeLayer` (`z-index: 3`):** Floating top bar (`HADAL` wordmark, live IP + state tag, Settings & Minimize `-` buttons), space HUD alerts (`hadald daemon offline`, tunnel errors), and bottom `atlas-dock` (selected location pill + `Connect`/`Disconnect` CTA + `Gaming` button).
  3. **`LocationsSheet` (`z-index: 5`):** `476px` solid `#0a1022` slide-up sheet over dimmed `.backdrop`, with search/clear + sync controls, `SegmentedTabs` (`All` / `Low Load` / `Static IP`), and country accordions that auto-expand & center the active/selected node.
  4. **`.full-layer` (`z-index: 6`):** Solid `#070b18` slide-in full views (`GamingView`, `SettingsView`, `SplitTunnelView`, `AddAppView`, `AboutView`) sharing `FullPageHeader` (`Back` on left, title, `MinimizeButton` `-` on right).
  5. **`AuthView` & Loading Fallback:** Both expose the top-right `MinimizeButton` (`-`) so the `alwaysOnTop` popover can always be tucked back into the tray (including after clicking `Open Web` during Quick Pair).

---

## 3. Iconography (`lucide-solid`)

All icons use `lucide-solid/icons/*` (`ISC` license):

| Surface | Component | Lucide Icon |
|---|---|---|
| Window minimize (all headers & Auth) | `MinimizeButton.tsx` | `Minus` (`16px`) |
| Sub-page back | `FullPageHeader.tsx` | `ArrowLeft` (`16px`) |
| Home header & dock | `HomeLayer.tsx` | `Settings`, `ChevronUp`, `Zap` |
| Locations sheet | `LocationsSheet.tsx` | `X`, `RefreshCw`, `ChevronDown`, `Check` |
| Search inputs | `SearchInput.tsx` | `Search`, `X` (clear) |
| Custom Select | `Select.tsx` | `ChevronDown` (`180deg` rotate), `Check` |
| Split tunnel & Apps | `SplitTunnelView.tsx`, `AddAppView.tsx`, `SettingsView.tsx` | `GitBranch`, `ChevronRight`, `Plus`, `RefreshCw`, `X` |
| Notice dismiss | `NoticeBanner.tsx` | `X` (`12px`) |

---

## 4. Motion, Synchronized Tabs & Escape Layering

* **Curves & Reduced Motion:** `--spring: cubic-bezier(0.34, 1.56, 0.64, 1)` and `--ease: cubic-bezier(0.22, 1, 0.36, 1)`. `@media (prefers-reduced-motion: reduce)` collapses transitions/animations to `0.001ms` and bypasses JS tab-exit timers.
* **GPU-Composited Sheets & Views:** `.sheet-layer` and `.full-layer` animate purely via `transform: translate3d(...)` and `visibility` with no layout reflow; `LocationsSheet` snaps accordion/scroll state inside `requestAnimationFrame` with transitions temporarily suppressed (`data-instant-acc="true"`).
* **Synchronized Segmented Tabs (`SegmentedTabs.tsx`):** Used in `LocationsSheet` (`All` / `Low Load` / `Static IP`) and `SplitTunnelView` (`Off` / `Bypass VPN` / `Route via VPN`). Sliding `.seg-thumb` starts on frame 0 while `renderedValue` holds on `data-phase="exiting"` until exit finishes, and external prop sync uses `untrack(targetValue)` so transitions never snap prematurely. (`AuthView` uses single-screen browser Quick Pair without password tabs.)
* **Escape Layering:** Capture-phase `Escape` closes open `Select` drawers (or active middle-click autoscroll) first (`stopPropagation()`); `appStore.ts` then pops one route from `routeStack` per `Escape` press, hiding to tray once back on `home` / `AuthView`.

---

## 5. Tray Icon, Legal Notices & Hyprland Rules (`crates/hadal-gui`)

* **Tray Badge (`render_tray_badge` in `src-tauri/src/tray.rs`, `64 × 64` RGBA):** Orbital Hadal crescent + depth-core squircle (`BADGE_BODY_RGB = (12, 16, 22)`, `BADGE_RIM_RGB = (42, 56, 74)`, `BADGE_MARK_RGB = (241, 245, 249)`) with state beacon dot: `Protected (16, 209, 144)`, `Connecting (34, 211, 238)`, `KillswitchLocked (244, 63, 94)`, `Disconnected (100, 116, 139)`.
* **GPLv3 & Third-Party Attribution:** `SettingsView` exposes a compact `About & Licenses` row (`v0.2.1 · GPL-3.0-or-later`) opening `AboutView` with copyright, no-warranty terms, and Mullvad/Natural Earth/Fontsource/Lucide notices (see `crates/hadal-gui/THIRD_PARTY_NOTICES.md`).
* **Hyprland Floating Rules (`hyprland.rs`):** `360 × 540`, `float = true`, `pin = true`, `border_size = 0`, `rounding = 8`, `opaque = true`, `no_blur = true`, `hyprbars:no_bar = true`, snapped above the active tray icon/panel edge.
