# Hadal VPN Architecture (Linux Flagship)

Hadal VPN is an open-source, Linux-native Surfshark WireGuard client built around a **privileged Rust daemon (`hadald`)**, a **Surfshark API & probing core (`hadal-core`)**, a **terminal controller (`hadal-cli`)**, and a **tray-resident SolidJS desktop popover (`hadal-gui`)**.

> **Scope:** Linux-only (`systemd`, kernel WireGuard, `nftables`, `rtnetlink`, `cgroupv2`).

---

## 1. Crate Topology

```text
crates/
├── hadal-core/   # Surfshark API client/auth, cluster & DoH probing, Gaming Mode, IPC schema, cgroupv2 helpers
├── hadald/       # Privileged systemd daemon: kernel WireGuard, rtnetlink routing, nftables killswitch/split, DNS
├── hadal-cli/    # CLI controller talking to hadald over Unix socket (auth, Gaming Mode, split tunneling, install info)
└── hadal-gui/    # Tauri v2 SNI tray + SolidJS popover talking to hadald over Unix socket
```

---

## 2. Control Plane vs. Data Plane

```text
┌─────────────────────────────┐      ┌──────────────────────────────┐
│  hadal-gui (SolidJS Tray)   │      │  hadal-cli (CLI)             │
│  Unprivileged user process  │      │  Unprivileged user process   │
└──────────────┬──────────────┘      └──────────────┬───────────────┘
               └──────────────────┬─────────────────┘
                      Unix Socket IPC (`/run/hadald/hadald.sock`, 0660 root:network)
                                  │
                                  ▼
┌───────────────────────────────────────────────────────────────────┐
│                    hadald (root systemd daemon)                   │
│                                                                   │
│  1. WireGuard (wireguard-control): kernel `hadal-wg` + fwmark     │
│  2. Routing (rtnetlink): table 51839 + priority policy rules      │
│  3. Firewall (nftables `table inet hadal_vpn`):                   │
│       - Airtight Killswitch (`policy drop` outside `hadal-wg`)    │
│       - IPv6 Leak Lock (rejects non-loopback IPv6 on WAN)         │
│       - DNS Leak Lock (drops non-tunnel UDP/TCP 53 & DoT 853)     │
│       - Split Tunneling (`socket cgroupv2` -> `0xca80` / `0xca81`)│
│  4. DNS (`zbus` -> `systemd-resolved` DoT, or `--dns-mode         │
│     resolv-conf` for isolated netns testing)                      │
│  5. Control Proxy (`CONTROL_FWMARK = 0xca6d`) for WAN probes     │
│     and API reconnects under `KillswitchLocked`                   │
└───────────────────────────────────────────────────────────────────┘
```

### Daemon & Backend Dependency Injection
* **`hadald` (`DaemonController`)**: Injects `WireGuardBackend`, `FirewallBackend`, `RoutingBackend`, `DnsBackend`, `SockDiagBackend`, `ControlBackend`, and `TunnelProber` traits so connect/rollback, killswitch locking, split-tunnel handoff, and IPC framing run deterministically in-memory without root or netns. `VerifyGamingTunnels` executes outside the state mutex so status queries and reconnects never stall.
* **`hadal-gui/src-tauri` (`AppController`)**: Injects `AccountApi`, `DaemonBridge`, `SettingsAndSplitBackend`, `TrayUpdater`, `StatusEmitter`, `NotificationTransport`, `SniWatcherChecker`, and `HyprlandTransport` traits so command orchestration, polling, notifications, and Hyprland popover snapping are unit-testable without a live daemon, compositor, or D-Bus session.

### Surfshark Client Engine (`hadal-core`)
* Sends honest client identification (`User-Agent: hadal-vpn/<version>`) and standard device headers (`x-device-id`, `x-device-type: desktop`, `x-device-platform: linux`, `x-device-version`).
* Handles 6-char Quick Pair authorization (`/v1/account/authorization/create` + `/v1/auth/remote`), proactive/401 JWT refresh (`POST /v1/auth/renew`), `/v5/server/clusters/all`, and ephemeral WireGuard keypair registration (`/v1/account/users/public-keys`) without touching user passwords.

---

## 3. Layer-3 Split Tunneling (`cgroupv2` + `nftables` + `SOCK_DIAG`)

* **App Bypass / VPN-Only:** Applications launch via `systemd-run --user --scope --slice=app-hadal_bypass.slice <app>` (or move existing PIDs into `app-hadal_bypass.slice/tracked` / `app-hadal_vpn.slice/tracked`, and back to `app-hadal_default.slice/tracked` when removed). `hadald` loads an atomic `nftables` mangle chain matching `socket cgroupv2` (`0xca80` bypass / `0xca81` only-VPN) and resets stale pre-existing TCP/UDP/QUIC sockets across moved PIDs in-process using `NETLINK_SOCK_DIAG` (`SOCK_DESTROY`).
* **LAN & Tailscale Safety:** Optional `bypass_lan` preserves RFC1918 + `100.64.0.0/10` routes in `main` (while blocking port `53`/`853` leaks to LAN resolvers).
* **Game-Only Split Routing:** Optional `game_only_cidrs` mode adds only the target game server `/24` prefixes to WireGuard's routing table (`51839`), keeping all other traffic on the direct ISP path.

---

## 4. Dynamic Gaming Mode

1. **Game Registry:** Pre-seeded server latency endpoints for 6 built-in games — **Fortnite** (`*.ds.on.epicgames.com`), **Apex Legends**, **PUBG**, **Dead by Daylight** (`dynamodb.<region>.amazonaws.com`), **FFXIV** (`neolobby*.ffxiv.com`), and **World of Tanks** (`login.p*.worldoftanks.eu`) — plus custom hosts/IPs.
2. **WAN-Accurate Global Discovery & 2-Pass Verification:**
   * Excludes `static` and `virtual` (geo-spoofed) Surfshark clusters so coordinates reflect physical routing paths.
   * Automatically routes DoH, ICMP baseline, WAN PMTU, and candidate endpoint probes through `hadald`'s `CONTROL_FWMARK` (`0xca6d`) whenever the tunnel is `Protected` or `KillswitchLocked`, while measuring live active-tunnel latency side-by-side when connected.
   * Uses cluster coordinates + parallel `edns_client_subnet`-sharded Cloudflare/Google **DoH resolution** to uncover rotating backend hosting pools behind nearby Surfshark domains in one burst, probes up to `MAX_PROBED_IPS_PER_CLUSTER` (24) IPs per cluster, auto-tunes MTU (`WAN PMTU - 80`, clamped `1280..1420`), and when disconnected runs a **2-pass WireGuard verification tournament** through an ephemeral `hadal-probe` interface (Pass 1: up to 12 city & `/16`-subnet diverse candidates with 4 samples; Pass 2: top 3 finalists with 8 steady-state samples).

---

## 5. Tray-First Desktop UI (`Tauri v2` + `SolidJS`)

* **Tray Integration:** Native Linux `ksni` D-Bus `StatusNotifierItem` (`IconPixmap` ARGB32 + `Activate` + `DBusMenu`) via Tauri `tray-icon` with dynamic status badges and `org.freedesktop.Notifications` desktop alerts on connection transitions.
* **Popover Window:** Compact `360×540` borderless tray-anchored popover (`Escape` or header `-` minimize button across home, full-screen sub-pages, and auth screen) built in **SolidJS + CSS + `lucide-solid`**, featuring an offline WebGL2 3D globe (`OrbitGlobe` / `MullvadGlobeGL`) and a `License & Notices` section (`THIRD_PARTY_NOTICES.md`). On Hyprland `0.55+` / `0.57+`, runtime `hyprctl eval` rules (`hl.window_rule` + `hyprbars:no_bar`) and [contrib/hyprland-hadal.lua](contrib/hyprland-hadal.lua) remove titlebars/borders and snap above the tray icon / reserved panel bar.

---

## 6. Automated & Leak-Proof Testing

* **Tier 1 (Unprivileged Unit, DI & Frontend Tests):**
  * `hadal-core`, `hadal-cli`, `hadald`, and `hadal-gui` (`src-tauri` + SolidJS Vitest suite) verify auth/token renewal, Gaming Mode math & tournament scoring, split-tunnel policy/cgroup parsing, daemon state machine & rollback invariants via injected mocks, `nft -c` syntax validation in `unshare -Urn`, Tauri controller/tray/Hyprland orchestration, and UI tab/dropdown behavior.
* **Tier 2 (Real-Kernel `unshare -Urn` + `veth` + Raw Packet Sniffer):**
  * `cargo test -p hadald --test netns_e2e -- --nocapture` runs `scripts/netns_harness.py` inside isolated unprivileged user/mount/network namespaces (`srv` + `cli` wired via `veth`), running the compiled `hadald` binary against a real kernel WireGuard peer + mock DNS + HTTP echo server + `AF_PACKET` sniffer to verify **zero IPv4 leaks, zero DNS/DoT leaks, zero IPv6 leaks, instant killswitch drop on tunnel collapse, and L3 `cgroupv2` + `SOCK_DIAG` split-tunnel handoff**.
