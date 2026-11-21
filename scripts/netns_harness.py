#!/usr/bin/env python3
"""
Unprivileged real-kernel WireGuard + nftables + DNS + IPv6 + cgroupv2 split-tunnel
integration test suite for `hadald`.

Runs inside `unshare -Ur`:
  - `srv` netns: mock ISP WAN (192.0.2.1/24, fd00:dead::1/64), kernel WireGuard server (wg-srv, 10.99.0.1/24),
                 target service IP 198.51.100.1:8080 (reports real client src IP -> VPN vs ISP!),
                 mock DNS server on 10.99.0.1:53 and trap DNS on 192.0.2.1:53/853,
                 and AF_PACKET sniffer on veth-srv asserting 0 leaked packets.
  - `cli` netns (+ mountns): runs the actual compiled `hadald` binary, exercises full connect,
                 DNS leak lock, IPv6 leak lock, abrupt wg interface drop (killswitch),
                 cgroupv2 split-tunnel bypass, and clean teardown.
"""
import base64
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def run(cmd, check=True):
    return subprocess.run(cmd, check=check, capture_output=True, text=True)


def generate_wg_keypair():
    # Use `python3` cryptography if available or x25519 via `wg`? `wg` isn't installed; use `hadal-cli` or Curve25519 via ctypes/openssl?
    # Better: use openssl x25519 PKCS8/SPKI or pass keys directly via tiny helper, OR use `openssl genpkey -algorithm X25519`!
    priv_der = subprocess.check_output(["openssl", "genpkey", "-algorithm", "X25519", "-outform", "DER"])
    priv_raw = priv_der[-32:]
    pub_der = subprocess.check_output(
        ["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"],
        input=priv_der,
    )
    pub_raw = pub_der[-32:]
    return base64.b64encode(priv_raw).decode(), base64.b64encode(pub_raw).decode()


def ipc_call(sock_path: str, req: dict) -> dict:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(10.0)
    s.connect(sock_path)
    s.sendall((json.dumps(req) + "\n").encode())
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
    s.close()
    return json.loads(buf.decode().strip())


def find_wg_helper(repo_root: Path) -> Path | None:
    if env_bin := os.environ.get("HADAL_WG_PEER_BIN"):
        p = Path(env_bin)
        return p if p.exists() else None
    for profile in ("debug", "release"):
        deps_dir = repo_root / "target" / profile / "deps"
        if not deps_dir.is_dir():
            continue
        candidates = sorted(
            (p for p in deps_dir.glob("netns_e2e-*") if p.is_file() and os.access(p, os.X_OK)),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if candidates:
            os.environ["HADAL_WG_PEER_HELPER"] = "1"
            return candidates[0]
    return None


def main():
    repo_root = Path(__file__).resolve().parents[1]
    hadald_bin = Path(os.environ.get("HADALD_BIN") or (repo_root / "target/debug/hadald"))
    wg_helper_bin = find_wg_helper(repo_root)
    if not hadald_bin.exists():
        print(f"Missing hadald binary at {hadald_bin}", file=sys.stderr)
        sys.exit(2)
    if wg_helper_bin is None:
        print(
            "Missing netns_e2e WireGuard peer helper; run via `cargo test -p hadald --test netns_e2e -- --nocapture`",
            file=sys.stderr,
        )
        sys.exit(2)

    # Outer check: re-exec inside `unshare -Urn` if not uid 0 (so veth creation gets CAP_NET_ADMIN)
    if os.geteuid() != 0:
        os.execvp("unshare", ["unshare", "-Urn", sys.executable, str(Path(__file__).resolve())])

    # Determine user's writable cgroupv2 app.slice for split-tunnel test
    cg_rel_bypass = ""
    with open("/proc/self/cgroup") as f:
        for line in f:
            if line.startswith("0::"):
                self_cg = line[3:].strip().lstrip("/")
                parent = self_cg.rsplit("/", 1)[0] if "/" in self_cg else "user.slice"
                cg_rel_bypass = f"{parent}/hadal-test-bypass.slice"
                break
    cg_full_bypass = Path("/sys/fs/cgroup") / cg_rel_bypass
    cg_full_bypass.mkdir(parents=True, exist_ok=True)

    tmpdir = Path(tempfile.mkdtemp(prefix="hadal-netns-"))
    srv_priv, srv_pub = generate_wg_keypair()
    cli_priv, cli_pub = generate_wg_keypair()

    srv_proc = None
    cli_proc = None
    try:
        # 1. Spawn `srv` namespace worker (in new netns)
        veth_moved = tmpdir / "veth.moved"
        srv_ready = tmpdir / "srv.ready"
        srv_stop = tmpdir / "srv.stop"
        sniff_json = tmpdir / "sniff.json"
        srv_code = f"""
import http.server, json, os, socket, struct, subprocess, sys, threading, time
from pathlib import Path

def run(c):
    subprocess.run(c, check=True)

# Wait until veth-srv is moved into our netns (poll marker since /sys reflects outer netns)
while not Path({json.dumps(str(veth_moved))}).exists():
    time.sleep(0.02)

run(["ip", "link", "set", "lo", "up"])
run(["ip", "addr", "add", "198.51.100.1/32", "dev", "lo"])
run(["ip", "link", "set", "veth-srv", "up"])
run(["ip", "addr", "add", "192.0.2.1/24", "dev", "veth-srv"])
run(["ip", "-6", "addr", "add", "fd00:dead::1/64", "dev", "veth-srv"])

# Create kernel WireGuard server interface via helper binary
run([
    {json.dumps(str(wg_helper_bin))},
    "--iface", "wg-srv",
    "--address", "10.99.0.1/24",
    "--listen-port", "51820",
    "--priv-key", {json.dumps(srv_priv)},
    "--peer-pub-key", {json.dumps(cli_pub)},
    "--allowed-ips", "10.99.0.2/32",
])
run(["ip", "route", "replace", "10.99.0.2/32", "dev", "wg-srv"])

# Echo HTTP server on 198.51.100.1:8080 returning client source IP!
class EchoHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = f"SRC={{self.client_address[0]}}".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass

httpd = http.server.ThreadingHTTPServer(("198.51.100.1", 8080), EchoHandler)
threading.Thread(target=httpd.serve_forever, daemon=True).start()

# Mock VPN DNS responder on 10.99.0.1:53 (answers A=198.51.100.1 for any query)
dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
dns_sock.bind(("10.99.0.1", 53))
def dns_loop():
    while True:
        try:
            data, addr = dns_sock.recvfrom(512)
            if len(data) < 12:
                continue
            tid = data[:2]
            # Find end of QNAME
            idx = 12
            while idx < len(data) and data[idx] != 0:
                idx += data[idx] + 1
            q_end = idx + 5
            q_sec = data[12:q_end]
            flags = b"\\x81\\x80"
            counts = struct.pack("!HHHH", 1, 1, 0, 0)
            ans = b"\\xc0\\x0c\\x00\\x01\\x00\\x01\\x00\\x00\\x00\\x3c\\x00\\x04" + socket.inet_aton("198.51.100.1")
            dns_sock.sendto(tid + flags + counts + q_sec + ans, addr)
        except Exception:
            break
threading.Thread(target=dns_loop, daemon=True).start()

# Raw AF_PACKET sniffer on veth-srv recording non-WG IPv4, rogue DNS (53/853), and non-ND IPv6 packets!
raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
raw.bind(("veth-srv", 0))
raw.settimeout(0.1)
events = {{"non_wg_v4": [], "rogue_dns": [], "ipv6_leaks": [], "wg_udp": 0, "bypass_http": 0}}
lock = threading.Lock()

def sniff_loop():
    while not Path({json.dumps(str(srv_stop))}).exists():
        try:
            pkt = raw.recv(65535)
        except TimeoutError:
            continue
        except Exception:
            break
        if len(pkt) < 14:
            continue
        ethertype = struct.unpack("!H", pkt[12:14])[0]
        if ethertype == 0x0800 and len(pkt) >= 34:
            ihl = (pkt[14] & 0x0f) * 4
            proto = pkt[23]
            src = socket.inet_ntoa(pkt[26:30])
            dst = socket.inet_ntoa(pkt[30:34])
            if src != "192.0.2.2":
                continue
            sport = dport = 0
            if proto in (6, 17) and len(pkt) >= 14 + ihl + 4:
                sport, dport = struct.unpack("!HH", pkt[14+ihl:14+ihl+4])
            with lock:
                if proto == 17 and dport == 51820 and dst == "192.0.2.1":
                    events["wg_udp"] += 1
                elif dport in (53, 853) or sport in (53, 853):
                    events["rogue_dns"].append((proto, src, dst, dport))
                elif proto == 6 and dport == 8080 and dst == "198.51.100.1":
                    events["bypass_http"] += 1
                else:
                    events["non_wg_v4"].append((proto, src, dst, dport))
        elif ethertype == 0x86DD and len(pkt) >= 54:
            src6 = socket.inet_ntop(socket.AF_INET6, pkt[22:38])
            if src6.startswith("fe80:") or src6 == "::":
                continue
            nxt = pkt[20]
            # Ignore ICMPv6 Neighbor Discovery (types 133..136)
            if nxt == 58 and len(pkt) >= 55 and pkt[54] in (133, 134, 135, 136):
                continue
            with lock:
                events["ipv6_leaks"].append((nxt, src6))

threading.Thread(target=sniff_loop, daemon=True).start()
Path({json.dumps(str(srv_ready))}).write_text("ok")

# Wait for stop signal
while not Path({json.dumps(str(srv_stop))}).exists():
    time.sleep(0.05)

with lock:
    Path({json.dumps(str(sniff_json))}).write_text(json.dumps(events))
"""
        srv_script = tmpdir / "srv.py"
        srv_script.write_text(srv_code)
        srv_log = tmpdir / "srv.log"
        srv_proc = subprocess.Popen(
            ["unshare", "-n", sys.executable, str(srv_script)],
            stdout=open(srv_log, "w"),
            stderr=subprocess.STDOUT,
        )

        # 2. Spawn `cli` namespace worker (new netns + mountns so /etc/resolv.conf bind mount is isolated!)
        cli_ready = tmpdir / "cli.ready"
        cli_done = tmpdir / "cli.done"
        resolv_file = tmpdir / "resolv.conf"
        resolv_file.write_text("nameserver 192.0.2.1\n")
        nsswitch_file = tmpdir / "nsswitch.conf"
        nsswitch_file.write_text("hosts: files dns\n")

        cli_code = f"""
import os, subprocess, time
from pathlib import Path

while not Path({json.dumps(str(veth_moved))}).exists():
    time.sleep(0.02)

subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
subprocess.run(["ip", "link", "set", "veth-cli", "up"], check=True)
subprocess.run(["ip", "addr", "add", "192.0.2.2/24", "dev", "veth-cli"], check=True)
subprocess.run(["ip", "route", "add", "default", "via", "192.0.2.1", "dev", "veth-cli"], check=True)
subprocess.run(["ip", "-6", "addr", "add", "fd00:dead::2/64", "dev", "veth-cli"], check=True)
subprocess.run(["ip", "-6", "route", "add", "default", "via", "fd00:dead::1", "dev", "veth-cli"], check=True)

# Isolate /etc/resolv.conf and /etc/nsswitch.conf (bypass host nss-resolve) inside this mount namespace only!
target_resolv = os.path.realpath("/etc/resolv.conf")
subprocess.run(["mount", "--bind", {json.dumps(str(resolv_file))}, target_resolv], check=True)
subprocess.run(["mount", "--bind", {json.dumps(str(nsswitch_file))}, "/etc/nsswitch.conf"], check=True)

Path({json.dumps(str(cli_ready))}).write_text("ok")
# Keep namespace alive until stopped
while not Path({json.dumps(str(cli_done))}).exists():
    time.sleep(0.1)
"""
        cli_script = tmpdir / "cli.py"
        cli_script.write_text(cli_code)
        cli_log = tmpdir / "cli.log"
        cli_proc = subprocess.Popen(
            ["unshare", "-mn", sys.executable, str(cli_script)],
            stdout=open(cli_log, "w"),
            stderr=subprocess.STDOUT,
        )

        # Give child namespaces a moment to exist, then wire veth pair across srv_proc <-> cli_proc
        time.sleep(0.25)
        run(["ip", "link", "add", "veth-srv", "type", "veth", "peer", "name", "veth-cli"])
        run(["ip", "link", "set", "veth-srv", "netns", str(srv_proc.pid)])
        run(["ip", "link", "set", "veth-cli", "netns", str(cli_proc.pid)])
        veth_moved.write_text("ok")

        for _ in range(100):
            if srv_ready.exists() and cli_ready.exists():
                break
            time.sleep(0.05)
        assert srv_ready.exists() and cli_ready.exists(), (
            f"Namespaces failed to initialize\nsrv_ready={srv_ready.exists()} cli_ready={cli_ready.exists()}\n"
            f"--- srv.log ---\n{srv_log.read_text()}\n--- cli.log ---\n{cli_log.read_text()}"
        )

        # 3. Start REAL `hadald` inside cli_proc's namespaces!
        sock_path = str(tmpdir / "hadald.sock")
        state_dir = str(tmpdir / "hadald_state")
        hadald_log = tmpdir / "hadald.log"
        hadald_proc = subprocess.Popen(
            [
                "nsenter", "-t", str(cli_proc.pid), "-m", "-n",
                str(hadald_bin),
                "--socket", sock_path,
                "--state-dir", state_dir,
                "--iface", "hadal-wg",
                "--dns-mode", "resolv-conf",
                "--resolv-conf", str(resolv_file),
            ],
            stdout=open(hadald_log, "w"),
            stderr=subprocess.STDOUT,
        )
        for _ in range(100):
            if Path(sock_path).exists():
                break
            time.sleep(0.05)
        assert Path(sock_path).exists(), f"hadald socket missing; log:\n{hadald_log.read_text()}"

        def ns_exec(py_snippet: str):
            return subprocess.run(
                ["nsenter", "-t", str(cli_proc.pid), "-m", "-n", sys.executable, "-c", py_snippet],
                capture_output=True,
                text=True,
                timeout=6,
            )

        # TEST 1: Connect via real hadald + verify traffic routes through VPN with 0 non-WG leaks
        print("[1/6] Connecting hadald with killswitch + IPv6 block + cgroupv2 bypass...")
        connect_req = {
            "op": "connect",
            "data": {
                "cluster_id": "test-1",
                "domain": "test.local",
                "endpoint_ip": "192.0.2.1",
                "endpoint_port": 51820,
                "pub_key": srv_pub,
                "priv_key": cli_priv,
                "address": "10.99.0.2/32",
                "dns": ["10.99.0.1"],
                "mtu": 1412,
                "killswitch": True,
                "ipv6_block": True,
                "bypass_lan": False,
                "split_mode": "bypass",
                "split_cgroup_paths": [cg_rel_bypass],
                "game_only_cidrs": [],
                "location": "NetnsLab",
                "country": "Test",
            },
        }
        resp = ipc_call(sock_path, connect_req)
        assert resp["status"] == "status" and resp["data"]["state"] == "protected", resp

        r_vpn = ns_exec("import urllib.request; print(urllib.request.urlopen('http://198.51.100.1:8080', timeout=3).read().decode())")
        if r_vpn.returncode != 0:
            dbg_cli = subprocess.run(["nsenter", "-t", str(cli_proc.pid), "-n", "sh", "-c", "ip -s link; echo ---; ip route get 192.0.2.1; echo ---; ip route get 192.0.2.1 mark 0xca7f; echo ---; ip rule; echo ---; nft list ruleset"], capture_output=True, text=True).stdout
            dbg_srv = subprocess.run(["nsenter", "-t", str(srv_proc.pid), "-n", "sh", "-c", "ip -s link; echo ---; ip route show table all"], capture_output=True, text=True).stdout
            srv_stop.write_text("stop")
            srv_proc.wait(timeout=3)
            st_dbg = ipc_call(sock_path, {"op": "status"})
            sniff_dbg = sniff_json.read_text() if sniff_json.exists() else "no sniff"
            raise AssertionError(
                f"VPN HTTP failed: {r_vpn.stderr}\nstatus={st_dbg}\nsniff={sniff_dbg}\n--- CLI ---\n{dbg_cli}\n--- SRV ---\n{dbg_srv}\n--- hadald.log ---\n{hadald_log.read_text()}"
            )
        assert r_vpn.stdout.strip() == "SRC=10.99.0.2", f"Expected VPN src 10.99.0.2, got: {r_vpn.stdout}"
        print(f"      PASS: HTTP seen by server = {r_vpn.stdout.strip()}")

        st = ipc_call(sock_path, {"op": "status"})["data"]
        assert st["rx_bytes"] > 0 and st["tx_bytes"] > 0, f"Expected WG telemetry > 0: {st}"
        assert st["last_handshake_epoch"] is not None, "Expected completed WireGuard handshake"
        print(f"      PASS: Handshake verified (rx={st['rx_bytes']}B, tx={st['tx_bytes']}B)")

        # TEST 2: DNS Leak Check (tunneled DNS succeeds; direct ISP DNS 192.0.2.1:53 & :853 blocked!)
        print("[2/6] Testing DNS leak lock...")
        r_dns_ok = ns_exec("import socket; print(socket.gethostbyname('vpn.hadal.test'))")
        assert r_dns_ok.returncode == 0 and r_dns_ok.stdout.strip() == "198.51.100.1", f"Tunneled DNS failed: {r_dns_ok.stderr} {r_dns_ok.stdout}"
        r_dns_leak = ns_exec("""
import socket
# Also verify an explicit socket bound straight to WAN NIC (e.g. rogue LAN/ISP DNS) is blocked with EPERM:
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, 25, b'veth-cli\\x00')  # SO_BINDTODEVICE
s.settimeout(0.5)
try:
    s.sendto(b'leak', ('192.0.2.1', 53))
    print('SENT_OK')
except Exception as e:
    print('BLOCKED:', type(e).__name__)
""")
        assert "BLOCKED:" in r_dns_leak.stdout, f"Expected EPERM/blocked on rogue UDP 53, got: {r_dns_leak.stdout}"
        print(f"      PASS: Tunneled DNS resolved 198.51.100.1; rogue ISP UDP/53 {r_dns_leak.stdout.strip()}")

        # TEST 3: IPv6 Leak Check (attempt IPv6 TCP & UDP to fd00:dead::1 -> must fail/block)
        print("[3/6] Testing IPv6 leak lock...")
        r_v6 = ns_exec("""
import socket
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
try:
    s.sendto(b'v6leak', ('fd00:dead::1', 8080))
    print('V6_SENT')
except Exception as e:
    print('V6_BLOCKED:', type(e).__name__)
""")
        assert "V6_BLOCKED:" in r_v6.stdout, f"Expected IPv6 blocked, got: {r_v6.stdout}"
        print(f"      PASS: {r_v6.stdout.strip()}")

        # TEST 4: cgroupv2 L3 Split Tunnel Bypass Check
        print("[4/6] Testing cgroupv2 L3 split-tunnel bypass...")
        r_split = subprocess.run(
            [
                "nsenter", "-t", str(cli_proc.pid), "-m", "-n",
                sys.executable, "-c",
                f"""
import os, urllib.request
with open('/sys/fs/cgroup/{cg_rel_bypass}/cgroup.procs', 'w') as f:
    f.write(str(os.getpid()))
print(urllib.request.urlopen('http://198.51.100.1:8080', timeout=3).read().decode())
""",
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
        assert r_split.returncode == 0, f"Bypassed app failed: {r_split.stderr}"
        assert r_split.stdout.strip() == "SRC=192.0.2.2", f"Expected ISP bypass src 192.0.2.2, got: {r_split.stdout}"
        print(f"      PASS: Bypassed cgroup process exited directly via {r_split.stdout.strip()}")

        # TEST 5: Already-running process holding pre-existing keep-alive VPN connection & UNCONN UDP/UDP6 QUIC sockets
        print("[5/6] Testing live running-process cgroup move + ResetAppSockets handoff...")
        pre_sock_code = f"""
import http.client, os, socket, sys
c = http.client.HTTPConnection('198.51.100.1', 8080, timeout=3)
c.request('GET', '/')
r1 = c.getresponse().read().decode().strip()

# Open unconnected HTTP/3-style UDP & dual-stack UDP6 sockets too
quic4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
quic4.bind(('0.0.0.0', 0))
quic4.sendto(b'q4-init', ('198.51.100.1', 9))

quic6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
quic6.bind(('::', 0))
quic6.sendto(b'q6-init', ('::ffff:198.51.100.1', 9))

with open('/sys/fs/cgroup/{cg_rel_bypass}/cgroup.procs', 'w') as f:
    f.write(str(os.getpid()))
print(f'BEFORE:{{r1}}:{{os.getpid()}}', flush=True)
sys.stdin.readline()

udp_aborted = []
for name, sock in (('u4', quic4), ('u6', quic6)):
    try:
        sock.sendto(b'after-move', ('198.51.100.1', 9) if name == 'u4' else ('::ffff:198.51.100.1', 9))
        udp_aborted.append(f'{{name}}=OK')
    except ConnectionAbortedError:
        udp_aborted.append(f'{{name}}=ABORTED')
    except Exception as ex:
        udp_aborted.append(f'{{name}}={{type(ex).__name__}}')
    finally:
        sock.close()

try:
    c.request('GET', '/')
    r2 = c.getresponse().read().decode().strip()
except Exception:
    c.close()
    c2 = http.client.HTTPConnection('198.51.100.1', 8080, timeout=3)
    c2.request('GET', '/')
    r2 = c2.getresponse().read().decode().strip()
print('AFTER:' + r2 + ':' + ','.join(udp_aborted), flush=True)
"""
        live_proc = subprocess.Popen(
            ["nsenter", "-t", str(cli_proc.pid), "-m", "-n", sys.executable, "-c", pre_sock_code],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        first_line = live_proc.stdout.readline().strip()
        assert first_line.startswith("BEFORE:SRC=10.99.0.2:"), f"Expected initial VPN keep-alive, got: {first_line}"
        inner_pid = int(first_line.split(":")[-1])
        # Test idempotent UpdateSplitTunnel + ResetAppSockets on moved PID!
        upd_resp = ipc_call(sock_path, {
            "op": "update_split_tunnel",
            "data": {
                "mode": "bypass",
                "apps": ["python3"],
                "bypass_apps": ["python3"],
                "only_vpn_apps": [],
                "cgroup_paths": [cg_rel_bypass],
                "game_only_cidrs": [],
            },
        })
        assert upd_resp["status"] == "status", upd_resp
        rst_resp = ipc_call(sock_path, {"op": "reset_app_sockets", "data": {"pids": [inner_pid]}})
        assert rst_resp["status"] == "ok", rst_resp
        live_proc.stdin.write("go\n")
        live_proc.stdin.flush()
        second_line = live_proc.stdout.readline().strip()
        live_proc.wait(timeout=4)
        assert second_line == "AFTER:SRC=192.0.2.2:u4=ABORTED,u6=ABORTED", (
            f"Expected ISP bypass + aborted QUIC UDP/UDP6 after ResetAppSockets, got: {second_line} stderr={live_proc.stderr.read()}"
        )
        # Verify another unmoved VPN request still works cleanly over 10.99.0.2!
        r_still_vpn = ns_exec("import urllib.request; print(urllib.request.urlopen('http://198.51.100.1:8080', timeout=3).read().decode())")
        assert r_still_vpn.stdout.strip() == "SRC=10.99.0.2", f"Unmoved traffic broke: {r_still_vpn.stdout} {r_still_vpn.stderr}"
        print(f"      PASS: Running PID shifted {first_line} -> {second_line}; default VPN traffic stayed intact")

        # TEST 6: Killswitch Collapse Check (abruptly delete hadal-wg; verify traffic is blocked!)
        print("[6/6] Testing killswitch under abrupt tunnel collapse...")
        subprocess.run(["nsenter", "-t", str(cli_proc.pid), "-n", "ip", "link", "del", "hadal-wg"], check=True)
        st_drop = ipc_call(sock_path, {"op": "status"})["data"]
        assert st_drop["state"] == "killswitch_locked", f"Expected killswitch_locked, got: {st_drop}"
        r_ks = ns_exec("""
import urllib.request
try:
    urllib.request.urlopen('http://198.51.100.1:8080', timeout=1)
    print('LEAKED')
except Exception as e:
    print('BLOCKED:', type(e).__name__)
""")
        assert "BLOCKED:" in r_ks.stdout, f"Killswitch failed! Output: {r_ks.stdout}"
        # Verify PrepareEndpoint + Connect can recover directly out of killswitch_locked
        prep = ipc_call(sock_path, {"op": "prepare_endpoint", "data": {"domain": "192.0.2.1", "discover_pmtu": False}})
        assert prep["status"] == "prepared" and prep["data"]["endpoint_ip"] == "192.0.2.1", prep
        reconn = ipc_call(sock_path, connect_req)
        assert reconn["status"] == "status" and reconn["data"]["state"] == "protected", reconn
        r_reconn = ns_exec("import urllib.request; print(urllib.request.urlopen('http://198.51.100.1:8080', timeout=3).read().decode())")
        assert r_reconn.stdout.strip() == "SRC=10.99.0.2", f"Reconnect traffic failed: {r_reconn.stdout} {r_reconn.stderr}"
        print(f"      PASS: State={st_drop['state']}, post-drop traffic {r_ks.stdout.strip()}, and reconnect from KillswitchLocked restored SRC=10.99.0.2")

        # Clean shutdown via IPC
        ipc_call(sock_path, {"op": "disconnect", "data": {"keep_killswitch": False}})
        ipc_call(sock_path, {"op": "shutdown"})
        hadald_proc.wait(timeout=5)

        # Signal sniffer to dump captured packet audit
        srv_stop.write_text("stop")
        srv_proc.wait(timeout=5)
        cli_done.write_text("done")
        cli_proc.wait(timeout=5)

        sniff = json.loads(sniff_json.read_text())
        print(f"[AUDIT] Wire sniffer summary: {sniff}")
        assert sniff["wg_udp"] > 0, "Expected WireGuard UDP packets on wire"
        assert sniff["bypass_http"] > 0, "Expected split-tunnel bypassed HTTP packets on wire"
        assert len(sniff["non_wg_v4"]) == 0, f"UNEXPECTED IPv4 LEAK PACKETS: {sniff['non_wg_v4']}"
        assert len(sniff["rogue_dns"]) == 0, f"UNEXPECTED DNS LEAK PACKETS: {sniff['rogue_dns']}"
        assert len(sniff["ipv6_leaks"]) == 0, f"UNEXPECTED IPv6 LEAK PACKETS: {sniff['ipv6_leaks']}"
        print("ALL 6 REAL-KERNEL NETNS LEAK & SPLIT-TUNNEL TESTS PASSED WITH 0 LEAKS!")

    finally:
        for p in (srv_proc, cli_proc):
            if p and p.poll() is None:
                p.kill()
                p.wait()
        try:
            if cg_full_bypass.exists():
                cg_full_bypass.rmdir()
        except OSError:
            pass
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    main()
