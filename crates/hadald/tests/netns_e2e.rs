//! Real-kernel network-namespace leak & split-tunnel end-to-end harness for `hadald`.
//!
//! Runs `scripts/netns_harness.py` inside unprivileged `unshare -Ur` user/net/mount namespaces.
//! Prerequisites: `python3`, `openssl`, `nft`, `ip` (`iproute2`), `cgroup2` in `/proc/filesystems`,
//! unprivileged user namespaces (`unshare -Urn`), and kernel `wireguard` netlink support.
//!
//! Environment gating:
//! - `HADAL_SKIP_NETNS_E2E=1`: skip cleanly without running the harness (overridden by `HADAL_REQUIRE_NETNS_E2E=1`).
//! - `HADAL_REQUIRE_NETNS_E2E=1`: fail instead of skipping when host prerequisites are missing.

use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;

use clap::Parser;
use ipnet::IpNet;
use wireguard_control::{Backend, DeviceUpdate, InterfaceName, Key, PeerConfigBuilder};

#[allow(dead_code)]
#[path = "../src/net/wireguard.rs"]
mod wg_net;

const TEST_NAME: &str = "netns_leak_and_split_tunnel_e2e";
const HARNESS_PASS_BANNER: &str = "ALL 6 REAL-KERNEL NETNS LEAK & SPLIT-TUNNEL TESTS PASSED WITH 0 LEAKS!";

#[derive(Parser)]
struct PeerArgs {
    #[arg(long)]
    iface: String,
    #[arg(long)]
    address: String,
    #[arg(long)]
    listen_port: u16,
    #[arg(long)]
    priv_key: String,
    #[arg(long)]
    peer_pub_key: String,
    #[arg(long)]
    allowed_ips: String,
}

fn run_wg_peer_helper() -> Result<(), Box<dyn std::error::Error>> {
    let args = PeerArgs::parse();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let handle = wg_net::netlink_handle().await?;
        let _ = wg_net::ensure_wg_interface(&handle, &args.iface, &args.address, 1412).await?;
        Ok::<(), hadal_core::HadalError>(())
    })?;

    let iface_name = InterfaceName::from_str(&args.iface)?;
    let priv_key = Key::from_base64(args.priv_key.trim())?;
    let pub_key = Key::from_base64(args.peer_pub_key.trim())?;
    let net: IpNet = args.allowed_ips.parse()?;

    DeviceUpdate::new()
        .set_private_key(priv_key)
        .set_listen_port(args.listen_port)
        .replace_peers()
        .add_peer(
            PeerConfigBuilder::new(&pub_key)
                .replace_allowed_ips()
                .add_allowed_ip(net.addr(), net.prefix_len()),
        )
        .apply(&iface_name, Backend::Kernel)?;

    Ok(())
}

struct FilterArgs {
    list_only: bool,
    only_ignored: bool,
    exact: bool,
    filters: Vec<String>,
    skips: Vec<String>,
}

fn parse_libtest_args(args: &[String]) -> FilterArgs {
    let mut parsed = FilterArgs {
        list_only: false,
        only_ignored: false,
        exact: false,
        filters: Vec::new(),
        skips: Vec::new(),
    };
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--list" => parsed.list_only = true,
            "--ignored" => parsed.only_ignored = true,
            "--include-ignored" => parsed.only_ignored = false,
            "--exact" => parsed.exact = true,
            "--skip" => {
                if let Some(pat) = iter.next() {
                    parsed.skips.push(pat.clone());
                }
            }
            "--format" | "--color" | "--logfile" | "--test-threads" => {
                let _ = iter.next();
            }
            a if a.starts_with("--skip=") => {
                parsed.skips.push(a.trim_start_matches("--skip=").to_string());
            }
            a if a.starts_with('-') => {}
            positional => parsed.filters.push(positional.to_string()),
        }
    }
    parsed
}

fn test_selected(args: &FilterArgs) -> bool {
    if args.only_ignored {
        return false;
    }
    let matches_pat = |pat: &str| {
        if args.exact {
            TEST_NAME == pat
        } else {
            TEST_NAME.contains(pat)
        }
    };
    if !args.filters.is_empty() && !args.filters.iter().any(|f| matches_pat(f)) {
        return false;
    }
    if args.skips.iter().any(|s| matches_pat(s)) {
        return false;
    }
    true
}

fn env_truthy(key: &str) -> bool {
    std::env::var(key)
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

fn detect_prereq_gap() -> Option<String> {
    let filesystems = std::fs::read_to_string("/proc/filesystems").unwrap_or_default();
    if !filesystems.contains("cgroup2") {
        return Some("kernel does not expose cgroup2 in /proc/filesystems".into());
    }

    for (bin, probe_args) in [
        ("python3", &["--version"][..]),
        ("openssl", &["version"][..]),
        ("nft", &["--version"][..]),
        ("ip", &["-V"][..]),
    ] {
        match Command::new(bin).args(probe_args).output() {
            Ok(out) if out.status.success() => {}
            Ok(out) => {
                return Some(format!(
                    "`{bin}` preflight failed (exit={:?})",
                    out.status.code()
                ));
            }
            Err(err) => return Some(format!("missing `{bin}`: {err}")),
        }
    }

    match Command::new("unshare")
        .args([
            "-Urn",
            "sh",
            "-c",
            "ip link add _hadal_wg_chk type wireguard && ip link del _hadal_wg_chk",
        ])
        .output()
    {
        Ok(out) if out.status.success() => None,
        Ok(out) => Some(format!(
            "unprivileged user/netns WireGuard probe failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )),
        Err(err) => Some(format!("failed to invoke `unshare`: {err}")),
    }
}

fn main() {
    if std::env::var_os("HADAL_WG_PEER_HELPER").is_some() {
        if let Err(err) = run_wg_peer_helper() {
            eprintln!("wg peer setup failed: {err}");
            std::process::exit(1);
        }
        return;
    }

    let raw_args: Vec<String> = std::env::args().skip(1).collect();
    let parsed = parse_libtest_args(&raw_args);
    let selected = test_selected(&parsed);

    if parsed.list_only {
        if selected {
            println!("{TEST_NAME}: test");
        }
        return;
    }

    if !selected {
        println!("\nrunning 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out\n");
        return;
    }

    let require_e2e = env_truthy("HADAL_REQUIRE_NETNS_E2E");
    if env_truthy("HADAL_SKIP_NETNS_E2E") && !require_e2e {
        println!("\nrunning 1 test");
        println!("test {TEST_NAME} ... ignored, HADAL_SKIP_NETNS_E2E is set");
        println!("\ntest result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out\n");
        return;
    }

    if let Some(gap) = detect_prereq_gap() {
        assert!(
            !require_e2e,
            "HADAL_REQUIRE_NETNS_E2E=1 but host prerequisites are missing: {gap}"
        );
        eprintln!("Skipping {TEST_NAME}: {gap} (set HADAL_REQUIRE_NETNS_E2E=1 to fail instead)");
        println!("\nrunning 1 test");
        println!("test {TEST_NAME} ... ignored, {gap}");
        println!("\ntest result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out\n");
        return;
    }

    let hadald_bin = PathBuf::from(env!("CARGO_BIN_EXE_hadald"));
    let self_exe = std::env::current_exe().expect("Failed to locate current test executable");
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let harness = manifest_dir.join("../../scripts/netns_harness.py");
    assert!(
        harness.exists(),
        "Missing netns harness at {}",
        harness.display()
    );

    println!("\nrunning 1 test");
    let out = Command::new("python3")
        .arg(&harness)
        .env("HADALD_BIN", &hadald_bin)
        .env("HADAL_WG_PEER_BIN", &self_exe)
        .env("HADAL_WG_PEER_HELPER", "1")
        .output()
        .expect("Failed to invoke python3 scripts/netns_harness.py");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "Real-kernel netns leak E2E harness failed (exit={:?}):\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
        out.status.code()
    );
    assert!(
        stdout.contains(HARNESS_PASS_BANNER),
        "netns harness exited 0 without printing completion banner `{HARNESS_PASS_BANNER}`:\n{stdout}"
    );

    print!("{stdout}");
    println!("test {TEST_NAME} ... ok");
    println!("\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n");
}
