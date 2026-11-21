use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use hadal_core::split_tunnel::{
    derive_slice_rel_path, find_matching_pids_by_aliases, is_in_slice_child_cgroup,
    parse_desktop_file, parse_self_cgroup_v2, process_matches, resolve_aliases_with_entries,
    split_exec_tokens, AppCatalog, CgroupManager, DesktopAppEntry, ProcessInspector,
    ProcessSnapshot, SplitTunnelManager, SystemdCgroupManager, XdgAppCatalog, TRACKED_LEAF_CGROUP,
};
use hadal_core::{
    active_slice_for_mode, Result, HadalError, SplitMode, SplitTunnelConfig, BYPASS_SLICE,
    DEFAULT_SLICE, VPN_SLICE,
};

struct TempDir(PathBuf);

impl TempDir {
    fn new(prefix: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hadal-split-{prefix}-{nanos}-{}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct FakeProcesses {
    self_pid: u32,
    procs: Vec<ProcessSnapshot>,
    binaries: HashMap<String, String>,
}

impl ProcessInspector for FakeProcesses {
    fn self_pid(&self) -> u32 {
        self.self_pid
    }
    fn list_processes(&self) -> Vec<ProcessSnapshot> {
        self.procs.clone()
    }
    fn resolve_binary(&self, app: &str) -> Result<String> {
        self.binaries
            .get(app)
            .cloned()
            .ok_or_else(|| HadalError::Custom(format!("missing {app}")))
    }
}

struct FakeCatalog(Vec<DesktopAppEntry>);
impl AppCatalog for FakeCatalog {
    fn list_entries(&self) -> Vec<DesktopAppEntry> {
        self.0.clone()
    }
}

struct FakeCgroups {
    slice_pids: Mutex<HashMap<String, Vec<u32>>>,
    pid_cgroups: Mutex<HashMap<u32, String>>,
    moves: Mutex<Vec<(PathBuf, u32)>>,
    launches: Mutex<Vec<(Vec<String>, String)>>,
}

impl FakeCgroups {
    fn new() -> Self {
        Self {
            slice_pids: Mutex::new(HashMap::new()),
            pid_cgroups: Mutex::new(HashMap::new()),
            moves: Mutex::new(Vec::new()),
            launches: Mutex::new(Vec::new()),
        }
    }

    fn slice_rel(slice: &str) -> String {
        format!("user.slice/user-1000.slice/user@1000.service/app.slice/{slice}")
    }
}

impl CgroupManager for FakeCgroups {
    fn resolve_user_slice_path(&self, slice_name: &str) -> Option<String> {
        Some(Self::slice_rel(slice_name))
    }

    fn ensure_user_slice_dir(&self, slice_name: &str) -> Option<String> {
        Some(Self::slice_rel(slice_name))
    }

    fn ensure_slice_tracked_procs(&self, slice_name: &str) -> Option<PathBuf> {
        Some(
            PathBuf::from("/fake/cgroup")
                .join(Self::slice_rel(slice_name))
                .join(TRACKED_LEAF_CGROUP)
                .join("cgroup.procs"),
        )
    }

    fn collect_slice_pids(&self, slice_rel: &str) -> Vec<u32> {
        self.slice_pids
            .lock()
            .unwrap()
            .get(slice_rel)
            .cloned()
            .unwrap_or_default()
    }

    fn pid_cgroup_v2(&self, pid: u32) -> Option<String> {
        self.pid_cgroups.lock().unwrap().get(&pid).cloned()
    }

    fn move_pid_to_procs_file(&self, procs_file: &Path, pid: u32) -> bool {
        self.moves.lock().unwrap().push((procs_file.to_path_buf(), pid));
        let path_str = procs_file.to_string_lossy();
        let target_rel = if path_str.contains(BYPASS_SLICE) {
            format!("{}/{TRACKED_LEAF_CGROUP}", Self::slice_rel(BYPASS_SLICE))
        } else if path_str.contains(VPN_SLICE) {
            format!("{}/{TRACKED_LEAF_CGROUP}", Self::slice_rel(VPN_SLICE))
        } else {
            format!("{}/{TRACKED_LEAF_CGROUP}", Self::slice_rel(DEFAULT_SLICE))
        };
        self.pid_cgroups.lock().unwrap().insert(pid, target_rel);
        true
    }

    fn launch_in_slice(&self, cmd_tokens: &[String], slice_name: &str) -> Result<u32> {
        self.launches
            .lock()
            .unwrap()
            .push((cmd_tokens.to_vec(), slice_name.to_string()));
        Ok(7777)
    }
}

#[test]
fn desktop_file_parsing_handles_quotes_escapes_tryexec_and_xdg_priority() {
    let tokens = split_exec_tokens(
        r#""/opt/My App/bin/app" --title="Hello \"World\"" %% %U %f"#,
    );
    assert_eq!(
        tokens,
        vec![
            "/opt/My App/bin/app",
            "--title=Hello \"World\"",
            "%",
        ]
    );

    let desktop = "\
[Desktop Entry]
Type=Application
Name=My Game
Exec=env FOO=bar \"/opt/My Game/launcher\" %u
TryExec=/opt/My Game/real-bin
Hidden=false
NoDisplay=false
";
    let entry = parse_desktop_file("my-game", desktop).unwrap();
    assert_eq!(entry.bin, "real-bin");
    assert_eq!(entry.exec, "env FOO=bar \"/opt/My Game/launcher\"");

    // Non-application & Hidden entries are skipped
    let link_only = "[Desktop Entry]\nType=Link\nName=Docs\nExec=/bin/true\n";
    assert!(parse_desktop_file("docs", link_only).is_none());
    let hidden = "[Desktop Entry]\nType=Application\nName=Hid\nExec=/bin/true\nHidden=true\n";
    assert!(parse_desktop_file("hid", hidden).is_none());

    // XdgAppCatalog deduplicates by lowercase stem, preferring earlier dir
    let dir1 = TempDir::new("xdg1");
    let dir2 = TempDir::new("xdg2");
    std::fs::write(
        dir1.path().join("Steam.desktop"),
        "[Desktop Entry]\nType=Application\nName=Steam Override\nExec=/usr/bin/steam\n",
    )
    .unwrap();
    std::fs::write(
        dir2.path().join("steam.desktop"),
        "[Desktop Entry]\nType=Application\nName=Steam System\nExec=/usr/bin/steam\n",
    )
    .unwrap();
    std::fs::write(dir2.path().join("ignore.txt"), "not a desktop file").unwrap();

    let catalog = XdgAppCatalog::from_dirs(vec![dir1.path().to_path_buf(), dir2.path().to_path_buf()]);
    let entries = catalog.list_entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "Steam Override");
}

#[test]
fn systemd_cgroup_manager_reads_mock_proc_and_cgroup_fs_roots() {
    let cg_root = TempDir::new("cg-root");
    let proc_root = TempDir::new("proc-root");

    std::fs::create_dir_all(proc_root.path().join("self")).unwrap();
    std::fs::write(
        proc_root.path().join("self/cgroup"),
        "0::/user.slice/user-1000.slice/user@1000.service/app.slice/kitty.scope\n",
    )
    .unwrap();
    std::fs::create_dir_all(proc_root.path().join("555")).unwrap();
    std::fs::write(
        proc_root.path().join("555/cgroup"),
        "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-hadal_bypass.slice/tracked\n",
    )
    .unwrap();

    let mgr = SystemdCgroupManager::with_roots(cg_root.path(), proc_root.path());
    let rel = mgr.resolve_user_slice_path(BYPASS_SLICE).unwrap();
    assert_eq!(
        rel,
        "user.slice/user-1000.slice/user@1000.service/app.slice/app-hadal_bypass.slice"
    );

    let procs_file = mgr.ensure_slice_tracked_procs(BYPASS_SLICE).unwrap();
    assert!(procs_file.parent().unwrap().exists());

    // Simulate moving PID 555 and a scope-launched PID 556 into root/child procs files
    assert!(mgr.move_pid_to_procs_file(&procs_file, 555));
    let scope_dir = cg_root.path().join(&rel).join("run-99.scope");
    std::fs::create_dir_all(&scope_dir).unwrap();
    std::fs::write(scope_dir.join("cgroup.procs"), "556\n").unwrap();

    let mut pids = mgr.collect_slice_pids(&rel);
    pids.sort_unstable();
    assert_eq!(pids, vec![555, 556]);
    assert!(is_in_slice_child_cgroup(
        &mgr.pid_cgroup_v2(555).unwrap(),
        BYPASS_SLICE
    ));

    // Additional cgroup path parsing edge cases
    assert_eq!(parse_self_cgroup_v2("1:name=systemd:/\n"), None);
    assert_eq!(
        derive_slice_rel_path("init.scope", VPN_SLICE),
        VPN_SLICE
    );
}

#[test]
fn process_matching_excludes_self_pid1_threads_and_matches_flatpak() {
    let entries = vec![DesktopAppEntry {
        id: "com.discordapp.Discord".into(),
        name: "Discord".into(),
        exec: "/usr/bin/flatpak run com.discordapp.Discord".into(),
        bin: "com.discordapp.Discord".into(),
        wm_class: Some("discord".into()),
        running: false,
    }];
    let aliases = resolve_aliases_with_entries("discord", &entries);
    assert!(aliases.iter().any(|a| a == "com.discordapp.Discord"));

    let procs = vec![
        ProcessSnapshot {
            pid: 1,
            name: "discord".into(),
            exe: None,
            cmd: vec![],
            is_thread: false,
        },
        ProcessSnapshot {
            pid: 999, // self_pid
            name: "discord".into(),
            exe: None,
            cmd: vec![],
            is_thread: false,
        },
        ProcessSnapshot {
            pid: 200,
            name: "discord".into(),
            exe: None,
            cmd: vec![],
            is_thread: true,
        },
        ProcessSnapshot {
            pid: 300,
            name: "flatpak-session".into(),
            exe: Some(PathBuf::from("/usr/bin/flatpak")),
            cmd: vec![
                "/usr/bin/flatpak".into(),
                "run".into(),
                "com.discordapp.Discord".into(),
            ],
            is_thread: false,
        },
        ProcessSnapshot {
            pid: 301,
            name: "Discord".into(),
            exe: Some(PathBuf::from("/opt/discord/Discord")),
            cmd: vec!["/opt/discord/Discord".into()],
            is_thread: false,
        },
    ];

    assert!(process_matches(&aliases, &procs[3]));
    let matched = find_matching_pids_by_aliases(&procs, &aliases, 999);
    assert_eq!(matched, vec![300, 301]);
}

#[test]
fn split_tunnel_manager_reconciles_slices_detects_statuses_and_launches() {
    let entries = vec![
        DesktopAppEntry {
            id: "steam".into(),
            name: "Steam".into(),
            exec: "/usr/bin/steam %U".into(),
            bin: "steam".into(),
            wm_class: None,
            running: false,
        },
        DesktopAppEntry {
            id: "firefox".into(),
            name: "Firefox".into(),
            exec: "/usr/bin/firefox %u".into(),
            bin: "firefox".into(),
            wm_class: Some("firefox".into()),
            running: false,
        },
    ];
    let procs = vec![
        ProcessSnapshot {
            pid: 101,
            name: "steam".into(),
            exe: Some(PathBuf::from("/usr/bin/steam")),
            cmd: vec!["/usr/bin/steam".into()],
            is_thread: false,
        },
        ProcessSnapshot {
            pid: 202,
            name: "firefox".into(),
            exe: Some(PathBuf::from("/usr/lib/firefox/firefox")),
            cmd: vec!["/usr/lib/firefox/firefox".into()],
            is_thread: false,
        },
    ];

    let cgroups = Arc::new(FakeCgroups::new());
    // Suppose PID 202 (firefox) was previously in BYPASS_SLICE, and PID 101 (steam) is in root slice
    cgroups.slice_pids.lock().unwrap().insert(
        FakeCgroups::slice_rel(BYPASS_SLICE),
        vec![202, 101],
    );
    cgroups.pid_cgroups.lock().unwrap().insert(
        101,
        FakeCgroups::slice_rel(BYPASS_SLICE), // directly in root, NOT child leaf
    );

    let mgr = SplitTunnelManager::new(
        Arc::new(FakeProcesses {
            self_pid: 9999,
            procs,
            binaries: HashMap::from([("custom".into(), "/usr/local/bin/custom".into())]),
        }),
        Arc::new(FakeCatalog(entries)),
        cgroups.clone(),
    );

    let discovered = mgr.discover_desktop_apps();
    assert_eq!(discovered.len(), 2);
    assert!(discovered.iter().all(|e| e.running));

    // Reconcile Bypass mode with only ["steam"]:
    // - PID 202 (removed firefox) must be drained back to DEFAULT_SLICE
    // - PID 101 (steam sitting in root slice) must be moved into BYPASS_SLICE/tracked
    let moved = mgr.reconcile_split_slices(&["steam".into()], SplitMode::Bypass);
    assert_eq!(moved, vec![101, 202]);

    // Check statuses for Bypass mode
    let statuses = mgr.app_statuses(&["steam".into(), "firefox".into()], Some(BYPASS_SLICE));
    assert!(statuses[0].running && statuses[0].in_split_slice);
    assert_eq!(statuses[0].slice.as_deref(), Some(BYPASS_SLICE));
    assert!(statuses[1].running && !statuses[1].in_split_slice);

    // Switch to SplitMode::OnlyVpn with ["firefox"]: drains BYPASS_SLICE (101 -> default) and moves 202 -> VPN_SLICE
    cgroups.slice_pids.lock().unwrap().insert(
        FakeCgroups::slice_rel(BYPASS_SLICE),
        vec![101],
    );
    let moved_only = mgr.reconcile_split_slices(&["firefox".into()], SplitMode::OnlyVpn);
    assert_eq!(moved_only, vec![101, 202]);

    // Launch desktop app strips %U and launches in VPN_SLICE
    let pid = mgr.launch_app_in_slice("steam", VPN_SLICE).unwrap();
    assert_eq!(pid, 7777);
    assert_eq!(
        cgroups.launches.lock().unwrap().as_slice(),
        &[(vec!["/usr/bin/steam".into()], VPN_SLICE.to_string())]
    );

    // SplitTunnelConfig helpers
    assert_eq!(active_slice_for_mode(SplitMode::Bypass), Some(BYPASS_SLICE));
    assert_eq!(active_slice_for_mode(SplitMode::OnlyVpn), Some(VPN_SLICE));
    assert_eq!(active_slice_for_mode(SplitMode::Off), None);
    let cfg = SplitTunnelConfig::default();
    assert_eq!(cfg.apps_for_mode(SplitMode::Off), &[] as &[String]);
}
