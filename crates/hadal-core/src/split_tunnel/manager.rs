use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

use crate::error::Result;
use crate::split_tunnel::cgroup::{is_in_slice_child_cgroup, CgroupManager, SystemdCgroupManager};
use crate::split_tunnel::desktop::{
    aliases_for_entry, find_desktop_entry, resolve_aliases_with_entries, split_exec_tokens,
    AppCatalog, DesktopAppEntry, XdgAppCatalog,
};
use crate::split_tunnel::policy::{
    active_slice_for_mode, SplitAppStatus, SplitMode, BYPASS_SLICE, DEFAULT_SLICE, VPN_SLICE,
};
use crate::split_tunnel::process::{
    find_matching_pids_by_aliases, ProcessInspector, ProcessSnapshot, SysinfoProcessInspector,
};

/// Orchestrates app discovery, process matching, and cgroupv2 slice reconciliation using injected seams.
#[derive(Clone)]
pub struct SplitTunnelManager {
    processes: Arc<dyn ProcessInspector>,
    catalog: Arc<dyn AppCatalog>,
    cgroups: Arc<dyn CgroupManager>,
}

impl SplitTunnelManager {
    pub fn new(
        processes: Arc<dyn ProcessInspector>,
        catalog: Arc<dyn AppCatalog>,
        cgroups: Arc<dyn CgroupManager>,
    ) -> Self {
        Self {
            processes,
            catalog,
            cgroups,
        }
    }

    pub fn system() -> Self {
        Self::new(
            Arc::new(SysinfoProcessInspector),
            Arc::new(XdgAppCatalog::system()),
            Arc::new(SystemdCgroupManager::system()),
        )
    }

    /// Scan desktop entries and mark which ones currently have running processes.
    pub fn discover_desktop_apps(&self) -> Vec<DesktopAppEntry> {
        let processes = self.processes.list_processes();
        let self_pid = self.processes.self_pid();
        let mut entries = self.catalog.list_entries();

        for entry in &mut entries {
            let aliases = aliases_for_entry(entry);
            entry.running =
                !find_matching_pids_by_aliases(&processes, &aliases, self_pid).is_empty();
        }

        entries.sort_by(|a, b| {
            b.running
                .cmp(&a.running)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        entries
    }

    pub fn find_app_pids(&self, app: &str) -> Vec<u32> {
        let processes = self.processes.list_processes();
        let entries = self.catalog.list_entries();
        self.find_pids_with_snapshot(&processes, &entries, app)
    }

    fn find_pids_with_snapshot(
        &self,
        processes: &[ProcessSnapshot],
        entries: &[DesktopAppEntry],
        app: &str,
    ) -> Vec<u32> {
        let aliases = resolve_aliases_with_entries(app, entries);
        find_matching_pids_by_aliases(processes, &aliases, self.processes.self_pid())
    }

    /// Launch a desktop app or binary inside the designated cgroupv2 slice so `hadald`
    /// routes all its TCP/UDP/ICMP sockets via `nftables socket cgroupv2` rules.
    pub fn launch_app_in_slice(&self, app: &str, slice_name: &str) -> Result<u32> {
        let entries = self.catalog.list_entries();
        let cmd_tokens: Vec<String> = if let Some(entry) = find_desktop_entry(&entries, app) {
            let tokens = split_exec_tokens(&entry.exec);
            if tokens.is_empty() {
                vec![self.processes.resolve_binary(app)?]
            } else {
                tokens
            }
        } else {
            vec![self.processes.resolve_binary(app)?]
        };
        self.cgroups.launch_in_slice(&cmd_tokens, slice_name)
    }

    /// Move all running PIDs matching `app` into the target cgroupv2 slice's leaf cgroup,
    /// returning the list of moved PIDs.
    pub fn move_app_to_slice_pids(&self, app: &str, slice_name: &str) -> Result<Vec<u32>> {
        let procs_file = self
            .cgroups
            .ensure_slice_tracked_procs(slice_name)
            .ok_or_else(|| {
                crate::error::HadalError::Custom(format!(
                    "Could not prepare cgroupv2 directory for {slice_name}"
                ))
            })?;
        let pids = self.find_app_pids(app);
        let mut moved = Vec::new();
        for pid in pids {
            if self.cgroups.move_pid_to_procs_file(&procs_file, pid) {
                moved.push(pid);
            }
        }
        Ok(moved)
    }

    /// Move all running PIDs matching `app` into the target cgroupv2 slice's leaf cgroup.
    pub fn move_app_to_slice(&self, app: &str, slice_name: &str) -> Result<usize> {
        Ok(self.move_app_to_slice_pids(app, slice_name)?.len())
    }

    /// Reconcile split-tunnel slice membership:
    /// move newly tracked running PIDs into `<BYPASS_SLICE|VPN_SLICE>/tracked`, and restore any removed
    /// PIDs (or all PIDs when `SplitMode::Off`) back to `<DEFAULT_SLICE>/tracked`.
    /// Returns all PIDs whose cgroup changed so `hadald` can drop stale `sk->sk_cgrp_data` sockets.
    pub fn reconcile_split_slices(&self, apps: &[String], mode: SplitMode) -> Vec<u32> {
        let processes = self.processes.list_processes();
        let entries = self.catalog.list_entries();
        let target_slice = active_slice_for_mode(mode);

        let mut desired_pids: HashSet<u32> = HashSet::new();
        if target_slice.is_some() {
            for app in apps {
                for pid in self.find_pids_with_snapshot(&processes, &entries, app) {
                    desired_pids.insert(pid);
                }
            }
        }

        let mut moved: HashSet<u32> = HashSet::new();
        let default_procs = self.cgroups.ensure_slice_tracked_procs(DEFAULT_SLICE);

        if let Some(ref def_procs) = default_procs {
            // Drain inactive split slices back to DEFAULT_SLICE
            for slice in [BYPASS_SLICE, VPN_SLICE] {
                if Some(slice) == target_slice {
                    continue;
                }
                if let Some(rel) = self.cgroups.resolve_user_slice_path(slice) {
                    self.move_pids_matching(&rel, def_procs, |_| true, &mut moved);
                }
            }

            // Restore removed apps still inside the currently active slice
            if let Some(target) = target_slice {
                if let Some(target_rel) = self.cgroups.resolve_user_slice_path(target) {
                    self.move_pids_matching(
                        &target_rel,
                        def_procs,
                        |pid| !desired_pids.contains(&pid),
                        &mut moved,
                    );
                }
            }
        }

        // Move tracked running PIDs into `<target_slice>/tracked`
        if let Some(slice_name) = target_slice {
            if let Some(procs_file) = self.cgroups.ensure_slice_tracked_procs(slice_name) {
                for pid in desired_pids {
                    let already_in_child = self
                        .cgroups
                        .pid_cgroup_v2(pid)
                        .is_some_and(|rel| is_in_slice_child_cgroup(&rel, slice_name));
                    if !already_in_child && self.cgroups.move_pid_to_procs_file(&procs_file, pid) {
                        moved.insert(pid);
                    }
                }
            }
        }

        let mut out: Vec<u32> = moved.into_iter().collect();
        out.sort_unstable();
        out
    }

    fn move_pids_matching(
        &self,
        slice_rel: &str,
        dest_procs: &Path,
        predicate: impl Fn(u32) -> bool,
        moved: &mut HashSet<u32>,
    ) {
        for pid in self.cgroups.collect_slice_pids(slice_rel) {
            if predicate(pid) && self.cgroups.move_pid_to_procs_file(dest_procs, pid) {
                moved.insert(pid);
            }
        }
    }

    pub fn app_statuses(
        &self,
        apps: &[String],
        expected_slice: Option<&str>,
    ) -> Vec<SplitAppStatus> {
        let processes = self.processes.list_processes();
        let entries = self.catalog.list_entries();

        apps.iter()
            .map(|app| {
                let display_name = find_desktop_entry(&entries, app)
                    .map(|e| e.name.clone())
                    .unwrap_or_else(|| app.clone());
                let pids = self.find_pids_with_snapshot(&processes, &entries, app);
                let mut active_slice = None;
                let mut in_expected = false;

                for &pid in &pids {
                    if let Some(rel) = self.cgroups.pid_cgroup_v2(pid) {
                        if rel.contains(BYPASS_SLICE) {
                            active_slice = Some(BYPASS_SLICE.to_string());
                        } else if rel.contains(VPN_SLICE) {
                            active_slice = Some(VPN_SLICE.to_string());
                        }
                        if expected_slice.is_some_and(|exp| rel.contains(exp)) {
                            in_expected = true;
                        }
                    }
                }

                SplitAppStatus {
                    name: app.clone(),
                    display_name,
                    running: !pids.is_empty(),
                    in_split_slice: in_expected,
                    slice: active_slice,
                    pids,
                }
            })
            .collect()
    }
}

impl Default for SplitTunnelManager {
    fn default() -> Self {
        Self::system()
    }
}

/// Scan standard XDG `.desktop` directories (DE/compositor-agnostic) and mark currently running apps.
pub fn discover_desktop_apps() -> Vec<DesktopAppEntry> {
    SplitTunnelManager::system().discover_desktop_apps()
}

/// Launch a desktop app or binary inside the designated cgroupv2 slice so `hadald`
/// routes all its TCP/UDP/ICMP sockets via `nftables socket cgroupv2` rules.
pub fn launch_app_in_slice(app: &str, slice_name: &str) -> Result<u32> {
    SplitTunnelManager::system().launch_app_in_slice(app, slice_name)
}

/// Move all running PIDs matching `app` into the target cgroupv2 slice's leaf cgroup.
pub fn move_app_to_slice(app: &str, slice_name: &str) -> Result<usize> {
    SplitTunnelManager::system().move_app_to_slice(app, slice_name)
}

pub fn reconcile_split_slices(apps: &[String], mode: SplitMode) -> Vec<u32> {
    SplitTunnelManager::system().reconcile_split_slices(apps, mode)
}

pub fn app_statuses(apps: &[String], expected_slice: Option<&str>) -> Vec<SplitAppStatus> {
    SplitTunnelManager::system().app_statuses(apps, expected_slice)
}

pub fn find_app_pids(app: &str) -> Vec<u32> {
    SplitTunnelManager::system().find_app_pids(app)
}
