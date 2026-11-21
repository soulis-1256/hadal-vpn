use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::error::{Result, HadalError};

pub const TRACKED_LEAF_CGROUP: &str = "tracked";

/// Parse the unified cgroupv2 path (`0::<rel>`) from `/proc/<pid>/cgroup`.
pub fn parse_self_cgroup_v2(proc_cgroup: &str) -> Option<String> {
    for line in proc_cgroup.lines() {
        if let Some(rest) = line.strip_prefix("0::") {
            let trimmed = rest.trim().trim_start_matches('/');
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

/// Derive the user session's sibling `app.slice/<slice_name>` cgroupv2 path from `self_rel`.
pub fn derive_slice_rel_path(self_rel: &str, slice_name: &str) -> String {
    if let Some(pos) = self_rel.find("app.slice") {
        let prefix = &self_rel[..pos + "app.slice".len()];
        return format!("{prefix}/{slice_name}");
    }
    if let Some(pos) = self_rel.find(".service/") {
        let prefix = &self_rel[..pos + ".service".len()];
        return format!("{prefix}/app.slice/{slice_name}");
    }
    let parts: Vec<&str> = self_rel.split('/').filter(|p| !p.is_empty()).collect();
    if parts.len() >= 2 && parts[0] == "user.slice" {
        return format!("{}/{}/app.slice/{slice_name}", parts[0], parts[1]);
    }
    slice_name.to_string()
}

/// Return `true` only when `rel` is already inside a leaf/scope child cgroup under `slice_name`
/// (not directly in the `slice_name` root, which would block `systemd-run --scope`).
pub fn is_in_slice_child_cgroup(rel: &str, slice_name: &str) -> bool {
    let trimmed = rel.trim().trim_end_matches('/');
    trimmed
        .split('/')
        .collect::<Vec<_>>()
        .windows(2)
        .any(|w| w[0] == slice_name && !w[1].is_empty())
}

/// Cgroupv2 slice inspection and process-migration seam.
pub trait CgroupManager: Send + Sync {
    fn resolve_user_slice_path(&self, slice_name: &str) -> Option<String>;
    fn ensure_user_slice_dir(&self, slice_name: &str) -> Option<String>;
    fn ensure_slice_tracked_procs(&self, slice_name: &str) -> Option<PathBuf>;
    fn collect_slice_pids(&self, slice_rel: &str) -> Vec<u32>;
    fn pid_cgroup_v2(&self, pid: u32) -> Option<String>;
    fn move_pid_to_procs_file(&self, procs_file: &Path, pid: u32) -> bool;
    fn launch_in_slice(&self, cmd_tokens: &[String], slice_name: &str) -> Result<u32>;
}

/// Production [`CgroupManager`] operating on `/sys/fs/cgroup`, `/proc`, and `systemd-run --user`.
#[derive(Debug, Clone)]
pub struct SystemdCgroupManager {
    cgroup_root: PathBuf,
    proc_root: PathBuf,
}

impl SystemdCgroupManager {
    pub fn system() -> Self {
        Self {
            cgroup_root: PathBuf::from("/sys/fs/cgroup"),
            proc_root: PathBuf::from("/proc"),
        }
    }

    pub fn with_roots(cgroup_root: impl Into<PathBuf>, proc_root: impl Into<PathBuf>) -> Self {
        Self {
            cgroup_root: cgroup_root.into(),
            proc_root: proc_root.into(),
        }
    }
}

impl Default for SystemdCgroupManager {
    fn default() -> Self {
        Self::system()
    }
}

impl CgroupManager for SystemdCgroupManager {
    fn resolve_user_slice_path(&self, slice_name: &str) -> Option<String> {
        let self_cg = std::fs::read_to_string(self.proc_root.join("self/cgroup")).ok()?;
        let rel = parse_self_cgroup_v2(&self_cg)?;
        Some(derive_slice_rel_path(&rel, slice_name))
    }

    fn ensure_user_slice_dir(&self, slice_name: &str) -> Option<String> {
        let rel = self.resolve_user_slice_path(slice_name)?;
        let full = self.cgroup_root.join(&rel);
        if !full.exists() {
            let _ = std::fs::create_dir_all(&full);
            if !full.exists() {
                let unit = format!("hadal-init-{}", slice_name.trim_end_matches(".slice"));
                let _ = Command::new("systemd-run")
                    .args([
                        "--user",
                        "--scope",
                        "--unit",
                        &unit,
                        "--slice",
                        slice_name,
                        "--quiet",
                        "/bin/true",
                    ])
                    .status();
            }
        }
        full.exists().then_some(rel)
    }

    /// Return `<slice>/tracked/cgroup.procs` so migrated PIDs never live directly in the slice root
    /// (which would violate cgroupv2's no-internal-processes rule and break `systemd-run --scope`).
    fn ensure_slice_tracked_procs(&self, slice_name: &str) -> Option<PathBuf> {
        let rel = self.ensure_user_slice_dir(slice_name)?;
        let leaf = self.cgroup_root.join(&rel).join(TRACKED_LEAF_CGROUP);
        if !leaf.exists() {
            let _ = std::fs::create_dir_all(&leaf);
        }
        leaf.exists().then(|| leaf.join("cgroup.procs"))
    }

    fn collect_slice_pids(&self, slice_rel: &str) -> Vec<u32> {
        let slice_dir = self.cgroup_root.join(slice_rel);
        let mut pids = Vec::new();
        let mut read_procs_file = |path: &Path| {
            if let Ok(raw) = std::fs::read_to_string(path) {
                for line in raw.lines() {
                    if let Ok(pid) = line.trim().parse::<u32>() {
                        pids.push(pid);
                    }
                }
            }
        };
        read_procs_file(&slice_dir.join("cgroup.procs"));
        if let Ok(entries) = std::fs::read_dir(&slice_dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    read_procs_file(&p.join("cgroup.procs"));
                }
            }
        }
        pids
    }

    fn pid_cgroup_v2(&self, pid: u32) -> Option<String> {
        let raw =
            std::fs::read_to_string(self.proc_root.join(pid.to_string()).join("cgroup")).ok()?;
        parse_self_cgroup_v2(&raw)
    }

    fn move_pid_to_procs_file(&self, procs_file: &Path, pid: u32) -> bool {
        std::fs::write(procs_file, pid.to_string()).is_ok()
    }

    fn launch_in_slice(&self, cmd_tokens: &[String], slice_name: &str) -> Result<u32> {
        let _ = self.ensure_user_slice_dir(slice_name);

        let mut cmd = Command::new("systemd-run");
        cmd.args(["--user", "--scope", "--slice", slice_name, "--quiet", "--"])
            .args(cmd_tokens)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        #[cfg(unix)]
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }

        let child = cmd.spawn().map_err(|e| {
            HadalError::Custom(format!(
                "Failed to launch {} in {slice_name}: {e}",
                cmd_tokens.first().map(String::as_str).unwrap_or("app")
            ))
        })?;
        Ok(child.id())
    }
}

/// Detect the user session's systemd `app.slice` cgroupv2 path (relative to `/sys/fs/cgroup`),
/// returning the child slice path for `slice_name` (e.g. `user.slice/user-1000.slice/user@1000.service/app.slice/app-hadal_bypass.slice`).
pub fn resolve_user_slice_cgroup_path(slice_name: &str) -> Option<String> {
    SystemdCgroupManager::system().resolve_user_slice_path(slice_name)
}

/// Ensure the leaf cgroupv2 slice directory exists before `nft` compiles a `socket cgroupv2` rule.
pub fn ensure_user_slice_dir(slice_name: &str) -> Option<String> {
    SystemdCgroupManager::system().ensure_user_slice_dir(slice_name)
}
