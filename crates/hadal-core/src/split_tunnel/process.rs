use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use sysinfo::System;

use crate::error::{Result, HadalError};
use crate::split_tunnel::desktop::app_aliases;

/// Lightweight, OS-independent view of a running process for deterministic matching tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessSnapshot {
    pub pid: u32,
    pub name: String,
    pub exe: Option<PathBuf>,
    pub cmd: Vec<String>,
    pub is_thread: bool,
}

/// Process enumeration and executable lookup seam.
pub trait ProcessInspector: Send + Sync {
    fn self_pid(&self) -> u32;
    fn list_processes(&self) -> Vec<ProcessSnapshot>;
    fn resolve_binary(&self, app: &str) -> Result<String>;
}

/// Production [`ProcessInspector`] backed by `sysinfo` and `which`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SysinfoProcessInspector;

impl ProcessInspector for SysinfoProcessInspector {
    fn self_pid(&self) -> u32 {
        std::process::id()
    }

    fn list_processes(&self) -> Vec<ProcessSnapshot> {
        let sys = System::new_all();
        sys.processes()
            .iter()
            .map(|(pid, proc_info)| ProcessSnapshot {
                pid: pid.as_u32(),
                name: proc_info.name().to_string_lossy().into_owned(),
                exe: proc_info.exe().map(Path::to_path_buf),
                cmd: proc_info
                    .cmd()
                    .iter()
                    .map(|s| s.to_string_lossy().into_owned())
                    .collect(),
                is_thread: proc_info.thread_kind().is_some(),
            })
            .collect()
    }

    fn resolve_binary(&self, app: &str) -> Result<String> {
        resolve_app_binary(app)
    }
}

fn path_file_name_lower(path: &Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase()
}

pub fn find_matching_pids_by_aliases(
    processes: &[ProcessSnapshot],
    aliases: &[String],
    self_pid: u32,
) -> Vec<u32> {
    let mut out = HashSet::new();
    for proc_info in processes {
        if proc_info.pid == self_pid || proc_info.pid <= 1 || proc_info.is_thread {
            continue;
        }
        if process_matches(aliases, proc_info) {
            out.insert(proc_info.pid);
        }
    }
    let mut list: Vec<u32> = out.into_iter().collect();
    list.sort_unstable();
    list
}

pub fn process_matches(aliases: &[String], proc_info: &ProcessSnapshot) -> bool {
    let name = proc_info.name.to_lowercase();
    let exe = proc_info
        .exe
        .as_deref()
        .map(|p| p.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let exe_base = proc_info
        .exe
        .as_deref()
        .map(path_file_name_lower)
        .unwrap_or_default();
    let cmd0 = proc_info
        .cmd
        .first()
        .map(|s| s.to_lowercase())
        .unwrap_or_default();
    let cmd0_base = path_file_name_lower(Path::new(&cmd0));
    let is_flatpak = cmd0_base == "flatpak" || cmd0_base.starts_with("flatpak-");

    aliases.iter().any(|alias| {
        let a = alias.to_lowercase();
        if a.is_empty() {
            return false;
        }
        name == a
            || exe_base == a
            || exe == a
            || cmd0_base == a
            || (is_flatpak
                && proc_info
                    .cmd
                    .iter()
                    .skip(1)
                    .any(|tok| tok.eq_ignore_ascii_case(&a)))
    })
}

pub fn resolve_app_binary(app: &str) -> Result<String> {
    let trimmed = app.trim();
    if trimmed.is_empty() {
        return Err(HadalError::Custom("Empty application name".into()));
    }
    if Path::new(trimmed).is_file() {
        return Ok(trimmed.to_string());
    }
    for alias in app_aliases(trimmed) {
        if alias.starts_with('/') && Path::new(&alias).exists() {
            return Ok(alias);
        }
        if let Ok(out) = Command::new("which").arg(&alias).output() {
            if out.status.success() {
                let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if !path.is_empty() {
                    return Ok(path);
                }
            }
        }
    }
    Err(HadalError::Custom(format!(
        "Executable for '{app}' not found on PATH"
    )))
}
