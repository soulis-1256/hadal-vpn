use std::process::Command;
use std::sync::Arc;

use hadal_core::split_tunnel::{CgroupManager, SplitTunnelManager};
use hadal_core::{active_slice_for_mode, Result, HadalError, SplitAppStatus, SplitMode};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceHop {
    Reached(String),
    Exceeded(String),
    Timeout,
}

/// System ICMP ping & TTL trace runner seam.
pub trait PingTool: Send + Sync {
    fn run_ping(&self, target: &str, count: u32) -> Result<()>;
    fn trace_hop(&self, target: &str, ttl: u8) -> Result<TraceHop>;
}

/// Production [`PingTool`] invoking `ping`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemPingTool;

impl PingTool for SystemPingTool {
    fn run_ping(&self, target: &str, count: u32) -> Result<()> {
        let status = Command::new("ping")
            .args(["-4", "-c", &count.to_string(), "-i", "0.2", target])
            .status()
            .map_err(|e| HadalError::Custom(format!("ping failed: {e}")))?;
        if !status.success() {
            return Err(HadalError::Custom(format!("ping exited with {status}")));
        }
        Ok(())
    }

    fn trace_hop(&self, target: &str, ttl: u8) -> Result<TraceHop> {
        let out = Command::new("ping")
            .args([
                "-4",
                "-n",
                "-c",
                "1",
                "-W",
                "1",
                "-t",
                &ttl.to_string(),
                target,
            ])
            .output()?;
        let txt = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        if let Some(line) = txt.lines().find(|l| l.contains("bytes from ")) {
            Ok(TraceHop::Reached(line.to_string()))
        } else if let Some(line) = txt.lines().find(|l| l.contains("Time to live exceeded")) {
            Ok(TraceHop::Exceeded(line.to_string()))
        } else {
            Ok(TraceHop::Timeout)
        }
    }
}

/// Split-tunnel slice and process management seam for CLI handlers.
pub trait SplitOps: Send + Sync {
    fn active_slice_cgroup_paths(&self, mode: SplitMode) -> Vec<String>;
    fn slice_cgroup_paths(&self, slice_name: &str) -> Vec<String>;
    fn launch_in_slice(&self, app: &str, slice_name: &str) -> Result<u32>;
    fn move_to_slice_pids(&self, app: &str, slice_name: &str) -> Result<Vec<u32>>;
    fn app_statuses(&self, apps: &[String], expected_slice: Option<&str>) -> Vec<SplitAppStatus>;
}

/// Production [`SplitOps`] backed by `hadal_core::split_tunnel`.
#[derive(Clone)]
pub struct CoreSplitOps {
    manager: SplitTunnelManager,
    cgroups: Arc<dyn CgroupManager>,
}

impl CoreSplitOps {
    pub fn new(manager: SplitTunnelManager, cgroups: Arc<dyn CgroupManager>) -> Self {
        Self { manager, cgroups }
    }

    pub fn system() -> Self {
        Self::new(
            SplitTunnelManager::system(),
            Arc::new(hadal_core::SystemdCgroupManager::system()),
        )
    }
}

impl Default for CoreSplitOps {
    fn default() -> Self {
        Self::system()
    }
}

impl SplitOps for CoreSplitOps {
    fn active_slice_cgroup_paths(&self, mode: SplitMode) -> Vec<String> {
        active_slice_for_mode(mode)
            .and_then(|slice| self.cgroups.ensure_user_slice_dir(slice))
            .into_iter()
            .collect()
    }

    fn slice_cgroup_paths(&self, slice_name: &str) -> Vec<String> {
        self.cgroups
            .ensure_user_slice_dir(slice_name)
            .into_iter()
            .collect()
    }

    fn launch_in_slice(&self, app: &str, slice_name: &str) -> Result<u32> {
        self.manager.launch_app_in_slice(app, slice_name)
    }

    fn move_to_slice_pids(&self, app: &str, slice_name: &str) -> Result<Vec<u32>> {
        self.manager.move_app_to_slice_pids(app, slice_name)
    }

    fn app_statuses(&self, apps: &[String], expected_slice: Option<&str>) -> Vec<SplitAppStatus> {
        self.manager.app_statuses(apps, expected_slice)
    }
}
