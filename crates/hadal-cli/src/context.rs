use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use hadal_core::{
    DaemonClient, DohTransport, FileSettingsStore, KeyPairGenerator, NetworkProber,
    OsKeyPairGenerator, ReqwestDohTransport, Result, SettingsStore, HadalApi, HadalClient, Sleeper,
    SystemNetworkProber, TokioSleeper, UnixDaemonClient,
};

use crate::traits::{CoreSplitOps, PingTool, SplitOps, SystemPingTool};

const DEFAULT_MAX_CODE_POLLS: usize = 200;

/// Dependency container injected into CLI command handlers for deterministic testing.
#[derive(Clone)]
pub struct CliContext {
    pub api: Arc<dyn HadalApi>,
    pub daemon: Arc<dyn DaemonClient>,
    pub settings: Arc<dyn SettingsStore>,
    pub split: Arc<dyn SplitOps>,
    pub doh: Arc<dyn DohTransport>,
    pub prober: Arc<dyn NetworkProber>,
    pub keys: Arc<dyn KeyPairGenerator>,
    pub ping: Arc<dyn PingTool>,
    pub sleeper: Arc<dyn Sleeper>,
    pub stdout: Arc<Mutex<dyn Write + Send>>,
    pub max_code_polls: usize,
}

impl CliContext {
    /// Construct the production [`CliContext`] wired to OS/network/daemon backends.
    pub fn system() -> Result<Self> {
        Ok(Self {
            api: Arc::new(HadalClient::new()),
            daemon: Arc::new(UnixDaemonClient::from_env()),
            settings: Arc::new(FileSettingsStore::system()),
            split: Arc::new(CoreSplitOps::system()),
            doh: Arc::new(ReqwestDohTransport::default_client(true)?),
            prober: Arc::new(SystemNetworkProber),
            keys: Arc::new(OsKeyPairGenerator),
            ping: Arc::new(SystemPingTool),
            sleeper: Arc::new(TokioSleeper),
            stdout: Arc::new(Mutex::new(io::stdout())),
            max_code_polls: DEFAULT_MAX_CODE_POLLS,
        })
    }

    pub fn println(&self, text: impl AsRef<str>) -> Result<()> {
        let mut out = self
            .stdout
            .lock()
            .map_err(|_| hadal_core::HadalError::Custom("Output lock poisoned".into()))?;
        writeln!(out, "{}", text.as_ref())?;
        out.flush()?;
        Ok(())
    }
}
