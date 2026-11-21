use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Boxed `Send` future alias for object-safe async dependency-injection traits.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Wall-clock time provider for deterministic expiry and timestamp checks.
pub trait Clock: Send + Sync {
    fn now_unix_secs(&self) -> u64;
}

/// Production [`Clock`] backed by `std::time::SystemTime`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// Async delay provider for deterministic retry/polling tests without wall-clock sleeps.
pub trait Sleeper: Send + Sync {
    fn sleep(&self, duration: Duration) -> BoxFuture<'_, ()>;
}

/// Production [`Sleeper`] backed by `tokio::time::sleep`.
#[derive(Debug, Default, Clone, Copy)]
pub struct TokioSleeper;

impl Sleeper for TokioSleeper {
    fn sleep(&self, duration: Duration) -> BoxFuture<'_, ()> {
        Box::pin(tokio::time::sleep(duration))
    }
}
