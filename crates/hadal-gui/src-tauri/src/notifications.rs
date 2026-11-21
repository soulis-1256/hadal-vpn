use std::collections::HashMap;
use std::time::Duration;

use hadal_core::{DaemonStatus, TunnelState};
use zbus::zvariant::Value;
use zbus::{proxy, Connection};

use crate::backend::BoxFuture;

#[proxy(
    interface = "org.freedesktop.Notifications",
    default_service = "org.freedesktop.Notifications",
    default_path = "/org/freedesktop/Notifications"
)]
trait FreedesktopNotifications {
    #[allow(clippy::too_many_arguments)]
    fn notify(
        &self,
        app_name: &str,
        replaces_id: u32,
        app_icon: &str,
        summary: &str,
        body: &str,
        actions: &[&str],
        hints: HashMap<&str, Value<'_>>,
        expire_timeout: i32,
    ) -> zbus::Result<u32>;
}

/// Abstraction over desktop notification delivery so state tests avoid D-Bus.
pub trait NotificationTransport: Send + Sync {
    fn notify_connected<'a>(&'a self, summary: &'a str, body: &'a str) -> BoxFuture<'a, ()>;
}

/// Real Linux `org.freedesktop.Notifications` D-Bus notifier.
pub struct FreedesktopNotifier;

impl NotificationTransport for FreedesktopNotifier {
    fn notify_connected<'a>(&'a self, summary: &'a str, body: &'a str) -> BoxFuture<'a, ()> {
        let summary = summary.to_string();
        let body = body.to_string();
        Box::pin(async move {
            tokio::spawn(async move {
                send_freedesktop_notification(&summary, &body).await;
            });
        })
    }
}

/// Abstraction over `StatusNotifierWatcher` D-Bus availability checks.
pub trait SniWatcherChecker: Send + Sync {
    fn wait_for_watcher(&self, timeout: Duration) -> BoxFuture<'_, bool>;
}

/// Real session D-Bus `org.kde.StatusNotifierWatcher` checker.
pub struct DbusSniWatcherChecker;

impl SniWatcherChecker for DbusSniWatcherChecker {
    fn wait_for_watcher(&self, timeout: Duration) -> BoxFuture<'_, bool> {
        Box::pin(wait_for_status_notifier_watcher(timeout))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ObservedTunnel {
    NotProtected,
    Protected(String),
}

/// Tracks tunnel transitions so each new protected area triggers exactly one notification.
#[derive(Debug, Default)]
pub struct ConnectionNotifier {
    last_observed: Option<ObservedTunnel>,
}

impl ConnectionNotifier {
    /// Update observed state and return `(summary, body)` if a new area connection should be notified.
    ///
    /// When `explicit_connect` is `false` (background polling), an already-active tunnel on the
    /// very first observation records its baseline without firing a spurious notification.
    pub fn record_and_check(
        &mut self,
        reachable: bool,
        status: &DaemonStatus,
        explicit_connect: bool,
    ) -> Option<(String, String)> {
        if !reachable {
            self.last_observed = Some(ObservedTunnel::NotProtected);
            return None;
        }

        let next = if status.state == TunnelState::Protected {
            ObservedTunnel::Protected(protected_area_key(status))
        } else {
            ObservedTunnel::NotProtected
        };

        let should_notify = match &self.last_observed {
            None => explicit_connect && matches!(next, ObservedTunnel::Protected(_)),
            Some(prev) => *prev != next && matches!(next, ObservedTunnel::Protected(_)),
        };

        self.last_observed = Some(next);

        if should_notify {
            format_connected_notification(status)
        } else {
            None
        }
    }
}

fn protected_area_key(status: &DaemonStatus) -> String {
    format!(
        "{}|{}|{}|{}",
        status.cluster_id.as_deref().unwrap_or(""),
        status.location.as_deref().unwrap_or(""),
        status.country.as_deref().unwrap_or(""),
        status.domain.as_deref().unwrap_or(""),
    )
}

/// Build the notification `(summary, body)` for a newly protected tunnel area.
pub fn format_connected_notification(status: &DaemonStatus) -> Option<(String, String)> {
    if status.state != TunnelState::Protected {
        return None;
    }

    let loc = status
        .location
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let country = status
        .country
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let domain = status
        .domain
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let endpoint = status
        .endpoint
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let area = match (loc, country) {
        (Some(l), Some(c)) if !l.eq_ignore_ascii_case(c) => format!("{l}, {c}"),
        (Some(l), _) => l.to_string(),
        (None, Some(c)) => c.to_string(),
        (None, None) => domain.unwrap_or("VPN").to_string(),
    };

    let summary = format!("Connected to {area}");

    let route = domain.or(endpoint);
    let mut details = Vec::new();
    if let Some(r) = route {
        details.push(r.to_string());
    }
    if let Some(mtu) = status.mtu {
        details.push(format!("MTU {mtu}"));
    }
    if !status.game_only_cidrs.is_empty() {
        details.push("Game-only".to_string());
    }

    let body = if details.is_empty() {
        "WireGuard tunnel active".to_string()
    } else {
        format!("WireGuard tunnel · {}", details.join(" · "))
    };

    Some((summary, body))
}

/// Send a native Linux desktop notification over `org.freedesktop.Notifications`.
pub async fn send_freedesktop_notification(summary: &str, body: &str) {
    let send_fut = async {
        let conn = Connection::session().await?;
        let proxy = FreedesktopNotificationsProxy::new(&conn).await?;
        let mut hints: HashMap<&str, Value<'_>> = HashMap::new();
        hints.insert("desktop-entry", Value::from("hadal-vpn"));
        hints.insert("category", Value::from("network.connected"));
        proxy
            .notify("Hadal VPN", 0, "hadal-vpn", summary, body, &[], hints, -1)
            .await
    };

    match tokio::time::timeout(Duration::from_secs(3), send_fut).await {
        Ok(Ok(_id)) => {}
        Ok(Err(e)) => eprintln!("Desktop notification failed: {e}"),
        Err(_) => eprintln!("Desktop notification timed out"),
    }
}

/// Wait until a `StatusNotifierWatcher` is present on the user's session D-Bus (for boot races).
pub async fn wait_for_status_notifier_watcher(timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    let Ok(conn) = Connection::session().await else {
        return false;
    };
    let Ok(dbus) = zbus::fdo::DBusProxy::new(&conn).await else {
        return false;
    };
    let Ok(name) = zbus::names::BusName::try_from("org.kde.StatusNotifierWatcher") else {
        return false;
    };

    loop {
        if let Ok(true) = dbus.name_has_owner(name.as_ref()).await {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_protected(cluster_id: &str, location: &str, country: &str) -> DaemonStatus {
        DaemonStatus {
            state: TunnelState::Protected,
            cluster_id: Some(cluster_id.to_string()),
            location: Some(location.to_string()),
            country: Some(country.to_string()),
            domain: Some("de-fra.prod.surfshark.com".to_string()),
            endpoint: Some("138.199.19.164:51820".to_string()),
            mtu: Some(1420),
            ..DaemonStatus::default()
        }
    }

    #[test]
    fn formats_area_summary_and_body() {
        let st = sample_protected("de-fra", "Frankfurt", "Germany");
        let (summary, body) = format_connected_notification(&st).unwrap();
        assert_eq!(summary, "Connected to Frankfurt, Germany");
        assert_eq!(
            body,
            "WireGuard tunnel · de-fra.prod.surfshark.com · MTU 1420"
        );
    }

    #[test]
    fn formats_country_without_duplication() {
        let st = sample_protected("sg-sin", "Singapore", "Singapore");
        let (summary, _) = format_connected_notification(&st).unwrap();
        assert_eq!(summary, "Connected to Singapore");
    }

    #[test]
    fn passive_startup_already_connected_does_not_spam() {
        let mut tracker = ConnectionNotifier::default();
        let st = sample_protected("de-fra", "Frankfurt", "Germany");
        assert_eq!(tracker.record_and_check(true, &st, false), None);
        assert_eq!(tracker.record_and_check(true, &st, false), None);
    }

    #[test]
    fn notifies_once_per_connection_and_area_change() {
        let mut tracker = ConnectionNotifier::default();
        let disc = DaemonStatus::default();
        let fra = sample_protected("de-fra", "Frankfurt", "Germany");
        let ams = sample_protected("nl-ams", "Amsterdam", "Netherlands");

        assert_eq!(tracker.record_and_check(true, &disc, false), None);

        let first = tracker.record_and_check(true, &fra, true);
        assert!(first.is_some());
        assert_eq!(first.unwrap().0, "Connected to Frankfurt, Germany");

        assert_eq!(tracker.record_and_check(true, &fra, false), None);

        let switched = tracker.record_and_check(true, &ams, false);
        assert_eq!(switched.unwrap().0, "Connected to Amsterdam, Netherlands");

        assert_eq!(tracker.record_and_check(true, &disc, false), None);
        let reconnected = tracker.record_and_check(true, &ams, false);
        assert_eq!(
            reconnected.unwrap().0,
            "Connected to Amsterdam, Netherlands"
        );
    }
}
