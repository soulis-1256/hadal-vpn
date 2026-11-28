use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::client::HadalClient;
use crate::error::{HadalError, Result};

pub const WG_KEY_FILENAME: &str = "wg_key.json";
pub const PUBLIC_KEYS_PATH: &str = "/v1/account/users/public-keys";
pub const PUBLIC_KEYS_VALIDATE_PATH: &str = "/v1/account/users/public-keys/validate";

/// Rotate/re-register the persisted WireGuard key when fewer than 12 hours remain
/// before Surfshark's `expiresAt` timestamp.
pub const WG_KEY_RENEWAL_MARGIN_SECS: u64 = 12 * 60 * 60;

/// Re-validate a locally valid key against Surfshark at most once per hour so rapid
/// scan+connect sequences incur zero extra HTTP calls while still self-healing if a
/// key is revoked early on the server.
pub const WG_KEY_VALIDATE_INTERVAL_SECS: u64 = 60 * 60;

/// Fallback local TTL when an API response omits `expiresAt`.
pub const WG_KEY_FALLBACK_TTL_SECS: u64 = 24 * 60 * 60;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WgKeyPair {
    pub private_key: String,
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterPublicKeyRequest {
    #[serde(rename = "pubKey")]
    pub pub_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterPublicKeyResponse {
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

/// Persisted WireGuard client keypair and its Surfshark registration metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersistedWgKey {
    pub private_key: String,
    pub public_key: String,
    pub address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_validated_epoch: Option<u64>,
}

/// Persistence abstraction for [`PersistedWgKey`].
pub trait WgKeyStore: Send + Sync {
    fn load(&self) -> Option<PersistedWgKey>;
    fn save(&self, key: &PersistedWgKey) -> Result<()>;
    fn clear(&self);
}

/// File-backed [`WgKeyStore`] persisting `wg_key.json` with `0600` permissions on Unix.
#[derive(Debug, Clone)]
pub struct FileWgKeyStore {
    dir: PathBuf,
}

impl FileWgKeyStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

impl WgKeyStore for FileWgKeyStore {
    fn load(&self) -> Option<PersistedWgKey> {
        PersistedWgKey::load_from(&self.dir)
    }

    fn save(&self, key: &PersistedWgKey) -> Result<()> {
        key.save_to(&self.dir)
    }

    fn clear(&self) {
        PersistedWgKey::clear_files_in(&self.dir);
    }
}

impl PersistedWgKey {
    pub fn from_registration(
        keys: WgKeyPair,
        resp: &RegisterPublicKeyResponse,
        now_epoch_secs: Option<u64>,
    ) -> Self {
        let expires_at = resp.expires_at().map(str::to_string);
        let expires_at_epoch = expires_at
            .as_deref()
            .and_then(parse_rfc3339_utc_secs)
            .or_else(|| now_epoch_secs.map(|now| now.saturating_add(WG_KEY_FALLBACK_TTL_SECS)));

        Self {
            private_key: keys.private_key,
            public_key: keys.public_key,
            address: resp.wireguard_address(),
            key_id: resp.key_id().map(str::to_string),
            expires_at,
            expires_at_epoch,
            last_validated_epoch: now_epoch_secs,
        }
    }

    pub fn apply_validation(
        &mut self,
        resp: &RegisterPublicKeyResponse,
        now_epoch_secs: u64,
    ) {
        let addr = resp.wireguard_address();
        if !addr.is_empty() {
            self.address = addr;
        }
        if let Some(id) = resp.key_id() {
            self.key_id = Some(id.to_string());
        }
        if let Some(exp_str) = resp.expires_at() {
            self.expires_at = Some(exp_str.to_string());
            if let Some(exp_epoch) = parse_rfc3339_utc_secs(exp_str) {
                self.expires_at_epoch = Some(exp_epoch);
            }
        }
        self.last_validated_epoch = Some(now_epoch_secs);
    }

    pub fn effective_expires_at_epoch(&self) -> Option<u64> {
        self.expires_at_epoch
            .or_else(|| self.expires_at.as_deref().and_then(parse_rfc3339_utc_secs))
    }

    pub fn has_material(&self) -> bool {
        !self.private_key.trim().is_empty()
            && !self.public_key.trim().is_empty()
            && !self.address.trim().is_empty()
    }

    pub fn is_valid_at(&self, now_epoch_secs: u64) -> bool {
        if !self.has_material() {
            return false;
        }
        self.effective_expires_at_epoch()
            .is_some_and(|exp| exp > now_epoch_secs.saturating_add(WG_KEY_RENEWAL_MARGIN_SECS))
    }

    pub fn needs_validation_at(&self, now_epoch_secs: u64) -> bool {
        match self.last_validated_epoch {
            Some(ts) => now_epoch_secs.saturating_sub(ts) >= WG_KEY_VALIDATE_INTERVAL_SECS,
            None => true,
        }
    }

    pub fn load_from(dir: &Path) -> Option<Self> {
        let path = dir.join(WG_KEY_FILENAME);
        let text = std::fs::read_to_string(&path).ok()?;
        let key = serde_json::from_str::<PersistedWgKey>(&text).ok()?;
        key.has_material().then_some(key)
    }

    pub fn save_to(&self, dir: &Path) -> Result<()> {
        if !self.has_material() {
            Self::clear_files_in(dir);
            return Ok(());
        }
        std::fs::create_dir_all(dir)?;
        let json = serde_json::to_string_pretty(self)?;
        let path = dir.join(WG_KEY_FILENAME);
        std::fs::write(&path, json)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    pub fn clear_files_in(dir: &Path) {
        let _ = std::fs::remove_file(dir.join(WG_KEY_FILENAME));
    }
}

/// Generator abstraction for WireGuard Curve25519 keypairs to enable deterministic tests.
pub trait KeyPairGenerator: Send + Sync {
    fn generate(&self) -> WgKeyPair;
}

/// Production [`KeyPairGenerator`] backed by OS randomness (`OsRng`).
#[derive(Debug, Default, Clone, Copy)]
pub struct OsKeyPairGenerator;

impl KeyPairGenerator for OsKeyPairGenerator {
    fn generate(&self) -> WgKeyPair {
        WgKeyPair::generate()
    }
}

impl WgKeyPair {
    /// Generate a fresh random WireGuard Curve25519 keypair using OS randomness.
    pub fn generate() -> Self {
        Self::generate_with_rng(&mut OsRng)
    }

    /// Generate a WireGuard Curve25519 keypair from an explicit RNG.
    pub fn generate_with_rng<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let secret = StaticSecret::random_from_rng(rng);
        let public = PublicKey::from(&secret);

        Self {
            private_key: BASE64.encode(secret.to_bytes()),
            public_key: BASE64.encode(public.as_bytes()),
        }
    }
}

impl RegisterPublicKeyResponse {
    /// WireGuard interface address in CIDR form (`ip/32` or `ip/128`).
    ///
    /// Surfshark returns the assigned tunnel IP when a public key is registered.
    /// If the payload omits it, fall back to the historical Surfshark WG address.
    pub fn wireguard_address(&self) -> String {
        let raw = self
            .ip
            .as_deref()
            .or_else(|| self.extra.get("ip").and_then(|v| v.as_str()))
            .or_else(|| self.extra.get("address").and_then(|v| v.as_str()))
            .or_else(|| self.extra.get("ipv4").and_then(|v| v.as_str()))
            .unwrap_or("10.14.0.2");
        normalize_wg_address(raw)
    }

    /// Surfshark server-assigned identifier for this registered public key (`id`).
    pub fn key_id(&self) -> Option<&str> {
        self.extra
            .get("id")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
    }

    /// RFC 3339 expiration timestamp returned by Surfshark (`expiresAt`).
    pub fn expires_at(&self) -> Option<&str> {
        self.extra
            .get("expiresAt")
            .or_else(|| self.extra.get("expires_at"))
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
    }
}

/// Force `/32` (IPv4) or `/128` (IPv6) on the WireGuard interface address.
pub fn normalize_wg_address(raw: &str) -> String {
    let ip = raw.split('/').next().unwrap_or(raw).trim();
    if ip.contains(':') {
        format!("{ip}/128")
    } else {
        format!("{ip}/32")
    }
}

/// Parse an RFC 3339 timestamp (`YYYY-MM-DDTHH:MM:SS[.frac](Z|+HH:MM|-HH:MM)`) into Unix UTC seconds.
pub fn parse_rfc3339_utc_secs(ts: &str) -> Option<u64> {
    let s = ts.trim();
    let bytes = s.as_bytes();
    if bytes.len() < 20 {
        return None;
    }
    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || !matches!(bytes[10], b'T' | b't' | b' ')
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return None;
    }

    let year: i64 = s[0..4].parse().ok()?;
    let month: u32 = s[5..7].parse().ok()?;
    let day: u32 = s[8..10].parse().ok()?;
    let hour: u32 = s[11..13].parse().ok()?;
    let minute: u32 = s[14..16].parse().ok()?;
    let second: u32 = s[17..19].parse().ok()?;

    if year < 1970 || !(1..=12).contains(&month) || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let max_day = days_in_month(year, month)?;
    if day == 0 || day > max_day {
        return None;
    }

    let mut rest = &s[19..];
    if let Some(after_dot) = rest.strip_prefix('.') {
        let frac_len = after_dot.bytes().take_while(|b| b.is_ascii_digit()).count();
        if frac_len == 0 {
            return None;
        }
        rest = &after_dot[frac_len..];
    }

    let offset_secs: i64 = if rest == "Z" || rest == "z" {
        0
    } else if rest.len() == 6 && matches!(rest.as_bytes()[0], b'+' | b'-') && rest.as_bytes()[3] == b':' {
        let sign: i64 = if rest.as_bytes()[0] == b'+' { 1 } else { -1 };
        let oh: i64 = rest[1..3].parse().ok()?;
        let om: i64 = rest[4..6].parse().ok()?;
        if oh > 23 || om > 59 {
            return None;
        }
        sign * (oh * 3600 + om * 60)
    } else {
        return None;
    };

    let days = days_from_civil(year, month, day);
    let sec_clamped = second.min(59) as i64;
    let total = days * 86_400 + (hour as i64) * 3600 + (minute as i64) * 60 + sec_clamped - offset_secs;
    u64::try_from(total).ok()
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

fn days_in_month(year: i64, month: u32) -> Option<u32> {
    Some(match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => return None,
    })
}

/// Howard Hinnant's civil-to-days algorithm (days since 1970-01-01).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400) as u64;
    let m_adj = if month > 2 { month - 3 } else { month + 9 } as u64;
    let doy = (153 * m_adj + 2) / 5 + (day as u64) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + (doe as i64) - 719_468
}

fn is_safe_key_id(key_id: &str) -> bool {
    !key_id.is_empty()
        && key_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

impl HadalClient {
    /// Register a WireGuard public key with Surfshark.
    /// If the backend returns `409 Conflict` (already registered), falls back to `/validate`.
    pub async fn register_public_key(&self, pub_key: &str) -> Result<RegisterPublicKeyResponse> {
        let req = RegisterPublicKeyRequest {
            pub_key: pub_key.to_string(),
        };
        let (status, bytes) = self.post_raw(PUBLIC_KEYS_PATH, &req).await?;
        if status == 409 {
            if let Some(existing) = self.validate_public_key(pub_key).await? {
                return Ok(existing);
            }
        }
        Self::parse_json_response(
            status,
            &bytes,
            &format!("Public key registration failed with HTTP {status}"),
        )
    }

    /// Check whether a WireGuard public key is currently registered and active on Surfshark.
    /// Returns `Ok(None)` when Surfshark responds with `404 Not Found`.
    pub async fn validate_public_key(
        &self,
        pub_key: &str,
    ) -> Result<Option<RegisterPublicKeyResponse>> {
        let req = RegisterPublicKeyRequest {
            pub_key: pub_key.to_string(),
        };
        let (status, bytes) = self.post_raw(PUBLIC_KEYS_VALIDATE_PATH, &req).await?;
        if status == 404 {
            return Ok(None);
        }
        let resp = Self::parse_json_response(
            status,
            &bytes,
            &format!("Public key validation failed with HTTP {status}"),
        )?;
        Ok(Some(resp))
    }

    /// Revoke a specific Surfshark public key owned by Hadal (`DELETE /v1/account/users/public-keys/{id}`).
    pub async fn delete_public_key(&self, key_id: &str) -> Result<()> {
        self.delete_public_key_inner(key_id, true).await
    }

    pub(crate) async fn delete_public_key_inner(
        &self,
        key_id: &str,
        allow_refresh: bool,
    ) -> Result<()> {
        if !is_safe_key_id(key_id) {
            return Err(HadalError::WireGuard(format!("Invalid key id '{key_id}'")));
        }
        let path = format!("{PUBLIC_KEYS_PATH}/{key_id}");
        let (status, bytes) = self.delete_raw(&path, allow_refresh).await?;
        if status == 404 {
            return Ok(());
        }
        Self::ensure_success(
            status,
            &bytes,
            &format!("Public key deletion failed with HTTP {status}"),
        )
    }

    /// Return Hadal's persisted WireGuard keypair, reusing it across connects and gaming scans.
    ///
    /// - Reuses the saved key with **zero HTTP requests** while valid and recently validated.
    /// - Periodically re-validates via `/validate` (read-only) to self-heal early revocation.
    /// - Only registers a new key when none exists, the server rejected it (`404`), or it is
    ///   within [`WG_KEY_RENEWAL_MARGIN_SECS`] of expiry (revoking Hadal's own previous `key_id`
    ///   best-effort before rotating so other keys on the user's account are left untouched).
    pub async fn ensure_wireguard_key(&self) -> Result<PersistedWgKey> {
        let _guard = self.lock_wg_key().await;
        let now = self.now_unix_secs();

        if let Some(mut cached) = self.load_cached_wg_key().await {
            if cached.is_valid_at(now) {
                if !cached.needs_validation_at(now) {
                    return Ok(cached);
                }
                match self.validate_public_key(&cached.public_key).await {
                    Ok(Some(resp)) => {
                        cached.apply_validation(&resp, now);
                        if cached.is_valid_at(now) {
                            self.save_cached_wg_key(&cached).await;
                            return Ok(cached);
                        }
                        if let Some(old_id) = cached.key_id.as_deref() {
                            let _ = self.delete_public_key(old_id).await;
                        }
                    }
                    Ok(None) => {
                        // Server no longer recognizes this key (expired/revoked early) — rotate below.
                    }
                    Err(_) => {
                        // Transient network/API failure while local expiry is still valid: reuse cached key.
                        return Ok(cached);
                    }
                }
            } else if let Some(old_id) = cached.key_id.as_deref() {
                let _ = self.delete_public_key(old_id).await;
            }
        }

        self.generate_register_and_persist_wg_key(now).await
    }

    /// Explicitly generate and register a fresh WireGuard keypair, replacing Hadal's persisted key
    /// and best-effort deleting Hadal's previous `key_id` from Surfshark.
    pub async fn rotate_wireguard_key(&self) -> Result<PersistedWgKey> {
        let _guard = self.lock_wg_key().await;
        let now = self.now_unix_secs();
        if let Some(cached) = self.load_cached_wg_key().await {
            if let Some(old_id) = cached.key_id.as_deref() {
                let _ = self.delete_public_key(old_id).await;
            }
        }
        self.generate_register_and_persist_wg_key(now).await
    }

    async fn generate_register_and_persist_wg_key(&self, now: u64) -> Result<PersistedWgKey> {
        let pair = self.generate_wg_keypair();
        let resp = self.register_public_key(&pair.public_key).await?;
        let persisted = PersistedWgKey::from_registration(pair, &resp, Some(now));
        self.save_cached_wg_key(&persisted).await;
        Ok(persisted)
    }
}
