use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::client::HadalClient;
use crate::error::{Result, HadalError};
use crate::platform::{Clock, SystemClock};

pub const AUTH_RENEW_PATH: &str = "/v1/auth/renew";

/// Persisted Surfshark session. Access JWTs are short-lived; `renewToken` is
/// used to obtain a fresh pair via `POST /v1/auth/renew`.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Session {
    pub token: Option<String>,
    #[serde(default, rename = "renewToken")]
    pub renew_token: Option<String>,
    #[serde(default, rename = "tokenExpiresAt")]
    pub token_expires_at: Option<String>,
}

/// Persistence abstraction for [`Session`] credentials.
pub trait SessionStore: Send + Sync {
    fn load(&self) -> Option<Session>;
    fn save(&self, session: &Session) -> Result<()>;
    fn clear(&self);
}

/// File-backed [`SessionStore`] persisting `session.json` with `0600` permissions on Unix.
#[derive(Debug, Clone)]
pub struct FileSessionStore {
    dir: PathBuf,
}

impl FileSessionStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

impl SessionStore for FileSessionStore {
    fn load(&self) -> Option<Session> {
        Session::load_from(&self.dir)
    }

    fn save(&self, session: &Session) -> Result<()> {
        session.save_to(&self.dir)
    }

    fn clear(&self) {
        Session::clear_files_in(&self.dir);
    }
}

impl Session {
    pub fn load_from(dir: &Path) -> Option<Self> {
        let session_path = dir.join("session.json");
        let text = std::fs::read_to_string(&session_path).ok()?;
        let session = serde_json::from_str::<Session>(&text).ok()?;
        session.has_access_token().then_some(session)
    }

    pub fn save_to(&self, dir: &Path) -> Result<()> {
        if !self.has_access_token() {
            Self::clear_files_in(dir);
            return Ok(());
        }
        std::fs::create_dir_all(dir)?;
        let json = serde_json::to_string_pretty(self)?;
        let session_path = dir.join("session.json");
        std::fs::write(&session_path, json)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&session_path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    pub fn clear_files_in(dir: &Path) {
        let _ = std::fs::remove_file(dir.join("session.json"));
    }

    pub fn has_access_token(&self) -> bool {
        self.token
            .as_deref()
            .map(|t| !t.trim().is_empty())
            .unwrap_or(false)
    }

    pub fn has_renew_token(&self) -> bool {
        self.renew_token
            .as_deref()
            .map(|t| !t.trim().is_empty())
            .unwrap_or(false)
    }

    /// Merge a login/renew API payload into this session, keeping previous
    /// fields when the response omits them.
    pub fn apply_auth_response(&mut self, resp: &AuthResponse) {
        if let Some(token) = resp.token.clone().filter(|t| !t.is_empty()) {
            self.token = Some(token);
        }
        if let Some(renew) = resp.renew_token.clone().filter(|t| !t.is_empty()) {
            self.renew_token = Some(renew);
        }
        if let Some(exp) = resp.token_expires_at.clone() {
            self.token_expires_at = Some(exp);
        }
    }
}

/// Best-effort JWT `exp` check at the current wall-clock timestamp.
pub fn jwt_is_expired(token: &str) -> bool {
    jwt_is_expired_at(token, SystemClock.now_unix_secs())
}

/// Best-effort JWT `exp` check at an explicit Unix timestamp (`now_epoch_secs`).
/// Unparseable tokens are treated as not expired so the API remains the source of truth.
pub fn jwt_is_expired_at(token: &str, now_epoch_secs: u64) -> bool {
    let payload = match token.split('.').nth(1) {
        Some(p) if !p.is_empty() => p,
        _ => return false,
    };
    let Some(decoded) = decode_jwt_segment(payload) else {
        return false;
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&decoded) else {
        return false;
    };
    let Some(exp) = value.get("exp").and_then(|v| v.as_u64()) else {
        return false;
    };
    exp <= now_epoch_secs
}

fn decode_jwt_segment(segment: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    let padded = match segment.len() % 4 {
        0 => segment.to_string(),
        2 => format!("{segment}=="),
        3 => format!("{segment}="),
        _ => return None,
    };
    base64::engine::general_purpose::URL_SAFE
        .decode(padded.as_bytes())
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(padded.as_bytes()))
        .ok()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub token: Option<String>,
    #[serde(rename = "tokenExpiresAt")]
    pub token_expires_at: Option<String>,
    #[serde(rename = "renewToken")]
    pub renew_token: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteCodeResponse {
    pub code: String,
    pub hash: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct RemoteLoginRequest {
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserMe {
    pub id: Option<String>,
    pub email: Option<String>,
    pub status: Option<String>,
    pub expires_at: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

impl HadalClient {
    /// Generate a 6-character code to authorize login via web or mobile app.
    pub async fn create_remote_login(&self) -> Result<RemoteCodeResponse> {
        self.post_empty("/v1/account/authorization/create").await
    }

    /// Check if the remote login code was authorized.
    pub async fn poll_remote_login(&self, hash: &str) -> Result<AuthResponse> {
        let req = RemoteLoginRequest {
            hash: hash.to_string(),
        };
        let resp: AuthResponse = self.post("/v1/auth/remote", &req).await?;
        self.apply_auth_response(&resp).await;
        Ok(resp)
    }

    /// Get information about currently logged-in user.
    pub async fn get_user_me(&self) -> Result<UserMe> {
        self.get("/v1/account/users/me").await
    }

    /// Exchange `renewToken` for a fresh access JWT via the configured [`HttpTransport`].
    pub async fn refresh_tokens(&self) -> Result<AuthResponse> {
        let renew = self
            .get_renew_token()
            .await
            .filter(|t| !t.is_empty())
            .ok_or(HadalError::SessionExpired)?;

        let headers = self.build_header_pairs(Some(&renew)).await;
        let url = format!("{}{}", self.base_url(), AUTH_RENEW_PATH);
        let resp = self
            .execute_http(reqwest::Method::POST, url, headers, None, None)
            .await
            .map_err(|_| HadalError::SessionExpired)?;

        if !(200..300).contains(&resp.status) {
            return Err(HadalError::SessionExpired);
        }

        let auth: AuthResponse =
            serde_json::from_slice(&resp.body).map_err(|_| HadalError::SessionExpired)?;
        if auth.token.as_deref().unwrap_or("").is_empty() {
            return Err(HadalError::SessionExpired);
        }
        self.apply_auth_response(&auth).await;
        Ok(auth)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "hadal-vpn-session-test-{nanos}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn encode_payload(json: &str) -> String {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json.as_bytes())
    }

    #[test]
    fn session_roundtrip_writes_session_json_only() {
        let dir = temp_dir();
        let session = Session {
            token: Some("access-jwt".into()),
            renew_token: Some("renew-jwt".into()),
            token_expires_at: Some("2026-10-09T12:00:00Z".into()),
        };
        session.save_to(&dir).unwrap();

        let loaded = Session::load_from(&dir).expect("session.json");
        assert_eq!(loaded, session);
        assert!(!dir.join("token.txt").exists());

        Session::clear_files_in(&dir);
        assert!(Session::load_from(&dir).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn apply_auth_response_keeps_existing_renew_when_omitted() {
        let mut session = Session {
            token: Some("old".into()),
            renew_token: Some("keep-me".into()),
            token_expires_at: None,
        };
        let resp = AuthResponse {
            token: Some("new".into()),
            token_expires_at: Some("later".into()),
            renew_token: None,
            extra: serde_json::json!({}),
        };
        session.apply_auth_response(&resp);
        assert_eq!(session.token.as_deref(), Some("new"));
        assert_eq!(session.renew_token.as_deref(), Some("keep-me"));
        assert_eq!(session.token_expires_at.as_deref(), Some("later"));
    }

    #[test]
    fn jwt_expiry_reads_exp_claim_at_explicit_time() {
        let valid = format!("aaa.{}.ccc", encode_payload(r#"{"exp":2000}"#));
        let expired = format!("aaa.{}.ccc", encode_payload(r#"{"exp":900}"#));
        assert!(!jwt_is_expired_at(&valid, 1000));
        assert!(jwt_is_expired_at(&expired, 1000));
        assert!(jwt_is_expired_at(&expired, 900));
        assert!(!jwt_is_expired_at("not-a-jwt", 1000));
    }
}
