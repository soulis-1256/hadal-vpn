use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::sync::{Mutex, RwLock};

use crate::auth::{
    jwt_is_expired_at, AuthResponse, FileSessionStore, RemoteCodeResponse, Session, SessionStore,
    UserMe, AUTH_RENEW_PATH,
};
use crate::config::{daemon_socket_path, hadal_config_dir};
use crate::error::{Result, HadalError};
use crate::ipc::DaemonClient;
use crate::platform::{BoxFuture, Clock, Sleeper, SystemClock, TokioSleeper};
use crate::servers::{Cluster, UserLocation};
use crate::wireguard::RegisterPublicKeyResponse;

pub use crate::transport::{HttpRequest, HttpResponse, HttpTransport, ReqwestHttpTransport};

pub const BASE_URL: &str = "https://ext2.surfshark.com";
pub const DEFAULT_USER_LOCATION_URL: &str = "https://api.surfshark.com/v1/server/user";

/// Minimal WireGuard key-registration seam for gaming verification.
pub trait KeyRegistrar: Send + Sync {
    fn has_session(&self) -> BoxFuture<'_, bool>;
    fn register_public_key<'a>(
        &'a self,
        pub_key: &'a str,
    ) -> BoxFuture<'a, Result<RegisterPublicKeyResponse>>;
}

/// High-level Surfshark account & server API trait for CLI/GUI dependency injection.
pub trait HadalApi: KeyRegistrar {
    fn create_remote_login(&self) -> BoxFuture<'_, Result<RemoteCodeResponse>>;
    fn poll_remote_login<'a>(&'a self, hash: &'a str) -> BoxFuture<'a, Result<AuthResponse>>;
    fn get_user_me(&self) -> BoxFuture<'_, Result<UserMe>>;
    fn get_clusters(&self) -> BoxFuture<'_, Result<Vec<Cluster>>>;
    fn get_user_location(&self) -> BoxFuture<'_, Result<UserLocation>>;
}

#[derive(Clone)]
pub struct HadalClient {
    transport: Arc<dyn HttpTransport>,
    session_store: Option<Arc<dyn SessionStore>>,
    clock: Arc<dyn Clock>,
    sleeper: Arc<dyn Sleeper>,
    base_url: String,
    user_location_url: String,
    device_id: String,
    token: Arc<RwLock<Option<String>>>,
    renew_token: Arc<RwLock<Option<String>>>,
    token_expires_at: Arc<RwLock<Option<String>>>,
    refresh_lock: Arc<Mutex<()>>,
    generation: Arc<AtomicU64>,
}

impl Default for HadalClient {
    fn default() -> Self {
        Self::new()
    }
}

impl HadalClient {
    pub fn new() -> Self {
        let dir = hadal_config_dir();
        let store: Arc<dyn SessionStore> = Arc::new(FileSessionStore::new(&dir));
        let loaded = store.load();
        let device_id = load_or_generate_device_id(&dir);

        let mut client = Self::blank_with_transport(
            Arc::new(ReqwestHttpTransport::with_socket_path(daemon_socket_path())),
            device_id,
        );
        client.session_store = Some(store);
        if let Some(session) = loaded {
            client.install_session_sync(session);
        }
        client
    }

    pub fn from_session(session: Session) -> Self {
        let client = Self::blank_with_transport(
            Arc::new(ReqwestHttpTransport::direct()),
            random_device_id(),
        );
        client.install_session_sync(session);
        client
    }

    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
        self
    }

    pub fn with_user_location_url(mut self, url: impl Into<String>) -> Self {
        self.user_location_url = url.into();
        self
    }

    pub fn with_config_dir(mut self, dir: PathBuf) -> Self {
        self.device_id = load_or_generate_device_id(&dir);
        self.session_store = Some(Arc::new(FileSessionStore::new(dir)));
        self
    }

    pub fn with_session_store(mut self, store: Arc<dyn SessionStore>) -> Self {
        self.session_store = Some(store);
        self
    }

    pub fn with_transport(mut self, transport: Arc<dyn HttpTransport>) -> Self {
        self.transport = transport;
        self
    }

    pub fn with_socket_path(mut self, socket_path: PathBuf) -> Self {
        self.transport = Arc::new(ReqwestHttpTransport::with_socket_path(socket_path));
        self
    }

    pub fn with_daemon_client(mut self, daemon: Arc<dyn DaemonClient>) -> Self {
        self.transport = Arc::new(ReqwestHttpTransport::with_daemon(daemon));
        self
    }

    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    pub fn with_sleeper(mut self, sleeper: Arc<dyn Sleeper>) -> Self {
        self.sleeper = sleeper;
        self
    }

    fn blank_with_transport(transport: Arc<dyn HttpTransport>, device_id: String) -> Self {
        Self {
            transport,
            session_store: None,
            clock: Arc::new(SystemClock),
            sleeper: Arc::new(TokioSleeper),
            base_url: BASE_URL.to_string(),
            user_location_url: DEFAULT_USER_LOCATION_URL.to_string(),
            device_id,
            token: Arc::new(RwLock::new(None)),
            renew_token: Arc::new(RwLock::new(None)),
            token_expires_at: Arc::new(RwLock::new(None)),
            refresh_lock: Arc::new(Mutex::new(())),
            generation: Arc::new(AtomicU64::new(0)),
        }
    }

    fn install_session_sync(&self, session: Session) {
        if let Ok(mut w) = self.token.try_write() {
            *w = session.token;
        }
        if let Ok(mut w) = self.renew_token.try_write() {
            *w = session.renew_token;
        }
        if let Ok(mut w) = self.token_expires_at.try_write() {
            *w = session.token_expires_at;
        }
        self.generation.fetch_add(1, Ordering::SeqCst);
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn user_location_url(&self) -> &str {
        &self.user_location_url
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub async fn get_token(&self) -> Option<String> {
        self.token.read().await.clone()
    }

    pub async fn get_renew_token(&self) -> Option<String> {
        self.renew_token.read().await.clone()
    }

    pub async fn get_session(&self) -> Session {
        Session {
            token: self.token.read().await.clone(),
            renew_token: self.renew_token.read().await.clone(),
            token_expires_at: self.token_expires_at.read().await.clone(),
        }
    }

    pub async fn apply_auth_response(&self, resp: &AuthResponse) {
        {
            if let Some(token) = resp.token.clone().filter(|t| !t.is_empty()) {
                *self.token.write().await = Some(token);
            }
            if let Some(renew) = resp.renew_token.clone().filter(|t| !t.is_empty()) {
                *self.renew_token.write().await = Some(renew);
            }
            if let Some(exp) = resp.token_expires_at.clone() {
                *self.token_expires_at.write().await = Some(exp);
            }
        }
        self.generation.fetch_add(1, Ordering::SeqCst);
        self.persist_session().await;
    }

    pub async fn clear_session(&self) {
        *self.token.write().await = None;
        *self.renew_token.write().await = None;
        *self.token_expires_at.write().await = None;
        self.generation.fetch_add(1, Ordering::SeqCst);
        if let Some(ref store) = self.session_store {
            store.clear();
        }
    }

    async fn persist_session(&self) {
        let Some(ref store) = self.session_store else {
            return;
        };
        let session = self.get_session().await;
        let _ = store.save(&session);
    }

    pub(crate) async fn build_header_pairs(&self, bearer: Option<&str>) -> Vec<(String, String)> {
        let mut headers = vec![
            ("x-device-id".into(), self.device_id.clone()),
            ("x-device-type".into(), "desktop".into()),
            ("x-device-platform".into(), "linux".into()),
            ("x-device-version".into(), env!("CARGO_PKG_VERSION").into()),
            ("content-type".into(), "application/json".into()),
            ("cache-control".into(), "no-cache".into()),
        ];
        if let Some(tok) = bearer {
            headers.push(("authorization".into(), format!("Bearer {tok}")));
        }
        headers
    }

    async fn current_header_pairs(&self, include_bearer: bool) -> Vec<(String, String)> {
        let token = if include_bearer {
            self.token.read().await.clone()
        } else {
            None
        };
        self.build_header_pairs(token.as_deref()).await
    }

    pub(crate) async fn execute_http(
        &self,
        method: reqwest::Method,
        url: String,
        headers: Vec<(String, String)>,
        body: Option<Vec<u8>>,
        timeout: Option<Duration>,
    ) -> Result<HttpResponse> {
        self.transport
            .execute(HttpRequest {
                method,
                url,
                headers,
                body,
                timeout,
            })
            .await
    }

    pub(crate) async fn sleep_for(&self, duration: Duration) {
        self.sleeper.sleep(duration).await;
    }

    pub(crate) fn sanitize_error(text: &str, empty_fallback: &str) -> String {
        if text.contains("<!DOCTYPE") || text.contains("<html") {
            "API endpoint returned an unexpected HTML response.".to_string()
        } else if text.is_empty() {
            empty_fallback.to_string()
        } else {
            text.to_string()
        }
    }

    pub(crate) fn ensure_success(status: u16, bytes: &[u8], empty_fallback: &str) -> Result<()> {
        if (200..300).contains(&status) {
            return Ok(());
        }
        let err_text = String::from_utf8_lossy(bytes);
        Err(HadalError::Api {
            status,
            message: Self::sanitize_error(&err_text, empty_fallback),
        })
    }

    pub(crate) fn parse_json_response<T: DeserializeOwned>(
        status: u16,
        bytes: &[u8],
        empty_fallback: &str,
    ) -> Result<T> {
        Self::ensure_success(status, bytes, empty_fallback)?;
        Ok(serde_json::from_slice::<T>(bytes)?)
    }

    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let (status, bytes) = self
            .request(
                reqwest::Method::GET,
                path,
                None,
                should_refresh_on_401(path),
            )
            .await?;
        Self::parse_json_response(
            status,
            &bytes,
            &format!("Request failed with HTTP {status}"),
        )
    }

    pub async fn post<B: Serialize, T: DeserializeOwned>(&self, path: &str, body: &B) -> Result<T> {
        let (status, resp_bytes) = self.post_raw(path, body).await?;
        Self::parse_json_response(
            status,
            &resp_bytes,
            &format!("Request failed with HTTP {status}"),
        )
    }

    pub async fn post_raw<B: Serialize>(&self, path: &str, body: &B) -> Result<(u16, Vec<u8>)> {
        let payload = serde_json::to_vec(body)?;
        self.request(
            reqwest::Method::POST,
            path,
            Some(payload.as_slice()),
            should_refresh_on_401(path),
        )
        .await
    }

    pub async fn post_empty<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let (status, bytes) = self
            .request(
                reqwest::Method::POST,
                path,
                None,
                should_refresh_on_401(path),
            )
            .await?;
        Self::parse_json_response(
            status,
            &bytes,
            &format!("Request failed with HTTP {status}"),
        )
    }

    async fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&[u8]>,
        allow_refresh: bool,
    ) -> Result<(u16, Vec<u8>)> {
        if allow_refresh {
            if let Some(tok) = self.get_token().await {
                if jwt_is_expired_at(&tok, self.clock.now_unix_secs())
                    && self.get_renew_token().await.is_some_and(|r| !r.is_empty())
                {
                    let _ = self.refresh_after_unauthorized().await?;
                }
            }
        }

        let (status, bytes) = self.request_once(&method, path, body).await?;
        if status != 401 || !allow_refresh {
            return Ok((status, bytes));
        }

        if !self.refresh_after_unauthorized().await? {
            return Err(HadalError::SessionExpired);
        }

        let (status2, bytes2) = self.request_once(&method, path, body).await?;
        if status2 == 401 {
            self.clear_session().await;
            return Err(HadalError::SessionExpired);
        }
        Ok((status2, bytes2))
    }

    async fn refresh_after_unauthorized(&self) -> Result<bool> {
        let generation = self.generation.load(Ordering::SeqCst);
        let _guard = self.refresh_lock.lock().await;
        if self.generation.load(Ordering::SeqCst) != generation {
            return Ok(true);
        }
        if !self.get_session().await.has_renew_token() {
            self.clear_session().await;
            return Err(HadalError::SessionExpired);
        }
        match self.refresh_tokens().await {
            Ok(_) => Ok(true),
            Err(_) => {
                self.clear_session().await;
                Err(HadalError::SessionExpired)
            }
        }
    }

    async fn request_once(
        &self,
        method: &reqwest::Method,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<(u16, Vec<u8>)> {
        let url = format!("{}{}", self.base_url, path);
        let skip_access_token = path == AUTH_RENEW_PATH;
        let headers = self.current_header_pairs(!skip_access_token).await;
        let resp = self
            .execute_http(method.clone(), url, headers, body.map(|b| b.to_vec()), None)
            .await?;
        Ok((resp.status, resp.body))
    }
}

impl KeyRegistrar for HadalClient {
    fn has_session(&self) -> BoxFuture<'_, bool> {
        Box::pin(async move {
            let session = self.get_session().await;
            session.has_access_token() || session.has_renew_token()
        })
    }

    fn register_public_key<'a>(
        &'a self,
        pub_key: &'a str,
    ) -> BoxFuture<'a, Result<RegisterPublicKeyResponse>> {
        Box::pin(async move { HadalClient::register_public_key(self, pub_key).await })
    }
}

impl HadalApi for HadalClient {
    fn create_remote_login(&self) -> BoxFuture<'_, Result<RemoteCodeResponse>> {
        Box::pin(async move { HadalClient::create_remote_login(self).await })
    }

    fn poll_remote_login<'a>(&'a self, hash: &'a str) -> BoxFuture<'a, Result<AuthResponse>> {
        Box::pin(async move { HadalClient::poll_remote_login(self, hash).await })
    }

    fn get_user_me(&self) -> BoxFuture<'_, Result<UserMe>> {
        Box::pin(async move { HadalClient::get_user_me(self).await })
    }

    fn get_clusters(&self) -> BoxFuture<'_, Result<Vec<Cluster>>> {
        Box::pin(async move { HadalClient::get_clusters(self).await })
    }

    fn get_user_location(&self) -> BoxFuture<'_, Result<UserLocation>> {
        Box::pin(async move { HadalClient::get_user_location(self).await })
    }
}

fn random_device_id() -> String {
    format!("{:032x}", rand::random::<u128>())
}

fn load_or_generate_device_id(dir: &Path) -> String {
    let id_file = dir.join("device_id");
    if let Ok(id) = std::fs::read_to_string(&id_file) {
        let trimmed = id.trim().to_string();
        if !trimmed.is_empty() {
            return trimmed;
        }
    }
    let new_id = random_device_id();
    let _ = std::fs::create_dir_all(dir);
    let _ = std::fs::write(&id_file, &new_id);
    new_id
}

fn should_refresh_on_401(path: &str) -> bool {
    path != AUTH_RENEW_PATH
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::UserMe;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc as StdArc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "hadal-vpn-client-test-{nanos}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn start_mock(handler: impl Fn(&str, &str) -> (u16, String) + Send + 'static) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(false).unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = match stream {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let mut buf = vec![0u8; 8192];
                let n = match stream.read(&mut buf) {
                    Ok(n) if n > 0 => n,
                    _ => continue,
                };
                let req = String::from_utf8_lossy(&buf[..n]);
                let first = req.lines().next().unwrap_or("");
                let auth = req
                    .lines()
                    .find(|l| l.to_ascii_lowercase().starts_with("authorization:"))
                    .unwrap_or("")
                    .to_string();
                let (code, body) = handler(first, &auth);
                let reason = match code {
                    200 => "OK",
                    401 => "Unauthorized",
                    _ => "Error",
                };
                let resp = format!(
                    "HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn refreshes_expired_jwt_and_retries() {
        let hits: StdArc<Mutex<Vec<String>>> = StdArc::new(Mutex::new(Vec::new()));
        let hits2 = hits.clone();
        let base = start_mock(move |first, auth| {
            hits2.lock().unwrap().push(format!("{first}|{auth}"));
            if first.starts_with("POST /v1/auth/renew") {
                assert!(auth.contains("Bearer renew-secret"));
                return (
                    200,
                    r#"{"token":"fresh-jwt","renewToken":"renew-2","tokenExpiresAt":"later"}"#
                        .into(),
                );
            }
            if first.starts_with("GET /v1/account/users/me") {
                if auth.contains("Bearer fresh-jwt") {
                    return (200, r#"{"email":"user@example.com"}"#.into());
                }
                return (401, r#"{"code":401,"message":"Expired JWT Token"}"#.into());
            }
            (404, r#"{"message":"nope"}"#.into())
        });

        let dir = test_dir();
        let client = HadalClient::from_session(Session {
            token: Some("expired-jwt".into()),
            renew_token: Some("renew-secret".into()),
            token_expires_at: None,
        })
        .with_base_url(base)
        .with_config_dir(dir.clone());

        let me: UserMe = client.get_user_me().await.expect("retry after renew");
        assert_eq!(me.email.as_deref(), Some("user@example.com"));
        assert_eq!(client.get_token().await.as_deref(), Some("fresh-jwt"));
        assert_eq!(client.get_renew_token().await.as_deref(), Some("renew-2"));

        let saved = Session::load_from(&dir).expect("persisted session");
        assert_eq!(saved.token.as_deref(), Some("fresh-jwt"));
        assert_eq!(saved.renew_token.as_deref(), Some("renew-2"));

        let log = hits.lock().unwrap().clone();
        assert!(log.iter().any(|l| l.contains("POST /v1/auth/renew")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn expired_jwt_without_renew_token_is_session_expired() {
        let base = start_mock(|_first, _auth| {
            (401, r#"{"code":401,"message":"Expired JWT Token"}"#.into())
        });
        let dir = test_dir();
        let client = HadalClient::from_session(Session {
            token: Some("expired-jwt".into()),
            renew_token: None,
            token_expires_at: None,
        })
        .with_base_url(base)
        .with_config_dir(dir.clone());

        let err = client.get_user_me().await.expect_err("must expire");
        assert!(matches!(err, HadalError::SessionExpired));
        assert!(client.get_token().await.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn failed_renew_is_session_expired() {
        let base = start_mock(|first, _auth| {
            if first.starts_with("POST /v1/auth/renew") {
                return (401, r#"{"code":401,"message":"Expired JWT Token"}"#.into());
            }
            (401, r#"{"code":401,"message":"Expired JWT Token"}"#.into())
        });
        let dir = test_dir();
        let client = HadalClient::from_session(Session {
            token: Some("expired-jwt".into()),
            renew_token: Some("dead-renew".into()),
            token_expires_at: None,
        })
        .with_base_url(base)
        .with_config_dir(dir.clone());

        let err = client.get_user_me().await.expect_err("must expire");
        assert!(matches!(err, HadalError::SessionExpired));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
