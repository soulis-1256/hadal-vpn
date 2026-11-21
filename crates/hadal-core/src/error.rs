use thiserror::Error;

#[derive(Error, Debug)]
pub enum HadalError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("API error (status {status}): {message}")]
    Api { status: u16, message: String },

    #[error("Authentication required")]
    Unauthorized,

    #[error("Session expired. Please log in again.")]
    SessionExpired,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("WireGuard error: {0}")]
    WireGuard(String),

    #[error("{0}")]
    Custom(String),
}

pub type Result<T> = std::result::Result<T, HadalError>;
