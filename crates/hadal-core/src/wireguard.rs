use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::client::HadalClient;
use crate::error::Result;

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

impl HadalClient {
    /// Register a WireGuard public key with Surfshark.
    pub async fn register_public_key(&self, pub_key: &str) -> Result<RegisterPublicKeyResponse> {
        let req = RegisterPublicKeyRequest {
            pub_key: pub_key.to_string(),
        };
        self.post("/v1/account/users/public-keys", &req).await
    }
}
