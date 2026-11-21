use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::client::HadalClient;
use crate::error::{Result, HadalError};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Coordinates {
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Cluster {
    pub id: String,
    pub country: Option<String>,
    #[serde(rename = "countryCode")]
    pub country_code: Option<String>,
    pub region: Option<String>,
    #[serde(rename = "regionCode")]
    pub region_code: Option<String>,
    pub location: Option<String>,
    #[serde(rename = "connectionName")]
    pub connection_name: Option<String>,
    #[serde(rename = "pubKey")]
    pub pub_key: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub load: Option<u32>,
    pub coordinates: Option<Coordinates>,
    #[serde(rename = "flagUrl")]
    pub flag_url: Option<String>,
    #[serde(rename = "type")]
    pub cluster_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserLocation {
    pub ip: String,
    pub isp: Option<String>,
    #[serde(rename = "countryCode")]
    pub country_code: Option<String>,
    pub country: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    #[serde(default)]
    pub secured: bool,
}

impl HadalClient {
    /// Fetch all available server clusters that carry a valid WireGuard public key.
    pub async fn get_clusters(&self) -> Result<Vec<Cluster>> {
        let clusters: Vec<Cluster> = self.get("/v5/server/clusters/all").await?;
        Ok(clusters
            .into_iter()
            .filter(|c| c.pub_key.as_deref().is_some_and(|k| !k.is_empty()))
            .collect())
    }

    /// Fetch current user IP, location, and security status from Surfshark.
    /// Routed through the client's [`HttpTransport`](crate::client::HttpTransport) so
    /// `KillswitchLocked` control-plane proxying works seamlessly.
    pub async fn get_user_location(&self) -> Result<UserLocation> {
        let url = self.user_location_url().to_string();
        let mut last_err: Option<HadalError> = None;

        for attempt in 0..3 {
            match self
                .execute_http(
                    reqwest::Method::GET,
                    url.clone(),
                    Vec::new(),
                    None,
                    Some(Duration::from_secs(5)),
                )
                .await
            {
                Ok(resp) => {
                    if (200..300).contains(&resp.status) {
                        if let Ok(loc) = serde_json::from_slice::<UserLocation>(&resp.body) {
                            return Ok(loc);
                        }
                    }
                    last_err = Some(HadalError::Api {
                        status: resp.status,
                        message: "Failed to decode user location response".into(),
                    });
                }
                Err(err) => {
                    last_err = Some(err);
                }
            }
            if attempt < 2 {
                self.sleep_for(Duration::from_millis(500)).await;
            }
        }

        Err(last_err.unwrap_or_else(|| HadalError::Custom("Failed to fetch user location".into())))
    }
}
