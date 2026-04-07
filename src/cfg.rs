use std::time::Duration;
use serde::Deserialize;
use crate::errors::ConfigError;

#[derive(Deserialize)]
pub struct Config {
    pub c2_endpoints: Vec<String>,
    pub beacon_interval_seconds: u64,
    pub jitter_percent: f64,
    pub server_public_key: String,
}

impl Config {
    pub fn load(path: &str) -> Result<Self, ConfigError> {
        let data = std::fs::read_to_string(path)?;
        let config: Config = serde_json::from_str(&data)?;
        Ok(config)
    }

    pub fn beacon_interval(&self) -> Duration {
        Duration::from_secs(self.beacon_interval_seconds)
    }

    pub fn server_public_key_bytes(&self) -> Result<Vec<u8>, ConfigError> {
        hex::decode(&self.server_public_key)
            .map_err(|e| ConfigError::InvalidServerKey(e.to_string()))
    }
}