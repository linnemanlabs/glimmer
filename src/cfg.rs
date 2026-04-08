use std::time::Duration;
use serde::Deserialize;
use crate::errors::ConfigError;

#[derive(Deserialize)]
pub struct Config {
    // c2 endpoints
    pub e: Vec<String>,

    // beacon interval seconds
    pub i: u64,

    // server public key
    pub k: String,
}

impl Config {

    pub fn load(path: &str) -> Result<Self, ConfigError> {
        let data = std::fs::read_to_string(path)?;
        let config: Config = serde_json::from_str(&data)?;
        Ok(config)
    }

    pub fn endpoints(&self) -> &[String] {
        &self.e
    }

    pub fn beacon_interval(&self) -> Duration {
        Duration::from_secs(self.i)
    }

    pub fn server_public_key_bytes(&self) -> Result<Vec<u8>, ConfigError> {
        hex::decode(&self.k)
            .map_err(|e| ConfigError::InvalidServerKey(e.to_string()))
    }

}