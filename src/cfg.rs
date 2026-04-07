use std::fs;
use std::time::Duration;

use serde::Deserialize;

#[derive(Deserialize)]
pub struct Config {
    pub c2_endpoints: Vec<String>,
    pub beacon_interval_seconds: u64,
    pub jitter_percent: f64,
}

impl Config {
    pub fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let data = fs::read_to_string(path)?;
        let config: Config = serde_json::from_str(&data)?;
        Ok(config)
    }

    pub fn beacon_interval(&self) -> Duration {
        Duration::from_secs(self.beacon_interval_seconds)
    }
}