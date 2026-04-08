use std::collections::HashMap;
use std::path::Path;

use crate::crypto::{self, StaticKeypair};

pub struct KeyStore {
    keys: HashMap<[u8; 4], StaticKeypair>,
}

impl KeyStore {
    pub fn load(dir: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut keys = HashMap::new();

        let path = Path::new(dir);
        if !path.exists() {
            return Err(format!("keys directory not found: {}", dir).into());
        }

        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let file_path = entry.path();

            if file_path.extension().and_then(|e| e.to_str()) != Some("key") {
                continue;
            }

            let secret_hex = std::fs::read_to_string(&file_path)?;
            let secret_bytes = hex::decode(secret_hex.trim())?;
            let keypair = StaticKeypair::from_secret_bytes(&secret_bytes)?;

            let pub_bytes = keypair.public_key_bytes();
            let kid = crypto::key_id(&pub_bytes);

            crate::dbg_log!("[dev] [keystore] loaded key {} from {}", hex::encode(kid), file_path.display());

            keys.insert(kid, keypair);
        }

        if keys.is_empty() {
            return Err("no keys found in keystore".into());
        }

        crate::dbg_log!("[dev] [keystore] {} key(s) loaded", keys.len());
        Ok(KeyStore { keys })
    }

    pub fn get(&self, key_id: &[u8; 4]) -> Option<&StaticKeypair> {
        self.keys.get(key_id)
    }

    pub fn key_count(&self) -> usize {
        self.keys.len()
    }
}