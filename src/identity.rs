use sha2::{Digest, Sha256};
use crate::sys;
use glimmer_obfstr::obfs;

pub fn generate_with_hostname(hostname: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();

    hasher.update(hostname.as_bytes());
    hasher.update(b"\0");

    if let Ok(mid) = sys::read_file_string(obfs!("/etc/machine-id").as_str()) {
        hasher.update(mid.as_bytes());
        hasher.update(b"\0");
    }

    hasher.update(std::env::consts::ARCH.as_bytes());
    hasher.update(b"\0");

    let hash = hasher.finalize();
    hash.into()
}