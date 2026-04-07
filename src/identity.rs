use sha2::{Digest, Sha256};

use crate::sys;

pub fn generate() -> String {
    let mut hasher = Sha256::new();

    if let Ok(mid) = sys::read_file_string("/etc/machine-id") {
        hasher.update(mid.as_bytes());
        hasher.update(b"\0");
    }

    if let Ok(mid) = sys::read_file_string("/var/lib/dbus/machine-id") {
        hasher.update(mid.as_bytes());
        hasher.update(b"\0");
    }

    hasher.update(std::env::consts::ARCH.as_bytes());
    hasher.update(b"\0");

    let hash = hasher.finalize();
    hex::encode(&hash[..8])
}