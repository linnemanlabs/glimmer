pub fn generate() -> String {
    use sha2::{Digest, Sha256};
    
    let mut hasher = Sha256::new();

    if let Ok(mid) = std::fs::read_to_string("/etc/machine-id") {
        hasher.update(mid.trim().as_bytes());
        hasher.update(b"\0");
    }

    if let Ok(mid) = std::fs::read_to_string("/var/lib/dbus/machine-id") {
        hasher.update(mid.trim().as_bytes());
        hasher.update(b"\0");
    }

    hasher.update(std::env::consts::ARCH.as_bytes());
    hasher.update(b"\0");

    let hash = hasher.finalize();
    hex::encode(&hash[..8])
}