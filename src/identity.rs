use sha2::{Digest, Sha256};
use crate::sys;
use crate::strings;

pub fn generate_with_hostname(hostname: &str) -> String {
    let mut hasher = Sha256::new();

    hasher.update(hostname.as_bytes());
    hasher.update(b"\0");

    if let Ok(mid) = sys::read_file_string(
        &strings::decode_str(strings::ETC_MACHINE_ID)
    ) {
        hasher.update(mid.as_bytes());
        hasher.update(b"\0");
    }

    hasher.update(std::env::consts::ARCH.as_bytes());
    hasher.update(b"\0");

    let hash = hasher.finalize();
    hex::encode(&hash[..8])
}