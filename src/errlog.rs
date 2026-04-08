use std::sync::Mutex;

/// Error codes — no descriptive strings in the binary.
/// Map maintained in documentation only.
pub mod codes {
    // Crypto
    pub const INVALID_PUBKEY: u8 = 0x01;
    pub const ENCRYPT_FAIL: u8 = 0x02;
    pub const DECRYPT_FAIL: u8 = 0x03;
    pub const SHORT_CIPHERTEXT: u8 = 0x04;
    pub const KEY_DERIVATION: u8 = 0x05;

    // Proto
    pub const SERIALIZE_FAIL: u8 = 0x10;
    pub const INVALID_ENVELOPE: u8 = 0x11;

    // Channel
    pub const SEND_FAIL: u8 = 0x20;
    pub const NO_ENDPOINTS: u8 = 0x21;
    pub const RESOLVE_FAIL: u8 = 0x22;
    pub const CONNECT_FAIL: u8 = 0x23;

    // Config
    pub const CONFIG_READ: u8 = 0x30;
    pub const CONFIG_PARSE: u8 = 0x31;
    pub const CONFIG_KEY: u8 = 0x32;

    // Identity
    pub const IDENTITY_FAIL: u8 = 0x40;

    // General
    pub const BOOTSTRAP_FAIL: u8 = 0xF0;
    pub const FATAL: u8 = 0xFF;
}

static LOG: Mutex<Vec<(u64, u8)>> = Mutex::new(Vec::new());

/// Record an error as timestamp + code. No strings.
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

/// Drain the error log for exfiltration.
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