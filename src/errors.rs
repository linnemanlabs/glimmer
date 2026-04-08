use thiserror::Error;
use crate::errlog;

// --- Crypto Errors ---

#[derive(Error)]
pub enum CryptoError {
    #[cfg_attr(feature = "debug", error("invalid public key: {0}"))]
    #[cfg_attr(not(feature = "debug"), error("{0}"))]
    InvalidPublicKey(String),

    #[cfg_attr(feature = "debug", error("encryption failed: {0}"))]
    #[cfg_attr(not(feature = "debug"), error("{0}"))]
    EncryptionFailed(String),

    #[cfg_attr(feature = "debug", error("decryption failed: {0}"))]
    #[cfg_attr(not(feature = "debug"), error("{0}"))]
    DecryptionFailed(String),

    #[cfg_attr(feature = "debug", error("ciphertext too short: {0}"))]
    #[cfg_attr(not(feature = "debug"), error("{0}"))]
    CiphertextTooShort(usize),

    #[cfg_attr(feature = "debug", error("key derivation failed: {0}"))]
    #[cfg_attr(not(feature = "debug"), error("{0}"))]
    KeyDerivation(String),
}

impl std::fmt::Debug for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "E{:02x}", match self {
            CryptoError::InvalidPublicKey(_) => 0x01u8,
            CryptoError::EncryptionFailed(_) => 0x02,
            CryptoError::DecryptionFailed(_) => 0x03,
            CryptoError::CiphertextTooShort(_) => 0x04,
            CryptoError::KeyDerivation(_) => 0x05,
        })
    }
}

impl CryptoError {
    pub fn record(&self) {
        let code = match self {
            CryptoError::InvalidPublicKey(_) => errlog::codes::INVALID_PUBKEY,
            CryptoError::EncryptionFailed(_) => errlog::codes::ENCRYPT_FAIL,
            CryptoError::DecryptionFailed(_) => errlog::codes::DECRYPT_FAIL,
            CryptoError::CiphertextTooShort(_) => errlog::codes::SHORT_CIPHERTEXT,
            CryptoError::KeyDerivation(_) => errlog::codes::KEY_DERIVATION,
        };
        errlog::record(code);
    }
}

// --- Proto Errors ---

#[derive(Error)]
pub enum ProtoError {
    #[cfg_attr(feature = "debug", error("serialization failed: {0}"))]
    #[cfg_attr(not(feature = "debug"), error("{0}"))]
    Serialize(#[from] serde_json::Error),

    #[cfg_attr(feature = "debug", error("invalid envelope: {0}"))]
    #[cfg_attr(not(feature = "debug"), error("{0}"))]
    InvalidEnvelope(String),
}

impl std::fmt::Debug for ProtoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "E{:02x}", match self {
            ProtoError::Serialize(_) => 0x10u8,
            ProtoError::InvalidEnvelope(_) => 0x11,
        })
    }
}

impl ProtoError {
    pub fn record(&self) {
        let code = match self {
            ProtoError::Serialize(_) => errlog::codes::SERIALIZE_FAIL,
            ProtoError::InvalidEnvelope(_) => errlog::codes::INVALID_ENVELOPE,
        };
        errlog::record(code);
    }
}

// --- Channel Errors ---

#[derive(Error)]
pub enum ChannelError {
    #[cfg_attr(feature = "debug", error("send failed: {0}"))]
    #[cfg_attr(not(feature = "debug"), error("{0}"))]
    SendFailed(String),

    #[cfg_attr(feature = "debug", error("no endpoints configured"))]
    #[cfg_attr(not(feature = "debug"), error("a"))]
    NoEndpoints,

    #[cfg_attr(feature = "debug", error("all endpoints exhausted"))]
    #[cfg_attr(not(feature = "debug"), error("b"))]
    AllEndpointsFailed,

    #[cfg_attr(feature = "debug", error("response error: {0}"))]
    #[cfg_attr(not(feature = "debug"), error("{0}"))]
    ResponseError(String),
}

impl std::fmt::Debug for ChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "E{:02x}", match self {
            ChannelError::SendFailed(_) => 0x20u8,
            ChannelError::NoEndpoints => 0x21,
            ChannelError::AllEndpointsFailed => 0x22,
            ChannelError::ResponseError(_) => 0x23,
        })
    }
}

impl ChannelError {
    pub fn record(&self) {
        let code = match self {
            ChannelError::SendFailed(_) => errlog::codes::SEND_FAIL,
            ChannelError::NoEndpoints => errlog::codes::NO_ENDPOINTS,
            ChannelError::AllEndpointsFailed => errlog::codes::CONNECT_FAIL,
            ChannelError::ResponseError(_) => errlog::codes::SEND_FAIL,
        };
        errlog::record(code);
    }
}

// --- Config Errors ---

#[derive(Error)]
pub enum ConfigError {
    #[cfg_attr(feature = "debug", error("file read error: {0}"))]
    #[cfg_attr(not(feature = "debug"), error("{0}"))]
    FileRead(#[from] std::io::Error),

    #[cfg_attr(feature = "debug", error("parse error: {0}"))]
    #[cfg_attr(not(feature = "debug"), error("{0}"))]
    Parse(#[from] serde_json::Error),

    #[cfg_attr(feature = "debug", error("invalid key: {0}"))]
    #[cfg_attr(not(feature = "debug"), error("{0}"))]
    InvalidServerKey(String),
}

impl std::fmt::Debug for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "E{:02x}", match self {
            ConfigError::FileRead(_) => 0x30u8,
            ConfigError::Parse(_) => 0x31,
            ConfigError::InvalidServerKey(_) => 0x32,
        })
    }
}

impl ConfigError {
    pub fn record(&self) {
        let code = match self {
            ConfigError::FileRead(_) => errlog::codes::CONFIG_READ,
            ConfigError::Parse(_) => errlog::codes::CONFIG_PARSE,
            ConfigError::InvalidServerKey(_) => errlog::codes::CONFIG_KEY,
        };
        errlog::record(code);
    }
}