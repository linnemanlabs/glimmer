use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("ciphertext too short ({0} bytes, need >= 12)")]
    CiphertextTooShort(usize),

    #[error("key derivation failed: {0}")]
    KeyDerivation(String),
}

#[derive(Error, Debug)]
pub enum ProtoError {
    #[error("serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),

    #[error("invalid envelope: {0}")]
    InvalidEnvelope(String),
}

#[derive(Error, Debug)]
pub enum ChannelError {
    #[error("send failed: {0}")]
    SendFailed(String),

    #[error("no endpoints configured")]
    NoEndpoints,

    #[error("all endpoints exhausted")]
    AllEndpointsFailed,

    #[error("response error: {0}")]
    ResponseError(String),
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("file read error: {0}")]
    FileRead(#[from] std::io::Error),

    #[error("parse error: {0}")]
    Parse(#[from] serde_json::Error),

    #[error("invalid server public key: {0}")]
    InvalidServerKey(String),
}