use thiserror::Error;

#[derive(Error, Debug)]
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

#[derive(Error, Debug)]
pub enum ProtoError {
    #[cfg_attr(feature = "debug", error("serialization failed: {0}"))]
    #[cfg_attr(not(feature = "debug"), error("{0}"))]
    Serialize(#[from] serde_json::Error),

    #[cfg_attr(feature = "debug", error("invalid envelope: {0}"))]
    #[cfg_attr(not(feature = "debug"), error("{0}"))]
    InvalidEnvelope(String),
}

#[derive(Error, Debug)]
pub enum ChannelError {
    #[cfg_attr(feature = "debug", error("send failed: {0}"))]
    #[cfg_attr(not(feature = "debug"), error("{0}"))]
    SendFailed(String),

    #[cfg_attr(feature = "debug", error("no endpoints configured"))]
    #[cfg_attr(not(feature = "debug"), error(""))]
    NoEndpoints,

    #[cfg_attr(feature = "debug", error("all endpoints exhausted"))]
    #[cfg_attr(not(feature = "debug"), error(""))]
    AllEndpointsFailed,

    #[cfg_attr(feature = "debug", error("response error: {0}"))]
    #[cfg_attr(not(feature = "debug"), error("{0}"))]
    ResponseError(String),
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[cfg_attr(feature = "debug", error("file read error: {0}"))]
    #[cfg_attr(not(feature = "debug"), error("{0}"))]
    FileRead(#[from] std::io::Error),

    #[cfg_attr(feature = "debug", error("parse error: {0}"))]
    #[cfg_attr(not(feature = "debug"), error("{0}"))]
    Parse(#[from] serde_json::Error),

    #[cfg_attr(feature = "debug", error("invalid server public key: {0}"))]
    #[cfg_attr(not(feature = "debug"), error("{0}"))]
    InvalidServerKey(String),
}