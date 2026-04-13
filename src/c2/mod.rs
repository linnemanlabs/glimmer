pub mod dnf;
pub mod http;

use crate::crypto;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Latency {
    Realtime,
    Minutes,
    Hours,
}

pub struct ChannelInfo {
    pub name: &'static str,
    pub max_payload: usize,
    pub bidirectional: bool,
    pub confirmed: bool,
    pub stealth: u8,
    pub latency: Latency,
}

/// Metadata that every channel must carry regardless of transport.
pub struct SendContext {
    pub key_id: [u8; 4],
    pub node_id: String,
    pub payload: Vec<u8>,
}

impl SendContext {
    pub fn new(server_pub_key: &[u8], node_id: &str, payload: Vec<u8>) -> Self {
        SendContext {
            key_id: crypto::key_id(server_pub_key),
            node_id: node_id.to_string(),
            payload,
        }
    }
}

pub trait Channel {
    fn info(&self) -> &ChannelInfo;

    /// Send payload with metadata. Returns optional response
    /// for bidirectional channels, None for fire-and-forget.
    fn send(&self, ctx: &SendContext) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>>;
}