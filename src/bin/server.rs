use std::io::Read;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use base64::Engine;

use glimmer::crypto;
use glimmer::keystore::KeyStore;
use glimmer::proto::{Envelope, MsgType};

struct Server {
    keystore: KeyStore,
}

impl Server {
    fn new() -> Self {
        let keystore = KeyStore::load("keys").expect("failed to load keystore");
        Server { keystore }
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

    glimmer::dbg_log!("headers: {:?}", _headers);

    if body.len() < 8 {
        return Err("body too short".into());
    }

    let key_id_hex = &body[..8];
    let payload_b64 = &body[8..];

    let key_id_bytes: [u8; 4] = hex::decode(key_id_hex)?
        .try_into()
        .map_err(|_| "invalid key_id length")?;

    let decoded = BASE64.decode(payload_b64)?;

    // Look up server keypair by key_id
    let keypair = server
        .keystore
        .get(&key_id_bytes)
        .ok_or_else(|| format!("unknown key_id: {}", key_id_hex))?;

    // Every message starts with 33-byte ephemeral pubkey
    // Check if there's a second 33-byte response pubkey
    let has_response_key = decoded.len() > 66
        && (decoded[0] == 0x02 || decoded[0] == 0x03)
        && (decoded[33] == 0x02 || decoded[33] == 0x03);

    let (plaintext, response_pub) = if has_response_key {
        let (plain, resp_pub) = crypto::decrypt_from_beacon_with_response(&decoded, keypair)?;
        (plain, Some(resp_pub))
    } else {
        let plain = crypto::decrypt_from_beacon(&decoded, keypair)?;
        (plain, None)
    };

    let envelope = Envelope::unmarshal(&plaintext)?;
    let ts = chrono::DateTime::from_timestamp(envelope.timestamp, 0)
        .map(|t| t.format("%H:%M:%S").to_string())
        .unwrap_or_else(|| "???".into());

    match envelope.msg_type {
        MsgType::Checkin => {
            if let Some(payload) = &envelope.payload {
                let checkin: glimmer::proto::CheckinData = serde_json::from_slice(payload)?;
                eprintln!(
                    "[checkin] {} node={} os={}/{} host={} pid={} key_id={} [ephemeral ECDH]",
                    ts,
                    envelope.node_id,
                    checkin.os,
                    checkin.arch,
                    checkin.host,
                    checkin.pid,
                    key_id_hex,
                );
            }
        }
        MsgType::Beacon => {
            eprintln!("[beacon] {} node={} key_id={}", ts, envelope.node_id, key_id_hex);
        }
        MsgType::Result => {
            eprintln!(
                "[result] {} node={} payload={} bytes",
                ts,
                envelope.node_id,
                envelope.payload.as_ref().map(|p| p.len()).unwrap_or(0),
            );
        }
    }

    // Send response
    let response = if response_pub.is_some() {
        // TODO: encrypt actual tasking here
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_string()
    } else {
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_string()
    };

    std::io::Write::write_all(&mut stream, response.as_bytes())?;

    Ok(())
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