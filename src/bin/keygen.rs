use glimmer::crypto::{self, StaticKeypair};

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| "keys".into());

    std::fs::create_dir_all(&path).expect("failed to create keys directory");

    let keypair = StaticKeypair::generate();
    let pub_bytes = keypair.public_key_bytes();
    let kid = crypto::key_id(&pub_bytes);
    let kid_hex = hex::encode(kid);
    let pub_hex = hex::encode(&pub_bytes);
    let secret_hex = keypair.secret_bytes_hex();

    let key_path = format!("{}/{}.key", path, kid_hex);
    std::fs::write(&key_path, &secret_hex).expect("failed to write key file");

    eprintln!("Key ID:     {}", kid_hex);
    eprintln!("Public key: {}", pub_hex);
    eprintln!("Saved to:   {}", key_path);
    eprintln!();
    eprintln!("Add to config.json:");
    eprintln!("  \"server_public_key\": \"{}\"", pub_hex);
}