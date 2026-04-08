fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: encode_string <key_hex> <string>");
        eprintln!("Example: encode_string 4f2a7b1d 'POST / HTTP/1.1'");
        std::process::exit(1);
    }

    let key = hex::decode(&args[1]).expect("invalid hex key");
    let plaintext = args[2].as_bytes();

    let encoded: Vec<u8> = plaintext
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect();

    // Output as Rust byte array literal
    print!("&[");
    for (i, b) in encoded.iter().enumerate() {
        if i > 0 { print!(", "); }
        print!("0x{:02x}", b);
    }
    println!("]");
}