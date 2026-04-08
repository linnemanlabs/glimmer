/// Decode bytes that were XOR-encoded at build time.
/// Key rotates per byte position for resistance to single-byte XOR analysis.
pub fn decode(encoded: &[u8], key: &[u8]) -> Vec<u8> {
    encoded
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect()
}

/// Encode bytes for embedding in source code.
pub fn encode(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    decode(plaintext, key)
}

/// Decode and return as String.
pub fn decode_string(encoded: &[u8], key: &[u8]) -> String {
    String::from_utf8_lossy(&decode(encoded, key)).to_string()
}