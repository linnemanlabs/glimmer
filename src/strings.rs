// Include the build-time generated encoded strings
include!(concat!(env!("OUT_DIR"), "/encoded_strings.rs"));

use crate::obfuscate;

/// Decode a build-time encoded string at runtime.
pub fn decode(encoded: &[u8]) -> Vec<u8> {
    obfuscate::decode(encoded, XOR_KEY)
}

/// Decode to String.
pub fn decode_str(encoded: &[u8]) -> String {
    obfuscate::decode_string(encoded, XOR_KEY)
}