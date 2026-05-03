//! Compile-time string obfuscation via proc macro.
//! Each obfs!("...") call site gets:
//!   - a unique random key generated at compile time
//!   - a per-byte operation selected by the key (XOR, ADD, SUB, NOT-XOR)
//!   - inline decode logic with no shared function to hook
//!   - stack-allocated output with volatile zeroing on drop
//! For strings ≤ 96 bytes, no loop pattern exists in the binary.

extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, LitStr};

/// Maximum string length for full unrolling
const UNROLL_THRESHOLD: usize = 96;

/// Four reversible byte operations, selected per-byte by `key[i] % 4`.
///   op 0: XOR          - encode: p ^ k,    decode: e ^ k
///   op 1: wrapping ADD - encode: p + k,    decode: e - k
///   op 2: wrapping SUB - encode: p - k,    decode: e + k
///   op 3: NOT-XOR      - encode: !(p ^ k), decode: !e ^ k
fn encode_byte(plain: u8, key: u8) -> u8 {
    match key % 4 {
        0 => plain ^ key,
        1 => plain.wrapping_add(key),
        2 => plain.wrapping_sub(key),
        3 => !(plain ^ key),
        _ => unreachable!(),
    }
}

/// Read n bytes from /dev/urandom. Proc macros execute on the build host at
/// compile time so /dev/urandom is fine
fn random_bytes(n: usize) -> Vec<u8> {
    use std::io::Read;
    let mut buf = vec![0u8; n];
    std::fs::File::open("/dev/urandom")
        .expect("failed to open /dev/urandom")
        .read_exact(&mut buf)
        .expect("failed to read /dev/urandom");
    buf
}

#[proc_macro]
pub fn obfs(input: TokenStream) -> TokenStream {
    let lit = parse_macro_input!(input as LitStr);
    let plaintext = lit.value();
    let bytes = plaintext.as_bytes();
    let len = bytes.len();

    if len == 0 {
        return quote! {
            glimmer_obfstr::SecureBuffer::<0>::new([])
        }
        .into();
    }

    let key = random_bytes(len);

    // Encode each byte with its position-dependent operation
    let encoded: Vec<u8> = bytes
        .iter()
        .enumerate()
        .map(|(i, &b)| encode_byte(b, key[i]))
        .collect();

    if len <= UNROLL_THRESHOLD {
        emit_unrolled(&encoded, &key, len)
    } else {
        emit_looped(&encoded, &key, len)
    }
}

/// Emit fully unrolled decode - no loop, no arrays, no patterns
fn emit_unrolled(encoded: &[u8], key: &[u8], len: usize) -> TokenStream {
    let assignments: Vec<proc_macro2::TokenStream> = encoded
        .iter()
        .enumerate()
        .map(|(i, &enc)| {
            let k = key[i];
            let idx = i;
            let op = k % 4;

            match op {
                // XOR - self-inverse
                0 => quote! { __buf[#idx] = core::hint::black_box(#enc) ^ #k; },
                // Reverse of wrapping_add
                1 => quote! { __buf[#idx] = core::hint::black_box(#enc).wrapping_sub(#k); },
                // Reverse of wrapping_sub
                2 => quote! { __buf[#idx] = core::hint::black_box(#enc).wrapping_add(#k); },
                // Reverse of NOT-XOR: decode = !enc ^ key
                3 => quote! { __buf[#idx] = (!core::hint::black_box(#enc)) ^ #k; },
                _ => unreachable!(),
            }
        })
        .collect();

    quote! {
        {
            let mut __buf = [0u8; #len];
            #(#assignments)*
            glimmer_obfstr::SecureBuffer::new(__buf)
        }
    }
    .into()
}

/// Emit loop-based decode for longer strings
fn emit_looped(encoded: &[u8], key: &[u8], len: usize) -> TokenStream {
    let ops: Vec<u8> = key.iter().map(|k| k % 4).collect();

    let enc_bytes = encoded.iter().copied();
    let key_bytes = key.iter().copied();
    let op_bytes = ops.iter().copied();

    quote! {
        {
            const __ENC: [u8; #len] = [#(#enc_bytes),*];
            const __KEY: [u8; #len] = [#(#key_bytes),*];
            const __OPS: [u8; #len] = [#(#op_bytes),*];
            let mut __buf = [0u8; #len];
            let mut __i = 0usize;
            while __i < #len {
                __buf[__i] = match __OPS[__i] {
                    0 => core::hint::black_box(__ENC[__i]) ^ __KEY[__i],
                    1 => core::hint::black_box(__ENC[__i]).wrapping_sub(__KEY[__i]),
                    2 => core::hint::black_box(__ENC[__i]).wrapping_add(__KEY[__i]),
                    _ => (!core::hint::black_box(__ENC[__i])) ^ __KEY[__i],
                };
                __i += 1;
            }
            glimmer_obfstr::SecureBuffer::new(__buf)
        }
    }
    .into()
}