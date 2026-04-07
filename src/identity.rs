use sha2::{Digest, Sha256};

use crate::sys;

pub fn generate() -> String {
    let mut hasher = Sha256::new();


    // Filesystem UUID from root partition via /proc/mounts
    let root_id = sys::read_file_string("/proc/mounts")
        .ok()
        .and_then(|m| extract_root_uuid(&m))
        .or_else(|| fallback_uuid());

    if let Some(uuid) = root_id {
        crate::dbg_log!("identity: root fs uuid = {}", uuid);
        hasher.update(uuid.as_bytes());
        hasher.update(b"\0");
    } else {
        crate::dbg_log!("identity: no root fs uuid found, skipping");
    }

    // CPU model - stable, unique enough for hardware differentiation,
    // /proc/cpuinfo is read constantly by normal processes
    if let Ok(cpuinfo) = sys::read_file_string("/proc/cpuinfo") {
        if let Some(model) = extract_cpu_model(&cpuinfo) {
            crate::dbg_log!("identity: cpu model = {}", model);
            hasher.update(model.as_bytes());
            hasher.update(b"\0");
        }
    }

    // Kernel version from /proc/version - unique per kernel build,
    // changes on kernel updates but stable between reboots
    if let Ok(version) = sys::read_file_string("/proc/version") {
        crate::dbg_log!("identity: kernel = {}", version);
        hasher.update(version.as_bytes());
        hasher.update(b"\0");
    }

    // Architecture
    let arch = std::env::consts::ARCH;
    crate::dbg_log!("identity: arch = {}", arch);
    hasher.update(arch.as_bytes());
    hasher.update(b"\0");

    let hash = hasher.finalize();
    hex::encode(&hash[..8])
}

/// Extract root filesystem UUID from /proc/mounts.
/// Lines look like: /dev/mapper/fedora-root / ext4 rw,seclabel,relatime 0 0
/// Or sometimes: UUID=xxxx-xxxx / ext4 ...
fn extract_root_uuid(mounts: &str) -> Option<String> {
    for line in mounts.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 2 && fields[1] == "/" {
            let device = fields[0];

            // Some systems mount with UUID= directly
            if device.starts_with("UUID=") {
                return Some(device.trim_start_matches("UUID=").to_string());
            }

            // For /dev/mapper or /dev/sdX, resolve through by-uuid symlinks
            // Try reading the dm uuid from sysfs
            if device.starts_with("/dev/mapper/") {
                let dm_name = device.trim_start_matches("/dev/mapper/");
                let uuid_path = format!("/sys/block/dm-0/dm/uuid");
                if let Ok(uuid) = sys::read_file_string(&uuid_path) {
                    if uuid.contains(dm_name) || !uuid.is_empty() {
                        return Some(uuid);
                    }
                }
            }

            // For regular block devices, check /sys/class/block/*/uuid
            if device.starts_with("/dev/") {
                let dev_name = device.trim_start_matches("/dev/");
                // Replace slashes for partition names like sda1
                let uuid_path = format!("/sys/class/block/{}/uuid", dev_name);
                if let Ok(uuid) = sys::read_file_string(&uuid_path) {
                    return Some(uuid);
                }
            }

            // Last resort: use the device path itself as identity component
            // Not a UUID but at least unique per mount configuration
            crate::dbg_log!("identity: no uuid found, using device path: {}", device);
            return Some(device.to_string());
        }
    }
    None
}

fn fallback_uuid() -> Option<String> {
    let mountinfo = sys::read_file_string("/proc/self/mountinfo").ok()?;

    for line in mountinfo.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 5 && fields[4] == "/" {
            let majmin = fields[2];
            let parts: Vec<&str> = majmin.split(':').collect();
            if parts.len() == 2 {
                if let Ok(major) = parts[0].parse::<u32>() {
                    if major == 252 || major == 253 {
                        let dm_name = format!("dm-{}", parts[1]);
                        let uuid_path = format!("/sys/block/{}/dm/uuid", dm_name);
                        if let Ok(uuid) = sys::read_file_string(&uuid_path) {
                            crate::dbg_log!("identity: fallback sysfs dm uuid = {}", uuid);
                            return Some(uuid);
                        }
                    }
                }
            }
        }
    }

    crate::dbg_log!("identity: fallback uuid also failed, skipping");
    None
}

fn extract_cpu_model(cpuinfo: &str) -> Option<String> {
    for line in cpuinfo.lines() {
        if line.starts_with("model name") {
            if let Some(value) = line.split(':').nth(1) {
                return Some(value.trim().to_string());
            }
        }
    }
    None
}