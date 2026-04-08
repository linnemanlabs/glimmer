use sha2::{Digest, Sha256};
use crate::sys;
use crate::strings;

pub fn generate() -> String {
    let mut hasher = Sha256::new();

    // Filesystem UUID from root partition
    let root_id = sys::read_file_string(&strings::decode_str(strings::PROC_MOUNTS))
        .ok()
        .and_then(|m| extract_root_uuid(&m))
        .or_else(|| fallback_uuid());

    if let Some(uuid) = root_id {
        crate::dbg_log!("[dev] identity: root fs uuid = {}", uuid);
        hasher.update(uuid.as_bytes());
        hasher.update(b"\0");
    } else {
        crate::dbg_log!("[dev] identity: no root fs uuid found, skipping");
    }

    // CPU model
    if let Ok(cpuinfo) = sys::read_file_string(&strings::decode_str(strings::PROC_CPUINFO)) {
        if let Some(model) = extract_cpu_model(&cpuinfo) {
            crate::dbg_log!("[dev] identity: cpu model = {}", model);
            hasher.update(model.as_bytes());
            hasher.update(b"\0");
        }
    }

    // Kernel version
    if let Ok(version) = sys::read_file_string(&strings::decode_str(strings::PROC_VERSION)) {
        crate::dbg_log!("[dev] identity: kernel = {}", version);
        hasher.update(version.as_bytes());
        hasher.update(b"\0");
    }

    // Architecture
    let arch = std::env::consts::ARCH;
    crate::dbg_log!("[dev] identity: arch = {}", arch);
    hasher.update(arch.as_bytes());
    hasher.update(b"\0");

    let hash = hasher.finalize();
    hex::encode(&hash[..8])
}

fn extract_root_uuid(mounts: &str) -> Option<String> {
    let uuid_prefix = strings::decode_str(strings::UUID_PREFIX);
    let dev_mapper = strings::decode_str(strings::DEV_MAPPER);
    let sys_dm_uuid = strings::decode_str(strings::SYS_DM_UUID);

    for line in mounts.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 2 && fields[1] == "/" {
            let device = fields[0];

            if device.starts_with(&uuid_prefix) {
                return Some(device.trim_start_matches(&uuid_prefix).to_string());
            }

            if device.starts_with(&dev_mapper) {
                if let Ok(uuid) = sys::read_file_string(&sys_dm_uuid) {
                    if !uuid.is_empty() {
                        return Some(uuid);
                    }
                }
            }

            if device.starts_with("/dev/") {
                let dev_name = device.trim_start_matches("/dev/");
                let uuid_path = format!("/sys/class/block/{}/uuid", dev_name);
                if let Ok(uuid) = sys::read_file_string(&uuid_path) {
                    return Some(uuid);
                }
            }

            crate::dbg_log!("[dev] identity: no uuid found, using device path: {}", device);
            return Some(device.to_string());
        }
    }
    None
}

fn fallback_uuid() -> Option<String> {
    let mountinfo = sys::read_file_string(&strings::decode_str(strings::PROC_MOUNTINFO)).ok()?;

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
                            crate::dbg_log!("[dev] identity: fallback sysfs dm uuid = {}", uuid);
                            return Some(uuid);
                        }
                    }
                }
            }
        }
    }

    crate::dbg_log!("[dev] identity: fallback uuid also failed, skipping");
    None
}

fn extract_cpu_model(cpuinfo: &str) -> Option<String> {
    let model_name = strings::decode_str(strings::MODEL_NAME);
    for line in cpuinfo.lines() {
        if line.starts_with(&model_name) {
            if let Some(value) = line.split(':').nth(1) {
                return Some(value.trim().to_string());
            }
        }
    }
    None
}