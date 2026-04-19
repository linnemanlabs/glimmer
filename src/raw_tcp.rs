use std::io;
use std::net::Ipv4Addr;

/// Raw TCP header - 20 bytes without options
#[repr(C, packed)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub data_offset_flags: u16,
    pub window: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
}

/// TCP flags
pub const TCP_SYN: u16 = 0x002;
pub const TCP_ACK: u16 = 0x010;
pub const TCP_FIN: u16 = 0x001;
pub const TCP_RST: u16 = 0x004;
pub const TCP_PSH: u16 = 0x008;

impl TcpHeader {
    /// Create a new TCP header with specified flags
    pub fn new(
        src_port: u16,
        dst_port: u16,
        seq_num: u32,
        ack_num: u32,
        flags: u16,
    ) -> Self {
        // Data offset = 5 (20 bytes / 4), shifted to upper 4 bits
        let data_offset_flags = (5u16 << 12) | flags;

        TcpHeader {
            src_port: src_port.to_be(),
            dst_port: dst_port.to_be(),
            seq_num: seq_num.to_be(),
            ack_num: ack_num.to_be(),
            data_offset_flags: data_offset_flags.to_be(),
            window: 65535u16.to_be(),
            checksum: 0,
            urgent_ptr: 0,
        }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> [u8; 20] {
        unsafe { std::mem::transmute_copy(self) }
    }
}

/// TCP pseudo-header for checksum calculation
#[repr(C, packed)]
struct PseudoHeader {
    src_addr: u32,
    dst_addr: u32,
    zero: u8,
    protocol: u8,
    tcp_length: u16,
}

/// Calculate TCP checksum over pseudo-header + TCP header + payload
pub fn tcp_checksum(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    tcp_header: &[u8],
    payload: &[u8],
) -> u16 {
    let pseudo = PseudoHeader {
        src_addr: u32::from(src_ip).to_be(),
        dst_addr: u32::from(dst_ip).to_be(),
        zero: 0,
        protocol: 6, // TCP
        tcp_length: ((tcp_header.len() + payload.len()) as u16).to_be(),
    };

    let pseudo_bytes: [u8; 12] =
        unsafe { std::mem::transmute(pseudo) };

    let mut sum: u32 = 0;

    // Sum pseudo-header
    for chunk in pseudo_bytes.chunks(2) {
        let word = u16::from_be_bytes([chunk[0], chunk[1]]);
        sum += word as u32;
    }

    // Sum TCP header
    for chunk in tcp_header.chunks(2) {
        if chunk.len() == 2 {
            let word = u16::from_be_bytes([chunk[0], chunk[1]]);
            sum += word as u32;
        } else {
            sum += (chunk[0] as u32) << 8;
        }
    }

    // Sum payload
    for chunk in payload.chunks(2) {
        if chunk.len() == 2 {
            let word = u16::from_be_bytes([chunk[0], chunk[1]]);
            sum += word as u32;
        } else {
            sum += (chunk[0] as u32) << 8;
        }
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

/// Create a raw TCP socket
pub fn create_raw_socket() -> Result<i32, io::Error> {
    // AF_INET = 2, SOCK_RAW = 3, IPPROTO_TCP = 6
    let fd = unsafe {
        libc::socket(2, 3, 6)
    };

    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

/// Send a raw TCP packet
pub fn send_raw_packet(
    fd: i32,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    packet: &[u8],
) -> Result<usize, io::Error> {
    let addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: dst_port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from(dst_ip).to_be(),
        },
        sin_zero: [0; 8],
    };

    let sent = unsafe {
        libc::sendto(
            fd,
            packet.as_ptr() as *const libc::c_void,
            packet.len(),
            0,
            &addr as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        )
    };

    if sent < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(sent as usize)
    }
}

/// Receive raw packets and filter for our connection
pub fn recv_raw_packet(
    fd: i32,
    buf: &mut [u8],
    timeout_ms: u64,
) -> Result<usize, io::Error> {
    // Set receive timeout
    let tv = libc::timeval {
        tv_sec: (timeout_ms / 1000) as i64,
        tv_usec: ((timeout_ms % 1000) * 1000) as i64,
    };

    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const libc::timeval as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as u32,
        );
    }

    let received = unsafe {
        libc::recvfrom(
            fd,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };

    if received < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(received as usize)
    }
}

/// Parse the TCP header from a received raw packet
/// Raw socket receives include the IP header (20 bytes typically)
pub fn parse_response_header(packet: &[u8]) -> Option<(u16, u16, u32, u32, u16)> {
    // IP header length is in the lower 4 bits of byte 0
    if packet.is_empty() {
        return None;
    }
    let ip_header_len = ((packet[0] & 0x0F) as usize) * 4;

    if packet.len() < ip_header_len + 20 {
        return None;
    }

    let tcp = &packet[ip_header_len..];

    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    let seq_num = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    let ack_num = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
    let flags = u16::from_be_bytes([tcp[12], tcp[13]]) & 0x01FF;

    Some((src_port, dst_port, seq_num, ack_num, flags))
}