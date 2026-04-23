// use glimmer::sys;
use std::io;
use glimmer::sys;

fn main() -> io::Result<()> {
    println!("[*] Creating raw socket...");
    
    let fd = unsafe { libc::socket(2, 3, 6) }; // AF_INET, SOCK_RAW, TCP
    //let fd = sys::socket_tcp()?;
    
    println!("[*] Socket fd: {}", fd);
    
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        println!("[!] Socket creation failed: {}", err);
        return Ok(());
    }

    // Set IP_HDRINCL, we are providing the IP header ourselves
    let one: i32 = 1;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_HDRINCL,
            &one as *const i32 as *const libc::c_void,
            std::mem::size_of::<i32>() as u32,
        )
    };
    println!("[*] IP_HDRINCL set: {}", if ret == 0 { "ok" } else { "FAILED" });

    // let r = sys::rand_u64();

    let src_ip: [u8; 4] = [127, 0, 0, 1];
    let dst_ip: [u8; 4] = [127, 0, 0, 1];
    let src_port: u16 = 45000;
    // let src_port: u16 = 1024 + ((r as u32) % (65536 - 1024)) as u16;
    let dst_port: u16 = 8080;
    let seq_num: u32 = 0xDEADBEEF;

    // Build IP header (20 bytes) + TCP header (20 bytes) = 40 bytes
    let mut packet: [u8; 40] = [0; 40];

    // IP Header
    packet[0] = 0x45;           // Version 4, IHL 5 (20 bytes)
    packet[1] = 0x00;           // DSCP/ECN
    let total_len: u16 = 40;
    packet[2..4].copy_from_slice(&total_len.to_be_bytes()); // Total length
    // packet[4..6].copy_from_slice(&0x1234u16.to_be_bytes()); // IPID
    let ip_id = sys::rand_u64() as u16;
    packet[4..6].copy_from_slice(&ip_id.to_be_bytes()); // IPID
    packet[6] = 0x40;           // Dont fragment
    packet[7] = 0x00;           // Fragment offset
    packet[8] = 64;             // TTL
    packet[9] = 6;              // Protocol: TCP
    // packet[10..12] = checksum (kernel fills this with IP_HDRINCL)
    packet[12..16].copy_from_slice(&src_ip);
    packet[16..20].copy_from_slice(&dst_ip);

    // TCP Header
    let tcp = &mut packet[20..];
    tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    tcp[4..8].copy_from_slice(&seq_num.to_be_bytes());
    // Ack = 0
    let offset_flags: u16 = (5 << 12) | 0x002; // SYN
    tcp[12..14].copy_from_slice(&offset_flags.to_be_bytes());
    tcp[14..16].copy_from_slice(&65535u16.to_be_bytes()); // Window

    // TCP checksum - compute over pseudo-header + tcp header
    let mut csum: u32 = 0;
    // Pseudo header
    csum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
    csum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
    csum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
    csum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
    csum += 6u32;    // protocol TCP
    csum += 20u32;   // TCP length
    // TCP header
    for i in (0..20).step_by(2) {
        csum += u16::from_be_bytes([tcp[i], tcp[i + 1]]) as u32;
    }
    while (csum >> 16) != 0 {
        csum = (csum & 0xFFFF) + (csum >> 16);
    }
    let checksum = !(csum as u16);
    tcp[16..18].copy_from_slice(&checksum.to_be_bytes());

    println!("[*] Full packet built: {} bytes (IP + TCP)", packet.len());
    println!("[*] TCP checksum: 0x{:04X}", checksum);

    let addr = libc::sockaddr_in {
        sin_family: 2,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(dst_ip),
        },
        sin_zero: [0; 8],
    };

    println!("[*] Sending...");

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
        let err = std::io::Error::last_os_error();
        println!("[!] sendto failed: {}", err);
    } else {
        println!("[+] Sent {} bytes!", sent);
    }

    unsafe { libc::close(fd); }
    println!("[*] Done");
    return Ok(())
}