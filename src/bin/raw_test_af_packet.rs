// use std::mem;
use libc::{socket,  AF_PACKET, SOCK_DGRAM, ETH_P_IP};
use std::ffi::CString;
use std::ffi::CStr;
use std::fs;
use std::io;
use glimmer::dns;
use glimmer::sys;

fn main() -> std::io::Result<()> {
    // Open AF_PACKET SOCK_DGRAM socket
    let fd = unsafe { socket(AF_PACKET, SOCK_DGRAM, (ETH_P_IP as u16).to_be() as i32) };
    if fd < 0 { return Err(std::io::Error::last_os_error()); }

    // hardcoding interface name  testing for now
    let ifname = CString::new("eno1").unwrap();

    // Figure out the gateway IP from the default route
    let gateway_ip = get_default_gateway()?;
    println!("[*] Gateway: {}", gateway_ip);
    let src_ip: [u8; 4] = get_interface_ipv4("eno1").expect("Could not find Ipv4 addr on eno1");
    println!("[*] Source IP: {:?}", src_ip);

    // 3. Look up gateway's MAC from ARP table
    let gateway_mac = get_gateway_mac(&gateway_ip)?;
    println!("[*] Gateway MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
             gateway_mac[0], gateway_mac[1], gateway_mac[2],
             gateway_mac[3], gateway_mac[4], gateway_mac[5]);

    // 4. Get interface index
    let if_index = unsafe { libc::if_nametoindex(ifname.as_ptr()) } as i32;

    // let src_ip: [u8; 4] = [10, 90, 90, 154];
    let dst_ip: [u8; 4] = [10, 90, 95, 53];

    let src_port = sys::rand_u64() as u16;
    let dst_port: u16 = 53;

    let mut dns_buf = [0u8; 512];
    let qid = sys::rand_u64() as u16; // random query id

    // Build the IP packet: IP header + UDP header + DNS query payload

    let dns_len = dns::build_dns_query(qid,"test.com", 1, &mut dns_buf)?;  // build dns query packet in dns_buf, return len
    let udp_len = 8 + dns_len as u16; // 8-byte UDP Header + payload (len of dns query in dns_buf)
    let total_len: u16 = 20 + udp_len; // 20-byte IP header + 8-byte UDP header + payload (len of dns query in dns_buf)

    let mut packet = vec![0u8; total_len as usize];

    // IP header (20 bytes):
    packet[0] = 0x45; // IPv4
    packet[1] = 0x00; // DSCP/ECN
    packet[2..4].copy_from_slice(&total_len.to_be_bytes()); // calc above: 20-byte IP header + 8-byte UDP header + payload (len of dns query in dns_buf)
    //packet[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
    let ip_id = sys::rand_u64() as u16;
    packet[4..6].copy_from_slice(&ip_id.to_be_bytes()); // IPID
    // packet[6] = 0x40; // dont fragment
    packet[6] = 0x00; // no flags, common for a small dns query packet
    packet[7] = 0x00;
    packet[8] = 64;
    packet[9] = 17;  // UDP
    packet[12..16].copy_from_slice(&src_ip);
    packet[16..20].copy_from_slice(&dst_ip);

    // Compute IP checksum (standard Internet checksum over the 20-byte header)
    let ip_csum = internet_checksum(&packet[0..20]);
    packet[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    // UDP header (8 bytes)
    packet[20..22].copy_from_slice(&src_port.to_be_bytes()); // src_port
    packet[22..24].copy_from_slice(&dst_port.to_be_bytes());  // 53
    packet[24..26].copy_from_slice(&udp_len.to_be_bytes()); // len of 8-byte header and udp payload
    // checksum in 26..28 is calculated after the rest of packet is built

    // DNS payload
    // packet[28..].copy_from_slice(&dns_payload);
    packet[28..28 + dns_len].copy_from_slice(&dns_buf[..dns_len]); // add the dns query we generated earlier to the packet

    // Calculate checksum over the full udp section (pseudo-header, udp header, dns payload)
    let udp_section = &packet[20..20 + udp_len as usize];
    let csum = compute_udp_checksum(src_ip, dst_ip, udp_section);
    packet[26..28].copy_from_slice(&csum.to_be_bytes());  // write checksum to 26..28 (6..8 of UDP header from earlier)

    // Ethernet Frame header
    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_protocol = (libc::ETH_P_IP as u16).to_be();
    /*
    addr.sll_ifindex = unsafe {
        libc::if_nametoindex(b"eno1\0".as_ptr() as *const _) as i32
    };
    */
    addr.sll_ifindex = if_index;
    addr.sll_halen = 6;
    addr.sll_addr[0..6].copy_from_slice(&gateway_mac);

    let sent = unsafe {
        libc::sendto(
            fd,
            packet.as_ptr() as *const libc::c_void,
            packet.len(),
            0,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as u32,
        )
    };

    if sent < 0 {
        return Err(std::io::Error::last_os_error());
    }
    
    println!("sent {} bytes via AF_PACKET", sent);
    Ok(())
}

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in data.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]]) as u32
        } else {
            (chunk[0] as u32) << 8
        };
        sum += word;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

// Compute UDP checksum over pseudo-header + UDP header + payload
fn compute_udp_checksum(src_ip: [u8; 4], dst_ip: [u8; 4], udp_packet: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    
    // Pseudo-header: src IP (4B) + dst IP (4B) + zero (1B) + protocol (1B) + UDP length (2B)
    sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
    sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
    sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
    sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
    sum += 17u32;  // UDP protocol number
    sum += udp_packet.len() as u32;  // UDP length
    
    // UDP header + payload, summed as 16-bit words
    let mut i = 0;
    while i + 1 < udp_packet.len() {
        sum += u16::from_be_bytes([udp_packet[i], udp_packet[i + 1]]) as u32;
        i += 2;
    }
    // Odd length gets padded with zero
    if i < udp_packet.len() {
        sum += (udp_packet[i] as u32) << 8;
    }
    
    // Fold 32-bit sum to 16 bits
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    let checksum = !(sum as u16);
    // 0 is reserved to mean "no checksum"
    // if checksum is 0, transmit as 0xFFFF
    if checksum == 0 { 0xFFFF } else { checksum }
}

fn get_default_gateway() -> io::Result<String> {
    let route = fs::read_to_string("/proc/net/route")?;
    
    for line in route.lines().skip(1) {  // skip header
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 3 && fields[1] == "00000000" {
            // Gateway is in hex, little-endian
            let gw_hex = u32::from_str_radix(fields[2], 16).unwrap_or(0);
            let gw_bytes = gw_hex.to_le_bytes();
            return Ok(format!("{}.{}.{}.{}", gw_bytes[0], gw_bytes[1], gw_bytes[2], gw_bytes[3]));
        }
    }
    
    Err(io::Error::new(io::ErrorKind::NotFound, "default gateway not found"))
}

fn get_gateway_mac(gateway_ip: &str) -> io::Result<[u8; 6]> {
    let arp = fs::read_to_string("/proc/net/arp")?;
    
    for line in arp.lines().skip(1) {  // skip header
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 4 && fields[0] == gateway_ip {
            let mac_str = fields[3];
            let mac_bytes: Vec<u8> = mac_str
                .split(':')
                .map(|b| u8::from_str_radix(b, 16).unwrap_or(0))
                .collect();
            if mac_bytes.len() == 6 {
                let mut result = [0u8; 6];
                result.copy_from_slice(&mac_bytes);
                return Ok(result);
            }
        }
    }
    
    Err(io::Error::new(io::ErrorKind::NotFound, "gateway MAC not found in ARP table"))
}

fn get_interface_ipv4(ifname: &str) -> Option<[u8; 4]> {
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut ifap) } != 0 {
        return None;
    }

    let mut current = ifap;
    let mut result = None;

    while !current.is_null() {
        unsafe {
            let name = CStr::from_ptr((*current).ifa_name).to_string_lossy();
            if name == ifname && !(*current).ifa_addr.is_null() {
                let sa = (*current).ifa_addr;
                if (*sa).sa_family as i32 == libc::AF_INET {
                    let sin = sa as *const libc::sockaddr_in;
                    let addr_bytes = (*sin).sin_addr.s_addr.to_ne_bytes();
                    result = Some(addr_bytes);
                    break;
                }
            }
            current = (*current).ifa_next;
        }
    }

    unsafe { libc::freeifaddrs(ifap) };
    result
}