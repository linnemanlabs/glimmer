use crate::sys;
use core::net::SocketAddr;
use std::error::Error;
use std::fmt;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};

pub type Result<T> = std::result::Result<T, LookupError>;

// RAII wrapper so the socket fd is closed on every return path, including
// error returns out of query_upstream_a / parse_a_aaaa_answers
struct OwnedFd(i32);

impl Drop for OwnedFd {
    fn drop(&mut self) {
        // nothing sensible to do if close(2) fails here
        let _ = sys::close(self.0);
    }
}

// Fresh random TXID per query
fn next_query_id() -> u16 {
    sys::rand_u64() as u16
}

#[derive(Debug)]
pub enum LookupError {
    Io(io::Error),
    Parse(ParseError),
    UpstreamRcode(u8),
}

impl fmt::Display for LookupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LookupError::Io(e) => write!(f, "i/o error: {e}"),
            LookupError::Parse(e) => write!(f, "dns parse error: {e}"),
            LookupError::UpstreamRcode(rcode) => {
                write!(f, "upstream returned DNS rcode {rcode}")
            }
        }
    }
}

impl Error for LookupError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            LookupError::Io(e) => Some(e),
            LookupError::Parse(e) => Some(e),
            LookupError::UpstreamRcode(_) => None,
        }
    }
}

impl From<io::Error> for LookupError {
    fn from(e: io::Error) -> Self {
        LookupError::Io(e)
    }
}

impl From<ParseError> for LookupError {
    fn from(e: ParseError) -> Self {
        LookupError::Parse(e)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    Short,
    NotAResponse,
    UnsupportedOpcode,
    BadName,
    PointerLoop,
    ReservedLabelKind,
    OutputTooSmall,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Short => write!(f, "short DNS message"),
            ParseError::NotAResponse => write!(f, "not a DNS response"),
            ParseError::UnsupportedOpcode => write!(f, "unsupported DNS opcode"),
            ParseError::BadName => write!(f, "invalid DNS name"),
            ParseError::PointerLoop => write!(f, "DNS compression pointer loop"),
            ParseError::ReservedLabelKind => write!(f, "reserved DNS label encoding"),
            ParseError::OutputTooSmall => write!(f, "output buffer too small"),
        }
    }
}

impl Error for ParseError {}

#[derive(Debug, Clone, Copy)]
pub struct DnsHeader {
    pub id: u16,
    pub flags: u16,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl DnsHeader {
    #[inline(always)]
    pub fn qr(self) -> bool {
        (self.flags & 0x8000) != 0
    }

    #[inline(always)]
    pub fn opcode(self) -> u8 {
        ((self.flags >> 11) & 0x0f) as u8
    }

    #[inline(always)]
    pub fn aa(self) -> bool {
        (self.flags & 0x0400) != 0
    }

    #[inline(always)]
    pub fn tc(self) -> bool {
        (self.flags & 0x0200) != 0
    }

    #[inline(always)]
    pub fn rd(self) -> bool {
        (self.flags & 0x0100) != 0
    }

    #[inline(always)]
    pub fn ra(self) -> bool {
        (self.flags & 0x0080) != 0
    }

    #[inline(always)]
    pub fn rcode(self) -> u8 {
        (self.flags & 0x000f) as u8
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ARecord {
    pub addr: Ipv4Addr,
    pub ttl: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct AaaaRecord {
    pub addr: Ipv6Addr,
    pub ttl: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct ParseResult {
    pub header: DnsHeader,
    pub v4_total: usize,
    pub v4_stored: usize,
    pub v6_total: usize,
    pub v6_stored: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct LookupResult {
    pub header: DnsHeader,
    pub v4: [ARecord; 8],
    pub v4_len: usize,
    pub v6: [AaaaRecord; 8],
    pub v6_len: usize,
}

impl LookupResult {
    pub fn v4_records(&self) -> &[ARecord] {
        &self.v4[..self.v4_len]
    }

    pub fn v6_records(&self) -> &[AaaaRecord] {
        &self.v6[..self.v6_len]
    }
}

fn encode_qname(name: &str, out: &mut [u8]) -> io::Result<usize> {
    let mut p = 0;
    let trimmed = name.trim_end_matches('.');

    if trimmed.is_empty() {
        if out.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "buffer too small"));
        }
        out[0] = 0;
        return Ok(1);
    }

    for label in trimmed.split('.') {
        let b = label.as_bytes();

        // Reject empty labels from leading/consecutive dots ("..", ".foo").
        // A zero-length label on the wire is the name terminator; emitting
        // one mid-name would truncate the encoded name.
        if b.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty label"));
        }

        if b.len() > 63 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "label > 63 bytes"));
        }

        if p + 1 + b.len() + 1 > out.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "buffer too small"));
        }

        out[p] = b.len() as u8;
        p += 1;
        out[p..p + b.len()].copy_from_slice(b);
        p += b.len();
    }

    // encoded name (label length octets + labels + root) <= 255.
    if p + 1 > 255 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "name > 255 bytes encoded",
        ));
    }

    out[p] = 0;
    Ok(p + 1)
}

pub fn build_dns_query(id: u16, qname: &str, qtype: u16, out: &mut [u8]) -> io::Result<usize> {
    if out.len() < 12 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "buffer too small"));
    }

    out[0..2].copy_from_slice(&id.to_be_bytes());
    out[2..4].copy_from_slice(&0x0100u16.to_be_bytes()); // RD=1
    out[4..6].copy_from_slice(&1u16.to_be_bytes());      // QDCOUNT=1
    out[6..8].copy_from_slice(&0u16.to_be_bytes());
    out[8..10].copy_from_slice(&0u16.to_be_bytes());
    out[10..12].copy_from_slice(&0u16.to_be_bytes());

    let mut p = 12;
    p += encode_qname(qname, &mut out[p..])?;

    if p + 4 > out.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "buffer too small"));
    }

    out[p..p + 2].copy_from_slice(&qtype.to_be_bytes());
    p += 2;
    out[p..p + 2].copy_from_slice(&1u16.to_be_bytes()); // IN
    p += 2;

    Ok(p)
}

fn query_upstream_a(fd: i32, name: &str, rx: &mut [u8]) -> io::Result<usize> {
    let mut tx = [0u8; 512];
    let id = next_query_id();
    let n = build_dns_query(id, name, 1, &mut tx)?;

    let sent = sys::write(fd, &tx[..n])?;
    if sent != n {
        return Err(io::Error::new(io::ErrorKind::WriteZero, "short write"));
    }
    crate::dbg_log!("[dns] sent query for {}", name);

    let got = sys::read(fd, rx)?;
    if got < 12 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "short DNS response",
        ));
    }

    if rx[0] != (id >> 8) as u8 || rx[1] != (id & 0xff) as u8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "mismatched DNS ID",
        ));
    }

    crate::dbg_log!("[dns] received response");
    Ok(got)
}

// A-only in the current form. need a second qtype=28 lookup fed through
// parse_a_aaaa_answers
//
// TC bit is not checked. Truncated answers are returned with whatever
// survived the 512-byte UDP cut. Acceptable for now
pub fn lookup_a(name: &str) -> Result<LookupResult> {
    let fd = OwnedFd(sys::socket_udp()?);

    let upstream = SocketAddr::from(([10, 90, 95, 53], 53));
    sys::connect_udp(fd.0, &upstream)?;

    // Cap upstream round-trip so a dropped response cannot hang the caller
    sys::set_read_timeout(fd.0, 5)?;

    let mut rx = [0u8; 4096];
    let n = query_upstream_a(fd.0, name, &mut rx)?;
    let msg = &rx[..n];

    // Short-circuit on upstream failure before walking the answer section
    let preview = parse_header(msg)?;
    if preview.rcode() != 0 {
        return Err(LookupError::UpstreamRcode(preview.rcode()));
    }

    let mut v4 = [ARecord {
        addr: Ipv4Addr::UNSPECIFIED,
        ttl: 0,
    }; 8];

    let mut v6 = [AaaaRecord {
        addr: Ipv6Addr::UNSPECIFIED,
        ttl: 0,
    }; 8];

    let parsed = parse_a_aaaa_answers(msg, &mut v4, &mut v6)?;

    Ok(LookupResult {
        header: parsed.header,
        v4,
        v4_len: parsed.v4_stored,
        v6,
        v6_len: parsed.v6_stored,
    })
}

#[inline(always)]
fn be_u16(buf: &[u8], off: usize) -> std::result::Result<u16, ParseError> {
    let s = buf.get(off..off + 2).ok_or(ParseError::Short)?;
    Ok(u16::from_be_bytes([s[0], s[1]]))
}

#[inline(always)]
fn be_u32(buf: &[u8], off: usize) -> std::result::Result<u32, ParseError> {
    let s = buf.get(off..off + 4).ok_or(ParseError::Short)?;
    Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

pub fn parse_header(msg: &[u8]) -> std::result::Result<DnsHeader, ParseError> {
    if msg.len() < 12 {
        return Err(ParseError::Short);
    }

    Ok(DnsHeader {
        id: be_u16(msg, 0)?,
        flags: be_u16(msg, 2)?,
        qdcount: be_u16(msg, 4)?,
        ancount: be_u16(msg, 6)?,
        nscount: be_u16(msg, 8)?,
        arcount: be_u16(msg, 10)?,
    })
}

pub fn skip_name(msg: &[u8], mut off: usize) -> std::result::Result<usize, ParseError> {
    let start = off;

    loop {
        let len = *msg.get(off).ok_or(ParseError::Short)?;

        match len & 0xC0 {
            0x00 => {
                if len == 0 {
                    return Ok(off + 1 - start);
                }

                let label_len = len as usize;
                off += 1;
                msg.get(off..off + label_len).ok_or(ParseError::Short)?;
                off += label_len;
            }
            0xC0 => {
                msg.get(off + 1).ok_or(ParseError::Short)?;
                return Ok(off + 2 - start);
            }
            _ => return Err(ParseError::ReservedLabelKind),
        }
    }
}

pub fn decode_name_into(
    msg: &[u8],
    start: usize,
    out: &mut [u8],
) -> std::result::Result<(usize, usize), ParseError> {
    let mut pos = start;
    let mut consumed = 0usize;
    let mut jumped = false;
    let mut w = 0usize;

    loop {
        let len = *msg.get(pos).ok_or(ParseError::Short)?;

        match len & 0xC0 {
            0x00 => {
                if len == 0 {
                    if !jumped {
                        consumed += 1;
                    }

                    if w == 0 {
                        if out.is_empty() {
                            return Err(ParseError::OutputTooSmall);
                        }
                        out[0] = b'.';
                        return Ok((consumed, 1));
                    }

                    return Ok((consumed, w));
                }

                let label_len = len as usize;
                let label_start = pos + 1;
                let label = msg
                    .get(label_start..label_start + label_len)
                    .ok_or(ParseError::Short)?;

                if w != 0 {
                    if w >= out.len() {
                        return Err(ParseError::OutputTooSmall);
                    }
                    out[w] = b'.';
                    w += 1;
                }

                if w + label_len > out.len() {
                    return Err(ParseError::OutputTooSmall);
                }

                out[w..w + label_len].copy_from_slice(label);
                w += label_len;

                if !jumped {
                    consumed += 1 + label_len;
                }

                pos = label_start + label_len;
            }
            0xC0 => {
                let b2 = *msg.get(pos + 1).ok_or(ParseError::Short)?;
                let ptr = ((len as usize & 0x3F) << 8) | b2 as usize;

                if ptr >= pos {
                    return Err(ParseError::PointerLoop);
                }

                if !jumped {
                    consumed += 2;
                }

                pos = ptr;
                jumped = true;
            }
            _ => return Err(ParseError::ReservedLabelKind),
        }
    }
}

pub fn parse_a_aaaa_answers(
    msg: &[u8],
    v4_out: &mut [ARecord],
    v6_out: &mut [AaaaRecord],
) -> std::result::Result<ParseResult, ParseError> {
    let hdr = parse_header(msg)?;

    if !hdr.qr() {
        return Err(ParseError::NotAResponse);
    }

    if hdr.opcode() != 0 {
        return Err(ParseError::UnsupportedOpcode);
    }

    let mut off = 12usize;

    for _ in 0..hdr.qdcount {
        let nlen = skip_name(msg, off)?;
        off += nlen;
        msg.get(off..off + 4).ok_or(ParseError::Short)?;
        off += 4;
    }

    let mut v4_total = 0usize;
    let mut v4_stored = 0usize;
    let mut v6_total = 0usize;
    let mut v6_stored = 0usize;

    for _ in 0..hdr.ancount {
        let nlen = skip_name(msg, off)?;
        off += nlen;

        let rr_type = be_u16(msg, off)?;
        let rr_class = be_u16(msg, off + 2)?;
        let ttl = be_u32(msg, off + 4)?;
        let rdlen = be_u16(msg, off + 8)? as usize;
        off += 10;

        let rdata = msg.get(off..off + rdlen).ok_or(ParseError::Short)?;

        if rr_class == 1 && rr_type == 1 && rdlen == 4 {
            v4_total += 1;
            if v4_stored < v4_out.len() {
                v4_out[v4_stored] = ARecord {
                    addr: Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]),
                    ttl,
                };
                v4_stored += 1;
            }
        } else if rr_class == 1 && rr_type == 28 && rdlen == 16 {
            v6_total += 1;
            if v6_stored < v6_out.len() {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(rdata);
                v6_out[v6_stored] = AaaaRecord {
                    addr: Ipv6Addr::from(octets),
                    ttl,
                };
                v6_stored += 1;
            }
        }

        off += rdlen;
    }

    Ok(ParseResult {
        header: hdr,
        v4_total,
        v4_stored,
        v6_total,
        v6_stored,
    })
}