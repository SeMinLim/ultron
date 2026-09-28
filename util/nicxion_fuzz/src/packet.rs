//! Ethernet / IPv4 / IPv6 / TCP-UDP-ICMP frame builder and a classic pcap writer.
//!
//! ICMP matches the host and C parsers: the payload starts right after the
//! type/code bytes (no checksum/rest-of-header is skipped).

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;

#[derive(Clone, Copy, Debug)]
pub struct L4 {
    pub proto: u8,
    pub sport: u16,
    pub dport: u16,
    pub icmp: (u8, u8),
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Shape {
    pub vlan: bool,
    pub ip_opt_words: u8,  // extra 32-bit words of IPv4 options (IHL = 5 + n)
    pub tcp_opt_words: u8, // extra 32-bit words of TCP options (doff = 5 + n)
    pub qinq: bool,        // 802.1ad outer tag in front of the 802.1Q tag
    pub ipv6: bool,        // IPv6 instead of IPv4 (ip_opt_words ignored)
    pub v6_ext: u8,        // IPv6 destination-options headers before L4 (8 B each)
    pub later_frag: bool,  // non-first fragment: the L4 bytes are only payload now
    pub pad: u8,           // Ethernet padding/trailer after the IP datagram
}

fn csum(b: &[u8]) -> u16 {
    let mut s: u32 = 0;
    for c in b.chunks(2) {
        let w = if c.len() == 2 { (c[0] as u32) << 8 | c[1] as u32 } else { (c[0] as u32) << 8 };
        s += w;
    }
    while s >> 16 != 0 {
        s = (s & 0xFFFF) + (s >> 16);
    }
    !(s as u16)
}

pub fn build(l4: &L4, payload: &[u8], shape: Shape) -> Vec<u8> {
    let mut f = Vec::with_capacity(payload.len() + 80);
    f.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB]);
    if shape.qinq {
        f.extend_from_slice(&[0x88, 0xA8, 0x00, 0x0A]);
    }
    if shape.vlan || shape.qinq {
        f.extend_from_slice(&[0x81, 0x00, 0x00, 0x2A]);
    }
    f.extend_from_slice(if shape.ipv6 { &[0x86, 0xDD] } else { &[0x08, 0x00] });

    let mut l4h = Vec::new();
    match l4.proto {
        6 => {
            let doff = 5 + shape.tcp_opt_words;
            l4h.extend_from_slice(&l4.sport.to_be_bytes());
            l4h.extend_from_slice(&l4.dport.to_be_bytes());
            l4h.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0]);
            l4h.push(doff << 4);
            l4h.push(0x18); // PSH|ACK
            l4h.extend_from_slice(&[0xFF, 0xFF, 0, 0, 0, 0]);
            for _ in 0..shape.tcp_opt_words {
                l4h.extend_from_slice(&[0x01, 0x01, 0x01, 0x01]); // NOPs
            }
        }
        17 => {
            l4h.extend_from_slice(&l4.sport.to_be_bytes());
            l4h.extend_from_slice(&l4.dport.to_be_bytes());
            l4h.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
            l4h.extend_from_slice(&[0, 0]);
        }
        1 => {
            l4h.push(l4.icmp.0);
            l4h.push(l4.icmp.1);
        }
        _ => {}
    }

    if shape.ipv6 {
        // extension chain: v6_ext dest-opts headers (PadN), then a fragment
        // header if later_frag, then the L4 bytes.
        let mut ext = Vec::new();
        let mut kinds: Vec<u8> = vec![60; shape.v6_ext as usize];
        if shape.later_frag {
            kinds.push(44);
        }
        for (i, k) in kinds.iter().enumerate() {
            let next = if i + 1 < kinds.len() { kinds[i + 1] } else { l4.proto };
            if *k == 44 {
                ext.extend_from_slice(&[next, 0, 0x03, 0x20, 0, 0, 0x12, 0x34]); // offset 100
            } else {
                ext.extend_from_slice(&[next, 0, 1, 4, 0, 0, 0, 0]);
            }
        }
        let first = kinds.first().copied().unwrap_or(l4.proto);
        let plen = ext.len() + l4h.len() + payload.len();
        f.extend_from_slice(&[0x60, 0, 0, 0, (plen >> 8) as u8, plen as u8, first, 64]);
        f.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        f.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        f.extend_from_slice(&ext);
        f.extend_from_slice(&l4h);
        f.extend_from_slice(payload);
        f.extend(std::iter::repeat(0u8).take(shape.pad as usize));
        return f;
    }

    let ihl = 5 + shape.ip_opt_words;
    let total = ihl as usize * 4 + l4h.len() + payload.len();
    let mut ip = vec![
        0x40 | ihl, 0, (total >> 8) as u8, total as u8, 0x12, 0x34,
        if shape.later_frag { 0x00 } else { 0x40 }, if shape.later_frag { 100 } else { 0 }, 64, l4.proto, 0, 0,
        10, 0, 0, 1, 10, 0, 0, 2,
    ];
    for _ in 0..shape.ip_opt_words {
        ip.extend_from_slice(&[0x01, 0x01, 0x01, 0x01]); // NOPs
    }
    let c = csum(&ip);
    ip[10] = (c >> 8) as u8;
    ip[11] = c as u8;

    f.extend_from_slice(&ip);
    f.extend_from_slice(&l4h);
    f.extend_from_slice(payload);
    f.extend(std::iter::repeat(0u8).take(shape.pad as usize));
    f
}

pub fn write_pcap(path: &Path, frames: &[Vec<u8>]) -> io::Result<()> {
    let mut w = BufWriter::new(File::create(path)?);
    w.write_all(&0xA1B2_C3D4u32.to_le_bytes())?;
    w.write_all(&2u16.to_le_bytes())?;
    w.write_all(&4u16.to_le_bytes())?;
    w.write_all(&0i32.to_le_bytes())?;
    w.write_all(&0u32.to_le_bytes())?;
    w.write_all(&65535u32.to_le_bytes())?;
    w.write_all(&1u32.to_le_bytes())?; // LINKTYPE_ETHERNET
    for (i, f) in frames.iter().enumerate() {
        w.write_all(&(i as u32).to_le_bytes())?;
        w.write_all(&0u32.to_le_bytes())?;
        w.write_all(&(f.len() as u32).to_le_bytes())?;
        w.write_all(&(f.len() as u32).to_le_bytes())?;
        w.write_all(f)?;
    }
    w.flush()
}
