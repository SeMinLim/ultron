//! Rule files, parsed the way `rule_loader.c` parses them.
//!
//! Mirrors the C loader on purpose: patterns longer than 64 bytes are dropped,
//! a quoted token ("protocol=icmp/11 0/request") runs to the closing quote,
//! ICMP type/code may be separated by a space or a comma, and the priority
//! value may follow "priority=" after spaces (the loader was fixed to match the
//! rule files on 2026-09-25; before that priorities all loaded as 0).

use std::fs;
use std::io;
use std::path::Path;

pub const MAX_PATTERN: usize = 64;

#[derive(Clone, Debug)]
pub struct Rule {
    pub id: usize,
    pub pattern: Vec<u8>,
    pub proto: u8,       // 6 tcp, 17 udp, 1 icmp
    pub port: u16,
    pub icmp: (u8, u8),
    pub is_request: i8,  // 1 request (dst port), 0 response (src port), -1 unspecified
    pub offset_val: i32,
    pub offset_mode: u8, // 0 any, 1 small, 2 big, 3 same
    pub priority: u8,
}

fn url_decode(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

fn token_after<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let k = line.find(key)?;
    let rest = &line[k + key.len()..];
    let quoted = k > 0 && line.as_bytes()[k - 1] == b'"';
    let end = if quoted {
        rest.find(|c: char| c == '"' || c == '\r' || c == '\n').unwrap_or(rest.len())
    } else {
        rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len())
    };
    Some(&rest[..end])
}

pub fn load(path: &Path) -> io::Result<Vec<Rule>> {
    let text = fs::read_to_string(path)?;
    let mut rules = Vec::new();
    for line in text.lines() {
        let Some(idtok) = token_after(line, "id=") else { continue };
        let Some(pat) = token_after(line, "pattern=") else { continue };
        let pattern = url_decode(pat);
        if pattern.len() > MAX_PATTERN {
            continue;
        }
        let (mut proto, mut port, mut icmp, mut is_request) = (0u8, 0u16, (0u8, 0u8), -1i8);
        if let Some(pr) = token_after(line, "protocol=") {
            let parts: Vec<&str> = pr.splitn(3, '/').collect();
            proto = match parts.first().copied().unwrap_or("") {
                "tcp" => 6,
                "udp" => 17,
                "icmp" => 1,
                other => other.parse().unwrap_or(0),
            };
            let f2 = parts.get(1).copied().unwrap_or("");
            if let Some((t, c)) = f2.split_once(|ch| ch == ',' || ch == ' ') {
                icmp = (t.trim().parse().unwrap_or(0), c.trim().parse().unwrap_or(0));
            } else {
                port = f2.parse().unwrap_or(0);
                is_request = match parts.get(2).copied().unwrap_or("") {
                    "request" => 1,
                    "response" => 0,
                    _ => -1,
                };
            }
        }
        let (mut offset_val, mut offset_mode) = (0i32, 0u8);
        if let Some(of) = token_after(line, "offset=") {
            let (v, m) = of.split_once('/').unwrap_or((of, ""));
            offset_val = v.parse().unwrap_or(0);
            offset_mode = match m {
                "small" => 1,
                "big" => 2,
                "same" => 3,
                _ => 0,
            };
        }
        let priority = match line.find("priority=") {
            Some(p) if line[p + 9..].trim_start().starts_with("high") => 2,
            Some(p) if line[p + 9..].trim_start().starts_with("low") => 1,
            _ => 0,
        };
        rules.push(Rule {
            // The file id: the C matcher and the DB generator both key on it.
            id: idtok.parse().unwrap_or(rules.len()),
            pattern,
            proto,
            port,
            icmp,
            is_request,
            offset_val,
            offset_mode,
            priority,
        });
    }
    Ok(rules)
}

pub fn write(path: &Path, rules: &[Rule]) -> io::Result<()> {
    let mut s = String::new();
    for r in rules {
        let proto = match r.proto { 6 => "tcp", 17 => "udp", 1 => "icmp", _ => "tcp" };
        let l4 = if r.proto == 1 {
            format!("{}/{},{}/request", proto, r.icmp.0, r.icmp.1)
        } else {
            let dir = match r.is_request { 1 => "request", 0 => "response", _ => "any" };
            format!("{}/{}/{}", proto, r.port, dir)
        };
        let mode = match r.offset_mode { 1 => "small", 2 => "big", 3 => "same", _ => "any" };
        let prio = match r.priority { 2 => "high", 1 => "low", _ => "medium" };
        let pat: String = r.pattern.iter().map(|b| format!("%{:02X}", b)).collect();
        s.push_str(&format!(
            "id={} protocol={} offset={}/{} priority={} pattern={}\n",
            r.id, l4, r.offset_val, mode, prio, pat
        ));
    }
    fs::write(path, s)
}
