//! Test-case generation: synthetic rulesets and adversarial packet streams.
//!
//! Packet strategies target the places this design has broken before:
//!   - pattern placement across the 16-byte feed chunks and 64-byte payload
//!     lines (lane / chunk / line boundary bugs)
//!   - offset-constraint boundaries (off-by-one in small/big/same)
//!   - near misses (one byte off, truncated at the payload end, wrong port)
//!   - several rules in one packet (priority / tie selection)
//!   - "gram soup" filler built from rule fragments, which floods the bitmap,
//!     cuckoo and exact-match stages (the metadata race only showed under load)
//!   - bursts of large packets followed by tiny ones (epoch reuse)

use crate::packet::{self, Shape, L4};
use crate::rng::Rng;
use crate::rules::{Rule, MAX_PATTERN};

pub struct GenCfg {
    pub max_payload: usize,
}

pub struct Case {
    pub frame: Vec<u8>,
    pub desc: String,
}

// ---------------------------------------------------------------- rulesets

/// A small adversarial ruleset.  Priorities are written in the no-space form
/// (both forms load since the loader fix).
pub fn synth_rules(rng: &mut Rng, n: usize) -> Vec<Rule> {
    let mut rules: Vec<Rule> = Vec::with_capacity(n);
    let ports = [80u16, 443, 53, 8080, 22, 25, 1, 65535];
    for id in 0..n {
        let len = match rng.weighted(&[3, 5, 4, 2]) {
            0 => rng.range(3, 4),
            1 => rng.range(5, 16),
            2 => rng.range(17, 40),
            _ => rng.range(41, MAX_PATTERN),
        };
        let pattern: Vec<u8> = match rng.weighted(&[5, 2, 2, 1]) {
            0 => (0..len).map(|_| *rng.pick(b"abcdefghijklmnopqrstuvwxyz0123456789/.-_=?&%<>\"' ")).collect(),
            1 => (0..len).map(|_| rng.byte()).collect(),                   // binary
            2 => {                                                          // share a prefix with an earlier rule
                if let Some(prev) = rules.last() {
                    let k = rng.range(1, prev.pattern.len().min(len));
                    let mut p = prev.pattern[..k].to_vec();
                    while p.len() < len { p.push(*rng.pick(b"abcdefghijklmnopqrstuvwxyz")); }
                    p
                } else {
                    (0..len).map(|_| *rng.pick(b"abcdefghijklmnopqrstuvwxyz")).collect()
                }
            }
            _ => {                                                          // low-entropy repeats
                let unit: Vec<u8> = (0..rng.range(1, 3)).map(|_| *rng.pick(b"ab0/")).collect();
                unit.iter().cycle().take(len).copied().collect()
            }
        };
        // The loader folds A-Z; store the folded form so equal-looking
        // patterns really are equal.
        let pattern: Vec<u8> = pattern.iter().map(|&c| if c.is_ascii_uppercase() { c | 0x20 } else { c }).collect();
        let proto = *rng.pick(&[6u8, 6, 6, 17, 1]);
        let (offset_mode, offset_val) = match rng.weighted(&[4, 3, 2, 1]) {
            0 => (0u8, 0i32),
            1 => (1, *rng.pick(&[0i32, 1, 15, 16, 63, 64, 100, 1500])),
            2 => (2, *rng.pick(&[0i32, 1, 16, 64, 200])),
            _ => (3, *rng.pick(&[0i32, 1, 15, 16, 64])),
        };
        rules.push(Rule {
            id,
            pattern,
            proto,
            port: *rng.pick(&ports),
            icmp: (rng.range(0, 3) as u8 * 8, rng.range(0, 1) as u8),
            is_request: *rng.pick(&[1i8, 1, 0, -1]),
            offset_val,
            offset_mode,
            priority: rng.range(0, 2) as u8,
        });
    }
    rules
}

// ----------------------------------------------------------------- packets

fn rand_case(rng: &mut Rng, p: &[u8]) -> Vec<u8> {
    p.iter()
        .map(|&c| if c.is_ascii_lowercase() && rng.chance(0.5) { c.to_ascii_uppercase() } else { c })
        .collect()
}

fn filler(rng: &mut Rng, n: usize, rules: &[Rule]) -> Vec<u8> {
    match rng.weighted(&[3, 3, 3, 1]) {
        0 => (0..n).map(|_| rng.byte()).collect(),
        1 => (0..n).map(|_| *rng.pick(b"abcdefghijklmnopqrstuvwxyz0123456789 /.=&?")).collect(),
        2 => soup(rng, n, rules),
        _ => vec![*rng.pick(b"a\x00 /"); n],
    }
}

/// Filler made of rule fragments: lots of bitmap/cuckoo candidates, few matches.
fn soup(rng: &mut Rng, n: usize, rules: &[Rule]) -> Vec<u8> {
    let mut out = Vec::with_capacity(n + 16);
    while out.len() < n {
        let r = rng.pick(rules);
        let a = rng.below(r.pattern.len());
        let b = (a + rng.range(3, 8)).min(r.pattern.len());
        out.extend(rand_case(rng, &r.pattern[a..b]));
    }
    out.truncate(n);
    out
}

/// Candidate start positions for a pattern of length l in a payload of length p.
fn placements(rng: &mut Rng, r: &Rule, l: usize, p: usize) -> (usize, &'static str) {
    let last = p - l;
    let clamp = |x: i64| x.clamp(0, last as i64) as usize;
    match rng.weighted(&[2, 2, 3, 3, 3, 2]) {
        0 => (0, "start"),
        1 => (last, "end"),
        2 => {
            let b = 16 * rng.range(1, (p / 16).max(1)) as i64;
            (clamp(b - rng.range(1, l.max(2) - 1) as i64), "x16")
        }
        3 => {
            let b = 64 * rng.range(1, (p / 64).max(1)) as i64;
            (clamp(b - rng.range(1, l.max(2) - 1) as i64), "x64")
        }
        4 if r.offset_mode != 0 => {
            let v = r.offset_val as i64 + rng.range(0, 2) as i64 - 1; // val-1, val, val+1
            (clamp(v), "offset")
        }
        _ => (rng.below(last + 1), "rand"),
    }
}

fn l4_for(rng: &mut Rng, r: &Rule) -> L4 {
    let eph = rng.range(1024, 65535) as u16;
    match r.proto {
        1 => L4 { proto: 1, sport: 0, dport: 0, icmp: r.icmp },
        proto => {
            let as_request = match r.is_request { 1 => true, 0 => false, _ => rng.chance(0.5) };
            if as_request {
                L4 { proto, sport: eph, dport: r.port, icmp: (0, 0) }
            } else {
                L4 { proto, sport: r.port, dport: eph, icmp: (0, 0) }
            }
        }
    }
}

/// NX_V6=P: share of packets built as IPv6 (random extension headers,
/// fragments, QinQ, padding).  Unset = 0, so existing seeds reproduce.
fn v6_share() -> f64 {
    static V: std::sync::OnceLock<f64> = std::sync::OnceLock::new();
    *V.get_or_init(|| std::env::var("NX_V6").ok().and_then(|v| v.parse().ok()).unwrap_or(0.0))
}

fn shape(rng: &mut Rng) -> Shape {
    let v6 = v6_share();
    if v6 > 0.0 && rng.chance(v6) {
        return Shape {
            vlan: rng.chance(0.3),
            ip_opt_words: 0,
            tcp_opt_words: rng.range(0, 3) as u8,
            qinq: rng.chance(0.2),
            ipv6: true,
            v6_ext: rng.range(0, 3) as u8,
            later_frag: rng.chance(0.05),
            pad: if rng.chance(0.3) { rng.range(1, 17) as u8 } else { 0 },
        };
    }
    if rng.chance(0.9) {
        Shape::default()
    } else {
        Shape {
            vlan: rng.chance(0.5),
            ip_opt_words: rng.range(0, 2) as u8,
            tcp_opt_words: rng.range(0, 3) as u8,
            qinq: rng.chance(0.2),
            ipv6: rng.chance(0.4),
            v6_ext: rng.range(0, 3) as u8,
            later_frag: rng.chance(0.1),
            pad: if rng.chance(0.3) { rng.range(1, 17) as u8 } else { 0 },
        }
    }
}

fn payload_len(rng: &mut Rng, min: usize, max: usize) -> usize {
    let min = min.max(1).min(max);
    match rng.weighted(&[3, 3, 2, 1]) {
        0 => rng.range(min, (min + 64).min(max)),
        1 => rng.range(min, max),
        2 => max,
        _ => min,
    }
}

/// Place `pat` into a payload; returns (payload, start, placement tag).
fn embed(rng: &mut Rng, r: &Rule, pat: &[u8], rules: &[Rule], cfg: &GenCfg) -> (Vec<u8>, usize, &'static str) {
    let want = if r.offset_mode != 0 { r.offset_val.max(0) as usize + pat.len() + 1 } else { pat.len() };
    let plen = payload_len(rng, want.min(cfg.max_payload).max(pat.len()), cfg.max_payload);
    let mut pay = filler(rng, plen, rules);
    let (at, tag) = placements(rng, r, pat.len(), plen);
    pay[at..at + pat.len()].copy_from_slice(pat);
    (pay, at, tag)
}

/// A rule whose offset constraint can be met within max_payload (production
/// rules include e.g. offset=3057/big, which no MTU-sized packet can satisfy).
fn pick_satisfiable<'a>(rng: &mut Rng, rules: &'a [Rule], cfg: &GenCfg) -> &'a Rule {
    for _ in 0..32 {
        let r = rng.pick(rules);
        let need = match r.offset_mode { 2 | 3 => r.offset_val.max(0) as usize + r.pattern.len(), _ => r.pattern.len() };
        if need <= cfg.max_payload { return r; }
    }
    rng.pick(rules)
}

/// NX_EDGE=P: share of generation steps that use the edge strategies below.
/// Unset = 0, so existing seeds reproduce.
fn edge_share() -> f64 {
    static V: std::sync::OnceLock<f64> = std::sync::OnceLock::new();
    *V.get_or_init(|| std::env::var("NX_EDGE").ok().and_then(|v| v.parse().ok()).unwrap_or(0.0))
}

/// Short payload made from a rule: the whole pattern when it fits, else a prefix.
fn short_hit(rng: &mut Rng, r: &Rule, max: usize) -> Vec<u8> {
    let k = r.pattern.len().min(max);
    rand_case(rng, &r.pattern[..k])
}

/// Edge strategies for the pipeline's packet-boundary and candidate paths:
///   tiny-run       back-to-back 1..17 byte packets (one-slice packets, epoch churn)
///   tail-len       payload length at 16/64-byte boundaries +-1, hit ending at the tail
///   gram-flood     one 3-byte gram repeated over a full payload (same chain walked
///                  over and over), sometimes with the real pattern inside
///   tail-then-tiny full packet with a hit in its last bytes, then tiny hit packets
///   skip-mix       empty payloads, non-IP frames and later fragments between tiny hits
///   span-line      pattern crossing a 64-byte line (two-line exact compare) or
///                  starting exactly on one
///   repeat-hit     one pattern repeated back to back over the payload (many hits)
///   offset-edge    offset rules with payload length and position at the limit +-1
///   tie            several equal-priority rules for the same L4 in one packet
/// NX_EDGE_ONLY=k forces strategy k.
fn edge_only() -> Option<usize> {
    static V: std::sync::OnceLock<Option<usize>> = std::sync::OnceLock::new();
    *V.get_or_init(|| std::env::var("NX_EDGE_ONLY").ok().and_then(|v| v.parse().ok()))
}

fn edge_cases(rng: &mut Rng, rules: &[Rule], cfg: &GenCfg, out: &mut Vec<Case>) {
    let k = match edge_only() { Some(k) => k, None => rng.below(9) };
    match k {
        4 => edge_skip_mix(rng, rules, out),
        5 => edge_span_line(rng, rules, cfg, out),
        6 => edge_repeat_hit(rng, rules, cfg, out),
        7 => edge_offset(rng, rules, cfg, out),
        8 => edge_tie(rng, rules, cfg, out),
        _ => edge_basic(rng, rules, cfg, out, k),
    }
}

fn edge_skip_mix(rng: &mut Rng, rules: &[Rule], out: &mut Vec<Case>) {
    for _ in 0..rng.range(8, 32) {
        let r = rng.pick(rules);
        let l4 = l4_for(rng, r);
        match rng.below(4) {
            0 => out.push(Case { frame: packet::build(&l4, &[], Shape::default()), desc: "skip-empty".into() }),
            1 => {
                let mut f = vec![0u8; 12];
                f.extend_from_slice(&[0x08, 0x06]);            // ARP ethertype
                let n = rng.range(28, 60);
                f.extend(filler(rng, n, rules));
                out.push(Case { frame: f, desc: "skip-arp".into() });
            }
            2 => {
                let pay = short_hit(rng, r, 40);
                let sh = Shape { later_frag: true, ..Shape::default() };
                out.push(Case { frame: packet::build(&l4, &pay, sh), desc: format!("skip-frag r{}", r.id) });
            }
            _ => {
                let pay = short_hit(rng, r, 17);
                out.push(Case { frame: packet::build(&l4, &pay, shape(rng)), desc: format!("skip-hit r{} len{}", r.id, pay.len()) });
            }
        }
    }
}

fn edge_span_line(rng: &mut Rng, rules: &[Rule], cfg: &GenCfg, out: &mut Vec<Case>) {
    let r = pick_satisfiable(rng, rules, cfg);
    let pat = rand_case(rng, &r.pattern);
    let l = pat.len();
    let b = 64 * rng.range(1, (cfg.max_payload / 64).max(1));
    let at = match rng.below(3) {
        0 => b.saturating_sub(l - 1),                       // one byte in the next line
        1 => b.saturating_sub(l / 2 + 1),                   // straddles the line
        _ => b,                                             // starts on the line
    };
    let plen = (at + l + rng.range(0, 64)).min(cfg.max_payload.max(at + l));
    let mut pay = filler(rng, plen, rules);
    pay[at..at + l].copy_from_slice(&pat);
    let l4 = l4_for(rng, r);
    out.push(Case { frame: packet::build(&l4, &pay, shape(rng)), desc: format!("span-line r{} @{} len{}", r.id, at, plen) });
}

fn edge_repeat_hit(rng: &mut Rng, rules: &[Rule], cfg: &GenCfg, out: &mut Vec<Case>) {
    let r = pick_satisfiable(rng, rules, cfg);
    let pat = rand_case(rng, &r.pattern);
    let reps = (cfg.max_payload / pat.len()).max(1).min(rng.range(2, 64));
    let pay: Vec<u8> = pat.iter().cycle().take(pat.len() * reps).copied().collect();
    let l4 = l4_for(rng, r);
    out.push(Case { frame: packet::build(&l4, &pay, shape(rng)), desc: format!("repeat-hit r{} x{} len{}", r.id, reps, pay.len()) });
}

fn edge_offset(rng: &mut Rng, rules: &[Rule], cfg: &GenCfg, out: &mut Vec<Case>) {
    let offs: Vec<&Rule> = rules.iter().filter(|r| r.offset_mode != 0 && r.offset_val >= 0).collect();
    let r = if offs.is_empty() { rng.pick(rules) } else { *rng.pick(&offs) };
    let pat = rand_case(rng, &r.pattern);
    let v = r.offset_val.max(0) as usize;
    let at = (v as i64 + rng.range(0, 2) as i64 - 1).max(0) as usize;   // val-1, val, val+1
    let plen = at + pat.len() + rng.range(0, 2);                          // ends right after, +1, +2
    if plen > cfg.max_payload.max(pat.len()) { return; }
    let mut pay = filler(rng, plen, rules);
    pay[at..at + pat.len()].copy_from_slice(&pat);
    let l4 = l4_for(rng, r);
    out.push(Case { frame: packet::build(&l4, &pay, shape(rng)), desc: format!("offset-edge r{} m{} v{} @{} len{}", r.id, r.offset_mode, v, at, plen) });
}

fn edge_tie(rng: &mut Rng, rules: &[Rule], cfg: &GenCfg, out: &mut Vec<Case>) {
    let same = |a: &Rule, b: &Rule| a.proto == b.proto && a.port == b.port && a.is_request == b.is_request
                                    && a.icmp == b.icmp && a.priority == b.priority && b.offset_mode == 0;
    let mut found = None;
    for _ in 0..16 {
        let r0 = rng.pick(rules);
        let peers: Vec<&Rule> = rules.iter().filter(|r| same(r0, r)).collect();
        if peers.len() >= 2 { found = Some((r0, peers)); break; }
    }
    // Rulesets without an equal-priority pair: fall back so the caller always progresses.
    let Some((r0, peers)) = found else { return edge_span_line(rng, rules, cfg, out) };
    let k = rng.range(2, 5).min(peers.len());
    let chosen: Vec<&Rule> = (0..k).map(|_| *rng.pick(&peers)).collect();
    let total: usize = chosen.iter().map(|r| r.pattern.len()).sum();
    let plen = rng.range(total, cfg.max_payload.max(total));
    let mut pay = filler(rng, plen, rules);
    let (mut at, mut left) = (0usize, total);
    let mut ids = Vec::new();
    for r in &chosen {                                       // disjoint, in order
        at += rng.below((plen - at - left) / 2 + 1);
        pay[at..at + r.pattern.len()].copy_from_slice(&rand_case(rng, &r.pattern));
        ids.push(format!("r{}@{}", r.id, at));
        at += r.pattern.len();
        left -= r.pattern.len();
    }
    let l4 = l4_for(rng, r0);
    out.push(Case { frame: packet::build(&l4, &pay, shape(rng)), desc: format!("tie {} len{}", ids.join(","), plen) });
}

fn edge_basic(rng: &mut Rng, rules: &[Rule], cfg: &GenCfg, out: &mut Vec<Case>, k: usize) {
    match k {
        0 => {
            for _ in 0..rng.range(16, 48) {
                let r = rng.pick(rules);
                let plen = rng.range(1, 17);
                let pay = if rng.chance(0.4) { short_hit(rng, r, plen) } else { filler(rng, plen, rules) };
                let l4 = l4_for(rng, r);
                out.push(Case { frame: packet::build(&l4, &pay, shape(rng)), desc: format!("tiny-run r{} len{}", r.id, pay.len()) });
            }
        }
        1 => {
            let r = pick_satisfiable(rng, rules, cfg);
            let unit = if rng.chance(0.5) { 16 } else { 64 };
            let k = rng.range(1, (cfg.max_payload / unit).max(1));
            let plen = ((unit * k) as i64 + rng.range(0, 2) as i64 - 1).max(r.pattern.len() as i64) as usize;
            let plen = plen.min(cfg.max_payload.max(r.pattern.len()));
            let pat = rand_case(rng, &r.pattern);
            let mut pay = filler(rng, plen, rules);
            let back = rng.range(0, 3).min(plen - pat.len());   // end 0..3 bytes before the tail
            let at = plen - pat.len() - back;
            pay[at..at + pat.len()].copy_from_slice(&pat);
            let l4 = l4_for(rng, r);
            out.push(Case { frame: packet::build(&l4, &pay, shape(rng)), desc: format!("tail-len r{} @{} len{}", r.id, at, plen) });
        }
        2 => {
            let r = rng.pick(rules);
            let a = rng.below(r.pattern.len().saturating_sub(2).max(1));
            let gram: Vec<u8> = r.pattern[a..(a + 3).min(r.pattern.len())].to_vec();
            let mut pay: Vec<u8> = gram.iter().cycle().take(cfg.max_payload).copied().collect();
            let mut tag = "plain";
            if rng.chance(0.5) && r.pattern.len() <= pay.len() {
                let at = rng.below(pay.len() - r.pattern.len() + 1);
                pay[at..at + r.pattern.len()].copy_from_slice(&rand_case(rng, &r.pattern));
                tag = "hit";
            }
            let l4 = l4_for(rng, r);
            out.push(Case { frame: packet::build(&l4, &pay, Shape::default()), desc: format!("gram-flood-{} r{} len{}", tag, r.id, pay.len()) });
        }
        _ => {
            let r = pick_satisfiable(rng, rules, cfg);
            let pat = rand_case(rng, &r.pattern);
            let plen = cfg.max_payload.max(pat.len());
            let mut pay = soup(rng, plen, rules);
            let at = plen - pat.len();
            pay[at..].copy_from_slice(&pat);
            let l4 = l4_for(rng, r);
            out.push(Case { frame: packet::build(&l4, &pay, Shape::default()), desc: format!("tail-big r{} @{} len{}", r.id, at, plen) });
            for _ in 0..rng.range(2, 10) {
                let t = rng.pick(rules);
                let pay = short_hit(rng, t, 16);
                let l4 = l4_for(rng, t);
                out.push(Case { frame: packet::build(&l4, &pay, Shape::default()), desc: format!("tail-tiny r{} len{}", t.id, pay.len()) });
            }
        }
    }
}

pub fn packets(rng: &mut Rng, rules: &[Rule], n: usize, cfg: &GenCfg) -> Vec<Case> {
    let mut out = Vec::with_capacity(n);
    let edge = edge_share();
    while out.len() < n {
        if edge > 0.0 && rng.chance(edge) {
            edge_cases(rng, rules, cfg, &mut out);
            continue;
        }
        let kind = rng.weighted(&[30, 16, 10, 12, 8, 6, 3, 3, 3]);
        match kind {
            // hit: rule pattern placed at a boundary-stressing position
            0 => {
                let r = if rng.chance(0.8) { pick_satisfiable(rng, rules, cfg) } else { rng.pick(rules) };
                let pat = rand_case(rng, &r.pattern);
                let (pay, at, tag) = embed(rng, r, &pat, rules, cfg);
                let l4 = l4_for(rng, r);
                out.push(Case { frame: packet::build(&l4, &pay, shape(rng)), desc: format!("hit r{} @{} {} len{}", r.id, at, tag, pay.len()) });
            }
            // near miss: one byte changed, truncated at the end, or wrong L4
            1 => {
                let r = rng.pick(rules);
                let mut pat = rand_case(rng, &r.pattern);
                let mut l4 = l4_for(rng, r);
                let how = rng.below(4);
                let tag = match how {
                    0 => {
                        let i = rng.below(pat.len());
                        let old = pat[i] | 0x20;
                        let mut c = rng.byte();
                        while c | 0x20 == old { c = rng.byte(); }
                        pat[i] = c;
                        "flip"
                    }
                    1 => "trunc",
                    2 => { if l4.proto == 1 { l4.icmp.0 ^= 1 } else { l4.dport ^= 1; l4.sport ^= 1 } "l4off" }
                    _ => { l4.proto = if l4.proto == 6 { 17 } else { 6 }; "proto" }
                };
                let (pay, at) = if how == 1 {
                    let plen = payload_len(rng, pat.len(), cfg.max_payload);
                    let mut pay = filler(rng, plen, rules);
                    let keep = pat.len() - 1;               // pattern cut by the payload end
                    let at = plen - keep;
                    pay[at..].copy_from_slice(&pat[..keep]);
                    (pay, at)
                } else {
                    let (pay, at, _) = embed(rng, r, &pat, rules, cfg);
                    (pay, at)
                };
                out.push(Case { frame: packet::build(&l4, &pay, shape(rng)), desc: format!("near-{} r{} @{} len{}", tag, r.id, at, pay.len()) });
            }
            // several rules sharing the packet's L4 -> priority selection
            2 => {
                let r0 = rng.pick(rules);
                let peers: Vec<&Rule> = rules.iter()
                    .filter(|r| r.proto == r0.proto && r.port == r0.port && r.is_request == r0.is_request && r.icmp == r0.icmp)
                    .collect();
                let k = rng.range(2, 4).min(peers.len());
                let chosen: Vec<&Rule> = (0..k).map(|_| *rng.pick(&peers)).collect();
                let total: usize = chosen.iter().map(|r| r.pattern.len()).sum();
                let plen = payload_len(rng, total, cfg.max_payload.max(total));
                let mut pay = filler(rng, plen, rules);
                let mut ids = Vec::new();
                for r in &chosen {
                    let at = rng.below(plen - r.pattern.len() + 1);
                    pay[at..at + r.pattern.len()].copy_from_slice(&rand_case(rng, &r.pattern));
                    ids.push(format!("r{}@{}", r.id, at));
                }
                let l4 = l4_for(rng, r0);
                out.push(Case { frame: packet::build(&l4, &pay, shape(rng)), desc: format!("multi {} len{}", ids.join(","), pay.len()) });
            }
            // gram soup: heavy candidate load, usually no match
            3 => {
                let r = rng.pick(rules);
                let plen = payload_len(rng, 64, cfg.max_payload);
                let pay = soup(rng, plen, rules);
                let l4 = l4_for(rng, r);
                out.push(Case { frame: packet::build(&l4, &pay, shape(rng)), desc: format!("soup r{}-l4 len{}", r.id, plen) });
            }
            // random payload
            4 => {
                let r = rng.pick(rules);
                let plen = payload_len(rng, 1, cfg.max_payload);
                let pay = filler(rng, plen, rules);
                let l4 = l4_for(rng, r);
                out.push(Case { frame: packet::build(&l4, &pay, shape(rng)), desc: format!("noise len{}", plen) });
            }
            // tiny payloads (< one gram) and exact-fit (pattern == whole payload)
            5 => {
                let r = rng.pick(rules);
                let pay = if rng.chance(0.5) {
                    let k = rng.range(1, 2).min(r.pattern.len());
                    rand_case(rng, &r.pattern[..k])
                } else {
                    rand_case(rng, &r.pattern)
                };
                let l4 = l4_for(rng, r);
                out.push(Case { frame: packet::build(&l4, &pay, shape(rng)), desc: format!("tiny r{} len{}", r.id, pay.len()) });
            }
            // empty payload (the C side skips these)
            6 => {
                let r = rng.pick(rules);
                let l4 = l4_for(rng, r);
                out.push(Case { frame: packet::build(&l4, &[], Shape::default()), desc: "empty".into() });
            }
            // not IPv4: the host feeds the whole frame as payload, C skips it
            7 => {
                let r = rng.pick(rules);
                let mut f = vec![0u8; 12];
                f.extend_from_slice(&[0x86, 0xDD]);
                f.extend(rand_case(rng, &r.pattern));
                let n = rng.range(0, 100);
                f.extend(filler(rng, n, rules));
                out.push(Case { frame: f, desc: format!("non-ipv4 r{}", r.id) });
            }
            // burst: max-size soup packets then tiny ones (epoch reuse under load)
            _ => {
                let r = rng.pick(rules);
                let big = rng.range(4, 12);
                for _ in 0..big {
                    let pay = soup(rng, cfg.max_payload, rules);
                    let l4 = l4_for(rng, r);
                    out.push(Case { frame: packet::build(&l4, &pay, Shape::default()), desc: format!("burst-big r{}-l4", r.id) });
                }
                for _ in 0..rng.range(4, 12) {
                    let pat = rand_case(rng, &r.pattern);
                    let l4 = l4_for(rng, r);
                    out.push(Case { frame: packet::build(&l4, &pat, Shape::default()), desc: format!("burst-tiny r{} len{}", r.id, pat.len()) });
                }
            }
        }
    }
    out.truncate(n);
    out
}
