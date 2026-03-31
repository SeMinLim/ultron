use std::collections::{HashMap, VecDeque};
use std::env;
use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::Path;

const N_GRAM: usize = 3;
const MAX_RULES: usize = 4096;
const MAX_PATTERN_LEN: usize = 256;

const BITMAP_BITS: usize = 1 << 24;
const BITMAP_BYTES: usize = BITMAP_BITS >> 3;
const BITMAP32_WORDS: usize = BITMAP_BITS >> 5;

const HT_MAX_LOOP: usize = 4096;
const HT_EMPTY_KEY: i32 = i32::MIN;
const HT_BRAM_CAPACITY: usize = MAX_RULES * 2;
const ASSIGN_BRAM_CAPACITY: usize = MAX_RULES;
const PATTERN_BRAM_BYTES: usize = ASSIGN_BRAM_CAPACITY * MAX_PATTERN_LEN;

#[derive(Debug)]
struct Rule {
    id: i32,
    pattern: Vec<u8>,
}

#[derive(Debug, Clone)]
struct GramAssign {
    gram_idx: u32,
    rule_id: i32,
    pre_offset: i32,
    post_offset: i32,
    #[allow(dead_code)]
    degree: i32,
}

#[derive(Debug)]
struct SingletonResult {
    assigns: Vec<GramAssign>,
    uncovered: usize,
    n_deg1: usize,   // rules covered by a gram unique to that rule (orig degree=1)
    n_shared: usize, // rules covered by a gram shared across rules (orig degree>1)
}

#[derive(Debug, Default)]
struct GNode {
    rule_ids: Vec<usize>,
    degree: i32,
    gone: bool,
}

#[derive(Debug, Clone)]
struct GramDbAssign {
    gram_idx: u32,
    rule_id: i32,
    pre_offset: i32,
    post_offset: i32,
    pat_len: u32,
    pattern: [u8; MAX_PATTERN_LEN],
}

#[derive(Debug, Clone, Copy)]
struct HEntry {
    key: i32,
    val: i32,
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn url_decode(src: &str) -> Vec<u8> {
    let b = src.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0usize;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h1), Some(h0)) = (hex_val(b[i + 1]), hex_val(b[i + 2])) {
                out.push((h1 << 4) | h0);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

fn parse_int_after(line: &str, key: &str) -> Option<i32> {
    let start = line.find(key)? + key.len();
    let bytes = line.as_bytes();
    let mut end = start;
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    if end == start {
        return None;
    }
    line[start..end].parse().ok()
}

fn parse_token_after<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let start = line.find(key)? + key.len();
    let tail = &line[start..];
    let end = tail
        .find(|c: char| c == ' ' || c == '\t' || c == '\r' || c == '\n')
        .unwrap_or(tail.len());
    Some(&tail[..end])
}

fn parse_rule_line(line: &str) -> Option<Rule> {
    let id = parse_int_after(line, "id=")?;
    let pat_enc = parse_token_after(line, "pattern=")?;
    Some(Rule {
        id,
        pattern: url_decode(pat_enc),
    })
}

fn load_rules(path: &Path) -> io::Result<Vec<Rule>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let mut rules = Vec::new();

    for line_res in reader.lines() {
        let line = line_res?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if let Some(rule) = parse_rule_line(trimmed) {
            rules.push(rule);
            if rules.len() >= MAX_RULES {
                break;
            }
        }
    }

    Ok(rules)
}

fn pack3(p: &[u8]) -> u32 {
    ((p[0] as u32) << 16) | ((p[1] as u32) << 8) | (p[2] as u32)
}

fn c_slot_key(gram: u32, mask: u32) -> u32 {
    gram & mask
}

fn singleton_build(rules: &[Rule]) -> SingletonResult {
    let nr = rules.len();

    // Compute C-compatible hash table size: smallest power of 2 >= (est+64)*2
    // where est = sum of (pat_len - N_GRAM + 1) for pat_len >= N_GRAM.
    // This matches ght_new(est+64) in singleton.c.
    let est: usize = rules
        .iter()
        .filter(|r| r.pattern.len() >= N_GRAM)
        .map(|r| r.pattern.len() - N_GRAM + 1)
        .sum();
    let min_size = (est + 64).saturating_mul(2);
    let mut table_size: usize = 1;
    while table_size < min_size {
        table_size <<= 1;
    }
    let slot_mask = (table_size - 1) as u32;

    let mut gram_map: HashMap<u32, GNode> = HashMap::new();
    let mut rule_grams: Vec<Vec<u32>> = vec![Vec::new(); nr];
    let mut rule_sel: Vec<Option<u32>> = vec![None; nr];
    let mut rule_cov: Vec<bool> = vec![false; nr];

    for (rid, rule) in rules.iter().enumerate() {
        if rule.pattern.len() < N_GRAM {
            continue;
        }
        for i in 0..=rule.pattern.len() - N_GRAM {
            let idx = pack3(&rule.pattern[i..i + N_GRAM]);
            if rule_grams[rid].contains(&idx) {
                continue;
            }
            rule_grams[rid].push(idx);
            let node = gram_map.entry(idx).or_default();
            node.rule_ids.push(rid);
            node.degree += 1;
        }
    }

    let mut n_uncov = rules.iter().filter(|r| r.pattern.len() >= N_GRAM).count();

    // Populate initial queue with degree-1 grams sorted by C slot order.
    let mut deg1: Vec<u32> = gram_map
        .iter()
        .filter_map(|(idx, node)| (node.degree == 1).then_some(*idx))
        .collect();
    deg1.sort_unstable_by_key(|&g| c_slot_key(g, slot_mask));
    let mut queue: VecDeque<u32> = deg1.into_iter().collect();

    while n_uncov > 0 {
        let mut sel_idx: Option<u32> = None;

        while let Some(gi) = queue.pop_front() {
            if let Some(n) = gram_map.get(&gi) {
                if !n.gone && n.degree > 0 {
                    sel_idx = Some(gi);
                    break;
                }
            }
        }

        if sel_idx.is_none() {
            // Fallback: pick minimum-degree gram in C slot order.
            let mut best = i32::MAX;
            let mut best_slot = u32::MAX;
            for (gi, node) in &gram_map {
                if node.gone || node.degree == 0 {
                    continue;
                }
                let slot = c_slot_key(*gi, slot_mask);
                if node.degree < best || (node.degree == best && slot < best_slot) {
                    best = node.degree;
                    best_slot = slot;
                    sel_idx = Some(*gi);
                }
            }
        }

        let Some(sel_idx) = sel_idx else {
            break;
        };

        let sel_rule_ids = {
            let sel = gram_map.get_mut(&sel_idx).expect("selected gram missing");
            sel.gone = true;
            sel.rule_ids.clone()
        };

        for rid in sel_rule_ids {
            if rule_cov[rid] {
                continue;
            }

            rule_cov[rid] = true;
            rule_sel[rid] = Some(sel_idx);
            n_uncov -= 1;

            for other in &rule_grams[rid] {
                if *other == sel_idx {
                    continue;
                }
                if let Some(on) = gram_map.get_mut(other) {
                    if on.gone {
                        continue;
                    }
                    on.degree -= 1;
                    if on.degree == 1 {
                        queue.push_back(*other);
                    }
                }
            }
        }
    }

    let n_covered = rule_cov.iter().filter(|&&c| c).count();
    let mut assigns = Vec::with_capacity(n_covered);

    for rid in 0..nr {
        if !rule_cov[rid] {
            continue;
        }

        let rule = &rules[rid];
        let gi = rule_sel[rid].expect("covered rule has no selected gram");

        let mut gram_pos = 0usize;
        if rule.pattern.len() >= N_GRAM {
            for i in 0..=rule.pattern.len() - N_GRAM {
                if pack3(&rule.pattern[i..i + N_GRAM]) == gi {
                    gram_pos = i;
                    break;
                }
            }
        }

        let degree = gram_map
            .get(&gi)
            .map(|n| n.rule_ids.len() as i32)
            .unwrap_or(1);

        assigns.push(GramAssign {
            gram_idx: gi,
            rule_id: rule.id,
            pre_offset: -(gram_pos as i32),
            post_offset: (rule.pattern.len() - gram_pos - N_GRAM) as i32,
            degree,
        });
    }

    let n_deg1   = assigns.iter().filter(|a| a.degree == 1).count();
    let n_shared = assigns.iter().filter(|a| a.degree >  1).count();

    SingletonResult {
        assigns,
        uncovered: nr - n_covered,
        n_deg1,
        n_shared,
    }
}

fn bitmap_set(bitmap: &mut [u8], idx: u32) {
    let byte_off = (idx as usize) >> 3;
    let bit_idx = (idx & 7) as u8;
    bitmap[byte_off] |= 1u8 << bit_idx;
}

fn bitmap_get(bitmap: &[u8], idx: u32) -> bool {
    let byte_off = (idx as usize) >> 3;
    let bit_idx = (idx & 7) as u8;
    ((bitmap[byte_off] >> bit_idx) & 1u8) != 0
}

fn write_bitmap(path: &Path, bitmap: &[u8]) -> Result<(), String> {
    let mut fp =
        File::create(path).map_err(|e| format!("failed to create {}: {e}", path.display()))?;
    fp.write_all(bitmap)
        .map_err(|e| format!("failed to write {}: {e}", path.display()))?;
    fp.flush()
        .map_err(|e| format!("failed to flush {}: {e}", path.display()))?;
    Ok(())
}

fn build_bitmap32_words(bitmap: &[u8]) -> Vec<u32> {
    let mut out = Vec::with_capacity(BITMAP32_WORDS);
    for chunk in bitmap.chunks_exact(4) {
        let w = (chunk[0] as u32)
            | ((chunk[1] as u32) << 8)
            | ((chunk[2] as u32) << 16)
            | ((chunk[3] as u32) << 24);
        out.push(w);
    }
    out
}

fn write_hex_u32_words(path: &Path, words: &[u32]) -> Result<(), String> {
    let fp = File::create(path).map_err(|e| format!("failed to create {}: {e}", path.display()))?;
    let mut bw = BufWriter::new(fp);
    for &w in words {
        writeln!(bw, "{w:08x}").map_err(|e| format!("failed to write {}: {e}", path.display()))?;
    }
    bw.flush()
        .map_err(|e| format!("failed to flush {}: {e}", path.display()))?;
    Ok(())
}

fn build_gramdb_assigns(
    rules: &[Rule],
    singleton: &SingletonResult,
) -> Result<Vec<GramDbAssign>, String> {
    let mut rule_by_id: HashMap<i32, &Rule> = HashMap::new();
    for r in rules {
        rule_by_id.entry(r.id).or_insert(r);
    }

    let mut out = Vec::with_capacity(singleton.assigns.len());
    for a in &singleton.assigns {
        let Some(rule) = rule_by_id.get(&a.rule_id) else {
            return Err(format!(
                "rule_id {} not found while building gramdb",
                a.rule_id
            ));
        };

        let mut pat = [0u8; MAX_PATTERN_LEN];
        let plen = rule.pattern.len().min(MAX_PATTERN_LEN);
        pat[..plen].copy_from_slice(&rule.pattern[..plen]);

        out.push(GramDbAssign {
            gram_idx: a.gram_idx,
            rule_id: a.rule_id,
            pre_offset: a.pre_offset,
            post_offset: a.post_offset,
            pat_len: plen as u32,
            pattern: pat,
        });
    }

    out.sort_by_key(|a| a.gram_idx);
    Ok(out)
}

fn h0(key: u32, cap: usize) -> usize {
    (key as usize) % cap
}

fn h1(key: u32, cap: usize) -> usize {
    (key.wrapping_mul(2654435761u32) as usize) % cap
}

fn ht_lookup(t0: &[HEntry], t1: &[HEntry], cap: usize, key: u32) -> Option<i32> {
    let k = key as i32;
    let p0 = h0(key, cap);
    if t0[p0].key == k {
        return Some(t0[p0].val);
    }
    let p1 = h1(key, cap);
    if t1[p1].key == k {
        return Some(t1[p1].val);
    }
    None
}

fn ht_insert(
    t0: &mut [HEntry],
    t1: &mut [HEntry],
    cap: usize,
    key: u32,
    val: i32,
) -> Result<(), String> {
    let key_i32 = key as i32;

    if let Some(existing) = ht_lookup(t0, t1, cap, key) {
        let p0 = h0(key, cap);
        if t0[p0].key == key_i32 {
            t0[p0].val = val;
        } else {
            let p1 = h1(key, cap);
            t1[p1].val = val;
        }
        if existing != val {
            return Ok(());
        }
        return Ok(());
    }

    let mut cur = HEntry { key: key_i32, val };
    let mut tid = 0usize;

    for _ in 0..HT_MAX_LOOP {
        let pos = if tid == 0 {
            h0(cur.key as u32, cap)
        } else {
            h1(cur.key as u32, cap)
        };
        let slot = if tid == 0 { &mut t0[pos] } else { &mut t1[pos] };

        if slot.key == HT_EMPTY_KEY {
            *slot = cur;
            return Ok(());
        }

        std::mem::swap(slot, &mut cur);
        tid ^= 1;
    }

    Err(format!("cuckoo insert cycle detected at key {}", cur.key))
}

fn build_hash_tables(
    assigns: &[GramDbAssign],
) -> Result<(Vec<HEntry>, Vec<HEntry>, usize, usize), String> {
    let cap = assigns.len().max(1) * 2;
    let mut t0 = vec![
        HEntry {
            key: HT_EMPTY_KEY,
            val: 0,
        };
        cap
    ];
    let mut t1 = vec![
        HEntry {
            key: HT_EMPTY_KEY,
            val: 0,
        };
        cap
    ];

    let mut unique_grams = 0usize;
    let mut prev: Option<u32> = None;
    for (i, a) in assigns.iter().enumerate() {
        if prev != Some(a.gram_idx) {
            ht_insert(&mut t0, &mut t1, cap, a.gram_idx, i as i32)?;
            unique_grams += 1;
            prev = Some(a.gram_idx);
        }
    }

    prev = None;
    for (i, a) in assigns.iter().enumerate() {
        if prev != Some(a.gram_idx) {
            let got = ht_lookup(&t0, &t1, cap, a.gram_idx)
                .ok_or_else(|| format!("lookup miss for gram_idx {}", a.gram_idx))?;
            if got != i as i32 {
                return Err(format!(
                    "lookup mismatch for gram_idx {}: expected base {} got {}",
                    a.gram_idx, i, got
                ));
            }
            prev = Some(a.gram_idx);
        }
    }

    Ok((t0, t1, cap, unique_grams))
}

fn collect_gram_ranges(assigns: &[GramDbAssign]) -> Vec<(u32, u32, u32)> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < assigns.len() {
        let gram = assigns[i].gram_idx;
        let base = i as u32;
        let mut j = i + 1;
        while j < assigns.len() && assigns[j].gram_idx == gram {
            j += 1;
        }
        let n_cands = (j - i) as u32;
        out.push((gram, base, n_cands));
        i = j;
    }
    out
}

fn pack_base_n(base: u32, n_cands: u32) -> Result<i32, String> {
    if base > 0xFFFF {
        return Err(format!("base index {base} exceeds 16-bit packed field"));
    }
    if n_cands > 0xFFFF {
        return Err(format!("n_cands {n_cands} exceeds 16-bit packed field"));
    }
    Ok(((n_cands << 16) | base) as i32)
}

fn build_bram_hash_tables(
    assigns: &[GramDbAssign],
) -> Result<(Vec<HEntry>, Vec<HEntry>, usize, usize), String> {
    let ranges = collect_gram_ranges(assigns);
    if ranges.len() > HT_BRAM_CAPACITY {
        return Err(format!(
            "too many unique grams {} for BRAM table cap {}",
            ranges.len(),
            HT_BRAM_CAPACITY
        ));
    }

    let start_cap = assigns.len().max(1) * 2;
    let mut chosen: Option<(Vec<HEntry>, Vec<HEntry>, usize)> = None;

    for cap in start_cap..=HT_BRAM_CAPACITY {
        let mut t0 = vec![
            HEntry {
                key: HT_EMPTY_KEY,
                val: 0,
            };
            cap
        ];
        let mut t1 = vec![
            HEntry {
                key: HT_EMPTY_KEY,
                val: 0,
            };
            cap
        ];

        let mut ok = true;
        for (gram, base, n_cands) in &ranges {
            let packed = pack_base_n(*base, *n_cands)?;
            if ht_insert(&mut t0, &mut t1, cap, *gram, packed).is_err() {
                ok = false;
                break;
            }
        }
        if !ok {
            continue;
        }

        for (gram, base, n_cands) in &ranges {
            let expected = pack_base_n(*base, *n_cands)?;
            let Some(got) = ht_lookup(&t0, &t1, cap, *gram) else {
                ok = false;
                break;
            };
            if got != expected {
                ok = false;
                break;
            }
        }

        if ok {
            chosen = Some((t0, t1, cap));
            break;
        }
    }

    let Some((mut t0, mut t1, cap)) = chosen else {
        return Err(format!(
            "failed to build BRAM hash table within cap {}",
            HT_BRAM_CAPACITY
        ));
    };

    t0.resize(
        HT_BRAM_CAPACITY,
        HEntry {
            key: HT_EMPTY_KEY,
            val: 0,
        },
    );
    t1.resize(
        HT_BRAM_CAPACITY,
        HEntry {
            key: HT_EMPTY_KEY,
            val: 0,
        },
    );

    Ok((t0, t1, cap, ranges.len()))
}

fn write_hex_i32_lines(path: &Path, vals: &[i32]) -> Result<(), String> {
    let fp = File::create(path).map_err(|e| format!("failed to create {}: {e}", path.display()))?;
    let mut bw = BufWriter::new(fp);
    for &v in vals {
        writeln!(bw, "{:08x}", v as u32)
            .map_err(|e| format!("failed to write {}: {e}", path.display()))?;
    }
    bw.flush()
        .map_err(|e| format!("failed to flush {}: {e}", path.display()))?;
    Ok(())
}

fn write_bram_hash_hex(
    t0: &[HEntry],
    t1: &[HEntry],
    t0_key_path: &Path,
    t0_val_path: &Path,
    t1_key_path: &Path,
    t1_val_path: &Path,
) -> Result<(), String> {
    let t0_keys: Vec<i32> = t0.iter().map(|e| e.key).collect();
    let t0_vals: Vec<i32> = t0.iter().map(|e| e.val).collect();
    let t1_keys: Vec<i32> = t1.iter().map(|e| e.key).collect();
    let t1_vals: Vec<i32> = t1.iter().map(|e| e.val).collect();

    write_hex_i32_lines(t0_key_path, &t0_keys)?;
    write_hex_i32_lines(t0_val_path, &t0_vals)?;
    write_hex_i32_lines(t1_key_path, &t1_keys)?;
    write_hex_i32_lines(t1_val_path, &t1_vals)?;

    Ok(())
}

fn write_gramht_meta_hex(path: &Path, ht_cap: usize) -> Result<(), String> {
    if ht_cap == 0 || ht_cap > HT_BRAM_CAPACITY {
        return Err(format!(
            "invalid gram hash capacity {} (max {})",
            ht_cap, HT_BRAM_CAPACITY
        ));
    }
    write_hex_u32_words(path, &[ht_cap as u32])
}

fn write_hex_u8_lines(path: &Path, vals: &[u8]) -> Result<(), String> {
    let fp = File::create(path).map_err(|e| format!("failed to create {}: {e}", path.display()))?;
    let mut bw = BufWriter::new(fp);
    for &v in vals {
        writeln!(bw, "{v:02x}").map_err(|e| format!("failed to write {}: {e}", path.display()))?;
    }
    bw.flush()
        .map_err(|e| format!("failed to flush {}: {e}", path.display()))?;
    Ok(())
}

fn write_exact_bram_hex(assigns: &[GramDbAssign], out_dir: &Path) -> Result<(), String> {
    if assigns.len() > ASSIGN_BRAM_CAPACITY {
        return Err(format!(
            "assign count {} exceeds BRAM capacity {}",
            assigns.len(),
            ASSIGN_BRAM_CAPACITY
        ));
    }

    let mut pre = vec![0i32; ASSIGN_BRAM_CAPACITY];
    let mut post = vec![0i32; ASSIGN_BRAM_CAPACITY];
    let mut lens = vec![0u32; ASSIGN_BRAM_CAPACITY];
    let mut pats = vec![0u8; PATTERN_BRAM_BYTES];

    for (i, a) in assigns.iter().enumerate() {
        pre[i] = a.pre_offset;
        post[i] = a.post_offset;
        lens[i] = a.pat_len;

        let pbase = i * MAX_PATTERN_LEN;
        pats[pbase..(pbase + MAX_PATTERN_LEN)].copy_from_slice(&a.pattern);
    }

    let meta_path = out_dir.join("gramdb_meta.hex");
    let pre_path = out_dir.join("gramdb_pre.hex");
    let post_path = out_dir.join("gramdb_post.hex");
    let len_path = out_dir.join("gramdb_len.hex");
    let pat_path = out_dir.join("gramdb_pat.hex");

    write_hex_u32_words(&meta_path, &[assigns.len() as u32])?;
    write_hex_i32_lines(&pre_path, &pre)?;
    write_hex_i32_lines(&post_path, &post)?;
    write_hex_u32_words(&len_path, &lens)?;
    write_hex_u8_lines(&pat_path, &pats)?;

    Ok(())
}

fn write_u32_le(fp: &mut File, v: u32) -> Result<(), String> {
    fp.write_all(&v.to_le_bytes())
        .map_err(|e| format!("write_u32_le failed: {e}"))
}

fn write_i32_le(fp: &mut File, v: i32) -> Result<(), String> {
    fp.write_all(&v.to_le_bytes())
        .map_err(|e| format!("write_i32_le failed: {e}"))
}

fn write_gramdb(
    path: &Path,
    assigns: &[GramDbAssign],
    t0: &[HEntry],
    t1: &[HEntry],
) -> Result<(), String> {
    let cap = t0.len();
    if cap != t1.len() {
        return Err("hash table size mismatch".to_string());
    }
    if cap > u32::MAX as usize {
        return Err("hash table too large for gramdb header".to_string());
    }
    if assigns.len() > u32::MAX as usize {
        return Err("assign count too large for gramdb header".to_string());
    }

    let mut fp =
        File::create(path).map_err(|e| format!("failed to create {}: {e}", path.display()))?;

    write_u32_le(&mut fp, assigns.len() as u32)?;
    write_u32_le(&mut fp, cap as u32)?;

    for a in assigns {
        write_u32_le(&mut fp, a.gram_idx)?;
        write_i32_le(&mut fp, a.rule_id)?;
        write_i32_le(&mut fp, a.pre_offset)?;
        write_i32_le(&mut fp, a.post_offset)?;
        write_u32_le(&mut fp, a.pat_len)?;
        fp.write_all(&a.pattern)
            .map_err(|e| format!("failed to write assign pattern: {e}"))?;
    }

    for e in t0 {
        write_i32_le(&mut fp, e.key)?;
        write_i32_le(&mut fp, e.val)?;
    }
    for e in t1 {
        write_i32_le(&mut fp, e.key)?;
        write_i32_le(&mut fp, e.val)?;
    }

    fp.flush()
        .map_err(|e| format!("failed to flush {}: {e}", path.display()))?;

    Ok(())
}

fn build_outputs(rule_file: &Path, bitmap_file: &Path, gramdb_file: &Path) -> Result<(), String> {
    let rules = load_rules(rule_file).map_err(|e| format!("failed to load rules: {e}"))?;
    if rules.is_empty() {
        return Err(format!("no rules loaded from {}", rule_file.display()));
    }

    let singleton = singleton_build(&rules);

    let mut bitmap = vec![0u8; BITMAP_BYTES];
    for a in &singleton.assigns {
        bitmap_set(&mut bitmap, a.gram_idx);
    }

    let verify_fail = singleton
        .assigns
        .iter()
        .filter(|a| !bitmap_get(&bitmap, a.gram_idx))
        .count();
    if verify_fail != 0 {
        return Err(format!("bitmap self-check failed: {verify_fail} miss(es)"));
    }

    let gramdb_assigns = build_gramdb_assigns(&rules, &singleton)?;
    let (table0, table1, _ht_capacity, _unique_grams) = build_hash_tables(&gramdb_assigns)?;

    let (bram_t0, bram_t1, bram_ht_cap, bram_unique_grams) =
        build_bram_hash_tables(&gramdb_assigns)?;

    let out_dir = bitmap_file
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| Path::new(".").to_path_buf());
    let bitmap_hex_path = out_dir.join("bitmap32.hex");
    let gramht_meta_path = out_dir.join("gramht_meta.hex");
    let t0_key_hex_path = out_dir.join("gramht_t0_key.hex");
    let t0_val_hex_path = out_dir.join("gramht_t0_val.hex");
    let t1_key_hex_path = out_dir.join("gramht_t1_key.hex");
    let t1_val_hex_path = out_dir.join("gramht_t1_val.hex");
    let gramdb_meta_path = out_dir.join("gramdb_meta.hex");
    let gramdb_pre_path = out_dir.join("gramdb_pre.hex");
    let gramdb_post_path = out_dir.join("gramdb_post.hex");
    let gramdb_len_path = out_dir.join("gramdb_len.hex");
    let gramdb_pat_path = out_dir.join("gramdb_pat.hex");

    write_bitmap(bitmap_file, &bitmap)?;
    write_gramdb(gramdb_file, &gramdb_assigns, &table0, &table1)?;

    let bitmap32_words = build_bitmap32_words(&bitmap);
    write_hex_u32_words(&bitmap_hex_path, &bitmap32_words)?;
    write_gramht_meta_hex(&gramht_meta_path, bram_ht_cap)?;
    write_bram_hash_hex(
        &bram_t0,
        &bram_t1,
        &t0_key_hex_path,
        &t0_val_hex_path,
        &t1_key_hex_path,
        &t1_val_hex_path,
    )?;
    write_exact_bram_hex(&gramdb_assigns, &out_dir)?;

    let bits_set: u32 = bitmap.iter().map(|b| b.count_ones()).sum();

    println!("file           : {}", rule_file.display());
    println!("rules          : {}", rules.len());
    println!();
    println!("=== singleton build ===");
    println!("covered        : {}", singleton.assigns.len());
    println!("uncovered      : {}  (pat_len < {})", singleton.uncovered, N_GRAM);
    println!("singletons     : {}  (degree=1, unique gram)", singleton.n_deg1);
    println!("shared         : {}  (degree>1, gram in multiple rules)", singleton.n_shared);
    println!();
    println!("=== bitmap ===");
    println!("grams in bitmap: {}", bits_set);
    println!("bitmap bytes   : {}  ({} MB)", BITMAP_BYTES, BITMAP_BYTES >> 20);
    println!("bitmap verify  : OK");
    println!();
    println!("=== gram hash table (BRAM) ===");
    println!("unique grams   : {}", bram_unique_grams);
    println!("ht capacity    : {}", bram_ht_cap);
    println!();
    println!("=== outputs ===");
    println!("bitmap bin     : {}", bitmap_file.display());
    println!("bitmap32 hex   : {}", bitmap_hex_path.display());
    println!("gramdb bin     : {}", gramdb_file.display());
    println!("gramht meta    : {}", gramht_meta_path.display());
    println!("gramht t0 key  : {}", t0_key_hex_path.display());
    println!("gramht t0 val  : {}", t0_val_hex_path.display());
    println!("gramht t1 key  : {}", t1_key_hex_path.display());
    println!("gramht t1 val  : {}", t1_val_hex_path.display());
    println!("gramdb meta    : {}", gramdb_meta_path.display());
    println!("gramdb pre     : {}", gramdb_pre_path.display());
    println!("gramdb post    : {}", gramdb_post_path.display());
    println!("gramdb len     : {}", gramdb_len_path.display());
    println!("gramdb pat     : {}", gramdb_pat_path.display());

    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();

    // Usage: bitmap_gen [rule.txt [bitmap.bin [gramdb.bin]]]
    let positional: Vec<&str> = args.iter().skip(1).map(String::as_str).collect();

    let rule_file = positional.first().copied().unwrap_or("rule.txt");
    let bitmap_file = positional.get(1).copied().unwrap_or("bitmap.bin");
    let gramdb_file = positional.get(2).copied().unwrap_or("gramdb.bin");

    if let Err(e) = build_outputs(
        Path::new(rule_file),
        Path::new(bitmap_file),
        Path::new(gramdb_file),
    ) {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
