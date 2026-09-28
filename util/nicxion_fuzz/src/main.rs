//! nicxion_fuzz: differential fuzzing of the nicxion PM kernel on the U50.
//!
//! Each iteration: ruleset (production or synthetic) -> DB -> packet stream ->
//! C oracle verdicts -> card reset -> run on the chip -> per-packet compare.
//! Failing iterations are saved under the output directory, and each failing
//! packet is re-run alone (and with its predecessors) to separate isolated bugs
//! from context-dependent ones such as pipeline races.

mod gen;
mod hw;
mod judge;
mod packet;
mod rng;
mod rules;

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use judge::Verdict;

struct Args {
    iters: usize,
    pkts: usize,
    seed: u64,
    rules: PathBuf,
    synth: f64,
    max_payload: usize,
    out: PathBuf,
    no_hw: bool,
    minimize: usize,
    timeout: u64,
}

fn usage() -> ! {
    eprintln!(
        "usage: nicxion_fuzz [--iters N] [--pkts N] [--seed S] [--rules FILE]\n\
         \x20                   [--synth P] [--max-payload N] [--out DIR] [--no-hw]\n\
         \x20                   [--minimize K] [--timeout SECS]\n\
         env: NX_KERNEL_DIR NX_HOST_DIR NX_XCLBIN NX_ORACLE NX_ORACLE_ARGS NX_BDF"
    );
    std::process::exit(2)
}

fn parse_args() -> Args {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(1);
    let mut a = Args {
        iters: 20,
        pkts: 2000,
        seed: now,
        rules: PathBuf::from(std::env::var("NX_RULES").unwrap_or_else(|_|
            format!("{}/rule.txt", std::env::var("NX_HOST_DIR").unwrap_or_else(|_| hw::repo_path("vitis/sw/nicxion_rev2_perf_opt"))))),
        synth: 0.5,
        max_payload: 1460,
        out: PathBuf::new(),
        no_hw: false,
        minimize: 4,
        timeout: 600,
    };
    let v: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < v.len() {
        let val = |i: usize| v.get(i + 1).cloned().unwrap_or_else(|| usage());
        match v[i].as_str() {
            "--iters" => { a.iters = val(i).parse().unwrap_or_else(|_| usage()); i += 1 }
            "--pkts" => { a.pkts = val(i).parse().unwrap_or_else(|_| usage()); i += 1 }
            "--seed" => { a.seed = val(i).parse().unwrap_or_else(|_| usage()); i += 1 }
            "--rules" => { a.rules = PathBuf::from(val(i)); i += 1 }
            "--synth" => { a.synth = val(i).parse().unwrap_or_else(|_| usage()); i += 1 }
            "--max-payload" => { a.max_payload = val(i).parse().unwrap_or_else(|_| usage()); i += 1 }
            "--out" => { a.out = PathBuf::from(val(i)); i += 1 }
            "--minimize" => { a.minimize = val(i).parse().unwrap_or_else(|_| usage()); i += 1 }
            "--timeout" => { a.timeout = val(i).parse().unwrap_or_else(|_| usage()); i += 1 }
            "--no-hw" => a.no_hw = true,
            _ => usage(),
        }
        i += 1;
    }
    if a.out.as_os_str().is_empty() {
        a.out = PathBuf::from(format!("{}/out/seed{}", env!("CARGO_MANIFEST_DIR"), a.seed));
    }
    a
}

fn fmt_expect(e: &hw::Expect) -> String {
    match e {
        hw::Expect::Skip => "SKIP".into(),
        hw::Expect::Miss => "MISS".into(),
        hw::Expect::Hit { prio, top, .. } => format!("HIT p{} {:?}", prio, top),
    }
}

/// Run one pcap on the chip (fresh card) and judge it.
fn hw_round(env: &hw::Env, db: &Path, rules: &Path, pcap: &Path, timeout: u64)
    -> Result<(Vec<hw::Expect>, hw::HwResult, Vec<Verdict>), String> {
    let exp = hw::oracle(env, rules, pcap)?;
    hw::reset_card(env)?;
    let res = hw::run(env, db, pcap, Duration::from_secs(timeout))?;
    let v = judge::judge_all(&exp, &res);
    Ok((exp, res, v))
}

fn main() {
    let mut a = parse_args();
    if !a.rules.exists() {
        eprintln!("rules file not found: {} (use --rules FILE or NX_RULES)", a.rules.display());
        std::process::exit(2);
    }
    let env = hw::Env::from_env();
    fs::create_dir_all(&a.out).expect("create out dir");
    // The host binary runs in its own directory, so every path it gets must be absolute.
    a.out = fs::canonicalize(&a.out).expect("resolve out dir");
    a.rules = fs::canonicalize(&a.rules).expect("resolve rules file");
    let mut rng = rng::Rng::new(a.seed);
    let cfg = gen::GenCfg { max_payload: a.max_payload };

    let base_rules = rules::load(&a.rules).expect("load base rules");
    let base_db = a.out.join("base_db.bin");
    if !a.no_hw {
        hw::dbgen(&env, &a.rules, &base_db).expect("base DB");
    }
    println!(
        "nicxion_fuzz seed={} iters={} pkts={} base={} ({} rules) out={}",
        a.seed, a.iters, a.pkts, a.rules.display(), base_rules.len(), a.out.display()
    );

    let mut summary = fs::OpenOptions::new().create(true).append(true).open(a.out.join("summary.tsv")).unwrap();
    let mut totals: BTreeMap<String, usize> = BTreeMap::new();

    for it in 0..a.iters {
        let dir = a.out.join(format!("iter_{:04}", it));
        fs::create_dir_all(&dir).unwrap();

        // Ruleset.
        let synth = rng.chance(a.synth);
        let (rule_vec, rules_path, db_path) = if synth {
            let n = rng.range(20, 400);
            let rs = gen::synth_rules(&mut rng, n);
            let p = dir.join("rules.txt");
            rules::write(&p, &rs).unwrap();
            let db = dir.join("db.bin");
            if !a.no_hw {
                if let Err(e) = hw::dbgen(&env, &p, &db) {
                    println!("iter {it}: synthetic ruleset rejected by DB generator: {e}");
                    *totals.entry("dbgen_reject".into()).or_default() += 1;
                    continue;
                }
            }
            (rs, p, db)
        } else {
            (base_rules.clone(), a.rules.clone(), base_db.clone())
        };

        // Packets.
        let cases = gen::packets(&mut rng, &rule_vec, a.pkts, &cfg);
        let frames: Vec<Vec<u8>> = cases.iter().map(|c| c.frame.clone()).collect();
        let pcap = dir.join("pkts.pcap");
        packet::write_pcap(&pcap, &frames).unwrap();

        if a.no_hw {
            let exp = hw::oracle(&env, &rules_path, &pcap).expect("oracle");
            let hits = exp.iter().filter(|e| matches!(e, hw::Expect::Hit { .. })).count();
            let skips = exp.iter().filter(|e| matches!(e, hw::Expect::Skip)).count();
            println!("iter {it}: {} rules{} | oracle hits {hits} skips {skips} / {}", rule_vec.len(), if synth {" (synth)"} else {""}, exp.len());
            if std::env::var("NX_KEEP").is_ok() {
                let t: String = cases.iter().zip(&exp).enumerate()
                    .map(|(i, (c, e))| format!("{i}\t{}\t{}\n", fmt_expect(e), c.desc)).collect();
                fs::write(dir.join("cases.tsv"), t).unwrap();
            } else {
                fs::remove_dir_all(&dir).ok();
            }
            continue;
        }

        let (exp, res, verdicts) = match hw_round(&env, &db_path, &rules_path, &pcap, a.timeout) {
            Ok(x) => x,
            Err(e) => { println!("iter {it}: infrastructure error: {e}"); continue; }
        };
        let hang = res.stuck || res.timed_out || res.processed != Some(a.pkts as u32);
        let mut counts: BTreeMap<Verdict, usize> = BTreeMap::new();
        for v in &verdicts { *counts.entry(*v).or_default() += 1; }
        let bugs: Vec<usize> = verdicts.iter().enumerate().filter(|(_, v)| v.is_bug()).map(|(i, _)| i).collect();
        let hits = exp.iter().filter(|e| matches!(e, hw::Expect::Hit { .. })).count();

        let line = format!(
            "iter {it}: {} rules{} | oracle hits {hits} | hw hits {} | bugs {}{}{}",
            rule_vec.len(), if synth {" (synth)"} else {""}, res.hits.len(), bugs.len(),
            if hang { " | HANG/INCOMPLETE" } else { "" },
            if counts.get(&Verdict::TieBreak).copied().unwrap_or(0) > 0 { format!(" | tie-break {}", counts[&Verdict::TieBreak]) } else { String::new() }
        );
        println!("{line}");
        writeln!(summary, "{}\t{}\t{}\t{}\t{}\t{}\t{:?}", it, rule_vec.len(), synth, hits, bugs.len(), hang, counts).unwrap();
        for (v, n) in &counts { *totals.entry(format!("{:?}", v)).or_default() += n; }
        if hang { *totals.entry("HANG".into()).or_default() += 1; }

        if bugs.is_empty() && !hang {
            fs::remove_dir_all(&dir).ok(); // keep only failing iterations
            continue;
        }

        // Save the failing case.
        fs::write(dir.join("hw.log"), &res.log).unwrap();
        let mut rep = String::new();
        for &i in &bugs {
            rep.push_str(&format!("{}\t{:?}\texpect={}\thw={:?}\t{}\n", i, verdicts[i], fmt_expect(&exp[i]), res.hits.get(&i), cases[i].desc));
        }
        fs::write(dir.join("failures.tsv"), &rep).unwrap();
        if !synth { fs::copy(&rules_path, dir.join("rules.txt")).ok(); }

        // Minimize: each failing packet alone, then with its 16 predecessors.
        let mut mrep = String::new();
        for &i in bugs.iter().take(a.minimize) {
            let one = dir.join(format!("min_{i}.pcap"));
            packet::write_pcap(&one, &frames[i..=i]).unwrap();
            let alone = hw_round(&env, &db_path, &rules_path, &one, a.timeout).map(|(_, _, v)| v[0]);
            let lo = i.saturating_sub(16);
            let ctx = dir.join(format!("ctx_{i}.pcap"));
            packet::write_pcap(&ctx, &frames[lo..=i]).unwrap();
            let with_ctx = hw_round(&env, &db_path, &rules_path, &ctx, a.timeout).map(|(_, _, v)| *v.last().unwrap());
            let kind = match (&alone, &with_ctx) {
                (Ok(v), _) if v.is_bug() => "ISOLATED",
                (_, Ok(v)) if v.is_bug() => "CONTEXT(<=16 pkts)",
                _ => "CONTEXT(long)",
            };
            mrep.push_str(&format!("{i}\talone={:?}\twith16={:?}\t{kind}\t{}\n", alone, with_ctx, cases[i].desc));
            println!("    pkt {i}: {kind}  ({})", cases[i].desc);
        }
        fs::write(dir.join("minimize.tsv"), mrep).unwrap();
    }

    println!("== totals: {:?}", totals);
}
