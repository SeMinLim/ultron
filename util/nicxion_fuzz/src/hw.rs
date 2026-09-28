//! External tools: C oracle, DB generator, card reset, and the host program.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

pub struct Env {
    pub host_dir: PathBuf,
    pub xclbin: PathBuf,
    pub oracle: PathBuf,
    pub bdf: String,
}

/// A path inside the repo this crate lives in (util/nicxion_fuzz -> repo root).
pub fn repo_path(rel: &str) -> String {
    format!("{}/../../{}", env!("CARGO_MANIFEST_DIR"), rel)
}

impl Env {
    pub fn from_env() -> Env {
        let get = |k: &str, d: String| std::env::var(k).unwrap_or(d);
        let kernel_dir = PathBuf::from(get("NX_KERNEL_DIR", repo_path("vitis/hw/nicxion_rev2_perf_opt")));
        let host_dir = PathBuf::from(get("NX_HOST_DIR", repo_path("vitis/sw/nicxion_rev2_perf_opt")));
        let xclbin = PathBuf::from(get("NX_XCLBIN", kernel_dir.join("hw/kernel.xclbin").to_string_lossy().into()));
        let oracle = PathBuf::from(get("NX_ORACLE", format!("{}/oracle/pm_oracle", env!("CARGO_MANIFEST_DIR"))));
        let bdf = get("NX_BDF", "0000:01:00.1".into());
        Env { host_dir, xclbin, oracle, bdf }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Expect {
    Skip,
    Miss,
    Hit { prio: u8, top: Vec<u16>, all: Vec<(u16, u8)> },
}

pub fn oracle(env: &Env, rules: &Path, pcap: &Path) -> Result<Vec<Expect>, String> {
    // NX_ORACLE_ARGS: oracle options.  The default matches the current (IPv6) host;
    // "--parser host" for the older IPv4-only hosts.
    let extra = std::env::var("NX_ORACLE_ARGS").unwrap_or_else(|_| "--parser host6".into());
    let out = Command::new(&env.oracle).arg(rules).arg(pcap).args(extra.split_whitespace())
        .output().map_err(|e| format!("oracle: {e}"))?;
    if !out.status.success() {
        return Err(format!("oracle failed: {}", String::from_utf8_lossy(&out.stderr)));
    }
    let mut v = Vec::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        let e = match f.get(1).copied() {
            Some("SKIP") => Expect::Skip,
            Some("MISS") => Expect::Miss,
            Some("HIT") => {
                let prio = f[2].parse().unwrap_or(0);
                let top = f[3].split(',').filter_map(|x| x.parse().ok()).collect();
                let all = f[4]
                    .split(',')
                    .filter_map(|x| x.split_once(':'))
                    .map(|(a, b)| (a.parse().unwrap_or(0), b.parse().unwrap_or(0)))
                    .collect();
                Expect::Hit { prio, top, all }
            }
            _ => return Err(format!("bad oracle line: {line}")),
        };
        v.push(e);
    }
    Ok(v)
}

pub fn dbgen(env: &Env, rules: &Path, db: &Path) -> Result<(), String> {
    let out = Command::new(env.host_dir.join("gen/ngram_db_gen"))
        .arg(rules)
        .arg(db)
        .output()
        .map_err(|e| format!("dbgen: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "ngram_db_gen rejected the ruleset: {}{}",
            String::from_utf8_lossy(&out.stdout).lines().last().unwrap_or(""),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

/// The kernel loads its DB once after reset, so every run needs a fresh card.
pub fn reset_card(env: &Env) -> Result<(), String> {
    let _ = Command::new("xrt-smi").args(["reset", "-d", &env.bdf, "--force"]).stdout(Stdio::null()).stderr(Stdio::null()).status();
    for _ in 0..30 {
        let out = Command::new("xrt-smi").arg("examine").output().map_err(|e| e.to_string())?;
        if String::from_utf8_lossy(&out.stdout).contains(&env.bdf) {
            return Ok(());
        }
        sleep(Duration::from_secs(2));
    }
    Err("card did not come back after reset".into())
}

pub struct HwResult {
    pub hits: HashMap<usize, u16>,
    pub processed: Option<u32>,
    pub stuck: bool,
    pub timed_out: bool,
    pub log: String,
}

pub fn run(env: &Env, db: &Path, pcap: &Path, timeout: Duration) -> Result<HwResult, String> {
    let mut child = Command::new(env.host_dir.join("obj/main"))
        .current_dir(&env.host_dir)
        .env_remove("XCL_EMULATION_MODE")
        .arg(&env.xclbin)
        .arg(db)
        .arg(pcap)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("host: {e}"))?;
    let t0 = Instant::now();
    let mut timed_out = false;
    loop {
        if child.try_wait().map_err(|e| e.to_string())?.is_some() {
            break;
        }
        if t0.elapsed() > timeout {
            let _ = child.kill(); // our own host process only
            timed_out = true;
            break;
        }
        sleep(Duration::from_millis(200));
    }
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    let log = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    let mut hits = HashMap::new();
    let mut processed = None;
    for line in log.lines() {
        let l = line.trim();
        if let Some(rest) = l.strip_prefix("pkt[") {
            if let Some((i, r)) = rest.split_once("] matched rule_id=") {
                if let (Ok(i), Ok(r)) = (i.parse(), r.trim().parse()) {
                    hits.insert(i, r);
                }
            }
        } else if let Some(rest) = l.strip_prefix("matched=") {
            processed = rest.split("processed=").nth(1).and_then(|x| x.trim().parse().ok());
        }
    }
    let stuck = log.contains("STUCK");
    Ok(HwResult { hits, processed, stuck, timed_out, log })
}
