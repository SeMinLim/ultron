//! Per-packet verdicts: hardware vs the C oracle.

use crate::hw::{Expect, HwResult};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Verdict {
    Ok,
    TieBreak,       // right priority, but not the lowest rule id among the tied rules
    FalseNegative,  // oracle hit, hardware silent
    FalsePositive,  // oracle miss, hardware hit
    WrongPriority,  // hardware rule matched, but not at the best priority
    WrongRule,      // hardware rule is not a match at all per the oracle
    SkipHit,        // C could not parse the frame, hardware still hit (parser divergence)
}

impl Verdict {
    pub fn is_bug(self) -> bool {
        !matches!(self, Verdict::Ok)
    }
}

pub fn judge(exp: &Expect, hw: Option<u16>) -> Verdict {
    match (exp, hw) {
        (Expect::Skip, None) | (Expect::Miss, None) => Verdict::Ok,
        (Expect::Skip, Some(_)) => Verdict::SkipHit,
        (Expect::Miss, Some(_)) => Verdict::FalsePositive,
        (Expect::Hit { .. }, None) => Verdict::FalseNegative,
        (Expect::Hit { top, all, .. }, Some(r)) => {
            // Equal priority -> the lowest rule id wins (kernel and C agree).
            if top.contains(&r) {
                if r == *top.iter().min().unwrap() { Verdict::Ok } else { Verdict::TieBreak }
            } else if all.iter().any(|&(id, _)| id == r) {
                Verdict::WrongPriority
            } else {
                Verdict::WrongRule
            }
        }
    }
}

pub fn judge_all(exp: &[Expect], hw: &HwResult) -> Vec<Verdict> {
    exp.iter().enumerate().map(|(i, e)| judge(e, hw.hits.get(&i).copied())).collect()
}
