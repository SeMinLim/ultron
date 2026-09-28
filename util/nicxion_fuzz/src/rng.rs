//! SplitMix64: tiny, seedable, and good enough for test-case generation.

pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in [0, n).  n == 0 returns 0.
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 { 0 } else { (self.next_u64() % n as u64) as usize }
    }

    /// Uniform in [lo, hi] (inclusive).
    pub fn range(&mut self, lo: usize, hi: usize) -> usize {
        if hi <= lo { lo } else { lo + self.below(hi - lo + 1) }
    }

    pub fn chance(&mut self, p: f64) -> bool {
        ((self.next_u64() >> 11) as f64 / (1u64 << 53) as f64) < p
    }

    pub fn pick<'a, T>(&mut self, v: &'a [T]) -> &'a T {
        &v[self.below(v.len())]
    }

    pub fn byte(&mut self) -> u8 {
        self.next_u64() as u8
    }

    /// Pick an index according to integer weights.
    pub fn weighted(&mut self, w: &[u32]) -> usize {
        let total: u32 = w.iter().sum();
        let mut x = self.below(total as usize) as u32;
        for (i, &wi) in w.iter().enumerate() {
            if x < wi { return i; }
            x -= wi;
        }
        w.len() - 1
    }
}
