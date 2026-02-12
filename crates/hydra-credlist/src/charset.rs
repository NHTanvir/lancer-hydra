//! `-x MIN:MAX:CHARSET` brute-force charset generator.
//!
//! CHARSET tokens: `a` → a-z, `A` → A-Z, `1` → 0-9; any other char is added
//! literally. So `aA1` is all alphanumerics, `a1` lower+digits, `abc` literal.

#[derive(Debug, Clone)]
pub struct CharsetSpec {
    pub min: usize,
    pub max: usize,
    pub charset: Vec<char>,
}

impl CharsetSpec {
    /// Parse `MIN:MAX:CHARSET`. `-y` (digits-only) can be applied by the caller.
    pub fn parse(s: &str) -> Result<Self, String> {
        let parts: Vec<&str> = s.splitn(3, ':').collect();
        if parts.len() != 3 {
            return Err(format!("charset spec must be MIN:MAX:CHARSET, got {s:?}"));
        }
        let min: usize = parts[0].parse().map_err(|_| "bad MIN".to_string())?;
        let max: usize = parts[1].parse().map_err(|_| "bad MAX".to_string())?;
        if min > max {
            return Err("MIN must be <= MAX".into());
        }
        let charset = expand_charset(parts[2]);
        if charset.is_empty() {
            return Err("empty charset".into());
        }
        Ok(Self { min, max, charset })
    }

    /// Total number of candidates (may be astronomically large; saturating).
    pub fn count(&self) -> u64 {
        let base = self.charset.len() as u64;
        let mut total: u64 = 0;
        for len in self.min..=self.max {
            total = total.saturating_add(base.saturating_pow(len as u32));
        }
        total
    }

    /// Lazy odometer iterator over all candidates.
    pub fn iter(&self) -> CharsetIter {
        CharsetIter {
            charset: self.charset.clone(),
            len: self.min,
            max: self.max,
            idx: vec![0; self.min],
            done: self.min > self.max,
        }
    }
}

fn expand_charset(spec: &str) -> Vec<char> {
    let mut out = Vec::new();
    for c in spec.chars() {
        match c {
            'a' => out.extend('a'..='z'),
            'A' => out.extend('A'..='Z'),
            '1' => out.extend('0'..='9'),
            other => out.push(other),
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// Odometer iterator: yields every string of length `min..=max`.
pub struct CharsetIter {
    charset: Vec<char>,
    len: usize,
    max: usize,
    idx: Vec<usize>,
    done: bool,
}

impl Iterator for CharsetIter {
    type Item = String;

    fn next(&mut self) -> Option<String> {
        if self.done {
            return None;
        }
        let s: String = self.idx.iter().map(|&i| self.charset[i]).collect();

        if self.len == 0 {
            // The empty string is the single candidate at length 0.
            self.len += 1;
            if self.len > self.max {
                self.done = true;
            } else {
                self.idx = vec![0; self.len];
            }
            return Some(s);
        }

        // Increment the odometer from the right.
        let mut pos = self.len;
        loop {
            if pos == 0 {
                self.len += 1;
                if self.len > self.max {
                    self.done = true;
                } else {
                    self.idx = vec![0; self.len];
                }
                break;
            }
            pos -= 1;
            self.idx[pos] += 1;
            if self.idx[pos] < self.charset.len() {
                break;
            }
            self.idx[pos] = 0;
        }
        Some(s)
    }
}
