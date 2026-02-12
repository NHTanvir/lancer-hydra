//! `-e nsr` extra password modes: null, same-as-login, reversed-login.

/// Which of the `-e` extra modes are enabled.
#[derive(Debug, Clone, Copy, Default)]
pub struct ExtraModes {
    /// `n` — also try the empty password.
    pub null: bool,
    /// `s` — also try password == login.
    pub same: bool,
    /// `r` — also try password == reversed login.
    pub reversed: bool,
}

impl ExtraModes {
    /// Parse the `-e` argument string (any subset/order of `n`, `s`, `r`).
    pub fn parse(s: &str) -> Self {
        Self {
            null: s.contains('n'),
            same: s.contains('s'),
            reversed: s.contains('r'),
        }
    }

    pub fn any(&self) -> bool {
        self.null || self.same || self.reversed
    }

    pub fn count(&self) -> u64 {
        self.null as u64 + self.same as u64 + self.reversed as u64
    }

    /// The extra passwords to try for a given login.
    pub fn passwords_for(&self, login: &str) -> Vec<String> {
        let mut v = Vec::new();
        if self.null {
            v.push(String::new());
        }
        if self.same {
            v.push(login.to_string());
        }
        if self.reversed {
            v.push(login.chars().rev().collect());
        }
        v
    }
}
