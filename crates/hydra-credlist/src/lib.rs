//! `hydra-credlist` — credential generation for lancer-hydra.
//!
//! Turns `-l/-L/-p/-P/-C/-x/-e/-u` into a lazy `(user, pass)` stream over a
//! bounded `tokio::sync::mpsc` channel so memory stays flat on 10M-line lists.

pub mod charset;
pub mod extra;
pub mod generator;
pub mod sources;

use tokio::sync::mpsc::{self, Receiver};

pub use charset::CharsetSpec;
pub use extra::ExtraModes;
pub use sources::{LoginSource, PassSource};

/// One credential to attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    pub user: String,
    pub pass: String,
}

impl Credential {
    pub fn new(user: impl Into<String>, pass: impl Into<String>) -> Self {
        Self {
            user: user.into(),
            pass: pass.into(),
        }
    }
}

/// Full credential-generation configuration assembled from the CLI flags.
#[derive(Debug, Clone)]
pub struct CredConfig {
    pub logins: LoginSource,
    pub passwords: PassSource,
    /// `-C` colon combo file (mutually exclusive with the cartesian product).
    pub combo: Option<std::path::PathBuf>,
    pub extra: ExtraModes,
    /// `-u`: loop users first (password spray) instead of passwords first.
    pub users_first: bool,
}

impl Default for CredConfig {
    fn default() -> Self {
        Self {
            logins: LoginSource::None,
            passwords: PassSource::None,
            combo: None,
            extra: ExtraModes::default(),
            users_first: false,
        }
    }
}

impl CredConfig {
    /// Spawn the generator and return a bounded receiver of credentials.
    pub fn stream(self, buffer: usize) -> Receiver<Credential> {
        let (tx, rx) = mpsc::channel(buffer.max(1));
        tokio::spawn(generator::produce(self, tx));
        rx
    }

    /// Best-effort total credential count for progress (None when unknowable,
    /// e.g. a password file that we deliberately do not pre-scan).
    pub async fn estimate(&self) -> Option<u64> {
        if self.combo.is_some() {
            return None;
        }
        let users = self.logins.count().await?;
        let passes = self.passwords.count()?;
        let extras = self.extra.count();
        Some(users.saturating_mul(passes.saturating_add(extras)))
    }
}
