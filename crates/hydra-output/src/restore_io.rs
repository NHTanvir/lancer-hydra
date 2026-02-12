//! Restore-file persistence (`hydra.restore`, JSON, atomic write via rename).
//!
//! Unlike upstream's packed-binary format, JSON is portable across endianness
//! and architecture — the same file resumes on any platform.

use std::path::Path;

use serde::{Deserialize, Serialize};

use hydra_protocols::Target;

use crate::Hit;

/// Position within the credential stream, per the plan's schema.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Cursor {
    pub user_index: u64,
    pub pass_index: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreHit {
    pub login: String,
    pub pass: String,
}

impl From<&Hit> for RestoreHit {
    fn from(h: &Hit) -> Self {
        Self {
            login: h.login.clone(),
            pass: h.password.clone(),
        }
    }
}

/// The on-disk restore document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreFile {
    pub version: String,
    pub command: String,
    pub targets: Vec<Target>,
    pub creds_done: u64,
    pub hits: Vec<RestoreHit>,
    pub credqueue_cursor: Cursor,
}

impl RestoreFile {
    /// Atomically replace `path`: write to `<path>.tmp` then rename over it.
    pub fn save_atomic(&self, path: &Path) -> std::io::Result<()> {
        let tmp = path.with_extension("restore.tmp");
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(&tmp, json)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn load(path: &Path) -> std::io::Result<Self> {
        let data = std::fs::read_to_string(path)?;
        serde_json::from_str(&data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}
