//! Login / password input sources (`-l`, `-L`, `-p`, `-P`, `-C`, `-x`).

use std::path::PathBuf;

use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader};

use crate::charset::CharsetSpec;

/// Where logins come from.
#[derive(Debug, Clone)]
pub enum LoginSource {
    /// `-l user`
    Single(String),
    /// `-L file`
    File(PathBuf),
    /// no `-l`/`-L` (e.g. password-only services like VNC/SNMP)
    None,
}

/// Where passwords come from.
#[derive(Debug, Clone)]
pub enum PassSource {
    /// `-p pass`
    Single(String),
    /// `-P file`
    File(PathBuf),
    /// `-x MIN:MAX:CHARSET`
    Charset(CharsetSpec),
    /// no password source (auth handled entirely by extras / combo)
    None,
}

impl LoginSource {
    /// Eagerly load the login list (logins are typically small).
    pub async fn load(&self) -> std::io::Result<Vec<String>> {
        match self {
            LoginSource::Single(u) => Ok(vec![u.clone()]),
            LoginSource::File(p) => read_lines(p).await,
            LoginSource::None => Ok(Vec::new()),
        }
    }

    /// Best-effort count for progress estimation.
    pub async fn count(&self) -> Option<u64> {
        match self {
            LoginSource::Single(_) => Some(1),
            LoginSource::File(p) => read_lines(p).await.ok().map(|v| v.len() as u64),
            LoginSource::None => Some(1),
        }
    }
}

impl PassSource {
    /// Exact count where cheaply knowable, else `None` (huge files stay streamed).
    pub fn count(&self) -> Option<u64> {
        match self {
            PassSource::Single(_) => Some(1),
            PassSource::Charset(c) => Some(c.count()),
            PassSource::File(_) => None,
            PassSource::None => Some(0),
        }
    }
}

/// Read a file into a `Vec<String>` of non-empty-trimmed... actually keep raw
/// lines verbatim (passwords may contain leading/trailing spaces) but drop the
/// trailing newline only.
pub async fn read_lines(path: &PathBuf) -> std::io::Result<Vec<String>> {
    let file = File::open(path).await?;
    let mut reader = BufReader::new(file).lines();
    let mut out = Vec::new();
    while let Some(line) = reader.next_line().await? {
        out.push(line);
    }
    Ok(out)
}
