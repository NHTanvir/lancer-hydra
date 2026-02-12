//! `hydra-output` — output formats, progress bar and restore-file IO.
//!
//! Mirrors upstream `-b text|json|jsonv1` and adds a Lancer `jsonl` streaming
//! variant (one JSON object per line as hits arrive).

pub mod json;
pub mod progress;
pub mod restore_io;
pub mod text;

use std::io::Write;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub use json::{ErrorMessage, Generator, JsonReport};
pub use progress::Progress;
pub use restore_io::{Cursor, RestoreFile, RestoreHit};

/// A discovered credential. Serialized verbatim into the JSON `results` array.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hit {
    pub host: String,
    pub port: u16,
    pub service: String,
    pub login: String,
    pub password: String,
    pub time_ms: u64,
}

/// Output encodings. `jsonv1` pins the upstream-compatible schema; `json` may
/// bump versions; `jsonl` streams one object per line; `text` is the classic line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
    JsonV1,
    Jsonl,
}

impl OutputFormat {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "text" | "txt" => Some(Self::Text),
            "json" => Some(Self::Json),
            "jsonv1" => Some(Self::JsonV1),
            "jsonl" | "ndjson" => Some(Self::Jsonl),
            _ => None,
        }
    }
}

/// Collects hits/errors and writes them out in the chosen format.
///
/// Both JSON file variants truncate the output file on open (upstream 9.0
/// behaviour); `text`/`jsonl` stream each hit as it is recorded.
pub struct OutputSink {
    format: OutputFormat,
    handle: Option<std::fs::File>,
    arguments: String,
    built: String,
    hits: Vec<Hit>,
    errors: Vec<ErrorMessage>,
}

impl OutputSink {
    pub fn new(format: OutputFormat, file: Option<PathBuf>, arguments: String) -> std::io::Result<Self> {
        let handle = match file {
            Some(p) => Some(
                std::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true) // upstream truncates the output file on open
                    .open(p)?,
            ),
            None => None,
        };
        Ok(Self {
            format,
            handle,
            arguments,
            built: build_stamp(),
            hits: Vec::new(),
            errors: Vec::new(),
        })
    }

    /// Record a hit. For streaming formats it is written to the file immediately.
    pub fn record(&mut self, hit: Hit) {
        if let Some(h) = self.handle.as_mut() {
            match self.format {
                OutputFormat::Text => {
                    let _ = writeln!(h, "{}", text::format_hit(&hit));
                }
                OutputFormat::Jsonl => {
                    if let Ok(line) = serde_json::to_string(&hit) {
                        let _ = writeln!(h, "{line}");
                    }
                }
                // json / jsonv1 accumulate and flush the whole document at finish.
                _ => {}
            }
        }
        self.hits.push(hit);
    }

    pub fn add_error(&mut self, error: impl Into<String>, host: impl Into<String>) {
        self.errors.push(ErrorMessage {
            error: error.into(),
            host: host.into(),
        });
    }

    pub fn hits(&self) -> &[Hit] {
        &self.hits
    }

    /// Build the JSON report (for `json`/`jsonv1`, and for the integration API).
    pub fn report(&self, success: bool) -> JsonReport {
        JsonReport {
            generator: Generator {
                version: format!("{}-lancer", env!("CARGO_PKG_VERSION")),
                built: self.built.clone(),
                binary: "lancer-hydra".to_string(),
                arguments: self.arguments.clone(),
            },
            errormessages: self.errors.clone(),
            success,
            quantityfound: self.hits.len(),
            results: self.hits.clone(),
        }
    }

    /// Flush the final document for JSON variants. Returns the serialized doc
    /// (so the caller can also echo it to stdout).
    pub fn finish(&mut self, success: bool) -> Option<String> {
        match self.format {
            OutputFormat::Json | OutputFormat::JsonV1 => {
                let doc = self.report(success).to_pretty();
                if let Some(h) = self.handle.as_mut() {
                    let _ = h.write_all(doc.as_bytes());
                }
                Some(doc)
            }
            _ => None,
        }
    }
}

/// Best-effort build/run timestamp (unix seconds; portable, no date crate).
fn build_stamp() -> String {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => format!("unix:{}", d.as_secs()),
        Err(_) => "unknown".to_string(),
    }
}
