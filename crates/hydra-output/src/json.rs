//! JSON output schema (mirrors upstream `-b json` / `-b jsonv1`).

use serde::{Deserialize, Serialize};

use crate::Hit;

/// `generator` block describing the run that produced the document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Generator {
    pub version: String,
    pub built: String,
    pub binary: String,
    pub arguments: String,
}

/// One non-fatal error recorded during the run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorMessage {
    pub error: String,
    pub host: String,
}

/// The top-level document for `-b json` / `-b jsonv1`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonReport {
    pub generator: Generator,
    pub errormessages: Vec<ErrorMessage>,
    pub success: bool,
    pub quantityfound: usize,
    pub results: Vec<Hit>,
}

impl JsonReport {
    pub fn to_pretty(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }
}
