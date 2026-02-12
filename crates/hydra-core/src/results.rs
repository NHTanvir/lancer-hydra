//! Thread-safe results aggregation + output sink wrapper.

use std::sync::Arc;

use tokio::sync::Mutex;

use hydra_output::{Hit, OutputSink};

/// Shared sink: workers record hits here; the engine flushes/serializes at the end.
#[derive(Clone)]
pub struct Results {
    sink: Arc<Mutex<OutputSink>>,
    found: Arc<Mutex<Vec<Hit>>>,
}

impl Results {
    pub fn new(sink: OutputSink) -> Self {
        Self {
            sink: Arc::new(Mutex::new(sink)),
            found: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Record a discovered credential (writes streaming formats immediately).
    pub async fn record(&self, hit: Hit) {
        self.found.lock().await.push(hit.clone());
        self.sink.lock().await.record(hit);
    }

    pub async fn add_error(&self, error: impl Into<String>, host: impl Into<String>) {
        self.sink.lock().await.add_error(error, host);
    }

    pub async fn snapshot(&self) -> Vec<Hit> {
        self.found.lock().await.clone()
    }

    pub async fn count(&self) -> usize {
        self.found.lock().await.len()
    }

    /// Flush the final document (JSON variants) and return it if produced.
    pub async fn finish(&self, success: bool) -> Option<String> {
        self.sink.lock().await.finish(success)
    }
}
