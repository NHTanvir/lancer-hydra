//! Restore-state assembly and the 5-minute auto-save ticker.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use hydra_output::{Cursor, RestoreFile, RestoreHit};
use hydra_protocols::Target;

use crate::results::Results;

/// Build a restore document from the current run state.
pub async fn build(command: &str, targets: &[Target], creds_done: u64, results: &Results) -> RestoreFile {
    let hits: Vec<RestoreHit> = results.snapshot().await.iter().map(RestoreHit::from).collect();
    RestoreFile {
        version: format!("{}-lancer", env!("CARGO_PKG_VERSION")),
        command: command.to_string(),
        targets: targets.to_vec(),
        creds_done,
        hits,
        credqueue_cursor: Cursor {
            user_index: 0,
            pass_index: creds_done,
        },
    }
}

/// Save a restore document atomically.
pub fn save(path: &PathBuf, restore: &RestoreFile) {
    if let Err(e) = restore.save_atomic(path) {
        tracing::warn!("could not write restore file {:?}: {e}", path);
    }
}

/// Spawn the upstream-style 5-minute auto-save ticker. Stops when `token` fires.
pub fn spawn_autosave(
    path: PathBuf,
    command: String,
    targets: Vec<Target>,
    creds_done: Arc<AtomicU64>,
    results: Results,
    token: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(300));
        ticker.tick().await; // skip the immediate first tick
        loop {
            tokio::select! {
                _ = token.cancelled() => break,
                _ = ticker.tick() => {
                    let done = creds_done.load(Ordering::Relaxed);
                    let restore = build(&command, &targets, done, &results).await;
                    save(&path, &restore);
                    tracing::debug!("restore auto-saved at {done} creds");
                }
            }
        }
    })
}
