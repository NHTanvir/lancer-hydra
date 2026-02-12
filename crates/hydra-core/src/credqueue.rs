//! Per-target credential queue: many workers pull from one lazy stream.
//!
//! Backed by a bounded `tokio::sync::mpsc` produced by `hydra-credlist`. The
//! receiver sits behind a `Mutex` so the `-t` workers share it; the lock is held
//! only across a single `recv()` (which returns promptly while the buffer has
//! items), so it does not serialize the actual credential attempts.

use std::sync::Arc;

use tokio::sync::mpsc::Receiver;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use hydra_credlist::Credential;

/// Shared, cancellable handle to a target's credential stream.
pub type SharedQueue = Arc<Mutex<Receiver<Credential>>>;

pub fn wrap(rx: Receiver<Credential>) -> SharedQueue {
    Arc::new(Mutex::new(rx))
}

/// Pull the next credential, or `None` if the stream is exhausted or the target
/// token is cancelled (stop-on-found / Ctrl-C).
pub async fn next(queue: &SharedQueue, token: &CancellationToken) -> Option<Credential> {
    let mut guard = queue.lock().await;
    tokio::select! {
        _ = token.cancelled() => None,
        cred = guard.recv() => cred,
    }
}
