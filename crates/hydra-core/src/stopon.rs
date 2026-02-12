//! Stop-on-found control (`-f` global, `-F` per-target) over `CancellationToken`.

use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct StopController {
    /// Cancelling this stops the entire run.
    pub global: CancellationToken,
    pub stop_global_on_found: bool,
    pub stop_target_on_found: bool,
}

impl StopController {
    pub fn new(stop_global_on_found: bool, stop_target_on_found: bool) -> Self {
        Self::with_token(None, stop_global_on_found, stop_target_on_found)
    }

    /// Build from an optional externally-owned token (the GUI keeps a handle to
    /// it so the Stop button can cancel the run).
    pub fn with_token(
        token: Option<CancellationToken>,
        stop_global_on_found: bool,
        stop_target_on_found: bool,
    ) -> Self {
        Self {
            global: token.unwrap_or_else(CancellationToken::new),
            stop_global_on_found,
            stop_target_on_found,
        }
    }

    /// A child token for one target; cancelled either by `-F` on that target or
    /// by the global token (so `-f` and Ctrl-C cascade down).
    pub fn target_token(&self) -> CancellationToken {
        self.global.child_token()
    }
}
