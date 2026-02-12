//! lancer-hydra — Rust THC-Hydra clone with a native GUI.
//!
//! A bare invocation opens the GUI; `--cli` (or the `lancer-hydra-cli` companion)
//! exposes the full command-line surface. See plan.md for the spec.

fn main() {
    lancer_hydra::dispatch();
}
