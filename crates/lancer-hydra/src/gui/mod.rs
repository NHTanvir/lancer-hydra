//! Native egui GUI (feature `gui`, the default). A bare `lancer-hydra` opens
//! this window; `--cli` falls through to the command-line surface.

mod app;
mod server;

pub use app::launch;
