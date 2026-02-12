//! `hydra-protocols` — the per-protocol auth modules for lancer-hydra.
//!
//! Every protocol is a small struct implementing [`traits::Protocol`]. Modules
//! register themselves with the compile-time [`registry`] via
//! [`register_protocol!`], so the CLI/engine never keep a hand-maintained list.
//!
//! The lowest crate in the workspace: it owns the shared types (`Target`,
//! `ModuleOpts`, `AuthOutcome`, `ProtocolError`).

pub mod asn1;
pub mod crypto;
pub mod net;
pub mod prelude;
pub mod registry;
pub mod traits;

pub mod modules;

pub use registry::{all, names, resolve, Registration};
pub use traits::{AuthOutcome, IpPref, ModuleOpts, Protocol, ProtocolError, Target};

/// Number of protocol modules compiled into this build.
pub fn module_count() -> usize {
    registry::all().count()
}
