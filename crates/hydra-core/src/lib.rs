//! `hydra-core` — orchestration: target tasks, per-target worker pools, the
//! credential queue, rate limiting, stop-on-found, restore, and aggregation.
//!
//! The engine is GUI/CLI-agnostic: frontends build an [`EngineOptions`] and call
//! [`Engine::run`].

pub mod credqueue;
pub mod engine;
pub mod options;
pub mod ratelimit;
pub mod restore;
pub mod results;
pub mod stopon;
pub mod target;
pub mod worker;

pub use engine::{Engine, EngineError};
pub use options::EngineOptions;
pub use target::{build_target, load_target_file, parse_target, ParsedTarget};

// Re-export the building-block types frontends need so they depend on one crate.
pub use hydra_credlist::{
    default_creds, CharsetSpec, CredConfig, Credential, ExtraModes, LoginSource, PassSource,
};
pub use hydra_output::{Hit, OutputFormat};
pub use hydra_protocols::{registry, AuthOutcome, IpPref, ModuleOpts, Protocol, Target};
