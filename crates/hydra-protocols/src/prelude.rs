//! The single import every protocol module uses: `use crate::prelude::*;`.
//!
//! Keeping the surface tight here is what makes the module files uniform and
//! lets new modules be dropped in without touching the rest of the crate.

pub use crate::net::{
    self, connect, connect_plain, connect_udp, tls_upgrade, udp_roundtrip, Conn,
};
pub use crate::register_protocol;
pub use crate::stub_module;
pub use crate::traits::{AuthOutcome, IpPref, ModuleOpts, Protocol, ProtocolError, Target};

pub use async_trait::async_trait;

/// Shorthand for a protocol error from a `&str`/`String` reason.
pub fn perr(msg: impl Into<String>) -> ProtocolError {
    ProtocolError::Protocol(msg.into())
}

/// Shorthand for a module-option error.
pub fn oerr(msg: impl Into<String>) -> ProtocolError {
    ProtocolError::Option(msg.into())
}

/// Substitute the upstream `^USER^` / `^PASS^` tokens (used by several modules,
/// not just HTTP-form).
pub fn subst_userpass(template: &str, user: &str, pass: &str) -> String {
    template.replace("^USER^", user).replace("^PASS^", pass)
}
