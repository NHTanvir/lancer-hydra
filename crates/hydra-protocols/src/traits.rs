//! The `Protocol` trait and the shared types every protocol module speaks.
//!
//! `hydra-protocols` is the lowest crate in the workspace: it defines `Target`,
//! `ModuleOpts`, `AuthOutcome`, `ProtocolError` and the `Protocol` trait. The
//! engine (`hydra-core`) drives these; the credlist (`hydra-credlist`) feeds
//! `(user, pass)` tuples into `try_credential`.

use std::collections::HashMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Address-family preference (`-4` / `-6`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum IpPref {
    #[default]
    Any,
    V4,
    V6,
}

/// A normalized scan target: `proto://host:port`, resolved lazily at connect time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    /// Protocol/service name as resolved against the registry (e.g. `ssh`, `http-post-form`).
    pub proto: String,
    /// Hostname or IP literal (DNS resolution happens in `net::connect`).
    pub host: String,
    /// Effective port (default-port resolution happens before this is built).
    pub port: u16,
    /// Whether to wrap the transport in TLS (`-S`, or an inherently-TLS module).
    pub ssl: bool,
    /// Address-family preference.
    pub ip_pref: IpPref,
}

impl Target {
    pub fn new(proto: impl Into<String>, host: impl Into<String>, port: u16) -> Self {
        Self {
            proto: proto.into(),
            host: host.into(),
            port,
            ssl: false,
            ip_pref: IpPref::Any,
        }
    }

    /// `host:port`, used for socket addressing and SNI.
    pub fn authority(&self) -> String {
        if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// Per-module configuration carried from the `-m` flag and timing flags.
///
/// Mirrors the upstream "module option string" plus the global timing knobs the
/// modules need (`-w`, `-W`, `-c`) and the SSL toggles.
#[derive(Debug, Clone)]
pub struct ModuleOpts {
    /// Raw `-m` string exactly as the user typed it (also the HTTP-form DSL).
    pub raw: Option<String>,
    /// Parsed `KEY=VALUE` pairs out of the `-m` string.
    pub map: HashMap<String, String>,
    /// Bare mechanism token from `-m` (e.g. `-m LOGIN`, `-m simple`, `-m v2c`).
    pub mech: Option<String>,
    /// `-w` wait time per response.
    pub wait_response: Duration,
    /// `-W` wait time between connects per thread.
    pub wait_connect: Duration,
    /// `-c` wait before retry on connection error.
    pub retry_wait: Duration,
    /// `-S` use the SSL/TLS variant.
    pub ssl: bool,
    /// `-O` use SSLv2 (legacy).
    pub sslv2: bool,
    /// `-v` / `-V` verbose.
    pub verbose: bool,
    /// `-d` debug (protocol trace).
    pub debug: bool,
    /// `-q` quiet (suppress connection-error warnings).
    pub quiet: bool,
    /// `-a` HTTP auth-type override (basic / ntlm / digest).
    pub http_auth: Option<String>,
    /// `--proxy` / `HYDRA_PROXY` — single upstream proxy URL the dialer tunnels
    /// through (`socks5://host:port` or `connect://host:port`).
    pub proxy: Option<String>,
    /// `--proxy-auth` / `HYDRA_PROXY_AUTH` — `user:pass` for the proxy above.
    pub proxy_auth: Option<String>,
    /// `HYDRA_PROXY_HTTP` — proxy used specifically by the HTTP modules,
    /// overriding `proxy` for `http*`/`https*` schemes.
    pub proxy_http: Option<String>,
    /// Extra `KEY=VALUE` flags such as the HTTP-form `2=NNN` success-status token.
    pub extras: HashMap<String, String>,
}

impl Default for ModuleOpts {
    fn default() -> Self {
        Self {
            raw: None,
            map: HashMap::new(),
            mech: None,
            wait_response: Duration::from_secs(32),
            wait_connect: Duration::ZERO,
            retry_wait: Duration::ZERO,
            ssl: false,
            sslv2: false,
            verbose: false,
            debug: false,
            quiet: false,
            http_auth: None,
            proxy: None,
            proxy_auth: None,
            proxy_http: None,
            extras: HashMap::new(),
        }
    }
}

impl ModuleOpts {
    /// Build from a raw `-m` string, parsing `KEY=VALUE` tokens and the bare mechanism.
    pub fn from_raw(raw: Option<String>) -> Self {
        let mut opts = ModuleOpts::default();
        if let Some(ref s) = raw {
            opts.raw = Some(s.clone());
            // The HTTP-form DSL is `:`-separated and handled by the module itself;
            // here we only opportunistically pull `KEY=VALUE` and a leading mech token.
            for tok in s.split([':', ',', ' ']).filter(|t| !t.is_empty()) {
                if let Some((k, v)) = tok.split_once('=') {
                    let key = k.trim().to_string();
                    let val = v.trim().to_string();
                    if key.chars().all(|c| c.is_ascii_digit()) {
                        opts.extras.insert(key, val);
                    } else {
                        opts.map.insert(key.to_uppercase(), val);
                    }
                } else if opts.mech.is_none() && !tok.contains('/') {
                    opts.mech = Some(tok.to_string());
                }
            }
        }
        opts
    }

    /// Case-insensitive lookup of a parsed `KEY=VALUE` option.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.map.get(&key.to_uppercase()).map(|s| s.as_str())
    }

    /// Selected mechanism, upper-cased, or a default.
    pub fn mech_or(&self, default: &'static str) -> String {
        self.mech
            .as_deref()
            .map(|m| m.to_uppercase())
            .unwrap_or_else(|| default.to_string())
    }
}

/// The result of one credential attempt against a target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthOutcome {
    /// Credentials accepted.
    Success,
    /// Credentials rejected (normal wrong-password path).
    Failure,
    /// Account/host locked — valid creds would now also fail; surface distinctly.
    Lockout,
    /// Could not determine (ambiguous server response / honeypot suspicion).
    Unknown,
}

/// Errors a protocol module can raise. Transient variants are retried by the worker.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("connect failed: {0}")]
    Connect(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("tls error: {0}")]
    Tls(String),
    #[error("timeout")]
    Timeout,
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("module option error: {0}")]
    Option(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
}

impl ProtocolError {
    /// Whether the worker should retry this error (honoring `-c`).
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            ProtocolError::Connect(_) | ProtocolError::Io(_) | ProtocolError::Timeout | ProtocolError::Tls(_)
        )
    }
}

/// The interface every protocol module implements.
#[async_trait::async_trait]
pub trait Protocol: Send + Sync {
    /// Canonical service name (matches the `proto://` scheme used on the CLI).
    fn name(&self) -> &'static str;

    /// Default TCP/UDP port when the user does not pass `-s`.
    fn default_port(&self) -> u16;

    /// Whether `-S` (SSL/TLS) is meaningful for this module.
    fn supports_ssl(&self) -> bool {
        false
    }

    /// Whether the connection can be reused across credentials (FTP/IMAP) vs.
    /// forced reconnect (SSH/RDP). The engine uses this to size pools.
    fn supports_reuse(&self) -> bool {
        false
    }

    /// Whether this module rides UDP rather than TCP (SNMP).
    fn is_udp(&self) -> bool {
        false
    }

    /// One-line description for `hydra -U <module>`.
    fn usage(&self) -> &'static str {
        "no module usage notes"
    }

    /// Try a single credential. The heart of the module.
    async fn try_credential(
        &self,
        target: &Target,
        user: &str,
        pass: &str,
        opts: &ModuleOpts,
    ) -> Result<AuthOutcome, ProtocolError>;
}
