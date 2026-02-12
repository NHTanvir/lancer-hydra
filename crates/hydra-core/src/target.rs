//! Target parsing: `proto://host:port`, bare `host`, `host:port`, and `-M` files.

use std::path::Path;

use hydra_protocols::{IpPref, Target};

/// A loosely-parsed target before default-port resolution.
#[derive(Debug, Clone, Default)]
pub struct ParsedTarget {
    pub scheme: Option<String>,
    pub host: String,
    pub port: Option<u16>,
}

/// Parse a single target token. Accepts `ssh://1.2.3.4:22`, `1.2.3.4:22`,
/// `[2001:db8::1]:22`, or a bare `host`.
pub fn parse_target(input: &str) -> ParsedTarget {
    let mut t = ParsedTarget::default();
    let rest = if let Some((scheme, rest)) = input.split_once("://") {
        t.scheme = Some(scheme.to_ascii_lowercase());
        rest
    } else {
        input
    };

    // IPv6 literal in brackets.
    if let Some(stripped) = rest.strip_prefix('[') {
        if let Some(end) = stripped.find(']') {
            t.host = stripped[..end].to_string();
            if let Some(p) = stripped[end + 1..].strip_prefix(':') {
                t.port = p.parse().ok();
            }
            return t;
        }
    }

    // host:port (single colon = not a bare IPv6 address)
    if rest.matches(':').count() == 1 {
        let (h, p) = rest.split_once(':').unwrap();
        t.host = h.to_string();
        t.port = p.parse().ok();
    } else {
        t.host = rest.to_string();
    }
    t
}

/// Build a concrete [`Target`] from parsed parts + run-wide defaults.
pub fn build_target(
    parsed: &ParsedTarget,
    scheme: &str,
    default_port: u16,
    port_override: Option<u16>,
    ssl: bool,
    ip_pref: IpPref,
) -> Target {
    Target {
        proto: scheme.to_string(),
        host: parsed.host.clone(),
        port: parsed.port.or(port_override).unwrap_or(default_port),
        ssl,
        ip_pref,
    }
}

/// Read a `-M` target file (one host per line; `#` comments and blanks skipped).
pub fn load_target_file(path: &Path) -> std::io::Result<Vec<String>> {
    let data = std::fs::read_to_string(path)?;
    Ok(data
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect())
}
