//! Upstream parity matrix.
//!
//! Pins the set of upstream `hydra` features we must support: every protocol
//! scheme resolves through the registry, the credential modes generate, and the
//! flag-derived option types parse. CI fails if any upstream feature regresses.
//! (Live-target canned outputs live under the repo-root `tests/upstream_parity/`
//! fixtures; this file exercises the in-process surface.)

use hydra_core::{
    registry, CharsetSpec, CredConfig, Engine, EngineError, EngineOptions, ExtraModes, LoginSource,
    ModuleOpts, OutputFormat, PassSource,
};

/// Every upstream protocol module must resolve by its primary scheme name.
const REQUIRED_SCHEMES: &[&str] = &[
    "ssh", "sshkey", "sftp", "ftp", "ftps", "telnet", "telnets", "pop3", "pop3s", "imap", "imaps",
    "smtp", "smtps", "smtp-enum", "http-head", "http-get", "http-post", "https-head", "https-get",
    "https-post", "http-get-form", "http-post-form", "https-get-form", "https-post-form",
    "http-proxy", "http-proxy-urlenum", "rdp", "vnc", "smb", "smb2", "ldap", "ldaps", "mysql",
    "postgres", "mssql", "oracle", "mongodb", "redis", "snmp", "mqtt", "xmpp", "nntp", "irc", "cvs",
    "svn", "asterisk", "cisco", "cisco-enable", "cisco-aaa", "icq", "teamspeak", "sap-r3",
    "firebird", "memcached", "s7-300", "adam6500", "socks5", "afp", "ncp", "rlogin", "rsh", "rexec",
    "radmin2", "cobaltstrike", "vmauthd", "rpcap", "sip", "time", "rtsp", "pcanywhere", "pcnfs",
];

/// Common alias spellings that must also resolve.
const REQUIRED_ALIASES: &[&str] = &[
    "ssh2", "http", "https", "postgresql", "mongo", "ldap2", "ldap3", "tacacs+", "cisco-auth",
    "jabber",
];

#[test]
fn every_required_scheme_resolves() {
    for scheme in REQUIRED_SCHEMES {
        assert!(
            registry::resolve(scheme).is_some(),
            "protocol scheme `{scheme}` is not registered — parity regression"
        );
    }
}

#[test]
fn aliases_resolve() {
    for alias in REQUIRED_ALIASES {
        assert!(
            registry::resolve(alias).is_some(),
            "alias `{alias}` does not resolve"
        );
    }
}

#[test]
fn module_count_covers_50_plus() {
    let n = registry::all().count();
    assert!(n >= 55, "expected 55+ protocol modules, found {n}");
}

#[test]
fn resolved_modules_report_sane_defaults() {
    for scheme in REQUIRED_SCHEMES {
        let p = registry::resolve(scheme).unwrap();
        assert!(p.default_port() > 0, "{scheme} has a zero default port");
        assert!(!p.name().is_empty());
        assert!(!p.usage().is_empty());
    }
}

#[test]
fn charset_generator_matches_upstream_x() {
    let spec = CharsetSpec::parse("1:2:a1").unwrap();
    // a-z (26) + 0-9 (10) = 36 symbols; lengths 1..=2 => 36 + 36^2 = 1332.
    assert_eq!(spec.count(), 36 + 36 * 36);
    let first: Vec<String> = spec.iter().take(3).collect();
    assert_eq!(first.len(), 3);
    assert!(CharsetSpec::parse("5:2:a").is_err(), "MIN>MAX must error");
}

#[test]
fn extra_modes_nsr() {
    let e = ExtraModes::parse("nsr");
    assert!(e.null && e.same && e.reversed);
    let pws = e.passwords_for("admin");
    assert!(pws.contains(&String::new()));
    assert!(pws.contains(&"admin".to_string()));
    assert!(pws.contains(&"nimda".to_string()));
}

#[test]
fn module_opts_parse_keyvalue_and_mech() {
    let mo = ModuleOpts::from_raw(Some("LOGIN DB=postgres 2=302".to_string()));
    assert_eq!(mo.mech.as_deref(), Some("LOGIN"));
    assert_eq!(mo.get("DB"), Some("postgres"));
    assert_eq!(mo.extras.get("2").map(String::as_str), Some("302"));
}

#[test]
fn output_formats_all_parse() {
    for f in ["text", "json", "jsonv1", "jsonl"] {
        assert!(OutputFormat::parse(f).is_some(), "format {f} missing");
    }
    assert!(OutputFormat::parse("bogus").is_none());
}

#[test]
fn target_parsing_variants() {
    let t = hydra_core::parse_target("ssh://1.2.3.4:2222");
    assert_eq!(t.scheme.as_deref(), Some("ssh"));
    assert_eq!(t.host, "1.2.3.4");
    assert_eq!(t.port, Some(2222));

    let t = hydra_core::parse_target("[2001:db8::1]:22");
    assert_eq!(t.host, "2001:db8::1");
    assert_eq!(t.port, Some(22));

    let t = hydra_core::parse_target("example.com");
    assert_eq!(t.host, "example.com");
    assert_eq!(t.port, None);
}

#[tokio::test]
async fn cred_estimate_cartesian() {
    let cfg = CredConfig {
        logins: LoginSource::Single("admin".into()),
        passwords: PassSource::Charset(CharsetSpec::parse("1:1:1").unwrap()),
        combo: None,
        extra: ExtraModes::default(),
        users_first: false,
        defaults: Vec::new(),
    };
    // 1 user × 10 single-digit passwords.
    assert_eq!(cfg.estimate().await, Some(10));
}

#[tokio::test]
async fn engine_rejects_empty_and_unknown() {
    let empty = EngineOptions::default();
    assert!(matches!(Engine::run(empty).await, Err(EngineError::NoTargets)));

    let mut opts = EngineOptions {
        scheme: "definitely-not-a-protocol".into(),
        ..Default::default()
    };
    opts.targets.push(hydra_core::Target::new("definitely-not-a-protocol", "127.0.0.1", 1));
    assert!(matches!(
        Engine::run(opts).await,
        Err(EngineError::UnknownProtocol(_))
    ));
}
