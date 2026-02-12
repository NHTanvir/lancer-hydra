//! Command-line surface — mirrors upstream `hydra -h` flag-for-flag, then drives
//! the engine. Reachable via `lancer-hydra --cli ...` or the `lancer-hydra-cli`
//! companion binary.

use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;

use hydra_core::{
    build_target, load_target_file, parse_target, registry, CharsetSpec, CredConfig, Engine,
    EngineOptions, ExtraModes, IpPref, LoginSource, ModuleOpts, OutputFormat, PassSource,
    ParsedTarget,
};

/// lancer-hydra — Rust THC-Hydra clone (CLI surface).
#[derive(Parser, Debug)]
#[command(
    name = "lancer-hydra",
    version,
    about = "Rust clone of THC-Hydra — parallelized network login brute-forcer",
    disable_version_flag = true,
    after_help = "Run `lancer-hydra -U <service>` for per-module options, or `--help-format` for the HTTP-form DSL."
)]
pub struct Cli {
    /// Single login name.
    #[arg(short = 'l')]
    login: Option<String>,
    /// File with logins, one per line.
    #[arg(short = 'L')]
    login_file: Option<PathBuf>,
    /// Single password.
    #[arg(short = 'p')]
    pass: Option<String>,
    /// File with passwords, one per line.
    #[arg(short = 'P')]
    pass_file: Option<PathBuf>,
    /// Colon-separated login:pass combo file.
    #[arg(short = 'C')]
    combo: Option<PathBuf>,
    /// Charset brute-force generator MIN:MAX:CHARSET (or `check`).
    #[arg(short = 'x')]
    charset: Option<String>,
    /// Disable letters in the -x charset (digits-only fast path).
    #[arg(short = 'y', default_value_t = false)]
    digits_only: bool,
    /// Extra modes: n=null, s=same-as-login, r=reversed-login.
    #[arg(short = 'e')]
    extra: Option<String>,
    /// Loop around users first (password spray), then passwords.
    #[arg(short = 'u', default_value_t = false)]
    users_first: bool,
    /// Parallel tasks per target.
    #[arg(short = 't', default_value_t = 16)]
    tasks: usize,
    /// Total parallel tasks across all targets (overrides the per-target sum).
    #[arg(short = 'T')]
    total_tasks: Option<usize>,
    /// Wait time per response (seconds).
    #[arg(short = 'w', default_value_t = 32)]
    wait_response: u64,
    /// Wait time between connects per thread (seconds).
    #[arg(short = 'W', default_value_t = 0)]
    wait_connect: u64,
    /// Wait time before retry on connection error (seconds).
    #[arg(short = 'c', default_value_t = 0)]
    retry_wait: u64,
    /// Override the default port.
    #[arg(short = 's')]
    port: Option<u16>,
    /// Use the SSL/TLS variant.
    #[arg(short = 'S', default_value_t = false)]
    ssl: bool,
    /// Use SSLv2 (legacy).
    #[arg(short = 'O', default_value_t = false)]
    sslv2: bool,
    /// Do not abort on a module-option error (continue).
    #[arg(short = 'K', default_value_t = false)]
    continue_on_error: bool,
    /// Quiet — suppress connection-error warnings.
    #[arg(short = 'q', default_value_t = false)]
    quiet: bool,
    /// Verbose.
    #[arg(short = 'v', default_value_t = false)]
    verbose: bool,
    /// Show login:pass for each attempt.
    #[arg(short = 'V', default_value_t = false)]
    show_attempts: bool,
    /// Debug — protocol-level trace.
    #[arg(short = 'd', default_value_t = false)]
    debug: bool,
    /// Stop after the first found pair globally.
    #[arg(short = 'f', default_value_t = false)]
    stop_global: bool,
    /// Stop after the first found pair per target.
    #[arg(short = 'F', default_value_t = false)]
    stop_target: bool,
    /// Target file (one host per line, optional :port or proto://).
    #[arg(short = 'M')]
    target_file: Option<PathBuf>,
    /// Module-specific option string (e.g. the HTTP-form DSL).
    #[arg(short = 'm')]
    module_opts: Option<String>,
    /// Output file for hits.
    #[arg(short = 'o')]
    output: Option<PathBuf>,
    /// Output format: text, json, jsonv1, jsonl.
    #[arg(short = 'b', default_value = "text")]
    format: String,
    /// Ignore an existing restore file.
    #[arg(short = 'I', default_value_t = false)]
    ignore_restore: bool,
    /// Resume from hydra.restore.
    #[arg(short = 'R', default_value_t = false)]
    resume: bool,
    /// Print service-module usage details and exit (e.g. -U ssh).
    #[arg(short = 'U')]
    module_usage: Option<String>,
    /// Force IPv4.
    #[arg(short = '4', default_value_t = false)]
    ipv4: bool,
    /// Force IPv6.
    #[arg(short = '6', default_value_t = false)]
    ipv6: bool,
    /// HTTP authentication-type override (basic / ntlm / digest).
    #[arg(short = 'a')]
    http_auth: Option<String>,
    /// Single SOCKS5 / HTTP-CONNECT proxy URL (alias for HYDRA_PROXY).
    #[arg(long = "proxy")]
    proxy: Option<String>,
    /// Proxy credentials user:pass (alias for HYDRA_PROXY_AUTH).
    #[arg(long = "proxy-auth")]
    proxy_auth: Option<String>,
    /// Optional global rate cap (attempts/second).
    #[arg(long = "rate")]
    rate: Option<u32>,
    /// Path to the restore file.
    #[arg(long = "restore-file", default_value = "hydra.restore")]
    restore_file: PathBuf,
    /// Run the parity self-test matrix and exit.
    #[arg(long = "self-test", default_value_t = false)]
    self_test: bool,
    /// Print the HTTP-form mini-DSL help and exit.
    #[arg(long = "help-format", default_value_t = false)]
    help_format: bool,
    /// Print version and exit.
    #[arg(long = "version", default_value_t = false)]
    version: bool,

    /// Target (host, host:port, or proto://host[:port]); or the service when -M is used.
    target: Option<String>,
    /// Service/protocol name (when not encoded in the target URL).
    service: Option<String>,
}

/// Parse args and run. Returns a process exit code.
pub fn run(args: Vec<String>) -> i32 {
    let cli = match Cli::try_parse_from(&args) {
        Ok(c) => c,
        Err(e) => {
            // clap prints help/version/errors itself.
            let _ = e.print();
            return if e.use_stderr() { 2 } else { 0 };
        }
    };
    init_tracing(cli.debug, cli.verbose);

    // Early-exit informational modes.
    if cli.version {
        println!("lancer-hydra {}-lancer", env!("CARGO_PKG_VERSION"));
        return 0;
    }
    if cli.help_format {
        print_help_format();
        return 0;
    }
    if cli.self_test {
        print_self_test();
        return 0;
    }
    if let Some(svc) = &cli.module_usage {
        return print_module_usage(svc);
    }
    if cli.charset.as_deref() == Some("check") {
        println!("charset spec accepted");
        return 0;
    }

    match build_options(&cli, &args) {
        Ok(opts) => {
            let rt = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("failed to start runtime: {e}");
                    return 1;
                }
            };
            match rt.block_on(Engine::run(opts)) {
                Ok(hits) => {
                    eprintln!(
                        "[lancer-hydra] finished — {} valid credential(s) found",
                        hits.len()
                    );
                    if hits.is_empty() {
                        1
                    } else {
                        0
                    }
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    if let hydra_core::EngineError::UnknownProtocol(_) = e {
                        eprintln!("known services: {}", registry::names().join(", "));
                    }
                    1
                }
            }
        }
        Err(msg) => {
            eprintln!("error: {msg}");
            2
        }
    }
}

/// Translate parsed CLI flags into a fully-resolved [`EngineOptions`].
fn build_options(cli: &Cli, args: &[String]) -> Result<EngineOptions, String> {
    // --- resolve scheme + raw target tokens ---
    let (scheme, raw_hosts) = resolve_targets(cli)?;
    let proto = registry::resolve(&scheme)
        .ok_or_else(|| format!("unknown service/protocol: {scheme}"))?;
    let default_port = proto.default_port();

    let ip_pref = if cli.ipv6 {
        IpPref::V6
    } else if cli.ipv4 {
        IpPref::V4
    } else {
        IpPref::Any
    };

    let targets: Vec<_> = raw_hosts
        .iter()
        .map(|h| {
            let parsed = parse_target(h);
            build_target(&parsed, &scheme, default_port, cli.port, cli.ssl, ip_pref)
        })
        .collect();
    if targets.is_empty() {
        return Err("no targets specified (use a host argument or -M file)".into());
    }

    // --- credential config ---
    let logins = match (&cli.login, &cli.login_file) {
        (Some(l), _) => LoginSource::Single(l.clone()),
        (None, Some(f)) => LoginSource::File(f.clone()),
        _ => LoginSource::None,
    };
    let passwords = match (&cli.pass, &cli.pass_file, &cli.charset) {
        (Some(p), _, _) => PassSource::Single(p.clone()),
        (None, Some(f), _) => PassSource::File(f.clone()),
        (None, None, Some(x)) => {
            let mut spec = CharsetSpec::parse(x).map_err(|e| format!("bad -x: {e}"))?;
            if cli.digits_only {
                spec.charset = ('0'..='9').collect();
            }
            PassSource::Charset(spec)
        }
        _ => PassSource::None,
    };
    let cred = CredConfig {
        logins,
        passwords,
        combo: cli.combo.clone(),
        extra: ExtraModes::parse(cli.extra.as_deref().unwrap_or("")),
        users_first: cli.users_first,
    };

    // --- module options + timing ---
    let mut module_opts = ModuleOpts::from_raw(cli.module_opts.clone());
    module_opts.wait_response = Duration::from_secs(cli.wait_response);
    module_opts.wait_connect = Duration::from_secs(cli.wait_connect);
    module_opts.retry_wait = Duration::from_secs(cli.retry_wait);
    module_opts.ssl = cli.ssl;
    module_opts.sslv2 = cli.sslv2;
    module_opts.verbose = cli.verbose;
    module_opts.debug = cli.debug;
    module_opts.quiet = cli.quiet;
    module_opts.http_auth = cli.http_auth.clone();

    // Honour upstream proxy env aliases (chaining not yet wired into the dialer).
    if let Some(p) = &cli.proxy {
        std::env::set_var("HYDRA_PROXY", p);
        tracing::warn!("--proxy recorded (HYDRA_PROXY); proxy dialing is not yet wired in");
    }
    if let Some(pa) = &cli.proxy_auth {
        std::env::set_var("HYDRA_PROXY_AUTH", pa);
    }

    let output_format = OutputFormat::parse(&cli.format)
        .ok_or_else(|| format!("unknown -b format: {}", cli.format))?;

    Ok(EngineOptions {
        scheme,
        targets,
        cred,
        module_opts,
        tasks_per_target: cli.tasks,
        total_tasks: cli.total_tasks,
        stop_on_first_global: cli.stop_global,
        stop_on_first_target: cli.stop_target,
        rate_per_sec: cli.rate,
        output_file: cli.output.clone(),
        output_format,
        restore_path: cli.restore_file.clone(),
        ignore_restore: cli.ignore_restore,
        resume: cli.resume,
        quiet: cli.quiet,
        verbose: cli.verbose,
        show_attempts: cli.show_attempts,
        command_line: args.join(" "),
        queue_buffer: 1024,
        external_cancel: None,
    })
}

/// Figure out the service scheme and the list of raw host tokens.
fn resolve_targets(cli: &Cli) -> Result<(String, Vec<String>), String> {
    if let Some(mf) = &cli.target_file {
        // With -M, the first positional is the SERVICE, not a host.
        let hosts = load_target_file(mf).map_err(|e| format!("reading {mf:?}: {e}"))?;
        let scheme = cli
            .service
            .clone()
            .or_else(|| cli.target.clone())
            .or_else(|| hosts.first().and_then(|h| parse_target(h).scheme))
            .ok_or("no service/protocol specified")?;
        return Ok((scheme, hosts));
    }

    let target = cli
        .target
        .clone()
        .ok_or("no target specified (give a host or proto://host, or use -M)")?;
    let parsed: ParsedTarget = parse_target(&target);
    let scheme = cli
        .service
        .clone()
        .or(parsed.scheme.clone())
        .ok_or("no service/protocol specified (e.g. ssh, or ssh://host)")?;
    Ok((scheme, vec![target]))
}

fn init_tracing(debug: bool, verbose: bool) {
    use tracing_subscriber::EnvFilter;
    let default = if debug {
        "debug"
    } else if verbose {
        "info"
    } else {
        "warn"
    };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

fn print_module_usage(service: &str) -> i32 {
    match registry::resolve(service) {
        Some(p) => {
            println!("{} (default port {})", p.name(), p.default_port());
            println!("  ssl: {}   reuse: {}   udp: {}", p.supports_ssl(), p.supports_reuse(), p.is_udp());
            println!("  {}", p.usage());
            0
        }
        None => {
            eprintln!("unknown service: {service}");
            eprintln!("known services: {}", registry::names().join(", "));
            1
        }
    }
}

fn print_help_format() {
    println!(
        "HTTP form module DSL (-m):\n\
         \n\
         \"<path>:<body>:<condition>[:<extra>...]\"\n\
         \n\
         path        request path, e.g. /login.php\n\
         body        POST/GET body with ^USER^ / ^PASS^ tokens\n\
         condition   F=<str>  failure string (response body contains => failed)\n\
                     S=<str>  success string (response body contains => success)\n\
                     bare third field defaults to a failure string\n\
         extras      H=Name: Value   add a header (repeatable)\n\
                     C=/path         GET first to harvest cookies (CSRF setup)\n\
                     2=NNN           treat HTTP status NNN as success (e.g. 302, 403)\n\
                     CSRF=<regex>    extract ^CSRF^ token from the harvest page\n\
         \n\
         example:\n\
         -m \"/login:user=^USER^&pass=^PASS^:F=incorrect:H=X-Requested-With: XMLHttpRequest\""
    );
}

fn print_self_test() {
    let names = registry::names();
    println!("lancer-hydra {}-lancer  self-test", env!("CARGO_PKG_VERSION"));
    println!("=========================================");
    println!("protocol modules registered : {}", hydra_protocols::module_count());
    println!("scheme names (incl. aliases) : {}", names.len());
    println!();
    println!("build feature flags (parity vs upstream C build):");
    println!("  PCRE2          : N/A  (pure-Rust `regex` crate)");
    println!("  FreeRDP3       : N/A  (hand-rolled X.224 negotiation)");
    println!("  libsmbclient   : N/A  (hand-rolled SMB2 negotiate)");
    println!("  libsmb2        : N/A  (hand-rolled SMB2 negotiate)");
    println!("  TLS backend    : native-tls (SChannel on Windows)");
    println!("  SSH backend    : pure-Rust curve25519 + aes-ctr transport");
    println!();
    println!("registered services:");
    for chunk in names.chunks(6) {
        println!("  {}", chunk.join("  "));
    }
}
