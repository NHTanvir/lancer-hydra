//! `EngineOptions` — the fully-resolved configuration the engine runs against.
//! The CLI/GUI translate flags into this struct; the engine never sees `clap`.

use std::path::PathBuf;

use hydra_credlist::CredConfig;
use hydra_output::OutputFormat;
use hydra_protocols::{ModuleOpts, Target};

#[derive(Debug, Clone)]
pub struct EngineOptions {
    /// Service scheme, resolved against the protocol registry (e.g. `ssh`).
    pub scheme: String,
    /// Resolved targets (each carries proto/host/port/ssl).
    pub targets: Vec<Target>,
    /// Credential generation configuration.
    pub cred: CredConfig,
    /// Per-module options + timing knobs.
    pub module_opts: ModuleOpts,
    /// `-t` parallel tasks per target.
    pub tasks_per_target: usize,
    /// `-T` total tasks across all targets (overrides the per-target sum).
    pub total_tasks: Option<usize>,
    /// `-f` stop globally on first hit.
    pub stop_on_first_global: bool,
    /// `-F` stop per-target on first hit.
    pub stop_on_first_target: bool,
    /// Optional global rate cap (attempts/sec).
    pub rate_per_sec: Option<u32>,
    /// `-o` output file.
    pub output_file: Option<PathBuf>,
    /// `-b` output format.
    pub output_format: OutputFormat,
    /// Restore-file path (`hydra.restore`).
    pub restore_path: PathBuf,
    /// `-I` ignore an existing restore file.
    pub ignore_restore: bool,
    /// `-R` resume from the restore file.
    pub resume: bool,
    pub quiet: bool,
    pub verbose: bool,
    /// `-V` show each login:pass attempt.
    pub show_attempts: bool,
    /// Original command line, recorded into restore/JSON output.
    pub command_line: String,
    /// Bounded credential-channel buffer size.
    pub queue_buffer: usize,
    /// Optional externally-owned cancellation token (the GUI Stop button adopts
    /// this so it can cancel a run it launched).
    pub external_cancel: Option<tokio_util::sync::CancellationToken>,
}

impl Default for EngineOptions {
    fn default() -> Self {
        Self {
            scheme: String::new(),
            targets: Vec::new(),
            cred: CredConfig::default(),
            module_opts: ModuleOpts::default(),
            tasks_per_target: 16,
            total_tasks: None,
            stop_on_first_global: false,
            stop_on_first_target: false,
            rate_per_sec: None,
            output_file: None,
            output_format: OutputFormat::Text,
            restore_path: PathBuf::from("hydra.restore"),
            ignore_restore: false,
            resume: false,
            quiet: false,
            verbose: false,
            show_attempts: false,
            command_line: String::new(),
            queue_buffer: 1024,
            external_cancel: None,
        }
    }
}
