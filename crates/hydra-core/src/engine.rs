//! The orchestration engine: target tasks → per-target worker pools.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::task::JoinSet;

use hydra_output::{Hit, OutputSink, Progress};
use hydra_protocols::Protocol;

use crate::credqueue;
use crate::options::EngineOptions;
use crate::ratelimit;
use crate::restore;
use crate::results::Results;
use crate::stopon::StopController;
use crate::worker::{self, WorkerCtx};

#[derive(thiserror::Error, Debug)]
pub enum EngineError {
    #[error("unknown service/protocol: {0}")]
    UnknownProtocol(String),
    #[error("no targets specified")]
    NoTargets,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub struct Engine;

impl Engine {
    /// Run a full Hydra invocation to completion, returning the hits found.
    pub async fn run(mut opts: EngineOptions) -> Result<Vec<Hit>, EngineError> {
        if opts.targets.is_empty() {
            return Err(EngineError::NoTargets);
        }
        let protocol: Arc<dyn Protocol> = match hydra_protocols::resolve(&opts.scheme) {
            Some(b) => Arc::from(b),
            None => return Err(EngineError::UnknownProtocol(opts.scheme.clone())),
        };

        // Fill in any unset ports from the module default; mark TLS variants.
        let default_port = protocol.default_port();
        for t in &mut opts.targets {
            if t.port == 0 {
                t.port = default_port;
            }
            if opts.module_opts.ssl {
                t.ssl = true;
            }
        }

        let sink = OutputSink::new(
            opts.output_format,
            opts.output_file.clone(),
            opts.command_line.clone(),
        )?;
        let results = Results::new(sink);
        let stop = StopController::with_token(
            opts.external_cancel.clone(),
            opts.stop_on_first_global,
            opts.stop_on_first_target,
        );
        let rate = ratelimit::make(opts.rate_per_sec);
        let creds_done = Arc::new(AtomicU64::new(0));

        // Resume (`-R`): skip the credentials a prior run already attempted. The
        // restore counter is a global total, so divide across targets (rounding
        // down never over-skips, so no credential is missed — at worst a few are
        // retried). Seed the live counter so the totals continue across resumes.
        let mut resume_skip = 0u64;
        if opts.resume {
            if let Ok(rf) = hydra_output::RestoreFile::load(&opts.restore_path) {
                let n = opts.targets.len().max(1) as u64;
                resume_skip = rf.creds_done / n;
                creds_done.store(rf.creds_done, Ordering::Relaxed);
                tracing::info!(
                    "resuming: skipping {resume_skip} cred(s)/target ({} previously attempted, {} prior hits)",
                    rf.creds_done,
                    rf.hits.len()
                );
            }
        }

        let per_target_total = opts.cred.estimate().await;
        let grand_total = per_target_total.map(|n| n.saturating_mul(opts.targets.len() as u64));
        let progress = Arc::new(Progress::new(grand_total));

        // Ctrl-C → cancel everything (restore is written on the way out).
        {
            let token = stop.global.clone();
            tokio::spawn(async move {
                if tokio::signal::ctrl_c().await.is_ok() {
                    token.cancel();
                }
            });
        }

        // Upstream-style 5-minute restore auto-save.
        let autosave = if opts.ignore_restore {
            None
        } else {
            Some(restore::spawn_autosave(
                opts.restore_path.clone(),
                opts.command_line.clone(),
                opts.targets.clone(),
                creds_done.clone(),
                results.clone(),
                stop.global.clone(),
            ))
        };

        // -T overrides the per-target task count.
        let tasks = match opts.total_tasks {
            Some(t) => (t / opts.targets.len().max(1)).max(1),
            None => opts.tasks_per_target.max(1),
        };

        // One task per target; each owns a worker pool over its own cred stream.
        let mut targets_set: JoinSet<()> = JoinSet::new();
        for target in opts.targets.clone() {
            let protocol = protocol.clone();
            let results = results.clone();
            let stop = stop.clone();
            let rate = rate.clone();
            let creds_done = creds_done.clone();
            let progress = progress.clone();
            let module_opts = opts.module_opts.clone();
            let cred = opts.cred.clone();
            let buffer = opts.queue_buffer;
            let show_attempts = opts.show_attempts;
            let quiet = opts.quiet;
            let wait_connect = module_opts.wait_connect;
            let retry_wait = module_opts.retry_wait;
            let skip = resume_skip;

            targets_set.spawn(async move {
                let rx = cred.stream(buffer, skip);
                let queue = credqueue::wrap(rx);
                let target_token = stop.target_token();
                let mut workers: JoinSet<()> = JoinSet::new();
                for _ in 0..tasks {
                    let ctx = WorkerCtx {
                        protocol: protocol.clone(),
                        target: target.clone(),
                        queue: queue.clone(),
                        module_opts: module_opts.clone(),
                        results: results.clone(),
                        global_token: stop.global.clone(),
                        target_token: target_token.clone(),
                        stop_global_on_found: stop.stop_global_on_found,
                        stop_target_on_found: stop.stop_target_on_found,
                        rate: rate.clone(),
                        creds_done: creds_done.clone(),
                        progress: Some(progress.clone()),
                        wait_connect,
                        retry_wait,
                        show_attempts,
                        quiet,
                    };
                    workers.spawn(worker::run(ctx));
                }
                while workers.join_next().await.is_some() {}
            });
        }
        while targets_set.join_next().await.is_some() {}

        // Flush output.
        let count = results.count().await;
        let success = count > 0;
        let doc = results.finish(success).await;
        progress.finish(format!("done — {count} credential(s) found"));
        if let Some(d) = doc {
            if opts.output_file.is_none() {
                println!("{d}");
            }
        }

        // Final restore snapshot, then stop the auto-saver.
        if !opts.ignore_restore {
            let done = creds_done.load(Ordering::Relaxed);
            let rf = restore::build(&opts.command_line, &opts.targets, done, &results).await;
            restore::save(&opts.restore_path, &rf);
        }
        stop.global.cancel();
        if let Some(h) = autosave {
            let _ = h.await;
        }

        Ok(results.snapshot().await)
    }
}
