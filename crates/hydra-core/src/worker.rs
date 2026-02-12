//! The per-credential worker loop.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio_util::sync::CancellationToken;

use hydra_output::{text, Hit, Progress};
use hydra_protocols::{AuthOutcome, ModuleOpts, Protocol, Target};

use crate::credqueue::{self, SharedQueue};
use crate::ratelimit::DirectLimiter;
use crate::results::Results;

/// Everything one worker needs. Cheap to clone (all `Arc`/`Copy`).
#[derive(Clone)]
pub struct WorkerCtx {
    pub protocol: Arc<dyn Protocol>,
    pub target: Target,
    pub queue: SharedQueue,
    pub module_opts: ModuleOpts,
    pub results: Results,
    pub global_token: CancellationToken,
    pub target_token: CancellationToken,
    pub stop_global_on_found: bool,
    pub stop_target_on_found: bool,
    pub rate: Option<Arc<DirectLimiter>>,
    pub creds_done: Arc<AtomicU64>,
    pub progress: Option<Arc<Progress>>,
    pub wait_connect: Duration,
    pub retry_wait: Duration,
    pub show_attempts: bool,
    pub quiet: bool,
}

impl WorkerCtx {
    fn print(&self, line: &str) {
        match &self.progress {
            Some(p) => p.println(line),
            None => println!("{line}"),
        }
    }
}

/// Pull credentials until the queue drains or a stop token fires.
pub async fn run(ctx: WorkerCtx) {
    while !ctx.target_token.is_cancelled() && !ctx.global_token.is_cancelled() {
        let cred = match credqueue::next(&ctx.queue, &ctx.target_token).await {
            Some(c) => c,
            None => break,
        };

        if let Some(rl) = &ctx.rate {
            rl.until_ready().await;
        }

        let start = Instant::now();
        let mut attempt = 0u32;
        let outcome = loop {
            match ctx
                .protocol
                .try_credential(&ctx.target, &cred.user, &cred.pass, &ctx.module_opts)
                .await
            {
                Ok(o) => break Ok(o),
                Err(e) if e.is_transient() && attempt < 2 => {
                    attempt += 1;
                    if !ctx.retry_wait.is_zero() {
                        tokio::time::sleep(ctx.retry_wait).await;
                    } else {
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                }
                Err(e) => break Err(e),
            }
        };
        let elapsed = start.elapsed().as_millis() as u64;

        ctx.creds_done.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &ctx.progress {
            p.inc(1);
            if ctx.show_attempts {
                p.set_message(format!("{}:{}", cred.user, cred.pass));
            }
        }

        match outcome {
            Ok(AuthOutcome::Success) => {
                let hit = Hit {
                    host: ctx.target.host.clone(),
                    port: ctx.target.port,
                    service: ctx.target.proto.clone(),
                    login: cred.user.clone(),
                    password: cred.pass.clone(),
                    time_ms: elapsed,
                };
                self_print_hit(&ctx, &hit);
                ctx.results.record(hit).await;
                if ctx.stop_target_on_found {
                    ctx.target_token.cancel();
                }
                if ctx.stop_global_on_found {
                    ctx.global_token.cancel();
                }
            }
            Ok(AuthOutcome::Lockout) => {
                if !ctx.quiet {
                    ctx.print(&format!(
                        "[WARNING] {}:{} reports lockout/rate-limit; backing off",
                        ctx.target.host, ctx.target.port
                    ));
                }
                // Adaptive back-off: ease pressure on a locking target.
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Ok(_) => {
                if ctx.show_attempts && !ctx.quiet {
                    ctx.print(&format!("[ATTEMPT] {} - {}:{}", ctx.target.proto, cred.user, cred.pass));
                }
            }
            Err(e) => {
                if !ctx.quiet {
                    tracing::debug!("{}:{} error: {e}", ctx.target.host, ctx.target.port);
                }
                ctx.results
                    .add_error(e.to_string(), ctx.target.host.clone())
                    .await;
            }
        }

        if !ctx.wait_connect.is_zero() {
            tokio::time::sleep(ctx.wait_connect).await;
        }
    }
}

fn self_print_hit(ctx: &WorkerCtx, hit: &Hit) {
    ctx.print(&format!("[{}] {}", "FOUND", text::format_hit(hit)));
}
