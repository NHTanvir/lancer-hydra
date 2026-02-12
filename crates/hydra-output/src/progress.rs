//! Live progress bar over `indicatif`.

use indicatif::{ProgressBar, ProgressStyle};

/// Thin wrapper so the engine doesn't depend on `indicatif` directly.
pub struct Progress {
    bar: ProgressBar,
}

impl Progress {
    pub fn new(total: Option<u64>) -> Self {
        let bar = match total {
            Some(n) => {
                let b = ProgressBar::new(n);
                b.set_style(
                    ProgressStyle::with_template(
                        "{spinner} [{elapsed_precise}] [{bar:40}] {pos}/{len} ({per_sec}) {msg}",
                    )
                    .unwrap_or_else(|_| ProgressStyle::default_bar())
                    .progress_chars("=>-"),
                );
                b
            }
            None => {
                let b = ProgressBar::new_spinner();
                b.set_style(
                    ProgressStyle::with_template("{spinner} [{elapsed_precise}] {pos} tried {msg}")
                        .unwrap_or_else(|_| ProgressStyle::default_spinner()),
                );
                b
            }
        };
        Self { bar }
    }

    pub fn inc(&self, n: u64) {
        self.bar.inc(n);
    }

    pub fn set_message(&self, msg: impl Into<std::borrow::Cow<'static, str>>) {
        self.bar.set_message(msg);
    }

    pub fn println(&self, line: impl AsRef<str>) {
        self.bar.println(line);
    }

    pub fn finish(&self, msg: impl Into<std::borrow::Cow<'static, str>>) {
        self.bar.finish_with_message(msg);
    }
}
