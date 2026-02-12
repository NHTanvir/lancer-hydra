//! Combine the sources into a lazy `(user, pass)` stream over a bounded channel.
//!
//! Memory stays flat on huge wordlists: logins load into a `Vec` (small), but
//! password files are re-streamed line-by-line per login rather than buffered.

use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc::Sender;

use crate::sources::PassSource;
use crate::{CredConfig, Credential};

/// Sends credentials into the channel, discarding the first `skip` of them so a
/// `-R` resume picks up where the previous run stopped. Returns `Err(())` once
/// the receiver is gone (engine stopped) so producers can bail early.
struct Emitter {
    tx: Sender<Credential>,
    skip_remaining: u64,
}

impl Emitter {
    async fn emit(&mut self, c: Credential) -> Result<(), ()> {
        if self.skip_remaining > 0 {
            self.skip_remaining -= 1;
            return Ok(());
        }
        self.tx.send(c).await.map_err(|_| ())
    }
}

/// Drive the generator, sending each credential into `tx`. `skip` discards that
/// many leading credentials (for `-R` resume). Returns when the list is
/// exhausted or the receiver is dropped (engine stopped).
pub async fn produce(config: CredConfig, tx: Sender<Credential>, skip: u64) {
    let mut em = Emitter { tx, skip_remaining: skip };

    // Combo file (`-C`) takes precedence: pre-paired login:pass entries.
    if let Some(combo) = &config.combo {
        if let Ok(file) = File::open(combo).await {
            let mut lines = BufReader::new(file).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let (user, pass) = match line.split_once(':') {
                    Some((u, p)) => (u.to_string(), p.to_string()),
                    None => (line.clone(), String::new()),
                };
                for ep in config.extra.passwords_for(&user) {
                    if em.emit(Credential::new(&user, ep)).await.is_err() {
                        return;
                    }
                }
                if em.emit(Credential::new(user, pass)).await.is_err() {
                    return;
                }
            }
        } else {
            tracing::error!("could not open combo file {:?}", combo);
        }
        return;
    }

    // Default credential corpus: only when the user gave no explicit source.
    if !config.has_explicit_creds() && !config.defaults.is_empty() {
        for (u, p) in &config.defaults {
            for ep in config.extra.passwords_for(u) {
                if em.emit(Credential::new(u, ep)).await.is_err() {
                    return;
                }
            }
            if em.emit(Credential::new(u, p)).await.is_err() {
                return;
            }
        }
        return;
    }

    let mut users = config.logins.load().await.unwrap_or_default();
    if users.is_empty() {
        users.push(String::new()); // password-only services (VNC, SNMP, redis)
    }

    if config.users_first {
        // password is the outer loop (password spray): stream passwords once,
        // trying every user for each — minimizes lockout per account per pass.
        match &config.passwords {
            PassSource::Single(p) => {
                for u in &users {
                    if em.emit(Credential::new(u, p)).await.is_err() {
                        return;
                    }
                }
            }
            PassSource::Charset(spec) => {
                for pw in spec.iter() {
                    for u in &users {
                        if em.emit(Credential::new(u, &pw)).await.is_err() {
                            return;
                        }
                    }
                }
            }
            PassSource::File(path) => {
                if let Ok(file) = File::open(path).await {
                    let mut lines = BufReader::new(file).lines();
                    while let Ok(Some(pw)) = lines.next_line().await {
                        for u in &users {
                            if em.emit(Credential::new(u, &pw)).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            }
            PassSource::None => {}
        }
        // Extras after the cartesian sweep.
        for u in &users {
            for ep in config.extra.passwords_for(u) {
                if em.emit(Credential::new(u, ep)).await.is_err() {
                    return;
                }
            }
        }
    } else {
        // default: login is the outer loop, passwords iterate fastest.
        for u in &users {
            for ep in config.extra.passwords_for(u) {
                if em.emit(Credential::new(u, ep)).await.is_err() {
                    return;
                }
            }
            match &config.passwords {
                PassSource::Single(p) => {
                    if em.emit(Credential::new(u, p)).await.is_err() {
                        return;
                    }
                }
                PassSource::Charset(spec) => {
                    for pw in spec.iter() {
                        if em.emit(Credential::new(u, &pw)).await.is_err() {
                            return;
                        }
                    }
                }
                PassSource::File(path) => {
                    // Re-open per login to keep memory flat on huge wordlists.
                    if let Ok(file) = File::open(path).await {
                        let mut lines = BufReader::new(file).lines();
                        while let Ok(Some(pw)) = lines.next_line().await {
                            if em.emit(Credential::new(u, &pw)).await.is_err() {
                                return;
                            }
                        }
                    }
                }
                PassSource::None => {}
            }
        }
    }
}
