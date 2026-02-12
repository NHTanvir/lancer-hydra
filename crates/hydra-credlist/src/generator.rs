//! Combine the sources into a lazy `(user, pass)` stream over a bounded channel.
//!
//! Memory stays flat on huge wordlists: logins load into a `Vec` (small), but
//! password files are re-streamed line-by-line per login rather than buffered.

use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc::Sender;

use crate::sources::PassSource;
use crate::{CredConfig, Credential};

/// Drive the generator, sending each credential into `tx`. Returns when the
/// list is exhausted or the receiver is dropped (engine stopped).
pub async fn produce(config: CredConfig, tx: Sender<Credential>) {
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
                    if tx.send(Credential::new(&user, ep)).await.is_err() {
                        return;
                    }
                }
                if tx.send(Credential::new(user, pass)).await.is_err() {
                    return;
                }
            }
        } else {
            tracing::error!("could not open combo file {:?}", combo);
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
                    if tx.send(Credential::new(u, p)).await.is_err() {
                        return;
                    }
                }
            }
            PassSource::Charset(spec) => {
                for pw in spec.iter() {
                    for u in &users {
                        if tx.send(Credential::new(u, &pw)).await.is_err() {
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
                            if tx.send(Credential::new(u, &pw)).await.is_err() {
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
                if tx.send(Credential::new(u, ep)).await.is_err() {
                    return;
                }
            }
        }
    } else {
        // default: login is the outer loop, passwords iterate fastest.
        for u in &users {
            for ep in config.extra.passwords_for(u) {
                if tx.send(Credential::new(u, ep)).await.is_err() {
                    return;
                }
            }
            match &config.passwords {
                PassSource::Single(p) => {
                    if tx.send(Credential::new(u, p)).await.is_err() {
                        return;
                    }
                }
                PassSource::Charset(spec) => {
                    for pw in spec.iter() {
                        if tx.send(Credential::new(u, &pw)).await.is_err() {
                            return;
                        }
                    }
                }
                PassSource::File(path) => {
                    // Re-open per login to keep memory flat on huge wordlists.
                    if let Ok(file) = File::open(path).await {
                        let mut lines = BufReader::new(file).lines();
                        while let Ok(Some(pw)) = lines.next_line().await {
                            if tx.send(Credential::new(u, &pw)).await.is_err() {
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
