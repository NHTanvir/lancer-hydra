//! Telnet / Telnets — IAC option negotiation + login-prompt matching.
//!
//! Telnet has no auth framing: we refuse all IAC options, wait for the login
//! prompt, send the user, wait for the password prompt, send the pass, then
//! score the trailing text for success/failure keywords.

use crate::prelude::*;

const IAC: u8 = 255;
const DONT: u8 = 254;
const DO: u8 = 253;
const WONT: u8 = 252;
const WILL: u8 = 251;
const SB: u8 = 250;
const SE: u8 = 240;

/// Strip and answer IAC negotiation, returning the printable text seen so far.
async fn pump(c: &mut Conn, replies: &mut Vec<u8>) -> Result<String, ProtocolError> {
    let data = c.read_some(4096).await?;
    let mut text = Vec::new();
    let mut i = 0;
    while i < data.len() {
        if data[i] == IAC && i + 1 < data.len() {
            match data[i + 1] {
                DO if i + 2 < data.len() => {
                    replies.extend_from_slice(&[IAC, WONT, data[i + 2]]);
                    i += 3;
                }
                WILL if i + 2 < data.len() => {
                    replies.extend_from_slice(&[IAC, DONT, data[i + 2]]);
                    i += 3;
                }
                WONT | DONT if i + 2 < data.len() => {
                    i += 3;
                }
                SB => {
                    // skip sub-negotiation up to IAC SE
                    i += 2;
                    while i + 1 < data.len() && !(data[i] == IAC && data[i + 1] == SE) {
                        i += 1;
                    }
                    i += 2;
                }
                IAC => {
                    text.push(IAC);
                    i += 2;
                }
                _ => i += 2,
            }
        } else {
            text.push(data[i]);
            i += 1;
        }
    }
    Ok(String::from_utf8_lossy(&text).to_string())
}

fn looks_like(s: &str, needles: &[&str]) -> bool {
    let low = s.to_lowercase();
    needles.iter().any(|n| low.contains(n))
}

async fn login(
    target: &Target,
    user: &str,
    pass: &str,
    opts: &ModuleOpts,
) -> Result<AuthOutcome, ProtocolError> {
    let mut c = connect(target, opts).await?;
    let mut transcript = String::new();

    // Negotiate + wait for the login prompt.
    for _ in 0..8 {
        let mut replies = Vec::new();
        let text = pump(&mut c, &mut replies).await?;
        if !replies.is_empty() {
            c.write_all(&replies).await?;
        }
        transcript.push_str(&text);
        if looks_like(&transcript, &["login:", "username:", "user:"]) {
            break;
        }
    }
    c.write_line(user).await?;

    // Wait for the password prompt.
    transcript.clear();
    for _ in 0..8 {
        let mut replies = Vec::new();
        let text = pump(&mut c, &mut replies).await?;
        if !replies.is_empty() {
            c.write_all(&replies).await?;
        }
        transcript.push_str(&text);
        if looks_like(&transcript, &["password:", "passcode:"]) {
            break;
        }
    }
    c.write_line(pass).await?;

    // Score the response.
    transcript.clear();
    for _ in 0..6 {
        let mut replies = Vec::new();
        match pump(&mut c, &mut replies).await {
            Ok(text) => transcript.push_str(&text),
            Err(_) => break,
        }
        if looks_like(&transcript, &["incorrect", "failed", "denied", "login:", "bad pass"]) {
            return Ok(AuthOutcome::Failure);
        }
        if looks_like(&transcript, &["last login", "welcome", "$ ", "# ", "> "]) {
            return Ok(AuthOutcome::Success);
        }
    }
    if looks_like(&transcript, &["incorrect", "failed", "denied", "login:"]) {
        Ok(AuthOutcome::Failure)
    } else if transcript.trim().is_empty() {
        Ok(AuthOutcome::Unknown)
    } else {
        Ok(AuthOutcome::Success)
    }
}

#[derive(Default)]
pub struct Telnet;

#[async_trait]
impl Protocol for Telnet {
    fn name(&self) -> &'static str {
        "telnet"
    }
    fn default_port(&self) -> u16 {
        23
    }
    fn supports_ssl(&self) -> bool {
        true
    }
    fn usage(&self) -> &'static str {
        "telnet: login-prompt matcher. Heuristic success/failure scoring."
    }
    async fn try_credential(
        &self,
        target: &Target,
        user: &str,
        pass: &str,
        opts: &ModuleOpts,
    ) -> Result<AuthOutcome, ProtocolError> {
        login(target, user, pass, opts).await
    }
}
register_protocol!(Telnet, "telnet");

#[derive(Default)]
pub struct Telnets;

#[async_trait]
impl Protocol for Telnets {
    fn name(&self) -> &'static str {
        "telnets"
    }
    fn default_port(&self) -> u16 {
        992
    }
    fn supports_ssl(&self) -> bool {
        true
    }
    async fn try_credential(
        &self,
        target: &Target,
        user: &str,
        pass: &str,
        opts: &ModuleOpts,
    ) -> Result<AuthOutcome, ProtocolError> {
        let mut t = target.clone();
        t.ssl = true;
        login(&t, user, pass, opts).await
    }
}
register_protocol!(Telnets, "telnets");
