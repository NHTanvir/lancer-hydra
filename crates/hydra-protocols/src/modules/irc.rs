//! IRC — server `PASS` brute-force (the password protecting the IRC server).

use crate::prelude::*;

#[derive(Default)]
pub struct Irc;

#[async_trait]
impl Protocol for Irc {
    fn name(&self) -> &'static str {
        "irc"
    }
    fn default_port(&self) -> u16 {
        6667
    }
    fn supports_ssl(&self) -> bool {
        true
    }
    fn usage(&self) -> &'static str {
        "irc: server PASS auth; the password field is the server password."
    }
    async fn try_credential(
        &self,
        target: &Target,
        user: &str,
        pass: &str,
        opts: &ModuleOpts,
    ) -> Result<AuthOutcome, ProtocolError> {
        let mut c = connect(target, opts).await?;
        let nick = if user.is_empty() { "lancer" } else { user };
        c.write_line(&format!("PASS {pass}")).await?;
        c.write_line(&format!("NICK {nick}")).await?;
        c.write_line(&format!("USER {nick} 0 * :{nick}")).await?;

        for _ in 0..12 {
            let line = match c.read_line().await {
                Ok(l) => l,
                Err(_) => break,
            };
            if line.starts_with("PING") {
                let token = line.trim_start_matches("PING").trim();
                let _ = c.write_line(&format!("PONG {token}")).await;
                continue;
            }
            // Numeric replies: 001 = welcome (registered), 464 = password mismatch.
            if line.contains(" 001 ") {
                return Ok(AuthOutcome::Success);
            }
            if line.contains(" 464 ") || line.to_uppercase().contains("PASSWORD MISMATCH") {
                return Ok(AuthOutcome::Failure);
            }
            if line.starts_with("ERROR") {
                return Ok(AuthOutcome::Failure);
            }
        }
        Ok(AuthOutcome::Unknown)
    }
}
register_protocol!(Irc, "irc");
