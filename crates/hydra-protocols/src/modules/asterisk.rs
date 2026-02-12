//! Asterisk Manager Interface (AMI, port 5038) — `Action: Login`.

use crate::prelude::*;

#[derive(Default)]
pub struct Asterisk;

#[async_trait]
impl Protocol for Asterisk {
    fn name(&self) -> &'static str {
        "asterisk"
    }
    fn default_port(&self) -> u16 {
        5038
    }
    fn usage(&self) -> &'static str {
        "asterisk: AMI Action: Login with Username/Secret."
    }
    async fn try_credential(
        &self,
        target: &Target,
        user: &str,
        pass: &str,
        opts: &ModuleOpts,
    ) -> Result<AuthOutcome, ProtocolError> {
        let mut c = connect(target, opts).await?;
        let greet = c.read_line().await?;
        if !greet.contains("Asterisk Call Manager") {
            return Err(perr("asterisk: not an AMI port"));
        }
        let login = format!(
            "Action: Login\r\nUsername: {user}\r\nSecret: {pass}\r\n\r\n"
        );
        c.write_all(login.as_bytes()).await?;

        // Response block, terminated by a blank line.
        let mut block = String::new();
        for _ in 0..16 {
            let line = match c.read_line().await {
                Ok(l) => l,
                Err(_) => break,
            };
            if line.is_empty() {
                break;
            }
            block.push_str(&line);
            block.push('\n');
        }
        let low = block.to_lowercase();
        Ok(if low.contains("response: success") {
            AuthOutcome::Success
        } else if low.contains("authentication failed") || low.contains("response: error") {
            AuthOutcome::Failure
        } else {
            AuthOutcome::Unknown
        })
    }
}
register_protocol!(Asterisk, "asterisk");
