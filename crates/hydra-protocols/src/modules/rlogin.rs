//! rlogin (port 513) — Berkeley remote login. Trust-based; if the server then
//! prompts for a password we send it and score the response.

use crate::prelude::*;

#[derive(Default)]
pub struct Rlogin;

#[async_trait]
impl Protocol for Rlogin {
    fn name(&self) -> &'static str {
        "rlogin"
    }
    fn default_port(&self) -> u16 {
        513
    }
    fn usage(&self) -> &'static str {
        "rlogin: BSD remote login (trust + optional password prompt)."
    }
    async fn try_credential(
        &self,
        target: &Target,
        user: &str,
        pass: &str,
        opts: &ModuleOpts,
    ) -> Result<AuthOutcome, ProtocolError> {
        let mut c = connect(target, opts).await?;
        let mut req = vec![0u8];
        req.extend_from_slice(user.as_bytes()); // client user
        req.push(0);
        req.extend_from_slice(user.as_bytes()); // server user
        req.push(0);
        req.extend_from_slice(b"vt100/9600");
        req.push(0);
        c.write_all(&req).await?;

        let first = c.read_some(512).await?;
        if first.first() == Some(&0) && first.len() == 1 {
            // zero byte ack with no password prompt → trusted login
            return Ok(AuthOutcome::Success);
        }
        let text = String::from_utf8_lossy(&first).to_lowercase();
        if text.contains("password:") {
            c.write_line(pass).await?;
            let resp = c.read_some(512).await?;
            let low = String::from_utf8_lossy(&resp).to_lowercase();
            if low.contains("incorrect") || low.contains("login:") || low.contains("denied") {
                return Ok(AuthOutcome::Failure);
            }
            return Ok(AuthOutcome::Success);
        }
        Ok(AuthOutcome::Unknown)
    }
}
register_protocol!(Rlogin, "rlogin");
