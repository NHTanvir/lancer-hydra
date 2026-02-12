//! rexec (port 512) — Berkeley remote execution with username/password.
//!
//! Wire format: `"<stderr-port>\0<user>\0<pass>\0<command>\0"`; the server
//! replies one status byte (0 = accepted).

use crate::prelude::*;

#[derive(Default)]
pub struct Rexec;

#[async_trait]
impl Protocol for Rexec {
    fn name(&self) -> &'static str {
        "rexec"
    }
    fn default_port(&self) -> u16 {
        512
    }
    fn usage(&self) -> &'static str {
        "rexec: BSD remote-exec auth (user/pass)."
    }
    async fn try_credential(
        &self,
        target: &Target,
        user: &str,
        pass: &str,
        opts: &ModuleOpts,
    ) -> Result<AuthOutcome, ProtocolError> {
        let mut c = connect(target, opts).await?;
        let mut req = Vec::new();
        req.extend_from_slice(b"0\0"); // no separate stderr channel
        req.extend_from_slice(user.as_bytes());
        req.push(0);
        req.extend_from_slice(pass.as_bytes());
        req.push(0);
        req.extend_from_slice(b"id\0");
        c.write_all(&req).await?;
        let status = c.read_exact(1).await?;
        Ok(match status[0] {
            0 => AuthOutcome::Success,
            _ => AuthOutcome::Failure,
        })
    }
}
register_protocol!(Rexec, "rexec");
