//! rsh (port 514) — Berkeley remote shell. Trust-based; we probe whether the
//! `(localuser, remoteuser)` pair is accepted from a `.rhosts`/`hosts.equiv` entry.

use crate::prelude::*;

#[derive(Default)]
pub struct Rsh;

#[async_trait]
impl Protocol for Rsh {
    fn name(&self) -> &'static str {
        "rsh"
    }
    fn default_port(&self) -> u16 {
        514
    }
    fn usage(&self) -> &'static str {
        "rsh: BSD remote shell trust probe (the user field is the remote user)."
    }
    async fn try_credential(
        &self,
        target: &Target,
        user: &str,
        _pass: &str,
        opts: &ModuleOpts,
    ) -> Result<AuthOutcome, ProtocolError> {
        let mut c = connect(target, opts).await?;
        let mut req = Vec::new();
        req.extend_from_slice(b"0\0");
        req.extend_from_slice(user.as_bytes()); // local user
        req.push(0);
        req.extend_from_slice(user.as_bytes()); // remote user
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
register_protocol!(Rsh, "rsh");
