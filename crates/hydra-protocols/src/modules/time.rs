//! Time protocol (RFC 868, port 37). Not an auth service — a reachability probe
//! kept for upstream parity (`hydra time://host`). A 4-byte time reply = up.

use crate::prelude::*;

#[derive(Default)]
pub struct Time;

#[async_trait]
impl Protocol for Time {
    fn name(&self) -> &'static str {
        "time"
    }
    fn default_port(&self) -> u16 {
        37
    }
    fn usage(&self) -> &'static str {
        "time: RFC 868 reachability probe (no authentication)."
    }
    async fn try_credential(
        &self,
        target: &Target,
        _user: &str,
        _pass: &str,
        opts: &ModuleOpts,
    ) -> Result<AuthOutcome, ProtocolError> {
        let mut c = connect(target, opts).await?;
        match c.read_exact(4).await {
            Ok(_) => Ok(AuthOutcome::Success),
            Err(_) => Ok(AuthOutcome::Failure),
        }
    }
}
register_protocol!(Time, "time", "rfc868");
