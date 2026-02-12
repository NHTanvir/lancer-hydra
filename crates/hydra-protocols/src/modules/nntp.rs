//! NNTP — `AUTHINFO USER` / `AUTHINFO PASS` (RFC 4643).

use crate::prelude::*;

async fn code(c: &mut Conn) -> Result<u16, ProtocolError> {
    let line = c.read_line().await?;
    line.get(0..3)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| perr(format!("nntp: bad reply {line}")))
}

#[derive(Default)]
pub struct Nntp;

#[async_trait]
impl Protocol for Nntp {
    fn name(&self) -> &'static str {
        "nntp"
    }
    fn default_port(&self) -> u16 {
        119
    }
    fn supports_ssl(&self) -> bool {
        true
    }
    fn usage(&self) -> &'static str {
        "nntp: AUTHINFO USER/PASS."
    }
    async fn try_credential(
        &self,
        target: &Target,
        user: &str,
        pass: &str,
        opts: &ModuleOpts,
    ) -> Result<AuthOutcome, ProtocolError> {
        let mut c = connect(target, opts).await?;
        let greet = code(&mut c).await?;
        if !(greet == 200 || greet == 201) {
            return Err(perr("nntp: bad greeting"));
        }
        c.write_line(&format!("AUTHINFO USER {user}")).await?;
        let r = code(&mut c).await?;
        if r == 281 {
            return Ok(AuthOutcome::Success); // accepted without password
        }
        if r != 381 {
            return Ok(AuthOutcome::Failure);
        }
        c.write_line(&format!("AUTHINFO PASS {pass}")).await?;
        let r = code(&mut c).await?;
        let _ = c.write_line("QUIT").await;
        Ok(match r {
            281 => AuthOutcome::Success,
            481 | 482 => AuthOutcome::Failure,
            _ => AuthOutcome::Unknown,
        })
    }
}
register_protocol!(Nntp, "nntp");
