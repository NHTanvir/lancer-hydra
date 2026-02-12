//! VMware Authentication Daemon (vmauthd, port 902) — FTP-style USER/PASS.

use crate::prelude::*;

async fn code(c: &mut Conn) -> Result<u16, ProtocolError> {
    let line = c.read_line().await?;
    line.get(0..3)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| perr(format!("vmauthd: bad reply {line}")))
}

#[derive(Default)]
pub struct VmAuthd;

#[async_trait]
impl Protocol for VmAuthd {
    fn name(&self) -> &'static str {
        "vmauthd"
    }
    fn default_port(&self) -> u16 {
        902
    }
    fn supports_ssl(&self) -> bool {
        true
    }
    fn usage(&self) -> &'static str {
        "vmauthd: USER/PASS like FTP. -m TLS=0 to skip STARTTLS on legacy ESXi 5.x."
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
        if greet != 220 {
            return Err(perr("vmauthd: bad greeting"));
        }
        c.write_line(&format!("USER {user}")).await?;
        let r = code(&mut c).await?;
        if r != 331 && r != 230 {
            return Ok(AuthOutcome::Failure);
        }
        if r == 230 {
            return Ok(AuthOutcome::Success);
        }
        c.write_line(&format!("PASS {pass}")).await?;
        let r = code(&mut c).await?;
        Ok(match r {
            230 => AuthOutcome::Success,
            530 => AuthOutcome::Failure,
            _ => AuthOutcome::Unknown,
        })
    }
}
register_protocol!(VmAuthd, "vmauthd");
