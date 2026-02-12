//! VNC — RFB 3.3 / 3.7 / 3.8 legacy DES-challenge authentication.

use crate::crypto;
use crate::prelude::*;

#[derive(Default)]
pub struct Vnc;

#[async_trait]
impl Protocol for Vnc {
    fn name(&self) -> &'static str {
        "vnc"
    }
    fn default_port(&self) -> u16 {
        5900
    }
    fn usage(&self) -> &'static str {
        "vnc: RFB DES-challenge auth (password only; username ignored)."
    }
    async fn try_credential(
        &self,
        target: &Target,
        _user: &str,
        pass: &str,
        opts: &ModuleOpts,
    ) -> Result<AuthOutcome, ProtocolError> {
        let mut c = connect(target, opts).await?;

        // ProtocolVersion handshake: server sends "RFB 003.00x\n".
        let server_ver = c.read_exact(12).await?;
        let minor = std::str::from_utf8(&server_ver[8..11])
            .ok()
            .and_then(|s| s.trim_start_matches('0').parse::<u32>().ok())
            .unwrap_or(3);
        // Reply with the version we support (cap at server's).
        let our = if minor >= 8 { "RFB 003.008\n" } else if minor >= 7 { "RFB 003.007\n" } else { "RFB 003.003\n" };
        c.write_all(our.as_bytes()).await?;

        // Security negotiation.
        if minor >= 7 {
            let n = c.read_exact(1).await?[0] as usize;
            if n == 0 {
                return Ok(AuthOutcome::Failure); // server gave a failure reason
            }
            let types = c.read_exact(n).await?;
            if !types.contains(&2) {
                if types.contains(&1) {
                    // type 1 = None: no password needed → open
                    c.write_all(&[1]).await?;
                    return Ok(AuthOutcome::Success);
                }
                return Err(perr("vnc: server offers no VNC-auth security type"));
            }
            c.write_all(&[2]).await?; // select VNC auth
        } else {
            // 3.3: server dictates the security type as a 4-byte value.
            let sec = c.read_exact(4).await?;
            let sec_type = u32::from_be_bytes(sec[..4].try_into().unwrap());
            match sec_type {
                1 => return Ok(AuthOutcome::Success), // None
                2 => {}
                _ => return Err(perr("vnc: unsupported 3.3 security type")),
            }
        }

        // Challenge (16 bytes) → DES response.
        let challenge = c.read_exact(16).await?;
        let response = crypto::vnc_des_response(pass, &challenge);
        c.write_all(&response).await?;

        // SecurityResult: 0 = OK, 1 = failed.
        let result = c.read_exact(4).await?;
        let code = u32::from_be_bytes(result[..4].try_into().unwrap());
        Ok(match code {
            0 => AuthOutcome::Success,
            1 => AuthOutcome::Failure,
            _ => AuthOutcome::Unknown,
        })
    }
}
register_protocol!(Vnc, "vnc");
