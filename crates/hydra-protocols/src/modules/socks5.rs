//! SOCKS5 — username/password auth method (RFC 1929).

use crate::prelude::*;

#[derive(Default)]
pub struct Socks5;

#[async_trait]
impl Protocol for Socks5 {
    fn name(&self) -> &'static str {
        "socks5"
    }
    fn default_port(&self) -> u16 {
        1080
    }
    fn usage(&self) -> &'static str {
        "socks5: -m AUTH=user-pass (default) or -m AUTH=gssapi (gssapi reserved)."
    }
    async fn try_credential(
        &self,
        target: &Target,
        user: &str,
        pass: &str,
        opts: &ModuleOpts,
    ) -> Result<AuthOutcome, ProtocolError> {
        // `-m AUTH=user-pass` (default) is implemented; `gssapi` needs SPNEGO/
        // Kerberos which is out of scope for the pure-Rust transport.
        if opts.get("AUTH").map(|v| v.eq_ignore_ascii_case("gssapi")).unwrap_or(false) {
            return Err(ProtocolError::Unsupported(
                "socks5 gssapi auth (SPNEGO/Kerberos) not supported; use AUTH=user-pass".into(),
            ));
        }
        let mut c = connect(target, opts).await?;
        // Greeting: VER=5, NMETHODS=1, METHOD=0x02 (user/pass).
        c.write_all(&[0x05, 0x01, 0x02]).await?;
        let sel = c.read_exact(2).await?;
        if sel[0] != 0x05 {
            return Err(perr("socks5: bad version"));
        }
        match sel[1] {
            0x00 => return Ok(AuthOutcome::Success), // no auth required (open proxy)
            0x02 => {}                                // proceed with user/pass
            0xFF => return Ok(AuthOutcome::Failure),  // no acceptable methods
            _ => return Ok(AuthOutcome::Unknown),
        }
        // Username/password sub-negotiation.
        let mut req = vec![0x01u8, user.len() as u8];
        req.extend_from_slice(user.as_bytes());
        req.push(pass.len() as u8);
        req.extend_from_slice(pass.as_bytes());
        c.write_all(&req).await?;
        let resp = c.read_exact(2).await?;
        Ok(match resp[1] {
            0x00 => AuthOutcome::Success,
            _ => AuthOutcome::Failure,
        })
    }
}
register_protocol!(Socks5, "socks5");
