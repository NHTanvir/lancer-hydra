//! FTP / FTPS — `USER` / `PASS` reply-code dialog (RFC 959).
//!
//! `ftp` is plain; `ftps` does explicit `AUTH TLS` then logs in over TLS.
//! Reply codes: 2xx = ok, 332/331 = need pass, 530 = login fail, 421 = busy.

use crate::prelude::*;

/// Read an FTP reply, joining `xyz-` multiline continuations until `xyz `.
async fn read_reply(c: &mut Conn) -> Result<(u16, String), ProtocolError> {
    let first = c.read_line().await?;
    let code = first
        .get(0..3)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| perr(format!("bad FTP reply: {first}")))?;
    let mut body = first.clone();
    if first.as_bytes().get(3) == Some(&b'-') {
        let stop = format!("{code} ");
        loop {
            let line = c.read_line().await?;
            body.push('\n');
            body.push_str(&line);
            if line.starts_with(&stop) {
                break;
            }
        }
    }
    Ok((code, body))
}

#[derive(Default)]
pub struct Ftp;

#[async_trait]
impl Protocol for Ftp {
    fn name(&self) -> &'static str {
        "ftp"
    }
    fn default_port(&self) -> u16 {
        21
    }
    fn supports_ssl(&self) -> bool {
        true
    }
    fn supports_reuse(&self) -> bool {
        true
    }
    fn usage(&self) -> &'static str {
        "ftp: plain control channel. Use ftps for explicit AUTH TLS, or -S for implicit (990)."
    }

    async fn try_credential(
        &self,
        target: &Target,
        user: &str,
        pass: &str,
        opts: &ModuleOpts,
    ) -> Result<AuthOutcome, ProtocolError> {
        let mut c = connect(target, opts).await?;
        let (code, _) = read_reply(&mut c).await?;
        if code == 421 {
            return Ok(AuthOutcome::Lockout); // service unavailable / too many connections
        }
        if code != 220 {
            return Err(perr(format!("unexpected banner code {code}")));
        }

        c.write_line(&format!("USER {user}")).await?;
        let (code, _) = read_reply(&mut c).await?;
        match code {
            230 => return Ok(AuthOutcome::Success), // logged in with no password
            331 | 332 => {}                          // password required
            530 => return Ok(AuthOutcome::Failure),
            421 => return Ok(AuthOutcome::Lockout),
            _ => return Ok(AuthOutcome::Unknown),
        }

        c.write_line(&format!("PASS {pass}")).await?;
        let (code, _) = read_reply(&mut c).await?;
        let _ = c.write_line("QUIT").await;
        Ok(match code {
            230 | 202 => AuthOutcome::Success,
            530 | 430 => AuthOutcome::Failure,
            421 => AuthOutcome::Lockout,
            _ => AuthOutcome::Unknown,
        })
    }
}

register_protocol!(Ftp, "ftp");

/// FTPS = FTP with explicit `AUTH TLS` (the module sets `ssl` via `-S` for implicit).
#[derive(Default)]
pub struct Ftps;

#[async_trait]
impl Protocol for Ftps {
    fn name(&self) -> &'static str {
        "ftps"
    }
    fn default_port(&self) -> u16 {
        21
    }
    fn supports_ssl(&self) -> bool {
        true
    }
    fn usage(&self) -> &'static str {
        "ftps: explicit FTP-over-TLS (AUTH TLS on 21). Implicit FTPS uses ftp -S on 990."
    }

    async fn try_credential(
        &self,
        target: &Target,
        user: &str,
        pass: &str,
        opts: &ModuleOpts,
    ) -> Result<AuthOutcome, ProtocolError> {
        // Explicit AUTH TLS upgrade on the plain control channel.
        let mut plain = connect_plain(target, opts).await?;
        let (code, _) = read_reply(&mut plain).await?;
        if code != 220 {
            return Err(perr(format!("unexpected banner code {code}")));
        }
        plain.write_line("AUTH TLS").await?;
        let (code, _) = read_reply(&mut plain).await?;
        if code != 234 {
            return Err(perr("server refused AUTH TLS".to_string()));
        }
        // After AUTH TLS we would wrap the existing socket. The buffered Conn
        // owns the socket, so for a correct (if not reused) attempt we reconnect
        // over implicit TLS and run the standard login dialog.
        let mut tls_target = target.clone();
        tls_target.ssl = true;
        let mut c = connect(&tls_target, opts).await?;
        let _ = read_reply(&mut c).await;
        c.write_line(&format!("USER {user}")).await?;
        let (code, _) = read_reply(&mut c).await?;
        if !(code == 331 || code == 332 || code == 230) {
            return Ok(AuthOutcome::Failure);
        }
        if code == 230 {
            return Ok(AuthOutcome::Success);
        }
        c.write_line(&format!("PASS {pass}")).await?;
        let (code, _) = read_reply(&mut c).await?;
        let _ = c.write_line("QUIT").await;
        Ok(match code {
            230 | 202 => AuthOutcome::Success,
            530 | 430 => AuthOutcome::Failure,
            421 => AuthOutcome::Lockout,
            _ => AuthOutcome::Unknown,
        })
    }
}

register_protocol!(Ftps, "ftps");
