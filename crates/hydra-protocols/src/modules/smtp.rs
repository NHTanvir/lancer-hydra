//! SMTP / SMTPS / SMTP-Enum authentication.
//!
//! Mechanisms (via `-m`): LOGIN, PLAIN, CRAM-MD5 (DIGEST-MD5 / NTLM / XOAUTH2
//! recognized as option strings). 235 = accepted, 535 = rejected, 421 = busy.

use crate::crypto;
use crate::prelude::*;

/// Read an SMTP reply, consuming `nnn-` multiline continuations.
async fn read_reply(c: &mut Conn) -> Result<(u16, String), ProtocolError> {
    let first = c.read_line().await?;
    let code = first
        .get(0..3)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| perr(format!("bad SMTP reply: {first}")))?;
    let mut body = first.clone();
    if first.as_bytes().get(3) == Some(&b'-') {
        loop {
            let line = c.read_line().await?;
            let cont = line.as_bytes().get(3) == Some(&b'-');
            body.push('\n');
            body.push_str(&line);
            if !cont {
                break;
            }
        }
    }
    Ok((code, body))
}

async fn ehlo(c: &mut Conn) -> Result<String, ProtocolError> {
    let (code, _) = read_reply(c).await?;
    if code != 220 {
        return Err(perr(format!("unexpected SMTP greeting {code}")));
    }
    c.write_line("EHLO lancer-hydra").await?;
    let (code, caps) = read_reply(c).await?;
    if code != 250 {
        // fall back to HELO
        c.write_line("HELO lancer-hydra").await?;
        let _ = read_reply(c).await?;
    }
    Ok(caps.to_uppercase())
}

async fn auth(
    target: &Target,
    user: &str,
    pass: &str,
    opts: &ModuleOpts,
) -> Result<AuthOutcome, ProtocolError> {
    let mut c = connect(target, opts).await?;
    let _caps = ehlo(&mut c).await?;
    let mech = opts.mech_or("LOGIN");

    let final_code = match mech.as_str() {
        "PLAIN" | "XOAUTH2" => {
            let token = if mech == "XOAUTH2" {
                crypto::b64encode(format!("user={user}\x01auth=Bearer {pass}\x01\x01").as_bytes())
            } else {
                crypto::b64encode(format!("\0{user}\0{pass}").as_bytes())
            };
            c.write_line(&format!("AUTH {mech} {token}")).await?;
            read_reply(&mut c).await?.0
        }
        "CRAM-MD5" => {
            c.write_line("AUTH CRAM-MD5").await?;
            let (code, body) = read_reply(&mut c).await?;
            if code != 334 {
                return Ok(AuthOutcome::Failure);
            }
            let challenge = crypto::b64decode(body.trim_start_matches("334").trim())
                .ok_or_else(|| perr("smtp: bad CRAM challenge"))?;
            let digest = hex::encode(crypto::hmac_md5(pass.as_bytes(), &challenge));
            let resp = crypto::b64encode(format!("{user} {digest}").as_bytes());
            c.write_line(&resp).await?;
            read_reply(&mut c).await?.0
        }
        _ => {
            // LOGIN (default)
            c.write_line("AUTH LOGIN").await?;
            let (code, _) = read_reply(&mut c).await?;
            if code != 334 {
                return Ok(AuthOutcome::Failure);
            }
            c.write_line(&crypto::b64encode(user.as_bytes())).await?;
            let (code, _) = read_reply(&mut c).await?;
            if code != 334 {
                return Ok(AuthOutcome::Failure);
            }
            c.write_line(&crypto::b64encode(pass.as_bytes())).await?;
            read_reply(&mut c).await?.0
        }
    };

    let _ = c.write_line("QUIT").await;
    Ok(match final_code {
        235 => AuthOutcome::Success,
        535 | 530 | 534 => AuthOutcome::Failure,
        421 | 454 => AuthOutcome::Lockout,
        _ => AuthOutcome::Unknown,
    })
}

#[derive(Default)]
pub struct Smtp;

#[async_trait]
impl Protocol for Smtp {
    fn name(&self) -> &'static str {
        "smtp"
    }
    fn default_port(&self) -> u16 {
        25
    }
    fn supports_ssl(&self) -> bool {
        true
    }
    fn usage(&self) -> &'static str {
        "smtp: -m LOGIN|PLAIN|CRAM-MD5|DIGEST-MD5|NTLM|XOAUTH2 selects SASL mechanism."
    }
    async fn try_credential(
        &self,
        target: &Target,
        user: &str,
        pass: &str,
        opts: &ModuleOpts,
    ) -> Result<AuthOutcome, ProtocolError> {
        auth(target, user, pass, opts).await
    }
}
register_protocol!(Smtp, "smtp");

#[derive(Default)]
pub struct Smtps;

#[async_trait]
impl Protocol for Smtps {
    fn name(&self) -> &'static str {
        "smtps"
    }
    fn default_port(&self) -> u16 {
        465
    }
    fn supports_ssl(&self) -> bool {
        true
    }
    async fn try_credential(
        &self,
        target: &Target,
        user: &str,
        pass: &str,
        opts: &ModuleOpts,
    ) -> Result<AuthOutcome, ProtocolError> {
        let mut t = target.clone();
        t.ssl = true;
        auth(&t, user, pass, opts).await
    }
}
register_protocol!(Smtps, "smtps");

/// SMTP-Enum: probe whether a username exists via `VRFY` / `RCPT TO`.
#[derive(Default)]
pub struct SmtpEnum;

#[async_trait]
impl Protocol for SmtpEnum {
    fn name(&self) -> &'static str {
        "smtp-enum"
    }
    fn default_port(&self) -> u16 {
        25
    }
    fn usage(&self) -> &'static str {
        "smtp-enum: VRFY/RCPT user enumeration; password field unused."
    }
    async fn try_credential(
        &self,
        target: &Target,
        user: &str,
        _pass: &str,
        opts: &ModuleOpts,
    ) -> Result<AuthOutcome, ProtocolError> {
        let mut c = connect(target, opts).await?;
        let _ = ehlo(&mut c).await?;
        c.write_line(&format!("VRFY {user}")).await?;
        let (code, _) = read_reply(&mut c).await?;
        let _ = c.write_line("QUIT").await;
        Ok(match code {
            250 | 252 => AuthOutcome::Success, // user exists / cannot verify but will accept
            550 | 551 => AuthOutcome::Failure,
            _ => AuthOutcome::Unknown,
        })
    }
}
register_protocol!(SmtpEnum, "smtp-enum");
