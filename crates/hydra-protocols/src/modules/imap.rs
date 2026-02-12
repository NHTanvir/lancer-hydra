//! IMAP / IMAPS — tagged `LOGIN` / `AUTHENTICATE` (RFC 3501).

use crate::prelude::*;

fn quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Read tagged lines until we see our tag, return the status word (OK/NO/BAD).
async fn read_tagged(c: &mut Conn, tag: &str) -> Result<String, ProtocolError> {
    loop {
        let line = c.read_line().await?;
        if let Some(rest) = line.strip_prefix(&format!("{tag} ")) {
            return Ok(rest.split_whitespace().next().unwrap_or("").to_uppercase());
        }
        if line.starts_with('+') {
            return Ok("+".to_string());
        }
    }
}

async fn auth(
    target: &Target,
    user: &str,
    pass: &str,
    opts: &ModuleOpts,
) -> Result<AuthOutcome, ProtocolError> {
    let mut c = connect(target, opts).await?;
    let greeting = c.read_line().await?;
    if !greeting.starts_with("* OK") {
        return Err(perr("imap: bad greeting"));
    }
    let mech = opts.mech_or("LOGIN");
    let status = match mech.as_str() {
        "PLAIN" => {
            c.write_line("a1 AUTHENTICATE PLAIN").await?;
            let _ = c.read_line().await?; // continuation
            let token = crate::crypto::b64encode(format!("\0{user}\0{pass}").as_bytes());
            c.write_line(&token).await?;
            read_tagged(&mut c, "a1").await?
        }
        "CRAM-MD5" => {
            c.write_line("a1 AUTHENTICATE CRAM-MD5").await?;
            let chall_line = c.read_line().await?;
            let chall = crate::crypto::b64decode(chall_line.trim_start_matches('+').trim())
                .ok_or_else(|| perr("imap: bad CRAM challenge"))?;
            let digest = hex::encode(crate::crypto::hmac_md5(pass.as_bytes(), &chall));
            let resp = crate::crypto::b64encode(format!("{user} {digest}").as_bytes());
            c.write_line(&resp).await?;
            read_tagged(&mut c, "a1").await?
        }
        "XOAUTH2" => {
            // SASL XOAUTH2: base64("user=<u>^Aauth=Bearer <token>^A^A") — the
            // password field carries the OAuth2 bearer token (M365 / Workspace).
            c.write_line("a1 AUTHENTICATE XOAUTH2").await?;
            let _ = c.read_line().await?; // continuation
            let token =
                crate::crypto::b64encode(format!("user={user}\x01auth=Bearer {pass}\x01\x01").as_bytes());
            c.write_line(&token).await?;
            read_tagged(&mut c, "a1").await?
        }
        _ => {
            c.write_line(&format!("a1 LOGIN {} {}", quote(user), quote(pass)))
                .await?;
            read_tagged(&mut c, "a1").await?
        }
    };
    let _ = c.write_line("a2 LOGOUT").await;
    Ok(match status.as_str() {
        "OK" => AuthOutcome::Success,
        "NO" => AuthOutcome::Failure,
        _ => AuthOutcome::Unknown,
    })
}

#[derive(Default)]
pub struct Imap;

#[async_trait]
impl Protocol for Imap {
    fn name(&self) -> &'static str {
        "imap"
    }
    fn default_port(&self) -> u16 {
        143
    }
    fn supports_ssl(&self) -> bool {
        true
    }
    fn usage(&self) -> &'static str {
        "imap: -m LOGIN|PLAIN|CRAM-MD5|NTLM|XOAUTH2 selects the AUTHENTICATE mechanism."
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
register_protocol!(Imap, "imap");

#[derive(Default)]
pub struct Imaps;

#[async_trait]
impl Protocol for Imaps {
    fn name(&self) -> &'static str {
        "imaps"
    }
    fn default_port(&self) -> u16 {
        993
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
register_protocol!(Imaps, "imaps");
