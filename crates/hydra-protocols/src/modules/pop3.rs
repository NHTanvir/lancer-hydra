//! POP3 / POP3S — `USER` / `PASS` with `+OK` / `-ERR` status lines (RFC 1939).

use crate::prelude::*;

async fn ok(c: &mut Conn) -> Result<bool, ProtocolError> {
    let line = c.read_line().await?;
    Ok(line.starts_with("+OK"))
}

async fn auth(
    target: &Target,
    user: &str,
    pass: &str,
    opts: &ModuleOpts,
) -> Result<AuthOutcome, ProtocolError> {
    let mut c = connect(target, opts).await?;
    if !ok(&mut c).await? {
        return Err(perr("pop3: bad greeting"));
    }
    let mech = opts.mech_or("USER");
    if mech == "PLAIN" {
        // SASL PLAIN
        c.write_line("AUTH PLAIN").await?;
        let _ = c.read_line().await?; // "+ " continuation
        let token = crate::crypto::b64encode(format!("\0{user}\0{pass}").as_bytes());
        c.write_line(&token).await?;
        return Ok(if ok(&mut c).await? {
            AuthOutcome::Success
        } else {
            AuthOutcome::Failure
        });
    }

    c.write_line(&format!("USER {user}")).await?;
    if !ok(&mut c).await? {
        return Ok(AuthOutcome::Failure);
    }
    c.write_line(&format!("PASS {pass}")).await?;
    let success = ok(&mut c).await?;
    let _ = c.write_line("QUIT").await;
    Ok(if success {
        AuthOutcome::Success
    } else {
        AuthOutcome::Failure
    })
}

#[derive(Default)]
pub struct Pop3;

#[async_trait]
impl Protocol for Pop3 {
    fn name(&self) -> &'static str {
        "pop3"
    }
    fn default_port(&self) -> u16 {
        110
    }
    fn supports_ssl(&self) -> bool {
        true
    }
    fn usage(&self) -> &'static str {
        "pop3: USER/PASS, or -m PLAIN for SASL PLAIN."
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
register_protocol!(Pop3, "pop3");

#[derive(Default)]
pub struct Pop3s;

#[async_trait]
impl Protocol for Pop3s {
    fn name(&self) -> &'static str {
        "pop3s"
    }
    fn default_port(&self) -> u16 {
        995
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
register_protocol!(Pop3s, "pop3s");
