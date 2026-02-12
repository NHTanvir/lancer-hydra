//! Cisco IOS auth family: `cisco` (password-only line auth), `cisco-enable`
//! (enable secret), and `cisco-aaa` / `cisco-auth` (username + password / TACACS).

use crate::prelude::*;

async fn read_text(c: &mut Conn) -> String {
    match c.read_some(4096).await {
        Ok(b) => String::from_utf8_lossy(&b).to_string(),
        Err(_) => String::new(),
    }
}

/// Read until the transcript contains one of `needles` (case-insensitive).
async fn wait_for(c: &mut Conn, needles: &[&str]) -> bool {
    let mut acc = String::new();
    for _ in 0..8 {
        acc.push_str(&read_text(c).await);
        let low = acc.to_lowercase();
        if needles.iter().any(|n| low.contains(n)) {
            return true;
        }
    }
    false
}

fn score(text: &str) -> AuthOutcome {
    let low = text.to_lowercase();
    if low.contains("% bad") || low.contains("fail") || low.contains("denied") || low.contains("password:") {
        AuthOutcome::Failure
    } else if low.contains('#') || low.contains('>') {
        AuthOutcome::Success
    } else {
        AuthOutcome::Unknown
    }
}

#[derive(Default)]
pub struct Cisco;

#[async_trait]
impl Protocol for Cisco {
    fn name(&self) -> &'static str {
        "cisco"
    }
    fn default_port(&self) -> u16 {
        23
    }
    fn usage(&self) -> &'static str {
        "cisco: password-only line auth (VTY)."
    }
    async fn try_credential(
        &self,
        target: &Target,
        _user: &str,
        pass: &str,
        opts: &ModuleOpts,
    ) -> Result<AuthOutcome, ProtocolError> {
        let mut c = connect(target, opts).await?;
        wait_for(&mut c, &["password:"]).await;
        c.write_line(pass).await?;
        let resp = read_text(&mut c).await;
        Ok(score(&resp))
    }
}
register_protocol!(Cisco, "cisco");

#[derive(Default)]
pub struct CiscoEnable;

#[async_trait]
impl Protocol for CiscoEnable {
    fn name(&self) -> &'static str {
        "cisco-enable"
    }
    fn default_port(&self) -> u16 {
        23
    }
    fn usage(&self) -> &'static str {
        "cisco-enable: enable-secret brute (typically chained after a line login)."
    }
    async fn try_credential(
        &self,
        target: &Target,
        _user: &str,
        pass: &str,
        opts: &ModuleOpts,
    ) -> Result<AuthOutcome, ProtocolError> {
        let mut c = connect(target, opts).await?;
        // If a line password is required first, supply it via -m PASS=.
        if let Some(line_pw) = opts.get("PASS") {
            wait_for(&mut c, &["password:"]).await;
            c.write_line(line_pw).await?;
        }
        c.write_line("enable").await?;
        wait_for(&mut c, &["password:"]).await;
        c.write_line(pass).await?;
        let resp = read_text(&mut c).await;
        Ok(score(&resp))
    }
}
register_protocol!(CiscoEnable, "cisco-enable");

#[derive(Default)]
pub struct CiscoAaa;

#[async_trait]
impl Protocol for CiscoAaa {
    fn name(&self) -> &'static str {
        "cisco-aaa"
    }
    fn default_port(&self) -> u16 {
        23
    }
    fn usage(&self) -> &'static str {
        "cisco-aaa: AAA username + password line auth."
    }
    async fn try_credential(
        &self,
        target: &Target,
        user: &str,
        pass: &str,
        opts: &ModuleOpts,
    ) -> Result<AuthOutcome, ProtocolError> {
        let mut c = connect(target, opts).await?;
        wait_for(&mut c, &["username:", "login:"]).await;
        c.write_line(user).await?;
        wait_for(&mut c, &["password:"]).await;
        c.write_line(pass).await?;
        let resp = read_text(&mut c).await;
        Ok(score(&resp))
    }
}
register_protocol!(CiscoAaa, "cisco-aaa", "cisco-auth", "tacacs+");
