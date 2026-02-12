//! Redis — `AUTH [user] pass` over RESP (Redis 6+ ACL multi-user supported).

use crate::prelude::*;

/// Encode a RESP array of bulk strings.
fn resp_cmd(args: &[&str]) -> Vec<u8> {
    let mut out = format!("*{}\r\n", args.len()).into_bytes();
    for a in args {
        out.extend_from_slice(format!("${}\r\n", a.len()).as_bytes());
        out.extend_from_slice(a.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out
}

#[derive(Default)]
pub struct Redis;

#[async_trait]
impl Protocol for Redis {
    fn name(&self) -> &'static str {
        "redis"
    }
    fn default_port(&self) -> u16 {
        6379
    }
    fn supports_ssl(&self) -> bool {
        true
    }
    fn usage(&self) -> &'static str {
        "redis: AUTH pass, or -m ACL=username for a Redis 6+ ACL user."
    }
    async fn try_credential(
        &self,
        target: &Target,
        user: &str,
        pass: &str,
        opts: &ModuleOpts,
    ) -> Result<AuthOutcome, ProtocolError> {
        let mut c = connect(target, opts).await?;
        // Username precedence: -m ACL=, else the -l/-L user, else "default".
        let acl_user = opts.get("ACL").map(|s| s.to_string());
        let cmd = match acl_user.as_deref().or(if user.is_empty() { None } else { Some(user) }) {
            Some(u) if u != "default" || !user.is_empty() => resp_cmd(&["AUTH", u, pass]),
            _ => resp_cmd(&["AUTH", pass]),
        };
        c.write_all(&cmd).await?;
        let reply = c.read_line().await?;
        Ok(match reply.chars().next() {
            Some('+') => AuthOutcome::Success, // +OK
            Some('-') => {
                if reply.contains("no password is set") || reply.contains("without any password") {
                    AuthOutcome::Success // open instance accepts/ignores AUTH
                } else {
                    AuthOutcome::Failure // -WRONGPASS / -ERR invalid
                }
            }
            _ => AuthOutcome::Unknown,
        })
    }
}
register_protocol!(Redis, "redis");
