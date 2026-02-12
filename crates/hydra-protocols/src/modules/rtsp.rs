//! RTSP (554) — `DESCRIBE` with Basic authentication (401 = rejected).

use crate::crypto;
use crate::prelude::*;

#[derive(Default)]
pub struct Rtsp;

#[async_trait]
impl Protocol for Rtsp {
    fn name(&self) -> &'static str {
        "rtsp"
    }
    fn default_port(&self) -> u16 {
        554
    }
    fn supports_ssl(&self) -> bool {
        true
    }
    fn usage(&self) -> &'static str {
        "rtsp: DESCRIBE with Basic auth (the path can be set via -m /stream)."
    }
    async fn try_credential(
        &self,
        target: &Target,
        user: &str,
        pass: &str,
        opts: &ModuleOpts,
    ) -> Result<AuthOutcome, ProtocolError> {
        let mut c = connect(target, opts).await?;
        let path = opts.raw.as_deref().unwrap_or("/");
        let scheme = if target.ssl { "rtsps" } else { "rtsp" };
        let url = format!("{scheme}://{}:{}{}", target.host, target.port, path);
        let token = crypto::b64encode(format!("{user}:{pass}").as_bytes());
        let req = format!(
            "DESCRIBE {url} RTSP/1.0\r\nCSeq: 1\r\nAuthorization: Basic {token}\r\nUser-Agent: lancer-hydra\r\n\r\n"
        );
        c.write_all(req.as_bytes()).await?;
        let status = c.read_line().await?;
        // "RTSP/1.0 200 OK" / "RTSP/1.0 401 Unauthorized"
        let code: u16 = status
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        Ok(match code {
            200 | 301 | 302 => AuthOutcome::Success,
            401 | 403 => AuthOutcome::Failure,
            _ => AuthOutcome::Unknown,
        })
    }
}
register_protocol!(Rtsp, "rtsp");
