//! HTTP-Proxy and HTTP-Proxy-URLEnum.
//!
//! `http-proxy` tests `Proxy-Authorization: Basic` against a forward proxy
//! (407 = rejected). `http-proxy-urlenum` feeds the proxy a target URL (from
//! `-m`) and looks for back-end auth behind it.

use super::http_util;
use crate::crypto;
use crate::prelude::*;

#[derive(Default)]
pub struct HttpProxy;

#[async_trait]
impl Protocol for HttpProxy {
    fn name(&self) -> &'static str {
        "http-proxy"
    }
    fn default_port(&self) -> u16 {
        8080
    }
    fn usage(&self) -> &'static str {
        "http-proxy: -m http://target/ probes Proxy-Authorization Basic auth (407 = fail)."
    }
    async fn try_credential(
        &self,
        target: &Target,
        user: &str,
        pass: &str,
        opts: &ModuleOpts,
    ) -> Result<AuthOutcome, ProtocolError> {
        let url = opts
            .raw
            .as_deref()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "http://www.google.com/".to_string());
        let token = crypto::b64encode(format!("{user}:{pass}").as_bytes());
        let headers = vec![("Proxy-Authorization".to_string(), format!("Basic {token}"))];
        let resp = http_util::request(target, opts, "GET", &url, &headers, None).await?;
        Ok(match resp.status {
            407 => AuthOutcome::Failure,
            200..=399 | 403 | 404 => AuthOutcome::Success, // proxy accepted us, forwarded request
            429 => AuthOutcome::Lockout,
            _ => AuthOutcome::Unknown,
        })
    }
}
register_protocol!(HttpProxy, "http-proxy");

#[derive(Default)]
pub struct HttpProxyUrlEnum;

#[async_trait]
impl Protocol for HttpProxyUrlEnum {
    fn name(&self) -> &'static str {
        "http-proxy-urlenum"
    }
    fn default_port(&self) -> u16 {
        8080
    }
    fn usage(&self) -> &'static str {
        "http-proxy-urlenum: -m <url> via proxy; looks for back-end auth (401/403)."
    }
    async fn try_credential(
        &self,
        target: &Target,
        _user: &str,
        _pass: &str,
        opts: &ModuleOpts,
    ) -> Result<AuthOutcome, ProtocolError> {
        let url = opts
            .raw
            .as_deref()
            .ok_or_else(|| oerr("http-proxy-urlenum requires -m <url>"))?;
        let resp = http_util::request(target, opts, "GET", url, &[], None).await?;
        Ok(match resp.status {
            401 | 403 => AuthOutcome::Success, // found a protected back-end resource
            _ => AuthOutcome::Failure,
        })
    }
}
register_protocol!(HttpProxyUrlEnum, "http-proxy-urlenum");
