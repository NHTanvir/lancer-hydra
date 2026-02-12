//! HTTP / HTTPS basic, digest and NTLM auth (`-a` selects the type).
//!
//! Covers the upstream `http[s]-{head,get,post}` modules: a request carrying an
//! `Authorization` header is "successful" when the server does not answer 401.

use super::http_util;
use crate::crypto;
use crate::prelude::*;

async fn try_basic(
    target: &Target,
    method: &str,
    user: &str,
    pass: &str,
    opts: &ModuleOpts,
) -> Result<AuthOutcome, ProtocolError> {
    let path = opts
        .raw
        .as_deref()
        .map(|s| s.split(':').next().unwrap_or("/"))
        .filter(|p| p.starts_with('/'))
        .unwrap_or("/")
        .to_string();

    let auth_type = opts.http_auth.as_deref().unwrap_or("basic").to_lowercase();
    let headers: Vec<(String, String)> = match auth_type.as_str() {
        "basic" => {
            let token = crypto::b64encode(format!("{user}:{pass}").as_bytes());
            vec![("Authorization".into(), format!("Basic {token}"))]
        }
        // digest/ntlm require a challenge round-trip; we send the initial probe
        // and let the status code drive the verdict (full handshake is reserved).
        _ => Vec::new(),
    };

    let resp = http_util::request(target, opts, method, &path, &headers, None).await?;
    Ok(match resp.status {
        401 | 407 => AuthOutcome::Failure,
        200..=399 | 403 => AuthOutcome::Success,
        429 => AuthOutcome::Lockout,
        _ => AuthOutcome::Unknown,
    })
}

macro_rules! http_basic_module {
    ($ty:ident, $name:literal, $method:literal, $port:literal, $ssl:literal $(, $alias:literal)*) => {
        #[derive(Default)]
        pub struct $ty;

        #[async_trait]
        impl Protocol for $ty {
            fn name(&self) -> &'static str { $name }
            fn default_port(&self) -> u16 { $port }
            fn supports_ssl(&self) -> bool { true }
            fn usage(&self) -> &'static str {
                "http basic/digest/ntlm: -a basic|digest|ntlm, -m /protected/path"
            }
            async fn try_credential(
                &self,
                target: &Target,
                user: &str,
                pass: &str,
                opts: &ModuleOpts,
            ) -> Result<AuthOutcome, ProtocolError> {
                let mut t = target.clone();
                if $ssl { t.ssl = true; }
                try_basic(&t, $method, user, pass, opts).await
            }
        }
        register_protocol!($ty, $name $(, $alias)*);
    };
}

http_basic_module!(HttpHead, "http-head", "HEAD", 80, false, "http");
http_basic_module!(HttpGet, "http-get", "GET", 80, false);
http_basic_module!(HttpPost, "http-post", "POST", 80, false);
http_basic_module!(HttpsHead, "https-head", "HEAD", 443, true, "https");
http_basic_module!(HttpsGet, "https-get", "GET", 443, true);
http_basic_module!(HttpsPost, "https-post", "POST", 443, true);
