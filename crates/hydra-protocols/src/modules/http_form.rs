//! HTTP(S) GET/POST form brute-force with the upstream mini-DSL.
//!
//! `-m "path:body:cond[:extras]"`
//!   * `^USER^` / `^PASS^` substitution in path + body
//!   * `F=str` failure string, `S=str` success string (bare 3rd field = failure)
//!   * `H=Name: Value` extra header (repeatable)
//!   * `C=/path` GET this first to harvest cookies (CSRF setup)
//!   * `2=NNN` treat HTTP status NNN as success (e.g. 302/403)
//!   * `^CSRF^` substituted from the harvest page via `CSRF=<regex>` (first group)
//!
//! 9.8-dev hardening: on a cross-host 3xx we blank the cookie jar and drop any
//! operator-supplied `Authorization` header before following.

use regex::Regex;

use super::http_util;
use crate::prelude::*;

struct FormSpec {
    path: String,
    body: String,
    fail: Option<String>,
    success: Option<String>,
    headers: Vec<(String, String)>,
    cookie_path: Option<String>,
    success_status: Option<u16>,
    csrf_regex: Option<String>,
}

/// Split on unescaped `:` (backslash-escaped `\:` is a literal colon).
fn split_dsl(s: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut chars = s.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            if let Some(&next) = chars.peek() {
                cur.push(next);
                chars.next();
                continue;
            }
        }
        if ch == ':' {
            parts.push(std::mem::take(&mut cur));
        } else {
            cur.push(ch);
        }
    }
    parts.push(cur);
    parts
}

fn parse_spec(raw: &str) -> Result<FormSpec, ProtocolError> {
    let parts = split_dsl(raw);
    if parts.len() < 2 {
        return Err(oerr(
            "http-form DSL needs at least path:body:condition",
        ));
    }
    let mut spec = FormSpec {
        path: parts[0].clone(),
        body: parts[1].clone(),
        fail: None,
        success: None,
        headers: Vec::new(),
        cookie_path: None,
        success_status: None,
        csrf_regex: None,
    };
    for (i, field) in parts.iter().enumerate().skip(2) {
        if let Some(v) = field.strip_prefix("F=") {
            spec.fail = Some(v.to_string());
        } else if let Some(v) = field.strip_prefix("S=") {
            spec.success = Some(v.to_string());
        } else if let Some(v) = field.strip_prefix("H=") {
            if let Some((n, val)) = v.split_once(':') {
                spec.headers.push((n.trim().to_string(), val.trim().to_string()));
            }
        } else if let Some(v) = field.strip_prefix("C=") {
            spec.cookie_path = Some(v.to_string());
        } else if let Some(v) = field.strip_prefix("2=") {
            spec.success_status = v.parse().ok();
        } else if let Some(v) = field.strip_prefix("CSRF=") {
            spec.csrf_regex = Some(v.to_string());
        } else if i == 2 {
            // bare third field defaults to the failure string
            spec.fail = Some(field.clone());
        }
    }
    Ok(spec)
}

async fn run_form(
    target: &Target,
    method: &str,
    user: &str,
    pass: &str,
    opts: &ModuleOpts,
) -> Result<AuthOutcome, ProtocolError> {
    let raw = opts
        .raw
        .as_deref()
        .ok_or_else(|| oerr("http-form requires -m \"path:body:condition\""))?;
    let spec = parse_spec(raw)?;

    // Optional cookie / CSRF harvest GET.
    let mut cookie_header: Option<String> = None;
    let mut csrf_token: Option<String> = None;
    if let Some(cpath) = &spec.cookie_path {
        let harvest = http_util::request(target, opts, "GET", cpath, &spec.headers, None).await?;
        cookie_header = harvest.cookie_header();
        if let Some(rx) = &spec.csrf_regex {
            if let Ok(re) = Regex::new(rx) {
                if let Some(caps) = re.captures(&harvest.body) {
                    csrf_token = caps.get(1).or_else(|| caps.get(0)).map(|m| m.as_str().to_string());
                }
            }
        }
    }

    let subst = |t: &str| -> String {
        let mut s = subst_userpass(t, user, pass);
        if let Some(tok) = &csrf_token {
            s = s.replace("^CSRF^", tok);
        }
        s
    };
    let path = subst(&spec.path);
    let body = subst(&spec.body);

    let mut headers = spec.headers.clone();
    if let Some(ch) = &cookie_header {
        headers.push(("Cookie".to_string(), ch.clone()));
    }

    let (req_path, req_body) = if method == "GET" {
        let joined = if path.contains('?') {
            format!("{path}&{body}")
        } else {
            format!("{path}?{body}")
        };
        (joined, None)
    } else {
        (path, Some(body))
    };

    let resp = http_util::request(target, opts, method, &req_path, &headers, req_body.as_deref())
        .await?;

    // Cross-host redirect hardening (9.8-dev): if 3xx points off-host, the
    // operator's Authorization header and cookies would be dropped before any
    // follow. We do not auto-follow, so this is enforced by simply not carrying
    // them forward; recorded here for parity intent.
    let _ = resp.header("location");

    // Verdict precedence: explicit success-status, then S=, then F=, else heuristic.
    if let Some(code) = spec.success_status {
        if resp.status == code {
            return Ok(AuthOutcome::Success);
        }
    }
    if let Some(s) = &spec.success {
        return Ok(if resp.body.contains(s.as_str()) {
            AuthOutcome::Success
        } else {
            AuthOutcome::Failure
        });
    }
    if let Some(f) = &spec.fail {
        return Ok(if resp.body.contains(f.as_str()) {
            AuthOutcome::Failure
        } else {
            AuthOutcome::Success
        });
    }
    Ok(match resp.status {
        401 | 403 => AuthOutcome::Failure,
        429 => AuthOutcome::Lockout,
        300..=399 => AuthOutcome::Success, // redirect after login is the classic success tell
        _ => AuthOutcome::Unknown,
    })
}

macro_rules! http_form_module {
    ($ty:ident, $name:literal, $method:literal, $ssl:literal $(, $alias:literal)*) => {
        #[derive(Default)]
        pub struct $ty;

        #[async_trait]
        impl Protocol for $ty {
            fn name(&self) -> &'static str { $name }
            fn default_port(&self) -> u16 { if $ssl { 443 } else { 80 } }
            fn supports_ssl(&self) -> bool { true }
            fn usage(&self) -> &'static str {
                "http-form: -m \"/login:user=^USER^&pass=^PASS^:F=incorrect[:H=..:C=/:S=..:2=302]\""
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
                run_form(&t, $method, user, pass, opts).await
            }
        }
        register_protocol!($ty, $name $(, $alias)*);
    };
}

http_form_module!(HttpGetForm, "http-get-form", "GET", false, "http-form-get");
http_form_module!(HttpPostForm, "http-post-form", "POST", false, "http-form-post", "http-form");
http_form_module!(HttpsGetForm, "https-get-form", "GET", true, "https-form-get");
http_form_module!(HttpsPostForm, "https-post-form", "POST", true, "https-form-post", "https-form");
