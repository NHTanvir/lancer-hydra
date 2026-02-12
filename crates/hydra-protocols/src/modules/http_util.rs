//! Minimal HTTP/1.1 client over the shared [`Conn`] transport.
//!
//! Hand-rolled to avoid pulling a second TLS stack (reqwest/hyper). Enough for
//! the auth modules: basic-auth, form POST/GET, status/header/body inspection,
//! cookie harvest and `Connection: close` body reads.

use crate::prelude::*;

#[derive(Debug, Default, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
    /// `Set-Cookie` values, normalized to `name=value`.
    pub cookies: Vec<String>,
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    /// `Cookie:` header value built from harvested cookies.
    pub fn cookie_header(&self) -> Option<String> {
        if self.cookies.is_empty() {
            None
        } else {
            Some(self.cookies.join("; "))
        }
    }
}

/// Issue one HTTP request and read the full response.
pub async fn request(
    target: &Target,
    opts: &ModuleOpts,
    method: &str,
    path: &str,
    extra_headers: &[(String, String)],
    body: Option<&str>,
) -> Result<HttpResponse, ProtocolError> {
    let mut c = connect(target, opts).await?;
    let host_hdr = if (target.ssl && target.port == 443) || (!target.ssl && target.port == 80) {
        target.host.clone()
    } else {
        format!("{}:{}", target.host, target.port)
    };

    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {host_hdr}\r\n");
    req.push_str("User-Agent: lancer-hydra/1.0\r\nAccept: */*\r\nConnection: close\r\n");
    let mut have_ct = false;
    for (k, v) in extra_headers {
        if k.eq_ignore_ascii_case("content-type") {
            have_ct = true;
        }
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if let Some(b) = body {
        if !have_ct {
            req.push_str("Content-Type: application/x-www-form-urlencoded\r\n");
        }
        req.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }
    req.push_str("\r\n");
    if let Some(b) = body {
        req.push_str(b);
    }
    c.write_all(req.as_bytes()).await?;

    // Status line.
    let status_line = c.read_line().await?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| perr(format!("bad status line: {status_line}")))?;

    // Headers.
    let mut headers = Vec::new();
    let mut cookies = Vec::new();
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    loop {
        let line = c.read_line().await?;
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim().to_string();
            let v = v.trim().to_string();
            if k.eq_ignore_ascii_case("content-length") {
                content_length = v.parse().ok();
            } else if k.eq_ignore_ascii_case("transfer-encoding")
                && v.to_lowercase().contains("chunked")
            {
                chunked = true;
            } else if k.eq_ignore_ascii_case("set-cookie") {
                if let Some(c) = v.split(';').next() {
                    cookies.push(c.trim().to_string());
                }
            }
            headers.push((k, v));
        }
    }

    // Body.
    let body = if let Some(len) = content_length {
        let bytes = c.read_exact(len.min(1 << 20)).await.unwrap_or_default();
        String::from_utf8_lossy(&bytes).to_string()
    } else if chunked {
        read_chunked(&mut c).await.unwrap_or_default()
    } else {
        // read until close
        let mut acc = Vec::new();
        loop {
            match c.read_some(8192).await {
                Ok(b) if b.is_empty() => break,
                Ok(b) => acc.extend_from_slice(&b),
                Err(_) => break,
            }
            if acc.len() > (1 << 20) {
                break;
            }
        }
        String::from_utf8_lossy(&acc).to_string()
    };

    Ok(HttpResponse {
        status,
        headers,
        body,
        cookies,
    })
}

async fn read_chunked(c: &mut Conn) -> Result<String, ProtocolError> {
    let mut out = Vec::new();
    loop {
        let size_line = c.read_line().await?;
        let size = usize::from_str_radix(size_line.trim().split(';').next().unwrap_or("0"), 16)
            .unwrap_or(0);
        if size == 0 {
            break;
        }
        let chunk = c.read_exact(size).await?;
        out.extend_from_slice(&chunk);
        let _ = c.read_line().await?; // trailing CRLF
        if out.len() > (1 << 20) {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&out).to_string())
}
