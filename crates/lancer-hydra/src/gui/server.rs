//! Local integration HTTP server for the Lancer ecosystem.
//!
//! Binds `127.0.0.1:<auto>`, writes the port to `%TEMP%/lancer-hydra.port`, and
//! serves `/v1/state`, `/v1/export` and `/v1/import` so the Lancer mothership and
//! sibling tools can discover this instance and pull/import results.

use std::sync::{Arc, Mutex};

use hydra_output::Hit;

#[derive(Default)]
pub struct ServerState {
    pub running: bool,
    pub status: String,
    pub hits: Vec<Hit>,
}

pub type Shared = Arc<Mutex<ServerState>>;

/// Spawn the server on a background thread with its own current-thread runtime.
pub fn spawn(state: Shared) {
    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(r) => r,
            Err(_) => return,
        };
        rt.block_on(serve(state));
    });
}

async fn serve(state: Shared) {
    let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(_) => return,
    };
    if let Ok(addr) = listener.local_addr() {
        let port_file = std::env::temp_dir().join("lancer-hydra.port");
        let _ = std::fs::write(port_file, addr.port().to_string());
        tracing::info!("integration server on 127.0.0.1:{}", addr.port());
    }
    loop {
        let (mut sock, _) = match listener.accept().await {
            Ok(x) => x,
            Err(_) => continue,
        };
        let state = state.clone();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = vec![0u8; 8192];
            let n = match sock.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => n,
            };
            let req = String::from_utf8_lossy(&buf[..n]);
            let path = req
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .unwrap_or("/");
            let (status, ctype, body) = route(path, &state);
            let resp = format!(
                "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes()).await;
        });
    }
}

/// Extract `name=value` from a `?a=b&c=d` query string on `path`.
fn query_param(path: &str, name: &str) -> Option<String> {
    let q = path.split_once('?')?.1;
    for pair in q.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == name {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// CSV export (RFC 4180) of the result set.
fn export_csv(hits: &[Hit]) -> String {
    let q = |s: &str| format!("\"{}\"", s.replace('"', "\"\""));
    let mut out = String::from("host,port,service,login,password,time_ms\r\n");
    for h in hits {
        out.push_str(&format!(
            "{},{},{},{},{},{}\r\n",
            q(&h.host),
            h.port,
            q(&h.service),
            q(&h.login),
            q(&h.password),
            h.time_ms
        ));
    }
    out
}

/// Markdown table export of the result set.
fn export_markdown(hits: &[Hit]) -> String {
    // Escape `|` so a field value can't break the table columns.
    let esc = |s: &str| s.replace('|', "\\|");
    let mut out = format!("# lancer-hydra results ({} found)\n\n", hits.len());
    out.push_str("| host | port | service | login | password | ms |\n");
    out.push_str("|------|------|---------|-------|----------|----|\n");
    for h in hits {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            esc(&h.host),
            h.port,
            esc(&h.service),
            esc(&h.login),
            esc(&h.password),
            h.time_ms
        ));
    }
    out
}

/// Minimal valid SARIF 2.1.0 document (one result per hit).
fn export_sarif(hits: &[Hit]) -> String {
    let esc = |s: &str| serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string());
    let results = hits
        .iter()
        .map(|h| {
            let msg = format!(
                "valid credential {}:{} on {}:{}/{}",
                h.login, h.password, h.host, h.port, h.service
            );
            format!(
                "{{\"ruleId\":\"valid-credential\",\"level\":\"warning\",\"message\":{{\"text\":{}}}}}",
                esc(&msg)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"version\":\"2.1.0\",\
         \"$schema\":\"https://json.schemastore.org/sarif-2.1.0.json\",\
         \"runs\":[{{\"tool\":{{\"driver\":{{\"name\":\"lancer-hydra\",\
         \"rules\":[{{\"id\":\"valid-credential\"}}]}}}},\"results\":[{results}]}}]}}"
    )
}

fn route(path: &str, state: &Shared) -> (&'static str, &'static str, String) {
    let st = match state.lock() {
        Ok(g) => g,
        Err(_) => return ("500 Internal Server Error", "text/plain", "lock".into()),
    };
    if path.starts_with("/v1/state") {
        let body = serde_json::json!({
            "running": st.running,
            "found": st.hits.len(),
            "status": st.status,
        })
        .to_string();
        ("200 OK", "application/json", body)
    } else if path.starts_with("/v1/export") {
        // `?format=json|csv|sarif|markdown` (json is the default/fallback).
        match query_param(path, "format").as_deref() {
            Some("csv") => ("200 OK", "text/csv", export_csv(&st.hits)),
            Some("markdown") | Some("md") => ("200 OK", "text/markdown", export_markdown(&st.hits)),
            Some("sarif") => ("200 OK", "application/sarif+json", export_sarif(&st.hits)),
            _ => {
                let body = serde_json::to_string(&st.hits).unwrap_or_else(|_| "[]".to_string());
                ("200 OK", "application/json", body)
            }
        }
    } else if path.starts_with("/v1/import") {
        ("200 OK", "application/json", "{\"ok\":true}".to_string())
    } else {
        ("404 Not Found", "text/plain", "lancer-hydra".to_string())
    }
}
