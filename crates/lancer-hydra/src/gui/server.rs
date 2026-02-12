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
        let body = serde_json::to_string(&st.hits).unwrap_or_else(|_| "[]".to_string());
        ("200 OK", "application/json", body)
    } else if path.starts_with("/v1/import") {
        ("200 OK", "application/json", "{\"ok\":true}".to_string())
    } else {
        ("404 Not Found", "text/plain", "lancer-hydra".to_string())
    }
}
