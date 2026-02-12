//! Transport helpers shared by every protocol module.
//!
//! Modules never touch `TcpStream` directly — they go through [`connect`] /
//! [`connect_udp`] and the [`Conn`] wrapper, which gives uniform timeouts, TLS
//! upgrade, line IO and binary read/write. This is what keeps the 50+ modules
//! short and consistent.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{lookup_host, TcpStream, UdpSocket};
use tokio_native_tls::TlsStream;

use crate::traits::{IpPref, ModuleOpts, ProtocolError, Target};

/// Anything we can read+write asynchronously and own. Both plain TCP and TLS
/// streams satisfy this, so [`Conn`] can hold either behind one type.
pub trait ReadWrite: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> ReadWrite for T {}

/// A buffered, timeout-aware connection used by every TCP module.
pub struct Conn {
    inner: BufReader<Box<dyn ReadWrite>>,
    /// Default per-operation timeout (from `-w`).
    pub timeout: Duration,
    /// Echo protocol traffic to the tracing log when `-d` is set.
    pub debug: bool,
}

impl Conn {
    fn new(stream: Box<dyn ReadWrite>, opts: &ModuleOpts) -> Self {
        Self {
            inner: BufReader::new(stream),
            timeout: if opts.wait_response.is_zero() {
                Duration::from_secs(32)
            } else {
                opts.wait_response
            },
            debug: opts.debug,
        }
    }

    /// Read one `\n`-terminated line (trailing CR/LF stripped). Errors on EOF.
    pub async fn read_line(&mut self) -> Result<String, ProtocolError> {
        let mut line = String::new();
        let n = tokio::time::timeout(self.timeout, self.inner.read_line(&mut line))
            .await
            .map_err(|_| ProtocolError::Timeout)??;
        if n == 0 {
            return Err(ProtocolError::Protocol("connection closed by peer".into()));
        }
        while line.ends_with('\n') || line.ends_with('\r') {
            line.pop();
        }
        if self.debug {
            tracing::debug!(target: "wire", direction = "<", "{line}");
        }
        Ok(line)
    }

    /// Read lines until one matches `pred` (returns the matching line). Used for
    /// multi-line greetings (e.g. SMTP `250-...` continuations ending `250 `).
    pub async fn read_until<F: Fn(&str) -> bool>(&mut self, pred: F) -> Result<String, ProtocolError> {
        loop {
            let line = self.read_line().await?;
            if pred(&line) {
                return Ok(line);
            }
        }
    }

    /// Write raw bytes and flush.
    pub async fn write_all(&mut self, data: &[u8]) -> Result<(), ProtocolError> {
        tokio::time::timeout(self.timeout, async {
            self.inner.write_all(data).await?;
            self.inner.flush().await
        })
        .await
        .map_err(|_| ProtocolError::Timeout)??;
        if self.debug {
            tracing::debug!(target: "wire", direction = ">", "{} bytes", data.len());
        }
        Ok(())
    }

    /// Write a line, appending CRLF (the wire convention for most text protocols).
    pub async fn write_line(&mut self, line: &str) -> Result<(), ProtocolError> {
        if self.debug {
            tracing::debug!(target: "wire", direction = ">", "{line}");
        }
        let mut buf = line.as_bytes().to_vec();
        buf.extend_from_slice(b"\r\n");
        self.write_all(&buf).await
    }

    /// Read exactly `n` bytes (binary protocols).
    pub async fn read_exact(&mut self, n: usize) -> Result<Vec<u8>, ProtocolError> {
        let mut buf = vec![0u8; n];
        tokio::time::timeout(self.timeout, self.inner.read_exact(&mut buf))
            .await
            .map_err(|_| ProtocolError::Timeout)??;
        Ok(buf)
    }

    /// Read up to `cap` bytes, returning whatever arrives in one read.
    pub async fn read_some(&mut self, cap: usize) -> Result<Vec<u8>, ProtocolError> {
        let mut buf = vec![0u8; cap];
        let n = tokio::time::timeout(self.timeout, self.inner.read(&mut buf))
            .await
            .map_err(|_| ProtocolError::Timeout)??;
        buf.truncate(n);
        Ok(buf)
    }
}

/// Resolve a target honoring `-4` / `-6`.
pub async fn resolve(target: &Target) -> Result<SocketAddr, ProtocolError> {
    let mut addrs: Vec<SocketAddr> = lookup_host(target.authority())
        .await
        .map_err(|e| ProtocolError::Connect(format!("dns: {e}")))?
        .collect();
    match target.ip_pref {
        IpPref::V4 => addrs.retain(|a| a.is_ipv4()),
        IpPref::V6 => addrs.retain(|a| a.is_ipv6()),
        IpPref::Any => {}
    }
    addrs
        .into_iter()
        .next()
        .ok_or_else(|| ProtocolError::Connect(format!("no address for {}", target.host)))
}

/// Open a TCP connection, upgrading to TLS when `target.ssl` / `opts.ssl` is set.
pub async fn connect(target: &Target, opts: &ModuleOpts) -> Result<Conn, ProtocolError> {
    let stream = dial(target, opts).await?;
    if target.ssl || opts.ssl {
        let tls = tls_upgrade(stream, &target.host, opts).await?;
        Ok(Conn::new(Box::new(tls), opts))
    } else {
        Ok(Conn::new(Box::new(stream), opts))
    }
}

/// Open a plain TCP connection without any TLS upgrade (for STARTTLS modules
/// that negotiate TLS mid-stream themselves).
pub async fn connect_plain(target: &Target, opts: &ModuleOpts) -> Result<Conn, ProtocolError> {
    let stream = dial(target, opts).await?;
    Ok(Conn::new(Box::new(stream), opts))
}

/// Establish the raw TCP stream to `target`, tunneling through a configured
/// proxy when one applies. Honors `-w` as the connect/handshake timeout. This is
/// the single dial chokepoint every TCP module reaches (directly or via the HTTP
/// helper), so wiring the proxy here covers the whole protocol fleet.
pub async fn dial(target: &Target, opts: &ModuleOpts) -> Result<TcpStream, ProtocolError> {
    let to = if opts.wait_response.is_zero() {
        Duration::from_secs(32)
    } else {
        opts.wait_response
    };
    let stream = tokio::time::timeout(to, dial_inner(target, opts))
        .await
        .map_err(|_| ProtocolError::Timeout)??;
    stream.set_nodelay(true).ok();
    Ok(stream)
}

async fn dial_inner(target: &Target, opts: &ModuleOpts) -> Result<TcpStream, ProtocolError> {
    match Proxy::select(target, opts) {
        Some(proxy) => proxy.connect(&target.host, target.port).await,
        None => {
            let addr = resolve(target).await?;
            TcpStream::connect(addr)
                .await
                .map_err(|e| ProtocolError::Connect(e.to_string()))
        }
    }
}

/// Which proxy protocol the dialer speaks to the proxy server.
enum ProxyKind {
    /// RFC 1928 SOCKS5 (with RFC 1929 username/password auth).
    Socks5,
    /// HTTP CONNECT tunnel (with RFC 7617 Basic proxy auth).
    HttpConnect,
}

/// A resolved upstream proxy the dialer tunnels target connections through.
struct Proxy {
    kind: ProxyKind,
    host: String,
    port: u16,
    auth: Option<(String, String)>,
}

impl Proxy {
    /// Pick the effective proxy for a target. HTTP(S) modules prefer the
    /// HTTP-specific proxy (`HYDRA_PROXY_HTTP`); everything else uses the general
    /// `HYDRA_PROXY`. `ModuleOpts` (set from `--proxy`/`--proxy-auth`) wins, with
    /// the environment variables as upstream-compatible fallbacks.
    fn select(target: &Target, opts: &ModuleOpts) -> Option<Proxy> {
        let is_http = target.proto.starts_with("http");
        let url = if is_http {
            opts.proxy_http
                .clone()
                .or_else(|| std::env::var("HYDRA_PROXY_HTTP").ok())
                .or_else(|| opts.proxy.clone())
                .or_else(|| std::env::var("HYDRA_PROXY").ok())
        } else {
            opts.proxy
                .clone()
                .or_else(|| std::env::var("HYDRA_PROXY").ok())
        };
        let url = url?;
        let url = url.trim();
        if url.is_empty() {
            return None;
        }
        let auth = opts
            .proxy_auth
            .clone()
            .or_else(|| std::env::var("HYDRA_PROXY_AUTH").ok());
        Proxy::parse(url, auth)
    }

    /// Parse `scheme://[user:pass@]host[:port]` (scheme + port optional).
    fn parse(url: &str, auth_override: Option<String>) -> Option<Proxy> {
        let (scheme, rest) = match url.split_once("://") {
            Some((s, r)) => (s.to_ascii_lowercase(), r.to_string()),
            None => ("socks5".to_string(), url.to_string()),
        };
        let (userinfo, hostport) = match rest.rsplit_once('@') {
            Some((u, hp)) => (Some(u.to_string()), hp.to_string()),
            None => (None, rest),
        };
        let (host, port) = parse_host_port(&hostport, default_proxy_port(&scheme))?;
        let split_creds = |s: &str| -> Option<(String, String)> {
            s.split_once(':').map(|(u, p)| (u.to_string(), p.to_string()))
        };
        let auth = auth_override
            .as_deref()
            .and_then(split_creds)
            .or_else(|| userinfo.as_deref().and_then(split_creds));
        let kind = match scheme.as_str() {
            "connect" | "http" | "https" | "http-connect" => ProxyKind::HttpConnect,
            _ => ProxyKind::Socks5,
        };
        Some(Proxy { kind, host, port, auth })
    }

    /// Connect to the proxy and tunnel through to `dst_host:dst_port`.
    async fn connect(&self, dst_host: &str, dst_port: u16) -> Result<TcpStream, ProtocolError> {
        let paddr = lookup_host((self.host.as_str(), self.port))
            .await
            .map_err(|e| ProtocolError::Connect(format!("proxy dns: {e}")))?
            .next()
            .ok_or_else(|| ProtocolError::Connect(format!("no address for proxy {}", self.host)))?;
        let mut stream = TcpStream::connect(paddr)
            .await
            .map_err(|e| ProtocolError::Connect(format!("proxy connect: {e}")))?;
        stream.set_nodelay(true).ok();
        match self.kind {
            ProxyKind::Socks5 => socks5_handshake(&mut stream, &self.auth, dst_host, dst_port).await?,
            ProxyKind::HttpConnect => {
                http_connect_handshake(&mut stream, &self.auth, dst_host, dst_port).await?
            }
        }
        Ok(stream)
    }
}

fn default_proxy_port(scheme: &str) -> u16 {
    match scheme {
        "connect" | "http" | "https" | "http-connect" => 8080,
        _ => 1080,
    }
}

/// Split `host[:port]` (incl. `[v6]:port`), defaulting the port when absent.
fn parse_host_port(s: &str, default_port: u16) -> Option<(String, u16)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (h, tail) = rest.split_once(']')?;
        let port = tail
            .strip_prefix(':')
            .and_then(|x| x.parse().ok())
            .unwrap_or(default_port);
        return Some((h.to_string(), port));
    }
    match s.rsplit_once(':') {
        Some((h, p)) => Some((h.to_string(), p.parse().ok()?)),
        None => Some((s.to_string(), default_port)),
    }
}

/// RFC 1928 SOCKS5 client greeting + (optional RFC 1929) auth + CONNECT request.
async fn socks5_handshake(
    s: &mut TcpStream,
    auth: &Option<(String, String)>,
    host: &str,
    port: u16,
) -> Result<(), ProtocolError> {
    // Greeting: offer no-auth, plus user/pass when we have credentials.
    let methods: &[u8] = if auth.is_some() { &[0x00, 0x02] } else { &[0x00] };
    let mut greet = vec![0x05u8, methods.len() as u8];
    greet.extend_from_slice(methods);
    s.write_all(&greet).await?;

    let mut reply = [0u8; 2];
    s.read_exact(&mut reply).await?;
    if reply[0] != 0x05 {
        return Err(ProtocolError::Protocol("socks5: bad version in method reply".into()));
    }
    match reply[1] {
        0x00 => {}
        0x02 => {
            let (u, p) = auth
                .as_ref()
                .ok_or_else(|| ProtocolError::Protocol("socks5: proxy demands auth but none given".into()))?;
            if u.len() > 255 || p.len() > 255 {
                return Err(ProtocolError::Protocol("socks5: credential too long".into()));
            }
            let mut frame = vec![0x01u8, u.len() as u8];
            frame.extend_from_slice(u.as_bytes());
            frame.push(p.len() as u8);
            frame.extend_from_slice(p.as_bytes());
            s.write_all(&frame).await?;
            let mut ar = [0u8; 2];
            s.read_exact(&mut ar).await?;
            // RFC 1929 §2: reply is [VER=0x01, STATUS]; STATUS 0x00 == success.
            if ar[0] != 0x01 {
                return Err(ProtocolError::Protocol("socks5: bad auth reply version".into()));
            }
            if ar[1] != 0x00 {
                return Err(ProtocolError::Protocol("socks5: proxy authentication failed".into()));
            }
        }
        0xFF => return Err(ProtocolError::Protocol("socks5: no acceptable auth method".into())),
        other => return Err(ProtocolError::Protocol(format!("socks5: unexpected method {other:#x}"))),
    }

    // CONNECT request with a DOMAINNAME address (let the proxy resolve DNS).
    if host.len() > 255 {
        return Err(ProtocolError::Protocol("socks5: hostname too long".into()));
    }
    let mut req = vec![0x05u8, 0x01, 0x00, 0x03, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await?;

    // Reply: VER REP RSV ATYP BND.ADDR BND.PORT — drain the bound address.
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    if head[1] != 0x00 {
        return Err(ProtocolError::Connect(format!(
            "socks5: connect rejected (reply {:#x})",
            head[1]
        )));
    }
    let bnd_len = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            l[0] as usize
        }
        other => return Err(ProtocolError::Protocol(format!("socks5: bad ATYP {other:#x}"))),
    };
    let mut drain = vec![0u8; bnd_len + 2];
    s.read_exact(&mut drain).await?;
    Ok(())
}

/// HTTP CONNECT tunnel establishment (with optional Basic proxy auth).
async fn http_connect_handshake(
    s: &mut TcpStream,
    auth: &Option<(String, String)>,
    host: &str,
    port: u16,
) -> Result<(), ProtocolError> {
    use base64::Engine;

    let mut req = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n");
    if let Some((u, p)) = auth {
        let token = base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}"));
        req.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    req.push_str("Proxy-Connection: keep-alive\r\n\r\n");
    s.write_all(req.as_bytes()).await?;

    // Read headers up to the terminating CRLFCRLF (small, byte-at-a-time is fine).
    let mut buf: Vec<u8> = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        let n = s.read(&mut byte).await?;
        if n == 0 {
            return Err(ProtocolError::Protocol("http-connect: proxy closed connection".into()));
        }
        buf.push(byte[0]);
        if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
            break;
        }
        if buf.len() > 8192 {
            return Err(ProtocolError::Protocol("http-connect: response header too large".into()));
        }
    }
    let head = String::from_utf8_lossy(&buf);
    let status_line = head.lines().next().unwrap_or("");
    let ok = status_line
        .split_whitespace()
        .nth(1)
        .map(|c| c == "200")
        .unwrap_or(false);
    if !ok {
        return Err(ProtocolError::Connect(format!(
            "http-connect: proxy refused: {status_line}"
        )));
    }
    Ok(())
}

/// Upgrade an already-connected `TcpStream` to TLS (used after STARTTLS too).
pub async fn tls_upgrade(
    stream: TcpStream,
    sni: &str,
    _opts: &ModuleOpts,
) -> Result<TlsStream<TcpStream>, ProtocolError> {
    let mut builder = native_tls::TlsConnector::builder();
    // Brute-forcing rarely targets PKI-valid certs; be permissive like upstream.
    builder
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true);
    let connector: tokio_native_tls::TlsConnector = builder
        .build()
        .map_err(|e| ProtocolError::Tls(e.to_string()))?
        .into();
    connector
        .connect(sni, stream)
        .await
        .map_err(|e| ProtocolError::Tls(e.to_string()))
}

/// Bind a UDP socket connected to the target (SNMP and friends).
pub async fn connect_udp(target: &Target) -> Result<UdpSocket, ProtocolError> {
    let addr = resolve(target).await?;
    let bind = if addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
    let sock = UdpSocket::bind(bind)
        .await
        .map_err(|e| ProtocolError::Connect(e.to_string()))?;
    sock.connect(addr)
        .await
        .map_err(|e| ProtocolError::Connect(e.to_string()))?;
    Ok(sock)
}

/// One UDP request/response round trip with `-w` timeout.
pub async fn udp_roundtrip(
    sock: &UdpSocket,
    payload: &[u8],
    opts: &ModuleOpts,
) -> Result<Vec<u8>, ProtocolError> {
    let to = if opts.wait_response.is_zero() {
        Duration::from_secs(5)
    } else {
        opts.wait_response
    };
    sock.send(payload).await?;
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(to, sock.recv(&mut buf))
        .await
        .map_err(|_| ProtocolError::Timeout)??;
    buf.truncate(n);
    Ok(buf)
}
