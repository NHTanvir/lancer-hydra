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
    let addr = resolve(target).await?;
    let connect_to = tokio::time::timeout(
        if opts.wait_response.is_zero() { Duration::from_secs(32) } else { opts.wait_response },
        TcpStream::connect(addr),
    )
    .await
    .map_err(|_| ProtocolError::Timeout)?
    .map_err(|e| ProtocolError::Connect(e.to_string()))?;
    connect_to.set_nodelay(true).ok();

    if target.ssl || opts.ssl {
        let tls = tls_upgrade(connect_to, &target.host, opts).await?;
        Ok(Conn::new(Box::new(tls), opts))
    } else {
        Ok(Conn::new(Box::new(connect_to), opts))
    }
}

/// Open a plain TCP connection without any TLS upgrade (for STARTTLS modules
/// that negotiate TLS mid-stream themselves).
pub async fn connect_plain(target: &Target, opts: &ModuleOpts) -> Result<Conn, ProtocolError> {
    let addr = resolve(target).await?;
    let stream = TcpStream::connect(addr)
        .await
        .map_err(|e| ProtocolError::Connect(e.to_string()))?;
    stream.set_nodelay(true).ok();
    Ok(Conn::new(Box::new(stream), opts))
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
