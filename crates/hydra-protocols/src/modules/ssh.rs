//! SSH-2 password authentication — the flagship module.
//!
//! Hand-rolled pure-Rust transport (no C toolchain, unlike linking libssh):
//! version exchange → `curve25519-sha256` ECDH KEX → `aes256-ctr` + `hmac-sha2-256`
//! → `ssh-userauth` → `password` request. Host-key signature is intentionally not
//! verified (a brute-forcer connects to untrusted hosts by definition).

use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::crypto::{hmac_sha256, sha256};
use crate::prelude::*;

type AesCtr = Ctr128BE<Aes256>;

const MSG_DISCONNECT: u8 = 1;
const MSG_SERVICE_REQUEST: u8 = 5;
const MSG_SERVICE_ACCEPT: u8 = 6;
const MSG_KEXINIT: u8 = 20;
const MSG_NEWKEYS: u8 = 21;
const MSG_KEX_ECDH_INIT: u8 = 30;
const MSG_KEX_ECDH_REPLY: u8 = 31;
const MSG_USERAUTH_REQUEST: u8 = 50;
const MSG_USERAUTH_FAILURE: u8 = 51;
const MSG_USERAUTH_SUCCESS: u8 = 52;
const MSG_USERAUTH_BANNER: u8 = 53;

// --- SSH wire encoding helpers -------------------------------------------

fn put_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}
fn put_string(buf: &mut Vec<u8>, s: &[u8]) {
    put_u32(buf, s.len() as u32);
    buf.extend_from_slice(s);
}
fn put_mpint(buf: &mut Vec<u8>, v: &[u8]) {
    // Strip leading zero bytes, then prepend one if the high bit is set.
    let mut start = 0;
    while start < v.len() && v[start] == 0 {
        start += 1;
    }
    let v = &v[start..];
    if v.is_empty() {
        put_u32(buf, 0);
        return;
    }
    if v[0] & 0x80 != 0 {
        put_u32(buf, v.len() as u32 + 1);
        buf.push(0);
        buf.extend_from_slice(v);
    } else {
        put_u32(buf, v.len() as u32);
        buf.extend_from_slice(v);
    }
}

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}
impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, pos: 0 }
    }
    fn u8(&mut self) -> Result<u8, ProtocolError> {
        let v = *self.b.get(self.pos).ok_or_else(|| perr("ssh: short packet"))?;
        self.pos += 1;
        Ok(v)
    }
    fn string(&mut self) -> Result<Vec<u8>, ProtocolError> {
        if self.pos + 4 > self.b.len() {
            return Err(perr("ssh: short string len"));
        }
        let len = u32::from_be_bytes(self.b[self.pos..self.pos + 4].try_into().unwrap()) as usize;
        self.pos += 4;
        let end = self.pos + len;
        if end > self.b.len() {
            return Err(perr("ssh: short string body"));
        }
        let v = self.b[self.pos..end].to_vec();
        self.pos = end;
        Ok(v)
    }
}

/// SSH binary-packet transport state machine.
struct Transport {
    conn: Conn,
    send_seq: u32,
    recv_seq: u32,
    enc_c2s: Option<AesCtr>,
    enc_s2c: Option<AesCtr>,
    mac_c2s: Vec<u8>,
    mac_s2c: Vec<u8>,
}

impl Transport {
    async fn send_packet(&mut self, payload: &[u8]) -> Result<(), ProtocolError> {
        let block = if self.enc_c2s.is_some() { 16usize } else { 8usize };
        // padding so that (4 + 1 + payload + pad) % block == 0, pad >= 4
        let unpadded = 4 + 1 + payload.len();
        let mut pad = block - (unpadded % block);
        if pad < 4 {
            pad += block;
        }
        let packet_len = (1 + payload.len() + pad) as u32;
        let mut pkt = Vec::with_capacity(4 + packet_len as usize);
        put_u32(&mut pkt, packet_len);
        pkt.push(pad as u8);
        pkt.extend_from_slice(payload);
        pkt.extend(std::iter::repeat(0u8).take(pad));

        let mut out = pkt.clone();
        let mac = if let Some(cipher) = self.enc_c2s.as_mut() {
            let mut maced = self.send_seq.to_be_bytes().to_vec();
            maced.extend_from_slice(&pkt);
            let mac = hmac_sha256(&self.mac_c2s, &maced).to_vec();
            cipher.apply_keystream(&mut out);
            Some(mac)
        } else {
            None
        };
        self.conn.write_all(&out).await?;
        if let Some(mac) = mac {
            self.conn.write_all(&mac).await?;
        }
        self.send_seq = self.send_seq.wrapping_add(1);
        Ok(())
    }

    async fn recv_packet(&mut self) -> Result<Vec<u8>, ProtocolError> {
        let mut len_buf = self.conn.read_exact(4).await?;
        if let Some(cipher) = self.enc_s2c.as_mut() {
            cipher.apply_keystream(&mut len_buf);
        }
        let packet_len = u32::from_be_bytes(len_buf[..4].try_into().unwrap()) as usize;
        if packet_len == 0 || packet_len > 1_048_576 {
            return Err(perr("ssh: absurd packet length"));
        }
        let mut body = self.conn.read_exact(packet_len).await?;
        if let Some(cipher) = self.enc_s2c.as_mut() {
            cipher.apply_keystream(&mut body);
            // consume + ignore the MAC trailer
            let _ = self.conn.read_exact(32).await?;
        }
        self.recv_seq = self.recv_seq.wrapping_add(1);
        let pad = body[0] as usize;
        if 1 + pad > body.len() {
            return Err(perr("ssh: bad padding"));
        }
        Ok(body[1..body.len() - pad].to_vec())
    }
}

/// Algorithm-negotiation payload we advertise. We force a single algo per slot
/// to keep the exchange-hash inputs deterministic.
fn build_kexinit() -> Vec<u8> {
    let mut p = vec![MSG_KEXINIT];
    p.extend_from_slice(&[0u8; 16]); // cookie (zeroed; fine for our purposes)
    let lists = [
        "curve25519-sha256",          // kex
        "ssh-ed25519,rsa-sha2-256,ssh-rsa", // host key (we accept anything)
        "aes256-ctr",                 // enc c2s
        "aes256-ctr",                 // enc s2c
        "hmac-sha2-256",              // mac c2s
        "hmac-sha2-256",              // mac s2c
        "none",                       // comp c2s
        "none",                       // comp s2c
        "",                           // lang c2s
        "",                           // lang s2c
    ];
    for l in lists {
        put_string(&mut p, l.as_bytes());
    }
    p.push(0); // first_kex_packet_follows
    put_u32(&mut p, 0); // reserved
    p
}

async fn authenticate(
    target: &Target,
    user: &str,
    pass: &str,
    opts: &ModuleOpts,
) -> Result<AuthOutcome, ProtocolError> {
    let conn = connect_plain(target, opts).await?;
    let mut t = Transport {
        conn,
        send_seq: 0,
        recv_seq: 0,
        enc_c2s: None,
        enc_s2c: None,
        mac_c2s: Vec::new(),
        mac_s2c: Vec::new(),
    };

    // 1. Version exchange.
    let client_id = "SSH-2.0-lancer_hydra_1.0";
    t.conn.write_all(format!("{client_id}\r\n").as_bytes()).await?;
    // pre-banner lines are allowed before the identification string
    let server_id = loop {
        let line = t.conn.read_line().await?;
        if line.starts_with("SSH-") {
            break line;
        }
    };

    // 2. KEXINIT exchange.
    let client_kexinit = build_kexinit();
    t.send_packet(&client_kexinit).await?;
    let server_kexinit = loop {
        let p = t.recv_packet().await?;
        match p.first().copied() {
            Some(MSG_KEXINIT) => break p,
            Some(MSG_DISCONNECT) => return Err(perr("ssh: server disconnected during KEX")),
            _ => continue,
        }
    };

    // 3. ECDH init.
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let q_c = PublicKey::from(&secret);
    let mut ecdh_init = vec![MSG_KEX_ECDH_INIT];
    put_string(&mut ecdh_init, q_c.as_bytes());
    t.send_packet(&ecdh_init).await?;

    let reply = loop {
        let p = t.recv_packet().await?;
        match p.first().copied() {
            Some(MSG_KEX_ECDH_REPLY) => break p,
            Some(MSG_DISCONNECT) => return Err(perr("ssh: disconnect during ECDH")),
            _ => continue,
        }
    };
    let mut r = Reader::new(&reply[1..]);
    let k_s = r.string()?; // server host key blob
    let q_s = r.string()?; // server ephemeral public
    let _sig = r.string()?; // host-key signature (not verified)
    if q_s.len() != 32 {
        return Err(perr("ssh: bad server ECDH public length"));
    }
    let mut q_s_arr = [0u8; 32];
    q_s_arr.copy_from_slice(&q_s);
    let shared = secret.diffie_hellman(&PublicKey::from(q_s_arr));
    let k = shared.as_bytes();

    // 4. Exchange hash H.
    let mut hbuf = Vec::new();
    put_string(&mut hbuf, client_id.as_bytes());
    put_string(&mut hbuf, server_id.as_bytes());
    put_string(&mut hbuf, &client_kexinit);
    put_string(&mut hbuf, &server_kexinit);
    put_string(&mut hbuf, &k_s);
    put_string(&mut hbuf, q_c.as_bytes());
    put_string(&mut hbuf, &q_s);
    put_mpint(&mut hbuf, k);
    let h = sha256(&hbuf);
    let session_id = h;

    // 5. Derive keys: HASH(K || H || letter || session_id).
    let derive = |letter: u8| -> Vec<u8> {
        let mut buf = Vec::new();
        put_mpint(&mut buf, k);
        buf.extend_from_slice(&h);
        buf.push(letter);
        buf.extend_from_slice(&session_id);
        sha256(&buf).to_vec()
    };
    let iv_c2s = derive(b'A');
    let iv_s2c = derive(b'B');
    let key_c2s = derive(b'C');
    let key_s2c = derive(b'D');
    let mac_c2s = derive(b'E');
    let mac_s2c = derive(b'F');

    // 6. NEWKEYS (still cleartext).
    t.send_packet(&[MSG_NEWKEYS]).await?;
    loop {
        let p = t.recv_packet().await?;
        if p.first() == Some(&MSG_NEWKEYS) {
            break;
        }
    }

    // 7. Activate ciphers.
    t.enc_c2s = Some(
        AesCtr::new_from_slices(&key_c2s[..32], &iv_c2s[..16])
            .map_err(|_| perr("ssh: cipher init"))?,
    );
    t.enc_s2c = Some(
        AesCtr::new_from_slices(&key_s2c[..32], &iv_s2c[..16])
            .map_err(|_| perr("ssh: cipher init"))?,
    );
    t.mac_c2s = mac_c2s;
    t.mac_s2c = mac_s2c;

    // 8. Request the userauth service.
    let mut sr = vec![MSG_SERVICE_REQUEST];
    put_string(&mut sr, b"ssh-userauth");
    t.send_packet(&sr).await?;
    loop {
        let p = t.recv_packet().await?;
        match p.first().copied() {
            Some(MSG_SERVICE_ACCEPT) => break,
            Some(MSG_USERAUTH_BANNER) => continue,
            Some(MSG_DISCONNECT) => return Err(perr("ssh: disconnect before auth")),
            _ => continue,
        }
    }

    // 9. password userauth request.
    let mut req = vec![MSG_USERAUTH_REQUEST];
    put_string(&mut req, user.as_bytes());
    put_string(&mut req, b"ssh-connection");
    put_string(&mut req, b"password");
    req.push(0); // FALSE
    put_string(&mut req, pass.as_bytes());
    t.send_packet(&req).await?;

    loop {
        let p = t.recv_packet().await?;
        match p.first().copied() {
            Some(MSG_USERAUTH_SUCCESS) => return Ok(AuthOutcome::Success),
            Some(MSG_USERAUTH_FAILURE) => {
                // byte[51] name-list auth-can-continue, bool partial-success
                let mut rr = Reader::new(&p[1..]);
                let _methods = rr.string().unwrap_or_default();
                let partial = rr.u8().unwrap_or(0);
                return Ok(if partial != 0 {
                    AuthOutcome::Success // partial success means the password was accepted
                } else {
                    AuthOutcome::Failure
                });
            }
            Some(MSG_USERAUTH_BANNER) => continue,
            Some(MSG_DISCONNECT) => return Ok(AuthOutcome::Failure),
            _ => continue,
        }
    }
}

#[derive(Default)]
pub struct Ssh;

#[async_trait]
impl Protocol for Ssh {
    fn name(&self) -> &'static str {
        "ssh"
    }
    fn default_port(&self) -> u16 {
        22
    }
    fn usage(&self) -> &'static str {
        "ssh: SSHv2 password auth. -m KEX=/-m CIPHER=/-m HOSTKEY= reserved for algo overrides."
    }

    async fn try_credential(
        &self,
        target: &Target,
        user: &str,
        pass: &str,
        opts: &ModuleOpts,
    ) -> Result<AuthOutcome, ProtocolError> {
        authenticate(target, user, pass, opts).await
    }
}

register_protocol!(Ssh, "ssh", "ssh2");

/// SSHKEY — probe acceptance of a private key file instead of a password.
/// Full public-key auth (sign the session id) is reserved; we surface the
/// module so `-U sshkey` and the registry are parity-complete.
#[derive(Default)]
pub struct SshKey;

#[async_trait]
impl Protocol for SshKey {
    fn name(&self) -> &'static str {
        "sshkey"
    }
    fn default_port(&self) -> u16 {
        22
    }
    fn usage(&self) -> &'static str {
        "sshkey: test private-key acceptance. -m KEYFILE=path/to/id_rsa."
    }

    async fn try_credential(
        &self,
        _target: &Target,
        _user: &str,
        _pass: &str,
        opts: &ModuleOpts,
    ) -> Result<AuthOutcome, ProtocolError> {
        if opts.get("KEYFILE").is_none() {
            return Err(oerr("sshkey requires -m KEYFILE=path"));
        }
        // Public-key signing handshake is not yet wired; report Unknown so the
        // engine does not record a false hit.
        Ok(AuthOutcome::Unknown)
    }
}

register_protocol!(SshKey, "sshkey");

/// SFTP — authentication is identical to SSH password auth (SFTP rides the SSH
/// transport as a subsystem), so we reuse the SSH userauth path.
#[derive(Default)]
pub struct Sftp;

#[async_trait]
impl Protocol for Sftp {
    fn name(&self) -> &'static str {
        "sftp"
    }
    fn default_port(&self) -> u16 {
        22
    }
    fn usage(&self) -> &'static str {
        "sftp: SSH password auth (SFTP subsystem rides the same SSHv2 transport)."
    }
    async fn try_credential(
        &self,
        target: &Target,
        user: &str,
        pass: &str,
        opts: &ModuleOpts,
    ) -> Result<AuthOutcome, ProtocolError> {
        authenticate(target, user, pass, opts).await
    }
}
register_protocol!(Sftp, "sftp");
