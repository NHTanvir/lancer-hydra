//! Shared crypto primitives used by the binary/auth modules (NTLM for SMB /
//! MSSQL / LDAP, DES challenge for VNC, HMAC for SNMPv3, SCRAM for Postgres /
//! MongoDB). All pure-Rust (RustCrypto), no system dependencies.

use des::cipher::generic_array::GenericArray;
use des::cipher::{BlockEncrypt, KeyInit};
use des::Des;
use hmac::{Hmac, Mac};
use md4::Md4;
use md5::Md5;
use sha1::Sha1;
// `Digest` is the same trait re-exported by every RustCrypto hash crate.
use sha2::{Digest, Sha256};

/// Copy a digest/hmac `GenericArray` output into a fixed-size array.
fn to_arr<const N: usize>(slice: &[u8]) -> [u8; N] {
    let mut a = [0u8; N];
    a.copy_from_slice(slice);
    a
}

use base64::Engine as _;
/// Standard base64 engine.
pub const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

/// Base64-encode (standard alphabet, padded).
pub fn b64encode(data: &[u8]) -> String {
    B64.encode(data)
}

/// Base64-decode (standard alphabet); returns `None` on malformed input.
pub fn b64decode(s: &str) -> Option<Vec<u8>> {
    B64.decode(s.trim()).ok()
}

// ---- digests -------------------------------------------------------------

pub fn md5(data: &[u8]) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(data);
    to_arr(&h.finalize())
}

pub fn md4(data: &[u8]) -> [u8; 16] {
    let mut h = Md4::new();
    h.update(data);
    to_arr(&h.finalize())
}

pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(data);
    to_arr(&h.finalize())
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    to_arr(&h.finalize())
}

// ---- HMAC ----------------------------------------------------------------

pub fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut m = <Hmac<Md5> as Mac>::new_from_slice(key).expect("hmac key");
    m.update(data);
    to_arr(&m.finalize().into_bytes())
}

pub fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    let mut m = <Hmac<Sha1> as Mac>::new_from_slice(key).expect("hmac key");
    m.update(data);
    to_arr(&m.finalize().into_bytes())
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac key");
    m.update(data);
    to_arr(&m.finalize().into_bytes())
}

// ---- UTF-16LE helper (NTLM passwords) ------------------------------------

pub fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

// ---- DES (VNC RFB legacy auth) -------------------------------------------

/// VNC reverses the bit order of each key byte before scheduling.
fn vnc_mangle_key(key: &[u8]) -> [u8; 8] {
    let mut k = [0u8; 8];
    for (i, b) in key.iter().take(8).enumerate() {
        k[i] = b.reverse_bits();
    }
    k
}

/// Encrypt a 16-byte VNC challenge with the (bit-reversed) password key.
pub fn vnc_des_response(password: &str, challenge: &[u8]) -> Vec<u8> {
    let mut key = [0u8; 8];
    for (i, b) in password.bytes().take(8).enumerate() {
        key[i] = b;
    }
    let mangled = vnc_mangle_key(&key);
    let cipher = Des::new(GenericArray::from_slice(&mangled));
    let mut out = Vec::with_capacity(16);
    for chunk in challenge.chunks(8) {
        let mut block = [0u8; 8];
        block[..chunk.len()].copy_from_slice(chunk);
        let mut ga = GenericArray::clone_from_slice(&block);
        cipher.encrypt_block(&mut ga);
        out.extend_from_slice(&ga);
    }
    out
}

// ---- NTLM (NTLMv2) -------------------------------------------------------

/// NT hash: MD4 of the UTF-16LE password.
pub fn nt_hash(password: &str) -> [u8; 16] {
    md4(&utf16le(password))
}

/// NTLMv2 response over a server challenge + blob.
///
/// `target_info` is the AV_PAIR blob echoed from the type-2 message.
pub fn ntlmv2_response(
    user: &str,
    domain: &str,
    password: &str,
    server_challenge: &[u8; 8],
    client_challenge: &[u8; 8],
    timestamp: u64,
    target_info: &[u8],
) -> Vec<u8> {
    let nt = nt_hash(password);
    let id = format!("{}{}", user.to_uppercase(), domain);
    let ntlmv2_hash = hmac_md5(&nt, &utf16le(&id));

    // The NTLMv2 "temp" blob.
    let mut blob = Vec::new();
    blob.extend_from_slice(&[0x01, 0x01, 0x00, 0x00]); // resp type / hi-resp type / reserved
    blob.extend_from_slice(&[0u8; 4]);
    blob.extend_from_slice(&timestamp.to_le_bytes());
    blob.extend_from_slice(client_challenge);
    blob.extend_from_slice(&[0u8; 4]);
    blob.extend_from_slice(target_info);
    blob.extend_from_slice(&[0u8; 4]);

    let mut to_mac = Vec::with_capacity(8 + blob.len());
    to_mac.extend_from_slice(server_challenge);
    to_mac.extend_from_slice(&blob);
    let proof = hmac_md5(&ntlmv2_hash, &to_mac);

    let mut resp = Vec::with_capacity(16 + blob.len());
    resp.extend_from_slice(&proof);
    resp.extend_from_slice(&blob);
    resp
}

// ---- SCRAM (Postgres scram-sha-256, MongoDB) -----------------------------

fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    // PBKDF2 with one 32-byte output block (dkLen == hLen), HMAC-SHA-256 PRF.
    let mut u = {
        let mut salted = salt.to_vec();
        salted.extend_from_slice(&1u32.to_be_bytes());
        hmac_sha256(password, &salted)
    };
    let mut out = u;
    for _ in 1..iterations {
        u = hmac_sha256(password, &u);
        for (o, b) in out.iter_mut().zip(u.iter()) {
            *o ^= *b;
        }
    }
    out
}

/// Compute a SCRAM-SHA-256 client proof.
///
/// Returns `(client_proof, server_signature)`. The caller base64-encodes the
/// proof into the `c=...,r=...,p=...` final message.
pub fn scram_sha256_proof(
    password: &str,
    salt: &[u8],
    iterations: u32,
    auth_message: &str,
) -> ([u8; 32], [u8; 32]) {
    let salted = pbkdf2_hmac_sha256(password.as_bytes(), salt, iterations);
    let client_key = hmac_sha256(&salted, b"Client Key");
    let stored_key = sha256(&client_key);
    let client_sig = hmac_sha256(&stored_key, auth_message.as_bytes());
    let mut proof = client_key;
    for (p, s) in proof.iter_mut().zip(client_sig.iter()) {
        *p ^= *s;
    }
    let server_key = hmac_sha256(&salted, b"Server Key");
    let server_sig = hmac_sha256(&server_key, auth_message.as_bytes());
    (proof, server_sig)
}

/// MySQL `mysql_native_password`: SHA1(pass) XOR SHA1(scramble + SHA1(SHA1(pass))).
pub fn mysql_native_password(password: &str, scramble: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }
    let h1 = sha1(password.as_bytes());
    let h2 = sha1(&h1);
    let mut concat = scramble.to_vec();
    concat.extend_from_slice(&h2);
    let h3 = sha1(&concat);
    h1.iter().zip(h3.iter()).map(|(a, b)| a ^ b).collect()
}

/// MySQL 8 `caching_sha2_password` fast-auth scramble:
/// `XOR( SHA256(pass), SHA256( SHA256(SHA256(pass)) || nonce ) )`.
pub fn caching_sha2_password(password: &str, nonce: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }
    let h1 = sha256(password.as_bytes());
    let h2 = sha256(&h1);
    let mut concat = h2.to_vec();
    concat.extend_from_slice(nonce);
    let h3 = sha256(&concat);
    h1.iter().zip(h3.iter()).map(|(a, b)| a ^ b).collect()
}

/// PostgreSQL legacy `md5` auth: "md5" + md5(md5(pass+user)+salt) as hex.
pub fn postgres_md5(user: &str, password: &str, salt: &[u8]) -> String {
    let inner = hex::encode(md5(format!("{password}{user}").as_bytes()));
    let mut data = inner.into_bytes();
    data.extend_from_slice(salt);
    format!("md5{}", hex::encode(md5(&data)))
}
