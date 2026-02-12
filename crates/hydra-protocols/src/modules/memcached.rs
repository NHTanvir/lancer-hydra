//! Memcached — binary-protocol SASL PLAIN auth (opcode 0x21).
//!
//! The text protocol has no auth; SASL rides the binary protocol. We send a
//! SASL Auth request with mechanism `PLAIN` and `\0user\0pass` and read the
//! response status word (0x0000 = ok, 0x0020 = auth error / further auth).

use crate::prelude::*;

const MAGIC_REQ: u8 = 0x80;
const OP_SASL_AUTH: u8 = 0x21;

fn bin_request(opcode: u8, key: &[u8], value: &[u8]) -> Vec<u8> {
    let mut h = vec![MAGIC_REQ, opcode];
    h.extend_from_slice(&(key.len() as u16).to_be_bytes()); // key length
    h.push(0); // extras length
    h.push(0); // data type
    h.extend_from_slice(&0u16.to_be_bytes()); // vbucket / status
    let total = (key.len() + value.len()) as u32;
    h.extend_from_slice(&total.to_be_bytes()); // total body
    h.extend_from_slice(&0u32.to_be_bytes()); // opaque
    h.extend_from_slice(&0u64.to_be_bytes()); // cas
    h.extend_from_slice(key);
    h.extend_from_slice(value);
    h
}

#[derive(Default)]
pub struct Memcached;

#[async_trait]
impl Protocol for Memcached {
    fn name(&self) -> &'static str {
        "memcached"
    }
    fn default_port(&self) -> u16 {
        11211
    }
    fn usage(&self) -> &'static str {
        "memcached: binary SASL PLAIN auth."
    }
    async fn try_credential(
        &self,
        target: &Target,
        user: &str,
        pass: &str,
        opts: &ModuleOpts,
    ) -> Result<AuthOutcome, ProtocolError> {
        let mut c = connect(target, opts).await?;
        let value = format!("\0{user}\0{pass}");
        let req = bin_request(OP_SASL_AUTH, b"PLAIN", value.as_bytes());
        c.write_all(&req).await?;
        let resp = c.read_exact(24).await?; // response header
        let status = u16::from_be_bytes([resp[6], resp[7]]);
        Ok(match status {
            0x0000 => AuthOutcome::Success,
            0x0020 | 0x0021 => AuthOutcome::Failure, // auth error / auth continue
            _ => AuthOutcome::Unknown,
        })
    }
}
register_protocol!(Memcached, "memcached");
