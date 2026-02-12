//! MySQL / MariaDB — protocol-41 handshake with `mysql_native_password` and
//! `caching_sha2_password` (MySQL 8 default) fast-auth.

use crate::crypto;
use crate::prelude::*;

const CLIENT_LONG_PASSWORD: u32 = 0x0000_0001;
const CLIENT_PROTOCOL_41: u32 = 0x0000_0200;
const CLIENT_SECURE_CONNECTION: u32 = 0x0000_8000;
const CLIENT_PLUGIN_AUTH: u32 = 0x0008_0000;

async fn read_packet(c: &mut Conn) -> Result<(u8, Vec<u8>), ProtocolError> {
    let hdr = c.read_exact(4).await?;
    let len = (hdr[0] as usize) | ((hdr[1] as usize) << 8) | ((hdr[2] as usize) << 16);
    let seq = hdr[3];
    let payload = c.read_exact(len).await?;
    Ok((seq, payload))
}

async fn write_packet(c: &mut Conn, seq: u8, payload: &[u8]) -> Result<(), ProtocolError> {
    let len = payload.len();
    let mut buf = vec![
        (len & 0xff) as u8,
        ((len >> 8) & 0xff) as u8,
        ((len >> 16) & 0xff) as u8,
        seq,
    ];
    buf.extend_from_slice(payload);
    c.write_all(&buf).await
}

fn cstr_end(buf: &[u8], from: usize) -> usize {
    buf[from..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| from + p)
        .unwrap_or(buf.len())
}

#[derive(Default)]
pub struct MySql;

#[async_trait]
impl Protocol for MySql {
    fn name(&self) -> &'static str {
        "mysql"
    }
    fn default_port(&self) -> u16 {
        3306
    }
    fn usage(&self) -> &'static str {
        "mysql: native + caching_sha2_password auto-detect. -m USE=db to verify a DB."
    }
    async fn try_credential(
        &self,
        target: &Target,
        user: &str,
        pass: &str,
        opts: &ModuleOpts,
    ) -> Result<AuthOutcome, ProtocolError> {
        let mut c = connect(target, opts).await?;
        let (_, handshake) = read_packet(&mut c).await?;
        if handshake.first() == Some(&0xff) {
            return Ok(AuthOutcome::Lockout); // ERR before handshake (host blocked)
        }
        if handshake.first() != Some(&10) {
            return Err(perr("mysql: unsupported protocol version"));
        }

        // Parse scramble + auth plugin name.
        let mut i = 1;
        i = cstr_end(&handshake, i) + 1; // server version
        i += 4; // thread id
        let scramble1 = handshake.get(i..i + 8).unwrap_or(&[]).to_vec();
        i += 8 + 1; // scramble1 + filler
        i += 2 + 1 + 2; // cap-lower + charset + status
        i += 2; // cap-upper
        let auth_len = *handshake.get(i).unwrap_or(&0) as usize;
        i += 1 + 10; // auth len + reserved
        let part2_len = auth_len.saturating_sub(8).max(13);
        let mut scramble = scramble1;
        if let Some(s2) = handshake.get(i..i + part2_len.min(handshake.len().saturating_sub(i))) {
            // trailing NUL not part of scramble
            scramble.extend_from_slice(&s2[..s2.len().min(12)]);
        }
        i += part2_len;
        let plugin = if i < handshake.len() {
            let end = cstr_end(&handshake, i);
            String::from_utf8_lossy(&handshake[i..end]).to_string()
        } else {
            "mysql_native_password".to_string()
        };

        let scramble: Vec<u8> = scramble.into_iter().take(20).collect();
        let (auth_resp, plugin_name) = if plugin.contains("caching_sha2") {
            (crypto::caching_sha2_password(pass, &scramble), "caching_sha2_password")
        } else {
            (crypto::mysql_native_password(pass, &scramble), "mysql_native_password")
        };

        // Handshake response.
        let caps = CLIENT_LONG_PASSWORD
            | CLIENT_PROTOCOL_41
            | CLIENT_SECURE_CONNECTION
            | CLIENT_PLUGIN_AUTH;
        let mut resp = Vec::new();
        resp.extend_from_slice(&caps.to_le_bytes());
        resp.extend_from_slice(&(16_777_216u32).to_le_bytes()); // max packet
        resp.push(33); // utf8_general_ci
        resp.extend_from_slice(&[0u8; 23]); // reserved
        resp.extend_from_slice(user.as_bytes());
        resp.push(0);
        resp.push(auth_resp.len() as u8);
        resp.extend_from_slice(&auth_resp);
        resp.extend_from_slice(plugin_name.as_bytes());
        resp.push(0);
        write_packet(&mut c, 1, &resp).await?;

        // Result / auth-more / auth-switch.
        loop {
            let (seq, payload) = read_packet(&mut c).await?;
            match payload.first().copied() {
                Some(0x00) => return Ok(AuthOutcome::Success), // OK
                Some(0xff) => return Ok(AuthOutcome::Failure),  // ERR (1045 access denied)
                Some(0xfe) => {
                    // AuthSwitchRequest: plugin\0 + data
                    let end = cstr_end(&payload, 1);
                    let new_plugin = String::from_utf8_lossy(&payload[1..end]).to_string();
                    let new_scramble: Vec<u8> =
                        payload.get(end + 1..).unwrap_or(&[]).iter().take(20).copied().collect();
                    let data = if new_plugin.contains("caching_sha2") {
                        crypto::caching_sha2_password(pass, &new_scramble)
                    } else {
                        crypto::mysql_native_password(pass, &new_scramble)
                    };
                    write_packet(&mut c, seq + 1, &data).await?;
                }
                Some(0x01) => {
                    // caching_sha2 AuthMoreData: 0x03 = fast success, 0x04 = full auth
                    match payload.get(1) {
                        Some(0x03) => continue, // expect OK next
                        Some(0x04) => {
                            // full auth requires TLS/RSA channel; only over TLS can we send plaintext
                            if target.ssl || opts.ssl {
                                let mut pw = pass.as_bytes().to_vec();
                                pw.push(0);
                                write_packet(&mut c, seq + 1, &pw).await?;
                            } else {
                                return Ok(AuthOutcome::Unknown);
                            }
                        }
                        _ => return Ok(AuthOutcome::Unknown),
                    }
                }
                _ => return Ok(AuthOutcome::Unknown),
            }
        }
    }
}
register_protocol!(MySql, "mysql");
