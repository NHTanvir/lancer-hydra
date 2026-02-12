//! PostgreSQL — startup + `cleartext` / `md5` / `SCRAM-SHA-256` authentication.

use rand::distributions::Alphanumeric;
use rand::Rng;

use crate::crypto;
use crate::prelude::*;

/// Read a typed backend message: `(type_byte, payload)`.
async fn read_message(c: &mut Conn) -> Result<(u8, Vec<u8>), ProtocolError> {
    let t = c.read_exact(1).await?[0];
    let len_buf = c.read_exact(4).await?;
    let len = u32::from_be_bytes(len_buf[..4].try_into().unwrap()) as usize;
    let payload = if len > 4 { c.read_exact(len - 4).await? } else { Vec::new() };
    Ok((t, payload))
}

fn client_nonce() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(20)
        .map(char::from)
        .collect()
}

#[derive(Default)]
pub struct PostgreSql;

#[async_trait]
impl Protocol for PostgreSql {
    fn name(&self) -> &'static str {
        "postgres"
    }
    fn default_port(&self) -> u16 {
        5432
    }
    fn usage(&self) -> &'static str {
        "postgres: -m DB=name to pick a database, -m PORT=5433 for custom port."
    }
    async fn try_credential(
        &self,
        target: &Target,
        user: &str,
        pass: &str,
        opts: &ModuleOpts,
    ) -> Result<AuthOutcome, ProtocolError> {
        let mut c = connect(target, opts).await?;
        let db = opts.get("DB").unwrap_or(user);

        // StartupMessage (protocol 3.0).
        let mut params = Vec::new();
        params.extend_from_slice(b"user\0");
        params.extend_from_slice(user.as_bytes());
        params.push(0);
        params.extend_from_slice(b"database\0");
        params.extend_from_slice(db.as_bytes());
        params.push(0);
        params.push(0); // terminating null
        let mut startup = Vec::new();
        startup.extend_from_slice(&((params.len() + 8) as u32).to_be_bytes());
        startup.extend_from_slice(&196_608u32.to_be_bytes());
        startup.extend_from_slice(&params);
        c.write_all(&startup).await?;

        loop {
            let (t, payload) = read_message(&mut c).await?;
            match t {
                b'E' => return Ok(AuthOutcome::Failure), // ErrorResponse (auth failed)
                b'R' => {
                    let sub = u32::from_be_bytes(payload[..4].try_into().unwrap());
                    match sub {
                        0 => return Ok(AuthOutcome::Success), // AuthenticationOk
                        3 => {
                            // cleartext
                            let mut msg = vec![b'p'];
                            let body_len = pass.len() + 1 + 4;
                            msg.extend_from_slice(&(body_len as u32).to_be_bytes());
                            msg.extend_from_slice(pass.as_bytes());
                            msg.push(0);
                            c.write_all(&msg).await?;
                        }
                        5 => {
                            // md5 with 4-byte salt
                            let salt = &payload[4..8];
                            let token = crypto::postgres_md5(user, pass, salt);
                            let mut msg = vec![b'p'];
                            let body_len = token.len() + 1 + 4;
                            msg.extend_from_slice(&(body_len as u32).to_be_bytes());
                            msg.extend_from_slice(token.as_bytes());
                            msg.push(0);
                            c.write_all(&msg).await?;
                        }
                        10 => {
                            // SASL SCRAM-SHA-256
                            match scram_exchange(&mut c, user, pass).await? {
                                true => return Ok(AuthOutcome::Success),
                                false => return Ok(AuthOutcome::Failure),
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

async fn scram_exchange(c: &mut Conn, _user: &str, pass: &str) -> Result<bool, ProtocolError> {
    let nonce = client_nonce();
    let client_first_bare = format!("n=,r={nonce}");
    let initial = format!("n,,{client_first_bare}");

    // SASLInitialResponse: mechanism\0 int32(len) bytes
    let mech = "SCRAM-SHA-256";
    let mut body = Vec::new();
    body.extend_from_slice(mech.as_bytes());
    body.push(0);
    body.extend_from_slice(&(initial.len() as u32).to_be_bytes());
    body.extend_from_slice(initial.as_bytes());
    let mut msg = vec![b'p'];
    msg.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
    msg.extend_from_slice(&body);
    c.write_all(&msg).await?;

    // Expect 'R' 11 SASLContinue.
    let (t, payload) = read_message(c).await?;
    if t != b'R' {
        return Ok(false);
    }
    let sub = u32::from_be_bytes(payload[..4].try_into().unwrap());
    if sub != 11 {
        return Ok(false);
    }
    let server_first = String::from_utf8_lossy(&payload[4..]).to_string();
    let mut r = String::new();
    let mut s = String::new();
    let mut i = 0u32;
    for kv in server_first.split(',') {
        if let Some(v) = kv.strip_prefix("r=") {
            r = v.to_string();
        } else if let Some(v) = kv.strip_prefix("s=") {
            s = v.to_string();
        } else if let Some(v) = kv.strip_prefix("i=") {
            i = v.parse().unwrap_or(4096);
        }
    }
    let salt = crypto::b64decode(&s).ok_or_else(|| perr("pg: bad SCRAM salt"))?;
    let client_final_bare = format!("c=biws,r={r}");
    let auth_message = format!("{client_first_bare},{server_first},{client_final_bare}");
    let (proof, _server_sig) = crypto::scram_sha256_proof(pass, &salt, i, &auth_message);
    let final_msg = format!("{client_final_bare},p={}", crypto::b64encode(&proof));

    let mut msg = vec![b'p'];
    msg.extend_from_slice(&((final_msg.len() + 4) as u32).to_be_bytes());
    msg.extend_from_slice(final_msg.as_bytes());
    c.write_all(&msg).await?;

    // Expect 'R' 12 SASLFinal, then 'R' 0 (ok) or 'E'.
    loop {
        let (t, payload) = read_message(c).await?;
        match t {
            b'E' => return Ok(false),
            b'R' => {
                let sub = u32::from_be_bytes(payload[..4].try_into().unwrap());
                if sub == 0 {
                    return Ok(true);
                }
                // sub == 12 SASLFinal -> keep reading for AuthenticationOk
            }
            _ => return Ok(false),
        }
    }
}

register_protocol!(PostgreSql, "postgres", "postgresql");
