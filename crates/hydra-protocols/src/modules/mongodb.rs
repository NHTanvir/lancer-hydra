//! MongoDB — `OP_MSG` + hand-rolled BSON + SCRAM-SHA-256 (`saslStart` /
//! `saslContinue`). Covers the modern wire protocol (v1 and v2 framing).

use rand::distributions::Alphanumeric;
use rand::Rng;

use crate::crypto;
use crate::prelude::*;

// --- tiny BSON encoder ----------------------------------------------------

struct Bson {
    body: Vec<u8>,
}
impl Bson {
    fn new() -> Self {
        Self { body: Vec::new() }
    }
    fn i32(&mut self, name: &str, v: i32) -> &mut Self {
        self.body.push(0x10);
        self.cname(name);
        self.body.extend_from_slice(&v.to_le_bytes());
        self
    }
    fn str(&mut self, name: &str, v: &str) -> &mut Self {
        self.body.push(0x02);
        self.cname(name);
        self.body.extend_from_slice(&((v.len() + 1) as i32).to_le_bytes());
        self.body.extend_from_slice(v.as_bytes());
        self.body.push(0);
        self
    }
    fn bin(&mut self, name: &str, v: &[u8]) -> &mut Self {
        self.body.push(0x05);
        self.cname(name);
        self.body.extend_from_slice(&(v.len() as i32).to_le_bytes());
        self.body.push(0x00); // generic subtype
        self.body.extend_from_slice(v);
        self
    }
    fn cname(&mut self, name: &str) {
        self.body.extend_from_slice(name.as_bytes());
        self.body.push(0);
    }
    fn finish(self) -> Vec<u8> {
        let mut doc = Vec::new();
        let total = (self.body.len() + 5) as i32;
        doc.extend_from_slice(&total.to_le_bytes());
        doc.extend_from_slice(&self.body);
        doc.push(0);
        doc
    }
}

// --- minimal BSON field extraction ---------------------------------------

#[derive(Default)]
struct Parsed {
    ok: bool,
    done: bool,
    conversation_id: i32,
    payload: Vec<u8>,
}

fn parse_doc(doc: &[u8]) -> Parsed {
    let mut out = Parsed::default();
    if doc.len() < 5 {
        return out;
    }
    let mut i = 4; // skip total length
    while i < doc.len() {
        let ty = doc[i];
        if ty == 0 {
            break;
        }
        i += 1;
        let name_start = i;
        while i < doc.len() && doc[i] != 0 {
            i += 1;
        }
        let name = String::from_utf8_lossy(&doc[name_start..i]).to_string();
        i += 1; // skip name null
        match ty {
            0x01 => {
                // double
                let v = f64::from_le_bytes(doc[i..i + 8].try_into().unwrap_or([0; 8]));
                if name == "ok" {
                    out.ok = v != 0.0;
                }
                i += 8;
            }
            0x10 => {
                let v = i32::from_le_bytes(doc[i..i + 4].try_into().unwrap_or([0; 4]));
                if name == "ok" {
                    out.ok = v != 0;
                } else if name == "conversationId" {
                    out.conversation_id = v;
                }
                i += 4;
            }
            0x12 => {
                let v = i64::from_le_bytes(doc[i..i + 8].try_into().unwrap_or([0; 8]));
                if name == "ok" {
                    out.ok = v != 0;
                }
                i += 8;
            }
            0x08 => {
                let v = doc.get(i).copied().unwrap_or(0) != 0;
                if name == "done" {
                    out.done = v;
                }
                i += 1;
            }
            0x02 => {
                let len = i32::from_le_bytes(doc[i..i + 4].try_into().unwrap_or([0; 4])) as usize;
                i += 4 + len;
            }
            0x05 => {
                let len = i32::from_le_bytes(doc[i..i + 4].try_into().unwrap_or([0; 4])) as usize;
                let _subtype = doc[i + 4];
                if name == "payload" {
                    out.payload = doc[i + 5..i + 5 + len].to_vec();
                }
                i += 5 + len;
            }
            _ => break, // unknown type: stop
        }
    }
    out
}

// --- OP_MSG framing -------------------------------------------------------

fn op_msg(request_id: i32, doc: &[u8]) -> Vec<u8> {
    let mut section = vec![0u8]; // kind 0 (body)
    section.extend_from_slice(doc);
    let mut body = Vec::new();
    body.extend_from_slice(&0u32.to_le_bytes()); // flagBits
    body.extend_from_slice(&section);

    let total = (16 + body.len()) as i32;
    let mut msg = Vec::new();
    msg.extend_from_slice(&total.to_le_bytes());
    msg.extend_from_slice(&request_id.to_le_bytes());
    msg.extend_from_slice(&0i32.to_le_bytes()); // responseTo
    msg.extend_from_slice(&2013i32.to_le_bytes()); // OP_MSG
    msg.extend_from_slice(&body);
    msg
}

async fn read_op_msg(c: &mut Conn) -> Result<Vec<u8>, ProtocolError> {
    let hdr = c.read_exact(16).await?;
    let total = i32::from_le_bytes(hdr[0..4].try_into().unwrap()) as usize;
    let rest = c.read_exact(total - 16).await?;
    // rest = flagBits(4) + kind(1) + document
    if rest.len() < 5 {
        return Err(perr("mongodb: short OP_MSG"));
    }
    Ok(rest[5..].to_vec())
}

fn escape_user(u: &str) -> String {
    u.replace('=', "=3D").replace(',', "=2C")
}

#[derive(Default)]
pub struct MongoDb;

#[async_trait]
impl Protocol for MongoDb {
    fn name(&self) -> &'static str {
        "mongodb"
    }
    fn default_port(&self) -> u16 {
        27017
    }
    fn usage(&self) -> &'static str {
        "mongodb: SCRAM-SHA-256. -m authdb=admin for the auth database, -m v2 framing."
    }
    async fn try_credential(
        &self,
        target: &Target,
        user: &str,
        pass: &str,
        opts: &ModuleOpts,
    ) -> Result<AuthOutcome, ProtocolError> {
        let mut c = connect(target, opts).await?;
        let authdb = opts.get("AUTHDB").or(opts.get("DB")).unwrap_or("admin");

        // client-first
        let nonce: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(20)
            .map(char::from)
            .collect();
        let client_first_bare = format!("n={},r={}", escape_user(user), nonce);
        let initial = format!("n,,{client_first_bare}");

        let mut start = Bson::new();
        start
            .i32("saslStart", 1)
            .str("mechanism", "SCRAM-SHA-256")
            .bin("payload", initial.as_bytes())
            .i32("autoAuthorize", 1)
            .str("$db", authdb);
        c.write_all(&op_msg(1, &start.finish())).await?;

        let resp = parse_doc(&read_op_msg(&mut c).await?);
        if !resp.ok {
            return Ok(AuthOutcome::Failure);
        }
        let server_first = String::from_utf8_lossy(&resp.payload).to_string();
        let mut r = String::new();
        let mut s = String::new();
        let mut iters = 4096u32;
        for kv in server_first.split(',') {
            if let Some(v) = kv.strip_prefix("r=") {
                r = v.to_string();
            } else if let Some(v) = kv.strip_prefix("s=") {
                s = v.to_string();
            } else if let Some(v) = kv.strip_prefix("i=") {
                iters = v.parse().unwrap_or(4096);
            }
        }
        let salt = crypto::b64decode(&s).ok_or_else(|| perr("mongodb: bad salt"))?;
        let client_final_bare = format!("c=biws,r={r}");
        let auth_message = format!("{client_first_bare},{server_first},{client_final_bare}");
        let (proof, _) = crypto::scram_sha256_proof(pass, &salt, iters, &auth_message);
        let client_final = format!("{client_final_bare},p={}", crypto::b64encode(&proof));

        let mut cont = Bson::new();
        cont.i32("saslContinue", 1)
            .i32("conversationId", resp.conversation_id)
            .bin("payload", client_final.as_bytes())
            .str("$db", authdb);
        c.write_all(&op_msg(2, &cont.finish())).await?;

        let resp2 = parse_doc(&read_op_msg(&mut c).await?);
        Ok(if resp2.ok {
            AuthOutcome::Success
        } else {
            AuthOutcome::Failure
        })
    }
}
register_protocol!(MongoDb, "mongodb", "mongo");
