//! Microsoft SQL Server — TDS PRELOGIN + LOGIN7 with SQL Server authentication.
//!
//! Windows/NTLM integrated auth is reserved; this does the SQL-login path which
//! covers the common `sa` / app-account brute case.

use crate::crypto;
use crate::prelude::*;

const PKT_PRELOGIN: u8 = 0x12;
const PKT_LOGIN7: u8 = 0x10;
const STATUS_EOM: u8 = 0x01;

fn tds_header(pkt_type: u8, body: &[u8]) -> Vec<u8> {
    let len = (body.len() + 8) as u16;
    let mut h = vec![pkt_type, STATUS_EOM];
    h.extend_from_slice(&len.to_be_bytes()); // length (incl header), big-endian
    h.extend_from_slice(&[0, 0]); // SPID
    h.push(1); // PacketID
    h.push(0); // Window
    h.extend_from_slice(body);
    h
}

fn prelogin_body() -> Vec<u8> {
    // Two options: VERSION (token 0x00) and ENCRYPTION (token 0x01), then 0xFF.
    let token_list_len = 2 * 5 + 1;
    let version = [0x09u8, 0x00, 0x00, 0x00, 0x00, 0x00];
    let encryption = [0x02u8]; // ENCRYPT_NOT_SUP
    let mut body = Vec::new();
    // VERSION
    body.push(0x00);
    body.extend_from_slice(&(token_list_len as u16).to_be_bytes());
    body.extend_from_slice(&(version.len() as u16).to_be_bytes());
    // ENCRYPTION
    body.push(0x01);
    body.extend_from_slice(&((token_list_len + version.len()) as u16).to_be_bytes());
    body.extend_from_slice(&(encryption.len() as u16).to_be_bytes());
    // TERMINATOR
    body.push(0xFF);
    body.extend_from_slice(&version);
    body.extend_from_slice(&encryption);
    body
}

/// TDS password obfuscation: swap nibbles, XOR 0xA5, over the UTF-16LE bytes.
fn enc_password(pass: &str) -> Vec<u8> {
    crypto::utf16le(pass)
        .iter()
        .map(|b| ((b >> 4) | (b << 4)) ^ 0xA5)
        .collect()
}

fn login7_body(user: &str, pass: &str, server: &str, database: &str) -> Vec<u8> {
    let hostname = crypto::utf16le("lancer");
    let username = crypto::utf16le(user);
    let password = enc_password(pass);
    let appname = crypto::utf16le("lancer-hydra");
    let servername = crypto::utf16le(server);
    let cltintname = crypto::utf16le("lancer-hydra");
    let language = crypto::utf16le("");
    let db = crypto::utf16le(database);

    const FIXED: usize = 36;
    const OFFSET_TABLE: usize = 58;
    let data_start = FIXED + OFFSET_TABLE;

    // Lay out the data section and remember (offset, char-count) for each field.
    let mut data = Vec::new();
    let push = |buf: &mut Vec<u8>, bytes: &[u8]| -> (u16, u16) {
        let off = (data_start + buf.len()) as u16;
        buf.extend_from_slice(bytes);
        (off, (bytes.len() / 2) as u16)
    };
    let (ho, hl) = push(&mut data, &hostname);
    let (uo, ul) = push(&mut data, &username);
    let (po, pl) = push(&mut data, &password);
    let (ao, al) = push(&mut data, &appname);
    let (so, sl) = push(&mut data, &servername);
    let (co, cl) = push(&mut data, &cltintname);
    let (lo, ll) = push(&mut data, &language);
    let (dbo, dbl) = push(&mut data, &db);

    let mut body = Vec::with_capacity(data_start + data.len());
    let total = (data_start + data.len()) as u32;
    body.extend_from_slice(&total.to_le_bytes()); // Length
    body.extend_from_slice(&0x7400_0004u32.to_le_bytes()); // TDS 7.4
    body.extend_from_slice(&4096u32.to_le_bytes()); // PacketSize
    body.extend_from_slice(&7u32.to_le_bytes()); // ClientProgVer
    body.extend_from_slice(&0u32.to_le_bytes()); // ClientPID
    body.extend_from_slice(&0u32.to_le_bytes()); // ConnectionID
    body.push(0xE0); // OptionFlags1 (use defaults: set lang/db fatal off)
    body.push(0x03); // OptionFlags2 (ODBC on)
    body.push(0x00); // TypeFlags
    body.push(0x00); // OptionFlags3
    body.extend_from_slice(&0u32.to_le_bytes()); // ClientTimeZone
    body.extend_from_slice(&0u32.to_le_bytes()); // ClientLCID

    let mut tbl = Vec::new();
    for (off, len) in [
        (ho, hl),
        (uo, ul),
        (po, pl),
        (ao, al),
        (so, sl),
    ] {
        tbl.extend_from_slice(&off.to_le_bytes());
        tbl.extend_from_slice(&len.to_le_bytes());
    }
    // Unused/Extension
    tbl.extend_from_slice(&0u16.to_le_bytes());
    tbl.extend_from_slice(&0u16.to_le_bytes());
    for (off, len) in [(co, cl), (lo, ll), (dbo, dbl)] {
        tbl.extend_from_slice(&off.to_le_bytes());
        tbl.extend_from_slice(&len.to_le_bytes());
    }
    tbl.extend_from_slice(&[0u8; 6]); // ClientID (MAC)
    tbl.extend_from_slice(&0u32.to_le_bytes()); // SSPI offset/len
    tbl.extend_from_slice(&0u32.to_le_bytes()); // AtchDBFile offset/len
    tbl.extend_from_slice(&0u32.to_le_bytes()); // ChangePassword offset/len
    tbl.extend_from_slice(&0u32.to_le_bytes()); // cbSSPILong
    debug_assert_eq!(tbl.len(), OFFSET_TABLE);
    body.extend_from_slice(&tbl);
    body.extend_from_slice(&data);
    body
}

/// Walk TDS response tokens: 0xAD LOGINACK = success, 0xAA ERROR = failure.
fn parse_response(body: &[u8]) -> AuthOutcome {
    let mut i = 0;
    let mut saw_error = false;
    while i < body.len() {
        let token = body[i];
        i += 1;
        match token {
            0xAD => return AuthOutcome::Success, // LOGINACK
            0xAA => saw_error = true,            // ERROR
            _ => {}
        }
        // Variable-length tokens carry a u16 little-endian length.
        match token {
            0xAA | 0xAB | 0xAD | 0xE3 | 0xE5 | 0xA9 => {
                if i + 2 > body.len() {
                    break;
                }
                let len = u16::from_le_bytes([body[i], body[i + 1]]) as usize;
                i += 2 + len;
            }
            0xFD | 0xFE | 0xFF => i += 12, // DONE / DONEPROC / DONEINPROC (TDS 7.2)
            _ => break,
        }
    }
    if saw_error {
        AuthOutcome::Failure
    } else {
        AuthOutcome::Unknown
    }
}

#[derive(Default)]
pub struct MsSql;

#[async_trait]
impl Protocol for MsSql {
    fn name(&self) -> &'static str {
        "mssql"
    }
    fn default_port(&self) -> u16 {
        1433
    }
    fn usage(&self) -> &'static str {
        "mssql: SQL Server authentication (LOGIN7). -m DB=name to select a database."
    }
    async fn try_credential(
        &self,
        target: &Target,
        user: &str,
        pass: &str,
        opts: &ModuleOpts,
    ) -> Result<AuthOutcome, ProtocolError> {
        let mut c = connect(target, opts).await?;
        // PRELOGIN.
        c.write_all(&tds_header(PKT_PRELOGIN, &prelogin_body())).await?;
        let hdr = c.read_exact(8).await?;
        let len = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;
        if len > 8 {
            let _ = c.read_exact(len - 8).await?;
        }
        // LOGIN7.
        let db = opts.get("DB").unwrap_or("");
        let body = login7_body(user, pass, &target.host, db);
        c.write_all(&tds_header(PKT_LOGIN7, &body)).await?;
        let hdr = c.read_exact(8).await?;
        let len = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;
        let payload = if len > 8 { c.read_exact(len - 8).await? } else { Vec::new() };
        Ok(parse_response(&payload))
    }
}
register_protocol!(MsSql, "mssql");
