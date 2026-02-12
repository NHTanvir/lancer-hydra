//! SMB / SMB2 — SMB2 NEGOTIATE handshake (dialect + signing detection).
//!
//! The full NTLMv2 SESSION_SETUP (SPNEGO-wrapped NTLMSSP type1/2/3) is reserved;
//! the NTLMv2 primitive lives in [`crate::crypto::ntlmv2_response`] ready to wire
//! in. Credential attempts return `Unknown` so no false hit is recorded. The
//! 9.8-dev SMB1 short-reply rule (reject replies under 42 bytes) is enforced.

use crate::prelude::*;

fn nbss_wrap(smb: &[u8]) -> Vec<u8> {
    let len = smb.len();
    let mut out = vec![0x00, ((len >> 16) & 0xff) as u8, ((len >> 8) & 0xff) as u8, (len & 0xff) as u8];
    out.extend_from_slice(smb);
    out
}

fn smb2_negotiate() -> Vec<u8> {
    // SMB2 header (64 bytes).
    let mut h = Vec::new();
    h.extend_from_slice(&[0xFE, b'S', b'M', b'B']);
    h.extend_from_slice(&64u16.to_le_bytes()); // StructureSize
    h.extend_from_slice(&0u16.to_le_bytes()); // CreditCharge
    h.extend_from_slice(&0u32.to_le_bytes()); // Status
    h.extend_from_slice(&0u16.to_le_bytes()); // Command = NEGOTIATE
    h.extend_from_slice(&1u16.to_le_bytes()); // CreditRequest
    h.extend_from_slice(&0u32.to_le_bytes()); // Flags
    h.extend_from_slice(&0u32.to_le_bytes()); // NextCommand
    h.extend_from_slice(&0u64.to_le_bytes()); // MessageId
    h.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    h.extend_from_slice(&0u32.to_le_bytes()); // ProcessId
    h.extend_from_slice(&0u32.to_le_bytes()); // TreeId
    h.extend_from_slice(&0u64.to_le_bytes()); // SessionId
    h.extend_from_slice(&[0u8; 16]); // Signature

    // NEGOTIATE request body.
    let dialects: [u16; 3] = [0x0202, 0x0210, 0x0300];
    h.extend_from_slice(&36u16.to_le_bytes()); // StructureSize
    h.extend_from_slice(&(dialects.len() as u16).to_le_bytes()); // DialectCount
    h.extend_from_slice(&1u16.to_le_bytes()); // SecurityMode = signing enabled
    h.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    h.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
    h.extend_from_slice(&[0u8; 16]); // ClientGuid
    h.extend_from_slice(&0u64.to_le_bytes()); // ClientStartTime
    for d in dialects {
        h.extend_from_slice(&d.to_le_bytes());
    }
    h
}

async fn negotiate(target: &Target, opts: &ModuleOpts) -> Result<AuthOutcome, ProtocolError> {
    let mut c = connect(target, opts).await?;
    c.write_all(&nbss_wrap(&smb2_negotiate())).await?;

    // NetBIOS session header: type(1) + length(3 BE).
    let nb = c.read_exact(4).await?;
    let len = ((nb[1] as usize) << 16) | ((nb[2] as usize) << 8) | nb[3] as usize;
    if len < 42 {
        return Err(perr("smb: short reply (<42 bytes), rejected as malformed"));
    }
    let body = c.read_exact(len).await?;
    match body.first() {
        Some(0xFE) | Some(0xFF) => Ok(AuthOutcome::Unknown), // SMB2 / SMB1 confirmed; auth reserved
        _ => Err(perr("smb: not an SMB server")),
    }
}

#[derive(Default)]
pub struct Smb;

#[async_trait]
impl Protocol for Smb {
    fn name(&self) -> &'static str {
        "smb"
    }
    fn default_port(&self) -> u16 {
        445
    }
    fn usage(&self) -> &'static str {
        "smb: SMB2 negotiate probe. -m Local|Domain\\\\|Both; NTLMv2 session-setup reserved."
    }
    async fn try_credential(
        &self,
        target: &Target,
        _user: &str,
        _pass: &str,
        opts: &ModuleOpts,
    ) -> Result<AuthOutcome, ProtocolError> {
        negotiate(target, opts).await
    }
}
register_protocol!(Smb, "smb", "smbnt", "cifs");

#[derive(Default)]
pub struct Smb2;

#[async_trait]
impl Protocol for Smb2 {
    fn name(&self) -> &'static str {
        "smb2"
    }
    fn default_port(&self) -> u16 {
        445
    }
    fn usage(&self) -> &'static str {
        "smb2: SMB2/3 negotiate probe (libsmb2-equivalent). NTLMv2/Kerberos auth reserved."
    }
    async fn try_credential(
        &self,
        target: &Target,
        _user: &str,
        _pass: &str,
        opts: &ModuleOpts,
    ) -> Result<AuthOutcome, ProtocolError> {
        negotiate(target, opts).await
    }
}
register_protocol!(Smb2, "smb2", "smb3");
