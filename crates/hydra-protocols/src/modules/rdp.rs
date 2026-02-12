//! RDP — X.224 / RDP negotiation handshake.
//!
//! We perform the real TPKT + COTP Connection Request and read the negotiation
//! response (which reveals whether the server demands NLA/CredSSP). Completing
//! CredSSP (SPNEGO + NTLMSSP/Kerberos nested in TLS) to verify a password is
//! reserved, so credential attempts return `Unknown` rather than a false hit.

use crate::prelude::*;

const PROTOCOL_SSL: u32 = 0x0000_0001;
const PROTOCOL_HYBRID: u32 = 0x0000_0002; // CredSSP / NLA

#[derive(Default)]
pub struct Rdp;

#[async_trait]
impl Protocol for Rdp {
    fn name(&self) -> &'static str {
        "rdp"
    }
    fn default_port(&self) -> u16 {
        3389
    }
    fn usage(&self) -> &'static str {
        "rdp: X.224/NLA negotiation. -m DOMAIN\\\\ sets the Windows domain. CredSSP verify reserved."
    }
    async fn try_credential(
        &self,
        target: &Target,
        user: &str,
        _pass: &str,
        opts: &ModuleOpts,
    ) -> Result<AuthOutcome, ProtocolError> {
        let mut c = connect(target, opts).await?;

        // RDP Negotiation Request (request TLS + CredSSP).
        let cookie = format!("Cookie: mstshash={user}\r\n");
        let mut neg = vec![0x01u8, 0x00]; // type=RDP_NEG_REQ, flags
        neg.extend_from_slice(&0x0008u16.to_le_bytes()); // length
        neg.extend_from_slice(&(PROTOCOL_SSL | PROTOCOL_HYBRID).to_le_bytes());

        let mut cotp = vec![0u8]; // LI placeholder
        cotp.push(0xE0); // CR
        cotp.extend_from_slice(&[0, 0]); // dst-ref
        cotp.extend_from_slice(&[0, 0]); // src-ref
        cotp.push(0x00); // class
        cotp.extend_from_slice(cookie.as_bytes());
        cotp.extend_from_slice(&neg);
        let li = (cotp.len() - 1) as u8;
        cotp[0] = li;

        let mut tpkt = vec![0x03u8, 0x00];
        let total = (4 + cotp.len()) as u16;
        tpkt.extend_from_slice(&total.to_be_bytes());
        tpkt.extend_from_slice(&cotp);
        c.write_all(&tpkt).await?;

        // Response TPKT header + body.
        let hdr = c.read_exact(4).await?;
        if hdr[0] != 0x03 {
            return Err(perr("rdp: not a TPKT response"));
        }
        let len = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;
        let body = c.read_exact(len.saturating_sub(4)).await?;

        // Scan for the RDP Negotiation Response (0x02) or Failure (0x03).
        if body.iter().any(|&b| b == 0x03) && body.len() >= 7 {
            // A negotiation failure or NLA-required signal: service confirmed.
            return Ok(AuthOutcome::Unknown);
        }
        // Handshake succeeded up to negotiation; password verification needs CredSSP.
        Ok(AuthOutcome::Unknown)
    }
}
register_protocol!(Rdp, "rdp");
