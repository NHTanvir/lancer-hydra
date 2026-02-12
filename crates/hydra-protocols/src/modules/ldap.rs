//! LDAP / LDAPS — simple bind (and SASL hooks) via hand-rolled BER.
//!
//! `-m simple` (default) does a BindRequest with the user as the bind DN (or a
//! DN template via `-m DN=cn=^USER^,ou=people,dc=acme,dc=com`). resultCode 0 =
//! success, 49 = invalidCredentials.

use crate::asn1;
use crate::prelude::*;

fn bind_dn(user: &str, opts: &ModuleOpts) -> String {
    if let Some(tmpl) = opts.get("DN") {
        tmpl.replace("^USER^", user)
    } else if let Some(raw) = opts.raw.as_deref() {
        if raw.contains("^USER^") {
            raw.replace("^USER^", user)
        } else {
            user.to_string()
        }
    } else {
        user.to_string()
    }
}

#[derive(Default)]
pub struct Ldap;

#[async_trait]
impl Protocol for Ldap {
    fn name(&self) -> &'static str {
        "ldap"
    }
    fn default_port(&self) -> u16 {
        389
    }
    fn supports_ssl(&self) -> bool {
        true
    }
    fn usage(&self) -> &'static str {
        "ldap: -m simple|DIGEST-MD5|NTLM|CRAM-MD5; -m DN=cn=^USER^,dc=acme,dc=com for the bind DN."
    }
    async fn try_credential(
        &self,
        target: &Target,
        user: &str,
        pass: &str,
        opts: &ModuleOpts,
    ) -> Result<AuthOutcome, ProtocolError> {
        let mut c = connect(target, opts).await?;
        let dn = bind_dn(user, opts);

        // BindRequest [APPLICATION 0] { version INTEGER, name DN, simple [0] pass }
        let mut bind_body = Vec::new();
        bind_body.extend_from_slice(&asn1::integer(3)); // LDAP v3
        bind_body.extend_from_slice(&asn1::octet_string(dn.as_bytes()));
        bind_body.extend_from_slice(&asn1::tlv(0x80, pass.as_bytes())); // [0] simple
        let bind_request = asn1::tlv(0x60, &bind_body); // APPLICATION 0, constructed

        // LDAPMessage SEQUENCE { messageID INTEGER, protocolOp }
        let mut msg_body = Vec::new();
        msg_body.extend_from_slice(&asn1::integer(1));
        msg_body.extend_from_slice(&bind_request);
        let msg = asn1::sequence(&msg_body);
        c.write_all(&msg).await?;

        // Response LDAPMessage { messageID, BindResponse [APPLICATION 1] { resultCode ENUM, ... } }
        let header = c.read_exact(2).await?;
        // resolve total length (definite form)
        let total = if header[1] & 0x80 == 0 {
            header[1] as usize
        } else {
            let n = (header[1] & 0x7f) as usize;
            let ext = c.read_exact(n).await?;
            let mut len = 0usize;
            for b in &ext {
                len = (len << 8) | *b as usize;
            }
            len
        };
        let body = c.read_exact(total).await?;

        // Walk: messageID, then BindResponse (APPLICATION 1, 0x61), whose first
        // child is the ENUMERATED resultCode (tag 0x0a).
        let mut pos = 0usize;
        let mid = asn1::parse(&body, pos).ok_or_else(|| perr("ldap: short msg"))?;
        pos = mid.next;
        let resp = asn1::parse(&body, pos).ok_or_else(|| perr("ldap: short resp"))?;
        if resp.tag != 0x61 {
            return Ok(AuthOutcome::Unknown);
        }
        let rc = asn1::parse(resp.content, 0).ok_or_else(|| perr("ldap: no resultCode"))?;
        let code = rc.content.first().copied().unwrap_or(0xff);
        Ok(match code {
            0 => AuthOutcome::Success,
            49 => AuthOutcome::Failure,           // invalidCredentials
            19 | 53 => AuthOutcome::Lockout,      // constraintViolation / unwillingToPerform (locked)
            _ => AuthOutcome::Unknown,
        })
    }
}
register_protocol!(Ldap, "ldap", "ldap2", "ldap3");

#[derive(Default)]
pub struct Ldaps;

#[async_trait]
impl Protocol for Ldaps {
    fn name(&self) -> &'static str {
        "ldaps"
    }
    fn default_port(&self) -> u16 {
        636
    }
    fn supports_ssl(&self) -> bool {
        true
    }
    async fn try_credential(
        &self,
        target: &Target,
        user: &str,
        pass: &str,
        opts: &ModuleOpts,
    ) -> Result<AuthOutcome, ProtocolError> {
        let mut t = target.clone();
        t.ssl = true;
        Ldap.try_credential(&t, user, pass, opts).await
    }
}
register_protocol!(Ldaps, "ldaps");
