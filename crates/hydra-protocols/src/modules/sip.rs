//! SIP (port 5060/UDP) — REGISTER with MD5 digest authentication.

use crate::crypto;
use crate::prelude::*;

fn extract_param(header: &str, key: &str) -> Option<String> {
    let pat = format!("{key}=");
    let start = header.find(&pat)? + pat.len();
    let rest = &header[start..];
    if let Some(stripped) = rest.strip_prefix('"') {
        stripped.find('"').map(|e| stripped[..e].to_string())
    } else {
        let end = rest.find([',', '\r', '\n']).unwrap_or(rest.len());
        Some(rest[..end].to_string())
    }
}

fn status_code(resp: &str) -> Option<u16> {
    resp.lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

#[derive(Default)]
pub struct Sip;

#[async_trait]
impl Protocol for Sip {
    fn name(&self) -> &'static str {
        "sip"
    }
    fn default_port(&self) -> u16 {
        5060
    }
    fn is_udp(&self) -> bool {
        true
    }
    fn usage(&self) -> &'static str {
        "sip: REGISTER with MD5 digest auth (the user field is the SIP user/extension)."
    }
    async fn try_credential(
        &self,
        target: &Target,
        user: &str,
        pass: &str,
        opts: &ModuleOpts,
    ) -> Result<AuthOutcome, ProtocolError> {
        let sock = connect_udp(target).await?;
        let domain = opts.get("REALM").unwrap_or(&target.host).to_string();
        let uri = format!("sip:{domain}");
        let from = format!("sip:{user}@{domain}");

        let base = |cseq: u32, auth: Option<&str>| -> String {
            let mut m = format!("REGISTER {uri} SIP/2.0\r\n");
            m.push_str("Via: SIP/2.0/UDP 0.0.0.0:5060;branch=z9hG4bK-lancer\r\n");
            m.push_str("Max-Forwards: 70\r\n");
            m.push_str(&format!("From: <{from}>;tag=lancer\r\n"));
            m.push_str(&format!("To: <{from}>\r\n"));
            m.push_str("Call-ID: lancer-hydra-callid\r\n");
            m.push_str(&format!("CSeq: {cseq} REGISTER\r\n"));
            m.push_str(&format!("Contact: <sip:{user}@0.0.0.0>\r\n"));
            if let Some(a) = auth {
                m.push_str(&format!("Authorization: {a}\r\n"));
            }
            m.push_str("Content-Length: 0\r\n\r\n");
            m
        };

        // First REGISTER → expect 401 with a challenge.
        let resp = udp_roundtrip(&sock, base(1, None).as_bytes(), opts).await?;
        let resp = String::from_utf8_lossy(&resp).to_string();
        let code = status_code(&resp).unwrap_or(0);
        if code == 200 {
            return Ok(AuthOutcome::Success); // no auth required
        }
        if code != 401 && code != 407 {
            return Ok(AuthOutcome::Unknown);
        }
        let wa = resp
            .lines()
            .find(|l| l.to_lowercase().starts_with("www-authenticate"))
            .or_else(|| resp.lines().find(|l| l.to_lowercase().starts_with("proxy-authenticate")))
            .ok_or_else(|| perr("sip: no auth challenge"))?;
        let realm = extract_param(wa, "realm").unwrap_or_else(|| domain.clone());
        let nonce = extract_param(wa, "nonce").ok_or_else(|| perr("sip: no nonce"))?;

        // Digest response = MD5( HA1 : nonce : HA2 ).
        let ha1 = hex::encode(crypto::md5(format!("{user}:{realm}:{pass}").as_bytes()));
        let ha2 = hex::encode(crypto::md5(format!("REGISTER:{uri}").as_bytes()));
        let response = hex::encode(crypto::md5(format!("{ha1}:{nonce}:{ha2}").as_bytes()));
        let auth = format!(
            "Digest username=\"{user}\", realm=\"{realm}\", nonce=\"{nonce}\", uri=\"{uri}\", response=\"{response}\""
        );

        let resp2 = udp_roundtrip(&sock, base(2, Some(&auth)).as_bytes(), opts).await?;
        let resp2 = String::from_utf8_lossy(&resp2).to_string();
        Ok(match status_code(&resp2) {
            Some(200) => AuthOutcome::Success,
            Some(401) | Some(403) | Some(407) => AuthOutcome::Failure,
            _ => AuthOutcome::Unknown,
        })
    }
}
register_protocol!(Sip, "sip");
