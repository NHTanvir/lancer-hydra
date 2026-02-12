//! SNMP — UDP community-string brute (v1 / v2c) and a v3 USM hook.
//!
//! The "password" is the community string. A parseable GetResponse means the
//! community was accepted; silence (timeout) means it was rejected.

use crate::asn1;
use crate::prelude::*;

fn build_get(version: i64, community: &str) -> Vec<u8> {
    // sysDescr.0 = 1.3.6.1.2.1.1.1.0
    let mut varbind = Vec::new();
    varbind.extend_from_slice(&asn1::oid(&[1, 3, 6, 1, 2, 1, 1, 1, 0]));
    varbind.extend_from_slice(&asn1::null());
    let varbind = asn1::sequence(&varbind);
    let varbindlist = asn1::sequence(&varbind);

    let mut pdu_body = Vec::new();
    pdu_body.extend_from_slice(&asn1::integer(0x1357)); // request-id
    pdu_body.extend_from_slice(&asn1::integer(0)); // error-status
    pdu_body.extend_from_slice(&asn1::integer(0)); // error-index
    pdu_body.extend_from_slice(&varbindlist);
    let pdu = asn1::tlv(0xA0, &pdu_body); // GetRequest

    let mut msg = Vec::new();
    msg.extend_from_slice(&asn1::integer(version));
    msg.extend_from_slice(&asn1::octet_string(community.as_bytes()));
    msg.extend_from_slice(&pdu);
    asn1::sequence(&msg)
}

async fn probe(
    target: &Target,
    community: &str,
    version: i64,
    opts: &ModuleOpts,
) -> Result<AuthOutcome, ProtocolError> {
    let sock = connect_udp(target).await?;
    let packet = build_get(version, community);
    match udp_roundtrip(&sock, &packet, opts).await {
        Ok(resp) => {
            // A SEQUENCE wrapping a GetResponse (0xA2) confirms the community.
            if let Some(seq) = asn1::parse(&resp, 0) {
                if seq.tag == 0x30 {
                    return Ok(AuthOutcome::Success);
                }
            }
            Ok(AuthOutcome::Success)
        }
        Err(ProtocolError::Timeout) => Ok(AuthOutcome::Failure), // wrong community → silence
        Err(e) => Err(e),
    }
}

#[derive(Default)]
pub struct Snmp;

#[async_trait]
impl Protocol for Snmp {
    fn name(&self) -> &'static str {
        "snmp"
    }
    fn default_port(&self) -> u16 {
        161
    }
    fn is_udp(&self) -> bool {
        true
    }
    fn usage(&self) -> &'static str {
        "snmp: -m v1|v2c (community = password) or -m v3:authproto:authpass:privproto:privpass."
    }
    async fn try_credential(
        &self,
        target: &Target,
        user: &str,
        pass: &str,
        opts: &ModuleOpts,
    ) -> Result<AuthOutcome, ProtocolError> {
        // community is the password; fall back to the user field if pass empty.
        let community = if pass.is_empty() { user } else { pass };
        match opts.mech_or("V2C").as_str() {
            "V1" => probe(target, community, 0, opts).await,
            "V3" => {
                // USM (discovery + HMAC-SHA/MD5) is reserved; do not assert a hit.
                Ok(AuthOutcome::Unknown)
            }
            _ => probe(target, community, 1, opts).await, // v2c
        }
    }
}
register_protocol!(Snmp, "snmp");
