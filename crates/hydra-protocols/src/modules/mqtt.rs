//! MQTT — CONNECT with username/password, read CONNACK return code (v3.1.1).

use crate::prelude::*;

fn encode_remaining_length(mut len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (len & 0x7f) as u8;
        len >>= 7;
        if len > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if len == 0 {
            break;
        }
    }
    out
}

fn mqtt_string(s: &str) -> Vec<u8> {
    let mut v = (s.len() as u16).to_be_bytes().to_vec();
    v.extend_from_slice(s.as_bytes());
    v
}

#[derive(Default)]
pub struct Mqtt;

#[async_trait]
impl Protocol for Mqtt {
    fn name(&self) -> &'static str {
        "mqtt"
    }
    fn default_port(&self) -> u16 {
        1883
    }
    fn supports_ssl(&self) -> bool {
        true
    }
    fn usage(&self) -> &'static str {
        "mqtt: CONNECT with username/password. -m v3.1.1|v5, -m TLS=1 for MQTTS."
    }
    async fn try_credential(
        &self,
        target: &Target,
        user: &str,
        pass: &str,
        opts: &ModuleOpts,
    ) -> Result<AuthOutcome, ProtocolError> {
        let mut t = target.clone();
        if opts.get("TLS").map(|v| v == "1").unwrap_or(false) {
            t.ssl = true;
        }
        let mut c = connect(&t, opts).await?;

        // `-m v5` selects MQTT 5.0 (protocol level 5), else 3.1.1 (level 4).
        let v5 = opts.mech_or("").to_uppercase().contains("V5") || opts.get("V5").is_some();

        // Variable header.
        let mut var = Vec::new();
        var.extend_from_slice(&mqtt_string("MQTT"));
        var.push(if v5 { 0x05 } else { 0x04 }); // protocol level
        var.push(0xC2); // flags: username + password + clean session
        var.extend_from_slice(&60u16.to_be_bytes()); // keepalive
        if v5 {
            var.push(0x00); // CONNECT properties length = 0 (v5 only)
        }

        // Payload: client id (empty) + username + password.
        let mut payload = Vec::new();
        payload.extend_from_slice(&mqtt_string(""));
        payload.extend_from_slice(&mqtt_string(user));
        payload.extend_from_slice(&mqtt_string(pass));

        let mut packet = vec![0x10u8]; // CONNECT
        let remaining = var.len() + payload.len();
        packet.extend_from_slice(&encode_remaining_length(remaining));
        packet.extend_from_slice(&var);
        packet.extend_from_slice(&payload);
        c.write_all(&packet).await?;

        // CONNACK: 0x20, len, session-present, return-code.
        let resp = c.read_exact(4).await?;
        if resp[0] != 0x20 {
            return Ok(AuthOutcome::Unknown);
        }
        // v3.1.1 CONNACK return codes and v5 reason codes share byte position 3:
        // 0x00 = accepted; anything else (0x04/0x05 v3, 0x86/0x87 v5) = rejected.
        Ok(match resp[3] {
            0x00 => AuthOutcome::Success,
            _ => AuthOutcome::Failure,
        })
    }
}
register_protocol!(Mqtt, "mqtt");
