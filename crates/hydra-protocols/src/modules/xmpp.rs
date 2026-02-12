//! XMPP (port 5222) — SASL PLAIN over the XML stream.

use crate::crypto;
use crate::prelude::*;

#[derive(Default)]
pub struct Xmpp;

#[async_trait]
impl Protocol for Xmpp {
    fn name(&self) -> &'static str {
        "xmpp"
    }
    fn default_port(&self) -> u16 {
        5222
    }
    fn supports_ssl(&self) -> bool {
        true
    }
    fn usage(&self) -> &'static str {
        "xmpp: SASL PLAIN. -m DOMAIN= sets the stream 'to' domain."
    }
    async fn try_credential(
        &self,
        target: &Target,
        user: &str,
        pass: &str,
        opts: &ModuleOpts,
    ) -> Result<AuthOutcome, ProtocolError> {
        let mut c = connect(target, opts).await?;
        let domain = opts.get("DOMAIN").unwrap_or(&target.host);
        let open = format!(
            "<?xml version='1.0'?><stream:stream to='{domain}' xmlns='jabber:client' \
             xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"
        );
        c.write_all(open.as_bytes()).await?;
        // Read stream features (best effort).
        let _ = c.read_some(4096).await?;

        let token = crypto::b64encode(format!("\0{user}\0{pass}").as_bytes());
        let auth = format!(
            "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{token}</auth>"
        );
        c.write_all(auth.as_bytes()).await?;

        let resp = c.read_some(4096).await?;
        let text = String::from_utf8_lossy(&resp);
        Ok(if text.contains("<success") {
            AuthOutcome::Success
        } else if text.contains("<failure") || text.contains("not-authorized") {
            AuthOutcome::Failure
        } else {
            AuthOutcome::Unknown
        })
    }
}
register_protocol!(Xmpp, "xmpp", "jabber");
