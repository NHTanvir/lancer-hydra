//! Plain-text hit formatting (`<service>://<host>:<port>  login: ..  password: ..`).

use crate::Hit;

/// The console / `-o` text line for a discovered credential.
pub fn format_hit(hit: &Hit) -> String {
    format!(
        "[{}][{}] host: {}   login: {}   password: {}",
        hit.port, hit.service, hit.host, hit.login, hit.password
    )
}
