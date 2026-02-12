//! Cobalt Strike team server (50050). The staging-credential hash check is
//! reserved; `-m HASH=<MD5>` carries the team-server credential string.

use crate::prelude::*;

stub_module!(
    CobaltStrike,
    "cobaltstrike",
    50050,
    "cobaltstrike: -m HASH=<MD5> team-server credential; TLS-staged auth reserved.",
    "cobalt-strike",
    "cs"
);
