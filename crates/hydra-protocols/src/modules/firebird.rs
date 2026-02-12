//! Firebird (gds_db, 3050). op_connect/op_attach wire auth is reserved.

use crate::prelude::*;

stub_module!(
    Firebird,
    "firebird",
    3050,
    "firebird: -m DB=path/to/db.fdb required; wire auth handshake reserved."
);
