//! SAP R/3 (DIAG/RFC, 3299). DIAG handshake + auth is reserved.

use crate::prelude::*;

stub_module!(
    SapR3,
    "sap-r3",
    3299,
    "sap-r3: -m CLIENT=000 SAP client number; DIAG/RFC auth reserved.",
    "sapr3",
    "sap"
);
