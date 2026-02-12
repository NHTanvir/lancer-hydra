//! Siemens S7-300 PLC (S7comm over ISO-TSAP, 102). COTP+S7 setup is reserved.

use crate::prelude::*;

stub_module!(
    S7_300,
    "s7-300",
    102,
    "s7-300: -m SLOT=2 -m RACK=0 chassis addressing; S7comm auth reserved.",
    "s7300"
);
