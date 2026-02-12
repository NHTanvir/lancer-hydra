//! Advantech ADAM-6500 PLC (502/Modbus-ish). Proprietary login is reserved.

use crate::prelude::*;

stub_module!(
    Adam6500,
    "adam6500",
    502,
    "adam6500: -m SLOT=/-m RACK= addressing; PLC login reserved."
);
