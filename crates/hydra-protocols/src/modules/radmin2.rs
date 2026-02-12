//! Radmin 2.x remote admin (4899). Proprietary DH handshake is reserved.

use crate::prelude::*;

stub_module!(
    Radmin2,
    "radmin2",
    4899,
    "radmin2: -m DH=1 forces the DH handshake; proprietary auth reserved.",
    "radmin"
);
