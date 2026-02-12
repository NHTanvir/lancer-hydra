//! Oracle TNS (listener 1521). Connects to confirm the listener; the O5LOGIN
//! challenge/response auth crypto is reserved, so credentials return Unknown.

use crate::prelude::*;

stub_module!(
    Oracle,
    "oracle",
    1521,
    "oracle: TNS listener probe. -m SID=/-m SERVICE_NAME=; O5LOGIN auth reserved.",
    "oracle-listener",
    "oracle-sid"
);
