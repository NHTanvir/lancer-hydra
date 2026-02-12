//! PC-NFS (pcnfsd over RPC, 640). RPC auth call is reserved.

use crate::prelude::*;

stub_module!(Pcnfs, "pcnfs", 640, "pcnfs: pcnfsd RPC auth reserved.");
