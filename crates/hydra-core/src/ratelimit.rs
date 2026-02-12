//! Optional global rate limiter built on `governor`.

use std::num::NonZeroU32;
use std::sync::Arc;

use governor::{Quota, RateLimiter};

/// A direct (non-keyed) in-memory rate limiter with the default clock.
pub type DirectLimiter = governor::DefaultDirectRateLimiter;

/// Build a shared limiter capped at `rps` attempts/second, or `None` for no cap.
pub fn make(rps: Option<u32>) -> Option<Arc<DirectLimiter>> {
    let q = NonZeroU32::new(rps?)?;
    Some(Arc::new(RateLimiter::direct(Quota::per_second(q))))
}
