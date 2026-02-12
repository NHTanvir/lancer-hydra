//! Compile-time protocol registry using the `inventory` crate.
//!
//! Each module file calls [`register_protocol!`] once at the bottom. The CLI
//! resolves a `proto://` scheme by walking [`all`] and matching `name()` /
//! aliases. No central list to keep in sync — adding a module file is enough.

use crate::traits::Protocol;

/// A registered factory: a stable name plus a constructor for the singleton.
pub struct Registration {
    pub name: &'static str,
    /// Extra scheme spellings that map to the same module (e.g. `https-get` etc.).
    pub aliases: &'static [&'static str],
    pub make: fn() -> Box<dyn Protocol>,
}

inventory::collect!(Registration);

/// Iterate every registered protocol factory.
pub fn all() -> impl Iterator<Item = &'static Registration> {
    inventory::iter::<Registration>.into_iter()
}

/// Resolve a `proto://` scheme (case-insensitive) to a freshly-built module.
pub fn resolve(scheme: &str) -> Option<Box<dyn Protocol>> {
    let want = scheme.to_ascii_lowercase();
    for reg in all() {
        if reg.name.eq_ignore_ascii_case(&want)
            || reg.aliases.iter().any(|a| a.eq_ignore_ascii_case(&want))
        {
            return Some((reg.make)());
        }
    }
    None
}

/// All known scheme names (primary + aliases), sorted, for `--help` / `-U`.
pub fn names() -> Vec<&'static str> {
    let mut v: Vec<&'static str> = Vec::new();
    for reg in all() {
        v.push(reg.name);
        v.extend_from_slice(reg.aliases);
    }
    v.sort_unstable();
    v.dedup();
    v
}

/// Define a "reachability probe" module for protocols whose full auth crypto is
/// not yet wired (proprietary/undocumented binary handshakes). It connects to
/// confirm the service is up, then returns [`AuthOutcome::Unknown`] so the
/// engine never records a false hit. This keeps the registry parity-complete —
/// every upstream module name resolves — while being honest about coverage.
#[macro_export]
macro_rules! stub_module {
    ($ty:ident, $name:literal, $port:literal, $usage:literal $(, $alias:literal)*) => {
        #[derive(Default)]
        pub struct $ty;

        #[::async_trait::async_trait]
        impl $crate::traits::Protocol for $ty {
            fn name(&self) -> &'static str { $name }
            fn default_port(&self) -> u16 { $port }
            fn usage(&self) -> &'static str { $usage }
            async fn try_credential(
                &self,
                target: &$crate::traits::Target,
                _user: &str,
                _pass: &str,
                opts: &$crate::traits::ModuleOpts,
            ) -> ::std::result::Result<$crate::traits::AuthOutcome, $crate::traits::ProtocolError> {
                // Confirm the service is reachable, then decline to assert a verdict.
                let _ = $crate::net::connect(target, opts).await?;
                ::std::result::Result::Ok($crate::traits::AuthOutcome::Unknown)
            }
        }
        $crate::register_protocol!($ty, $name $(, $alias)*);
    };
}

/// Register a protocol module. Use inside each module file:
/// ```ignore
/// register_protocol!(Ssh, "ssh");
/// register_protocol!(HttpsGetForm, "https-get-form", "https-form-get");
/// ```
#[macro_export]
macro_rules! register_protocol {
    ($ty:ty, $name:literal $(, $alias:literal)* $(,)?) => {
        inventory::submit! {
            $crate::registry::Registration {
                name: $name,
                aliases: &[ $($alias),* ],
                make: || ::std::boxed::Box::new(<$ty as ::std::default::Default>::default())
                    as ::std::boxed::Box<dyn $crate::traits::Protocol>,
            }
        }
    };
}
