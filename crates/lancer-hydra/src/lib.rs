//! lancer-hydra binary crate library: the CLI surface and (optionally) the GUI.
//!
//! Both the default `lancer-hydra` binary and the `lancer-hydra-cli` companion
//! reuse these modules.

pub mod cli;

#[cfg(feature = "gui")]
pub mod gui;

/// Default-binary dispatch: open the GUI on a bare/`--gui` invocation, otherwise
/// fall through to the CLI surface (also via `--cli`).
pub fn dispatch() {
    let raw: Vec<String> = std::env::args().collect();

    #[cfg(feature = "gui")]
    {
        let bare = raw.len() == 1;
        let forced = raw.get(1).map(|s| s == "--gui").unwrap_or(false);
        if bare || forced {
            gui::launch();
            return;
        }
    }

    // CLI path — drop a leading `--cli` / `--gui` selector token if present.
    let mut args = raw;
    if args.get(1).map(|s| s == "--cli" || s == "--gui").unwrap_or(false) {
        args.remove(1);
    }
    std::process::exit(cli::run(args));
}
