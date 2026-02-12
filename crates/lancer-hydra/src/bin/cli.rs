//! `lancer-hydra-cli` — CLI-only companion binary (headless / CI / scripting).

fn main() {
    let code = lancer_hydra::cli::run(std::env::args().collect());
    std::process::exit(code);
}
