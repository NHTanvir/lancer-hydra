//! lancer-hydra
//! Rust clone of hydra. See plan.md (local, gitignored) for the spec.

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "lancer-hydra", version, about = "Rust clone of hydra")]
struct Cli {}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let _cli = Cli::parse();
    println!("lancer-hydra - scaffold ready. Implement per plan.md.");
    Ok(())
}
