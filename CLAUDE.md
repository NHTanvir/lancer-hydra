# CLAUDE.md

Guidance for Claude Code (and humans) working in this repository.

## What this is

`lancer-hydra` — A Rust clone of THC-Hydra: a parallelized, multi-protocol network login brute-forcer with a native desktop GUI built on egui. It is part of the Lancer 2026 bug-bounty ecosystem, supporting 50+ protocols (SSH, FTP, HTTP(S), RDP, SMB, databases, and more) for authorized penetration testing, CTFs, and security research. A bare invocation opens the GUI; `--cli` exposes the full headless command-line surface.

## Architecture

This is a Cargo workspace. All crates live under `crates/`.

- `crates/lancer-hydra/src/main.rs` — binary entry point; dispatches to GUI or CLI mode
- `crates/lancer-hydra/src/lib.rs` — library entry point for the top-level crate
- `crates/lancer-hydra/src/cli.rs` — full CLI surface (`--cli` flag and argument parsing via clap)
- `crates/lancer-hydra/src/gui/mod.rs` — egui desktop GUI module entry point
- `crates/lancer-hydra/src/gui/app.rs` — main egui application struct and update loop
- `crates/lancer-hydra/src/gui/server.rs` — background server/bridge feeding GUI state
- `crates/hydra-core/src/engine.rs` — orchestration engine: worker pools, queues, stop-on-found
- `crates/hydra-core/src/worker.rs` — async worker implementation
- `crates/hydra-core/src/ratelimit.rs` — rate limiting via `governor`
- `crates/hydra-core/src/restore.rs` — session restore-file logic
- `crates/hydra-core/src/credqueue.rs` — credential streaming queue
- `crates/hydra-core/src/target.rs` — target/service parsing
- `crates/hydra-protocols/src/traits.rs` — shared `Protocol` trait all modules implement
- `crates/hydra-protocols/src/registry.rs` — protocol module registry (via `inventory`)
- `crates/hydra-protocols/src/modules/` — per-protocol auth implementations
- `crates/hydra-protocols/src/crypto.rs` — hand-rolled SSH crypto (curve25519 + AES-CTR)
- `crates/hydra-credlist/src/generator.rs` — credential generation (`-x` brute-force charset expansion)
- `crates/hydra-credlist/src/sources.rs` — credential sources: `-l/-L/-p/-P/-C/-e/-u` flags
- `crates/hydra-output/src/text.rs` — human-readable text output formatter
- `crates/hydra-output/src/json.rs` — JSON / jsonv1 / jsonl output formatters
- `crates/hydra-output/src/progress.rs` — progress bar rendering
- `crates/hydra-output/src/restore_io.rs` — restore-file I/O

## Conventions

- Error propagation uses `anyhow::Result`; no `unwrap`/`expect` on fallible I/O.
- GUI is gated behind the default `gui` feature; `--no-default-features` builds a headless CLI binary.
- Library code lives in each crate's `src/lib.rs`; binary entry point in `crates/lancer-hydra/src/main.rs`.
- Protocol modules register themselves via the `inventory` crate; add a new protocol by implementing the `Protocol` trait and calling the inventory macro — no central dispatch table to edit.
- All async code runs on Tokio (`tokio = { version = "1", features = ["full"] }`); blocking calls must be wrapped in `spawn_blocking`.
- TLS uses `native-tls` (SChannel on Windows); no C toolchain or system libraries are required — pure Rust throughout.

## Build / test / run

```
build.bat                   # Windows -> build\lancer-hydra.exe
build-windows.bat           # Windows -> dist\lancer-hydra-windows-x86_64\bin\lancer-hydra.exe
./build-linux.sh            # Linux/macOS -> build/lancer-hydra
./build-mac.sh              # macOS -> build/lancer-hydra (+ .app via cargo-bundle if present)
cargo build --release       # standard release build
cargo test                  # unit + integration tests
```

Minimum supported Rust version: **1.74**

## Repo notes

- `plan.md` is local-only and must NOT be committed. It is gitignored; if ever tracked, run `git rm --cached plan.md`.
- `.claude/` and `target/`/`build/`/`dist/` are local-only and gitignored.
- For authorized security testing only. Online credential testing against systems you do not own is illegal in most jurisdictions.
