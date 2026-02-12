#!/usr/bin/env bash
# macOS build for lancer-hydra. Produces build/lancer-hydra and, when
# `cargo-bundle` is installed, a lancer-hydra.app bundle.
set -euo pipefail

REPO="$(cd "$(dirname "$0")" && pwd)"
BUILD="$REPO/build"
BIN="lancer-hydra"

echo "================================================"
echo "  lancer-hydra Build (macOS)"
echo "================================================"

echo "[1/3] Building release binary..."
cargo build --release -p lancer-hydra

echo "[2/3] Copying to build/..."
mkdir -p "$BUILD"
cp "$REPO/target/release/$BIN" "$BUILD/"
[ -f "$REPO/target/release/$BIN-cli" ] && cp "$REPO/target/release/$BIN-cli" "$BUILD/" || true

echo "[3/3] Bundling .app (optional)..."
if command -v cargo-bundle >/dev/null 2>&1; then
    (cd "$REPO/crates/lancer-hydra" && cargo bundle --release) || true
    echo "  bundled via cargo-bundle (see target/release/bundle/osx)"
else
    echo "  cargo-bundle not found — skipping .app bundle"
    echo "  install with: cargo install cargo-bundle"
fi

echo ""
echo "================================================"
echo "  Done!  Binary ready: $BUILD/$BIN"
echo "================================================"
