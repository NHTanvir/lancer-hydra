#!/usr/bin/env bash
set -euo pipefail

REPO="$(cd "$(dirname "$0")" && pwd)"
BUILD="$REPO/build"
BIN="lancer-hydra"

echo "================================================"
echo "  lancer-hydra Build"
echo "================================================"
echo ""
echo "  Repo   : $REPO"
echo "  Output : $BUILD/$BIN"
echo ""

echo "[1/2] Building release binary..."
cargo build --release -p lancer-hydra

echo "[2/2] Copying to build/..."
mkdir -p "$BUILD"
cp "$REPO/target/release/$BIN" "$BUILD/"
[ -f "$REPO/target/release/$BIN-cli" ] && cp "$REPO/target/release/$BIN-cli" "$BUILD/" || true

# Optional desktop integration: ./build-linux.sh --install
if [ "${1:-}" = "--install" ]; then
    APPDIR="$HOME/.local/share/applications"
    BINDIR="$HOME/.local/bin"
    mkdir -p "$APPDIR" "$BINDIR"
    cp "$BUILD/$BIN" "$BINDIR/"
    cat > "$APPDIR/$BIN.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=lancer-hydra
Comment=Parallelized network login brute-forcer (Lancer toolkit)
Exec=$BINDIR/$BIN
Terminal=false
Categories=Network;Security;
EOF
    echo "Installed $BIN to $BINDIR and a .desktop entry to $APPDIR"
fi

echo ""
echo "================================================"
echo "  Done!  Binary ready: $BUILD/$BIN"
echo "================================================"
