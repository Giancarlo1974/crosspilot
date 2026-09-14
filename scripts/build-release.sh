#!/usr/bin/env bash
# build-release.sh — Compila il binario Linux con l'exe Windows embeddato.
#
# Procedura:
#   1. Cross-compila il binario Windows (x86_64-pc-windows-gnu)
#   2. Copia l'exe in assets/winboat-bridge.exe
#   3. Compila il binario Linux (embedda l'exe via include_bytes!)
#
# Uso:
#   ./scripts/build-release.sh           # release ottimizzato
#   ./scripts/build-release.sh --debug   # debug build
#
# Requisiti:
#   - Rust toolchain con target x86_64-pc-windows-gnu installato:
#       rustup target add x86_64-pc-windows-gnu
#   - MinGW cross-compiler (x86_64-w64-mingw32-gcc) nel PATH
#   - Su Nix: nix-shell -p rustc cargo pkgsCross.mingwW64.buildPackages.gcc
#
# L'exe Windows embeddato viene verificato con SHA-256 a runtime dal client
# durante l'auto-deploy: se l'exe remoto ha hash diverso, viene re-uploadato.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ASSETS_DIR="$ROOT_DIR/assets"
EXE_NAME="winboat-bridge.exe"
WINDOWS_EXE="$ASSETS_DIR/$EXE_NAME"

cd "$ROOT_DIR"

# --- Argomenti ---
PROFILE="release"
CARGO_FLAGS=""
if [[ "${1:-}" == "--debug" ]]; then
    PROFILE="dev"
    CARGO_FLAGS=""
fi

echo "=== build-release.sh: profilo=$PROFILE ==="

# --- Step 1: cross-compila binario Windows ---
echo ""
echo "[1/3] Cross-compilazione binario Windows (x86_64-pc-windows-gnu)..."
cargo build --target x86_64-pc-windows-gnu --bin winboat-bridge --profile "$PROFILE"

WINDOWS_BUILD_EXE="target/x86_64-pc-windows-gnu/$PROFILE/$EXE_NAME"
if [[ ! -f "$WINDOWS_BUILD_EXE" ]]; then
    echo "ERRORE: binario Windows non trovato: $WINDOWS_BUILD_EXE" >&2
    exit 1
fi

# --- Step 2: copia exe in assets/ ---
echo ""
echo "[2/3] Copia exe Windows in assets/..."
mkdir -p "$ASSETS_DIR"
cp -f "$WINDOWS_BUILD_EXE" "$WINDOWS_EXE"

EXE_SIZE=$(stat -c%s "$WINDOWS_EXE" 2>/dev/null || stat -f%z "$WINDOWS_EXE")
EXE_SHA256=$(sha256sum "$WINDOWS_EXE" | cut -d' ' -f1)
echo "  $WINDOWS_EXE ($EXE_SIZE byte, sha256=${EXE_SHA256:0:16})"

# --- Step 3: compila binario Linux (embedda l'exe) ---
echo ""
echo "[3/3] Compilazione binario Linux (con exe Windows embeddato)..."
cargo build --bin winboat-bridge --profile "$PROFILE"

LINUX_BIN="target/$PROFILE/winboat-bridge"
if [[ ! -f "$LINUX_BIN" ]]; then
    echo "ERRORE: binario Linux non trovato: $LINUX_BIN" >&2
    exit 1
fi

LINUX_SIZE=$(stat -c%s "$LINUX_BIN" 2>/dev/null || stat -f%z "$LINUX_BIN")
echo ""
echo "=== Build completato ==="
echo "  Linux: $LINUX_BIN ($LINUX_SIZE byte)"
echo "  Windows (embeddato): $WINDOWS_EXE ($EXE_SIZE byte, sha256=${EXE_SHA256:0:16})"
echo ""
echo "Il binario Linux contiene l'exe Windows embeddato."
echo "Distribuisci solo target/$PROFILE/winboat-bridge — auto-deploy funzionerà ovunque."
