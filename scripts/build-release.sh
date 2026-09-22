#!/usr/bin/env bash
# build-release.sh — Compila il binario Linux con gli artefatti embeddati.
#
# Procedura:
#   1. Cross-compila il binario Windows (x86_64-pc-windows-gnu) -> assets/crosspilot.exe
#   2. Compila il binario Linux musl statico (x86_64-unknown-linux-musl)
#      -> assets/crosspilot.linux (sidecar per il self-update)
#   3. Compila il binario Linux host (embedda entrambi via include_bytes!)
#
# Uso:
#   ./scripts/build-release.sh           # release ottimizzato
#   ./scripts/build-release.sh --debug   # debug build
#
# Requisiti:
#   - Rust toolchain con target x86_64-pc-windows-gnu installato:
#       rustup target add x86_64-pc-windows-gnu
#   - MinGW cross-compiler (x86_64-w64-mingw32-gcc) nel PATH
#   - (per il sidecar self-update) target musl:
#       rustup target add x86_64-unknown-linux-musl
#   - Su Nix: nix-shell -p rustc cargo pkgsCross.mingwW64.buildPackages.gcc
#
# AUTO-UPDATE: tutti gli artefatti della stessa release condividono
# CROSSPILOT_BUILD_TS (export prima dei cargo build): il confronto di
# versione tra client e server remoto si basa su questo timestamp.
# Senza ts condiviso ogni build avrebbe un ts diverso -> deploy ad ogni
# bootstrap. Il sidecar linux e' MUSL STATICO: un unico artefatto gira
# su Ubuntu, NixOS, Alpine e container minimali (niente matrice distro).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ASSETS_DIR="$ROOT_DIR/assets"
EXE_NAME="crosspilot.exe"
LINUX_SIDECAR_NAME="crosspilot.linux"
WINDOWS_EXE="$ASSETS_DIR/$EXE_NAME"
LINUX_SIDECAR="$ASSETS_DIR/$LINUX_SIDECAR_NAME"

cd "$ROOT_DIR"

# --- Timestamp di build condiviso da TUTTI gli artefatti ---
# build.rs lo legge dall'ambiente (cargo:rerun-if-env-changed) e lo
# embedda come CROSSPILOT_BUILD_TS. Stesso ts = stessa release.
export CROSSPILOT_BUILD_TS="${CROSSPILOT_BUILD_TS:-$(date +%s)}"
echo "=== build-release.sh: CROSSPILOT_BUILD_TS=$CROSSPILOT_BUILD_TS ==="

# --- Argomenti ---
PROFILE="release"
if [[ "${1:-}" == "--debug" ]]; then
    PROFILE="dev"
fi

echo "=== build-release.sh: profilo=$PROFILE ==="

# --- Step 1: cross-compila binario Windows ---
echo ""
echo "[1/4] Cross-compilazione binario Windows (x86_64-pc-windows-gnu)..."
cargo build --target x86_64-pc-windows-gnu --bin crosspilot --profile "$PROFILE"

WINDOWS_BUILD_EXE="target/x86_64-pc-windows-gnu/$PROFILE/$EXE_NAME"
if [[ ! -f "$WINDOWS_BUILD_EXE" ]]; then
    echo "ERRORE: binario Windows non trovato: $WINDOWS_BUILD_EXE" >&2
    exit 1
fi

# --- Step 2: copia exe in assets/ ---
echo ""
echo "[2/4] Copia exe Windows in assets/..."
mkdir -p "$ASSETS_DIR"
cp -f "$WINDOWS_BUILD_EXE" "$WINDOWS_EXE"

EXE_SIZE=$(stat -c%s "$WINDOWS_EXE" 2>/dev/null || stat -f%z "$WINDOWS_EXE")
EXE_SHA256=$(sha256sum "$WINDOWS_EXE" | cut -d' ' -f1)
echo "  $WINDOWS_EXE ($EXE_SIZE byte, sha256=${EXE_SHA256:0:16})"

# --- Step 3: binario Linux musl statico (sidecar self-update) ---
# Un artefatto musl statico gira su qualunque distro Linux: e' il formato
# canonico scaricato dai client piu' vecchi durante il self-update.
# Se il target musl non e' installato si prosegue SENZA sidecar: il build
# resta utilizzabile ma il self-update da questo remoto non sara' possibile.
echo ""
echo "[3/4] Compilazione binario Linux musl statico (sidecar self-update)..."
MUSL_TARGET="x86_64-unknown-linux-musl"
if rustup target list --installed 2>/dev/null | grep -q "^$MUSL_TARGET$"; then
    # L'asset .linux deve essere rimosso PRIMA del build musl: altrimenti
    # il sidecar embedderebbe il sidecar della build precedente (include_bytes!
    # attivo su tutti i target non-Windows) e la dimensione crescerebbe ad
    # ogni release. Col file assente build.rs usa lo stub vuoto: il sidecar
    # porta solo l'exe Windows, non un altro sidecar (documentato: un client
    # musl self-updated deploya l'exe ma non puo' offrire il sidecar a un
    # remote vergine — il sidecar arriva dai build fatti con questo script).
    rm -f "$LINUX_SIDECAR"
    RUSTFLAGS="-C target-feature=+crt-static" \
        cargo build --target "$MUSL_TARGET" --bin crosspilot --profile "$PROFILE"
    MUSL_BIN="target/$MUSL_TARGET/$PROFILE/crosspilot"
    if [[ -f "$MUSL_BIN" ]]; then
        cp -f "$MUSL_BIN" "$LINUX_SIDECAR"
        SIDECAR_SIZE=$(stat -c%s "$LINUX_SIDECAR" 2>/dev/null || stat -f%z "$LINUX_SIDECAR")
        SIDECAR_SHA256=$(sha256sum "$LINUX_SIDECAR" | cut -d' ' -f1)
        echo "  $LINUX_SIDECAR ($SIDECAR_SIZE byte, sha256=${SIDECAR_SHA256:0:16})"
        # Sanity check: il sidecar deve essere davvero statico.
        # ldd stampa "not a dynamic executable" o "statically linked"
        # a seconda della versione di glibc: accettiamo entrambe.
        if ldd "$LINUX_SIDECAR" 2>&1 | grep -qE "not a dynamic executable|statically linked"; then
            echo "  verificato: binario musl statico (nessuna dipendenza libc)"
        else
            echo "  WARNING: ldd non conferma che il sidecar sia statico" >&2
        fi
    else
        echo "  WARNING: binario musl non trovato: $MUSL_BIN (sidecar non embeddato)" >&2
    fi
else
    echo "  WARNING: target $MUSL_TARGET non installato -> sidecar linux NON embeddato." >&2
    echo "           (il self-update da questo client non sara' disponibile)" >&2
    echo "           Installare con: rustup target add $MUSL_TARGET" >&2
    rm -f "$LINUX_SIDECAR"  # evita di embeddare uno stale di un build precedente
fi

# --- Step 4: compila binario Linux host (embedda exe + sidecar) ---
echo ""
echo "[4/4] Compilazione binario Linux host (con exe Windows + sidecar embeddati)..."
cargo build --bin crosspilot --profile "$PROFILE"

LINUX_BIN="target/$PROFILE/crosspilot"
if [[ ! -f "$LINUX_BIN" ]]; then
    echo "ERRORE: binario Linux non trovato: $LINUX_BIN" >&2
    exit 1
fi

LINUX_SIZE=$(stat -c%s "$LINUX_BIN" 2>/dev/null || stat -f%z "$LINUX_BIN")
echo ""
echo "=== Build completato (ts=$CROSSPILOT_BUILD_TS) ==="
echo "  Linux: $LINUX_BIN ($LINUX_SIZE byte)"
echo "  Windows (embeddato): $WINDOWS_EXE ($EXE_SIZE byte, sha256=${EXE_SHA256:0:16})"
if [[ -f "$LINUX_SIDECAR" ]]; then
    echo "  Sidecar linux (embeddato): $LINUX_SIDECAR ($SIDECAR_SIZE byte)"
fi
echo ""
echo "Il binario Linux contiene l'exe Windows + il sidecar musl embeddati."
echo "Distribuisci solo target/$PROFILE/crosspilot — auto-deploy e"
echo "self-update bidirezionale funzioneranno ovunque."
