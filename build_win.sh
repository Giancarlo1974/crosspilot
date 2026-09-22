#!/usr/bin/env bash
# Script helper per compilare crosspilot per Windows su NixOS

echo "Ricerca libreria pthread per mingw..."
PTHREAD_LIB=$(find /nix/store -name "libpthread.a" 2>/dev/null | grep mingw | head -n 1)

if [ -z "$PTHREAD_LIB" ]; then
    echo "Errore: libpthread.a per mingw non trovata."
    exit 1
fi

PTHREAD_DIR=$(dirname "$PTHREAD_LIB")
echo "Libreria trovata in: $PTHREAD_DIR"

echo "Compilazione per Windows (Release)..."
RUSTFLAGS="-L native=$PTHREAD_DIR" cargo build --release --target x86_64-pc-windows-gnu

if [ $? -eq 0 ]; then
    echo "Compilazione completata con successo!"
    echo "Eseguibile: target/x86_64-pc-windows-gnu/release/crosspilot.exe"
else
    echo "Errore durante la compilazione."
    exit 1
fi
