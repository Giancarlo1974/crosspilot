#!/usr/bin/env bash
# Script per compilare la versione Windows su Linux (NixOS environment)

# Percorso della libreria pthread per MinGW
PTHREAD_LIB_PATH="/nix/store/z7dknpmqpp0rr2x12mfvfd32s00gbd12-mingw_w64-pthreads-x86_64-w64-mingw32-13.0.0/lib"

echo "Compilazione per Windows (x86_64-pc-windows-gnu)..."
RUSTFLAGS="-L native=${PTHREAD_LIB_PATH} -C target-feature=+crt-static" cargo build --target x86_64-pc-windows-gnu --release

if [ $? -eq 0 ]; then
    echo "Compilazione riuscita!"
    echo "L'eseguibile si trova in: target/x86_64-pc-windows-gnu/release/crosspilot.exe"
else
    echo "Errore durante la compilazione."
    exit 1
fi
