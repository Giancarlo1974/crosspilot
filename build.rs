// build.rs — genera le costanti di build usate dal sistema di auto-update.
//
// 1. CROSSPILOT_BUILD_TS: timestamp unix del build. Usato come "versione"
//    confrontabile per decidere chi e' piu' nuovo tra client Linux e
//    server Windows remoto (il solo hash SHA-256 dice "diverso" ma non
//    "piu' vecchio/piu' nuovo").
//
//    IMPORTANTE: build-release.sh esporta CROSSPILOT_BUILD_TS nell'ambiente
//    prima di invocare cargo, cosi' TUTTI gli artefatti della stessa
//    release (exe Windows, binario linux musl, binario linux host)
//    condividono lo stesso timestamp. Senza la variabile, ogni cargo
//    build genererebbe un ts diverso e il confronto remoto/locale
//    risulterebbe sempre "diverso" -> deploy ad ogni bootstrap.
//
// 2. CROSSPILOT_TARGET: target triple della compilazione corrente
//    (es. x86_64-pc-windows-gnu, x86_64-unknown-linux-musl). Stampato da
//    --version e usato nei debug log.
//
// 3. CROSSPILOT_LINUX_ASSET: path dell'artefatto linux (musl statico) da
//    embeddare come sidecar per il self-update dei client. Se
//    assets/crosspilot.linux non esiste (build di sviluppo senza
//    build-release.sh), viene generato uno stub vuoto in OUT_DIR:
//    il codice compila comunque e deploy.rs skippa l'upload del sidecar
//    con un warning esplicito.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR non settato da cargo");

    // --- Build timestamp ---
    // Priorita': variabile d'ambiente (settata da build-release.sh per
    // condividere il ts tra i 3 build della release), altrimenti "ora".
    let build_ts = env::var("CROSSPILOT_BUILD_TS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        });
    println!("cargo:rustc-env=CROSSPILOT_BUILD_TS={}", build_ts);
    // Se lo script cambia il ts, il build script deve rieseguirsi.
    println!("cargo:rerun-if-env-changed=CROSSPILOT_BUILD_TS");

    // --- Target triple ---
    // TARGET e' sempre settato da cargo per il build script.
    let target = env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());
    println!("cargo:rustc-env=CROSSPILOT_TARGET={}", target);

    // --- Asset linux (musl) opzionale ---
    // assets/crosspilot.linux e' prodotto da build-release.sh.
    // Se manca, embeddiamo uno stub vuoto: deploy.rs riconosce il caso
    // (slice vuota) e skippa l'upload del sidecar con warning.
    let asset_path = PathBuf::from(&manifest_dir)
        .join("assets")
        .join("crosspilot.linux");

    let embed_path = if asset_path.is_file() {
        asset_path
    } else {
        let stub = PathBuf::from(&out_dir).join("crosspilot.linux.stub");
        // Lo stub esiste sempre (creazione idempotente): include_bytes!
        // fallirebbe a compile-time su path mancante.
        if let Err(e) = fs::write(&stub, b"") {
            println!("cargo:warning=impossibile creare stub linux asset: {}", e);
        }
        println!(
            "cargo:warning=assets/crosspilot.linux assente: sidecar self-update disabilitato (usa scripts/build-release.sh)"
        );
        stub
    };

    println!("cargo:rustc-env=CROSSPILOT_LINUX_ASSET={}", embed_path.display());

    // Rebuild se gli asset cambiano (l'exe Windows ha gia' include_bytes!
    // diretto su assets/crosspilot.exe, che fa da trigger implicito).
    println!("cargo:rerun-if-changed=assets/crosspilot.linux");
    println!("cargo:rerun-if-changed=assets/crosspilot.exe");
}
