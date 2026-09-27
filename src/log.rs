//! Gating minimale dell'output diagnostico.
//!
//! Tutto il logging del tool va su stderr (`eprintln!`), l'output utile dei
//! comandi su stdout (`println!`). DEFAULT INVERTITO (richiesta utente):
//! quiet e' ATTIVO di default — il chiacchiericcio di progresso/debug
//! (`qprintln!`) e' soppresso a meno che l'utente non passi `-v/--verbose`
//! (opt-in). `-q/--quiet` resta accettato per compat con gli script.
//! Warning ed errori restano sempre visibili (`eprintln!` diretto).
//!
//! Policy:
//! - `qprintln!`  -> dettaglio/progresso: soppresso di default, `-v` mostra
//!   ([DEBUG], "Connecting...", "Connected", progressi [sync], [update], ...).
//! - `eprintln!`  -> semaforico: MAI soppresso
//!   ([WARN], [ERROR], [HINT], errori di comando, riepiloghi finali).
//! - `println!`   -> output utente su stdout (report status, usage, ...):
//!   gestito dai flag --quiet dei singoli sottocomandi, non da questo gate.

use std::sync::atomic::{AtomicBool, Ordering};

/// Flag globale: QUIET ATTIVO di default (i diagnostici sono opt-in via
/// -v/--verbose, settato una volta in main() dopo il parse del CLI).
/// AtomicBool (non OnceCell) per permettere reset nei test.
static QUIET: AtomicBool = AtomicBool::new(true);

/// Attiva/disattiva la modalita' quiet (chiamata una volta da main).
pub fn set_quiet(quiet: bool) {
    QUIET.store(quiet, Ordering::Relaxed);
}

/// True se la modalita' quiet e' attiva (letta da `qprintln!`).
pub fn is_quiet() -> bool {
    QUIET.load(Ordering::Relaxed)
}

/// Come `eprintln!` ma soppressa in modalita' quiet (default; `-v` mostra).
/// Da usare SOLO per dettaglio/progresso — mai per warning o errori.
///
/// E' `#[macro_export]` (crate root) per essere chiamabile da ogni modulo
/// come `crate::qprintln!(...)` senza import.
#[macro_export]
macro_rules! qprintln {
    ($($arg:tt)*) => {{
        if !$crate::log::is_quiet() {
            eprintln!($($arg)*);
        }
    }};
}
