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
//!
//! Eccezione all'opt-in: l'avvio di un auto-update riapre il gate da solo
//! (`verbose_unless_forced`) — operazione lunga che deve essere visibile
//! anche senza -v. Un `-q` ESPLICITO (QUIET_FORCED) non viene mai
//! scavalcato: resta il contratto machine-readable per script/CI.

use std::sync::atomic::{AtomicBool, Ordering};

/// Flag globale: QUIET ATTIVO di default (i diagnostici sono opt-in via
/// -v/--verbose, settato una volta in main() dopo il parse del CLI).
/// AtomicBool (non OnceCell) per permettere reset nei test.
static QUIET: AtomicBool = AtomicBool::new(true);

/// `-q/--quiet` passato ESPLICITAMENTE: il gate non si riapre mai da solo.
/// Distinto da QUIET perche' il default quiet puo' essere riaperto
/// automaticamente (auto-verbose dell'auto-update), un -q esplicito no:
/// e' un contratto per script/CI che leggono stderr machine-readable.
static QUIET_FORCED: AtomicBool = AtomicBool::new(false);

/// Attiva/disattiva la modalita' quiet (chiamata una volta da main).
pub fn set_quiet(quiet: bool) {
    QUIET.store(quiet, Ordering::Relaxed);
}

/// Registra che l'utente ha chiesto quiet ESPLICITAMENTE (-q/--quiet
/// globale). Chiamata da main insieme a set_quiet.
pub fn set_quiet_forced(forced: bool) {
    QUIET_FORCED.store(forced, Ordering::Relaxed);
}

/// True se la modalita' quiet e' attiva (letta da `qprintln!`).
pub fn is_quiet() -> bool {
    QUIET.load(Ordering::Relaxed)
}

/// Riapre il gate diagnostico (quiet -> verbose) a meno che l'utente non
/// abbia passato -q esplicito. Ritorna true se il gate era quiet ed e'
/// stato riaperto (false se gia' verbose o quiet forzato). Usato
/// dall'auto-update: operazione lunga e insolita che deve essere visibile
/// anche quando il comando e' stato lanciato senza -v (richiesta utente:
/// "il verbose si dovrebbe attivare in automatico").
pub fn verbose_unless_forced() -> bool {
    if QUIET_FORCED.load(Ordering::Relaxed) {
        return false;
    }
    let was_quiet = QUIET.swap(false, Ordering::Relaxed);
    was_quiet
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
