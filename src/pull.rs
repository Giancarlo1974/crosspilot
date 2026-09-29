//! Download ricorsivo di una directory remota ("pull") — `get` dir-aware.
//!
//! Bug report utente: `crosspilot get <dir remota> <dir locale>` rispondeva
//! "ERR 2: file non trovato" perche' il server trattava la directory come
//! file (su Windows File::open(dir) fallisce; su Unix open(dir) riesce e
//! il transfer partiva su metadata sbagliati). Ora il client riconosce il
//! tipo remoto (probe LIST del parent, stessa risoluzione di `sync <file>`)
//! e scarica la directory ricorsivamente componendo le primitive esistenti:
//!
//!   1. LIST ricorsiva (`sync::list_remote_dir`) -> entry file/dir;
//!   2. mkdir locale per ogni entry directory;
//!   3. GET (`transfer::get_client`: delta rsync + verifica SHA-256) per file.
//!
//! Tutte le operazioni viaggiano su UNA `SyncSession` (connessione
//! persistente con reconnect-on-drop; fallback conn-per-op automatico su
//! server pre-sessione). Niente connessioni parallele (best-practice).

use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::Result;

use crate::sync::{self, SyncSession};
use crate::tls::Link;
use crate::transfer;

/// Intervallo minimo tra due righe di progresso aggregate (stderr):
/// un pull da GB puo' durare minuti e il quiet di default non mostra i
/// dettagli per-file — una riga ogni ~10s rende il lavoro osservabile
/// senza spam (report utente: "317 MB completamente silenzioso").
const PROGRESS_EVERY_SECS: u64 = 10;

/// Report finale di un pull ricorsivo.
#[derive(Debug, Default)]
pub struct PullReport {
    /// File scaricati con successo.
    pub file_count: u32,
    /// Directory remote enumerate (create localmente).
    pub dir_count: u32,
    /// Byte complessivi dei file scaricati (dimensioni remote da LIST).
    pub bytes_total: u64,
    /// Errori per-file: il pull continua sugli altri file e l'exit code
    /// finale e' 1 se non vuoto (stessa semantica di sync).
    pub errors: Vec<String>,
    /// Sotto-directory remote non leggibili (trailer LIST_RES): contenuto
    /// ignoto, segnalato come warning nel report.
    pub skipped_remote: Vec<String>,
    /// Durata complessiva.
    pub elapsed: Duration,
}

/// Join di un rel_path (separatore '/' di protocollo) sotto una directory
/// remota usando il separatore dell'OS REMOTO ('/' unix, '\' windows).
/// `join_remote_path` di sync.rs decide sul target di BUILD (l'OS del
/// client): corretto nel caso comune client-Linux/server-Windows ma
/// sbagliato su combinazioni incrociate — qui l'OS e' quello risolto
/// via INFO_RES/env dal chiamante.
fn join_remote(remote_dir: &str, rel_path: &str, remote_unix: bool) -> String {
    if rel_path.is_empty() {
        return remote_dir.to_string();
    }
    let sep = if remote_unix { "/" } else { "\\" };
    let rel_native = rel_path.replace('/', sep);
    if remote_dir.ends_with('/') || remote_dir.ends_with('\\') {
        return format!("{}{}", remote_dir, rel_native);
    }
    format!("{}{}{}", remote_dir, sep, rel_native)
}

/// Scarica ricorsivamente `remote_dir` dentro `local_dir` (la dir locale
/// E' il mirror del contenuto remoto — semantica rovesciata di `sync`).
///
/// Errori per-file non fatali: accumulati in `report.errors` e il pull
/// prosegue (un file bloccato non deve abortire gli altri). Errori di
/// protocollo sulla LIST iniziale o mkdir della root locale sono fatali.
pub async fn pull_remote_dir(
    session: &mut SyncSession,
    remote_dir: &str,
    local_dir: &Path,
    remote_unix: bool,
) -> Result<PullReport> {
    let start = Instant::now();
    let mut report = PullReport::default();

    // LIST ricorsiva della directory remota (with_hash=0: la GET fa gia'
    // verifica SHA-256 whole-file per file — niente doppio hashing remoto).
    let mut outcome = session
        .op(async |link: &mut Link| {
            sync::list_remote_dir(link, remote_dir, false, true).await
        })
        .await?;
    // Move-out del trailer skipped (entries resta usato sotto).
    report.skipped_remote = std::mem::take(&mut outcome.skipped);
    for skipped in &report.skipped_remote {
        eprintln!(
            "[pull] WARN directory remota non leggibile (contenuto saltato): {}",
            skipped
        );
    }

    // La root locale e' la directory specchio: va creata anche a remote
    // vuoto (pull di dir vuota = dir vuota, non errore).
    if let Err(e) = fs::create_dir_all(local_dir) {
        anyhow::bail!(
            "impossibile creare la directory locale {}: {}",
            local_dir.display(),
            e
        );
    }

    // Passo 1: crea tutte le directory locali (gli entry dir arrivano
    // ordinati per rel_path dal server; create_dir_all e' comunque
    // idempotente e copre ordini imprevisti).
    for entry in &outcome.entries {
        if entry.is_dir != 1 {
            continue;
        }
        let local_full = local_dir.join(&entry.rel_path);
        match fs::create_dir_all(&local_full) {
            Ok(()) => {
                report.dir_count += 1;
            }
            Err(e) => {
                let msg = format!("mkdir locale {} fallita: {}", local_full.display(), e);
                eprintln!("[pull] ERRORE {}", msg);
                report.errors.push(msg);
            }
        }
    }

    // Passo 2: GET sequenziale per ogni file sulla stessa sessione.
    // Conteggio esplicito (niente iteratori a catena, best-practice).
    let mut total_files = 0usize;
    for entry in &outcome.entries {
        if entry.is_dir == 0 {
            total_files += 1;
        }
    }
    let mut done_files: u32 = 0;
    let mut last_progress = Instant::now();
    for entry in &outcome.entries {
        if entry.is_dir == 1 {
            continue;
        }
        let remote_full = join_remote(remote_dir, &entry.rel_path, remote_unix);
        let local_full = local_dir.join(&entry.rel_path);
        // Il parent potrebbe mancare se la sua mkdir e' fallita sopra:
        // riprovare qui e' gratuito (create_dir_all idempotente) e rende
        // l'errore per-file piu' chiaro nel report.
        if let Some(parent) = local_full.parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                let msg = format!(
                    "{}: mkdir del parent {} fallita: {}",
                    entry.rel_path,
                    parent.display(),
                    e
                );
                eprintln!("[pull] ERRORE {}", msg);
                report.errors.push(msg);
                continue;
            }
        }
        let local_str = match local_full.to_str() {
            Some(s) => s.to_string(),
            None => {
                let msg = format!("path locale non UTF-8: {}", local_full.display());
                eprintln!("[pull] ERRORE {}", msg);
                report.errors.push(msg);
                continue;
            }
        };
        crate::qprintln!(
            "[pull] GET {} ({} byte) -> {}",
            entry.rel_path,
            entry.size,
            local_str
        );
        let get_result = session
            .op(async |link: &mut Link| {
                transfer::get_client(link, &remote_full, &local_str).await
            })
            .await;
        match get_result {
            Ok(()) => {
                report.file_count += 1;
                report.bytes_total += entry.size;
            }
            Err(e) => {
                // Errore per-file (es. file sparito tra LIST e GET,
                // permessi): si accumula e si prosegue — il pull completa
                // tutti i file possibili, come sync (semantica rsync).
                let msg = format!("{}: {}", entry.rel_path, e);
                eprintln!("[pull] ERRORE {}", msg);
                report.errors.push(msg);
            }
        }
        done_files += 1;
        // Progresso aggregato non-gateato (bug report: download lunghi
        // totalmente silenziosi): una riga ogni PROGRESS_EVERY_SECS.
        if last_progress.elapsed() >= Duration::from_secs(PROGRESS_EVERY_SECS) {
            eprintln!(
                "[pull] {}/{} file scaricati, {} byte",
                done_files, total_files, report.bytes_total
            );
            last_progress = Instant::now();
        }
    }

    if session.reconnects > 0 {
        crate::qprintln!("[pull] riconnessioni effettuate: {}", session.reconnects);
    }
    report.elapsed = start.elapsed();
    Ok(report)
}

/// Stampa il riepilogo finale del pull (stdout: e' il RISULTATO
/// dell'operazione richiesta, non diagnostica — mai qprintln qui).
pub fn print_pull_report(report: &PullReport, remote_dir: &str, local_dir: &Path) {
    if !report.errors.is_empty() {
        eprintln!("[pull] errori ({}):", report.errors.len());
        for err in &report.errors {
            eprintln!("  {}", err);
        }
    }
    println!(
        "get: {} file scaricati ({} byte) da {} in {} [{:.1?}]",
        report.file_count,
        report.bytes_total,
        remote_dir,
        local_dir.display(),
        report.elapsed
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_remote_unix() {
        // Remote unix: '/' come separatore, rel '/' -> '/'.
        assert_eq!(
            join_remote("/srv/app", "a/b.txt", true),
            "/srv/app/a/b.txt"
        );
        assert_eq!(join_remote("/srv/app/", "x", true), "/srv/app/x");
        assert_eq!(join_remote("/", "x", true), "/x");
    }

    #[test]
    fn join_remote_windows() {
        // Remote Windows: '\' e rel convertito. D:\ root resta intatta.
        assert_eq!(
            join_remote("D:\\dir", "a/b.txt", false),
            "D:\\dir\\a\\b.txt"
        );
        assert_eq!(join_remote("D:\\dir\\", "x", false), "D:\\dir\\x");
        assert_eq!(join_remote("D:\\", "x", false), "D:\\x");
    }

    #[test]
    fn join_remote_empty_rel() {
        assert_eq!(join_remote("/srv", "", true), "/srv");
        assert_eq!(join_remote("D:\\x", "", false), "D:\\x");
    }
}
