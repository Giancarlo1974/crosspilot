//! Validazione dei path per il transfer file (spec §12).
//!
//! Regole:
//! - **Server (Windows):** solo path assoluti con lettera di unità (`C:\...`).
//!   Rifiuta path relativi, `..` (dopo normalizzazione), UNC (`\\host`).
//! - **Server (Linux, per test locali):** path assoluto (`/...`), niente `..`.
//! - **Client (Linux):** path locale normale; `..` consentito (macchina dell'utente).
//!   `local_src` per `put` deve esistere.

use std::path::{Path, PathBuf};

use crate::proto::{TransferError, ERR_FILE_NOT_FOUND, ERR_PATH_FORBIDDEN};

/// Valida un path lato server (la destinazione/sorgente remota).
///
/// Su Windows richiede path assoluto con lettera di unità, niente UNC, niente `..`.
/// Su Linux (per test locali) richiede path assoluto, niente `..`.
/// Ritorna `Err(TransferError)` con codice `ERR_PATH_FORBIDDEN` se il path è invalido.
pub fn validate_server_path(path: &str) -> Result<(), TransferError> {
    // Rifiuta path vuoto.
    if path.is_empty() {
        return Err(TransferError::new(
            ERR_PATH_FORBIDDEN,
            "path vuoto",
        ));
    }

    #[cfg(target_os = "windows")]
    {
        validate_server_path_windows(path)
    }
    #[cfg(not(target_os = "windows"))]
    {
        validate_server_path_linux(path)
    }
}

/// Validazione path server su Windows.
#[cfg(target_os = "windows")]
fn validate_server_path_windows(path: &str) -> Result<(), TransferError> {
    // Rifiuta UNC: path che iniziano con "\\" (es. \\host\share).
    if path.starts_with(r"\\") {
        return Err(TransferError::new(
            ERR_PATH_FORBIDDEN,
            format!("path UNC non consentito: {}", path),
        ));
    }

    // Richiede lettera di unità: pattern <lettera>:\  (es. C:\).
    let bytes = path.as_bytes();
    if bytes.len() < 3 {
        return Err(TransferError::new(
            ERR_PATH_FORBIDDEN,
            format!("path non assoluto (manca lettera di unità): {}", path),
        ));
    }
    let is_drive_letter = bytes[0].is_ascii_alphabetic();
    let has_colon_backslash = bytes[1] == b':' && (bytes[2] == b'\\' || bytes[2] == b'/');
    if !is_drive_letter || !has_colon_backslash {
        return Err(TransferError::new(
            ERR_PATH_FORBIDDEN,
            format!("path non assoluto (richiesto <lettera>:\\...): {}", path),
        ));
    }

    // Rifiuta componenti ".." dopo normalizzazione (no escape directory).
    if contains_parent_component(path) {
        return Err(TransferError::new(
            ERR_PATH_FORBIDDEN,
            format!("path contiene '..' non consentito: {}", path),
        ));
    }

    Ok(())
}

/// Validazione path server su Linux (per test locali su stessa macchina).
#[cfg(not(target_os = "windows"))]
fn validate_server_path_linux(path: &str) -> Result<(), TransferError> {
    // Richiede path assoluto (inizia con '/').
    if !path.starts_with('/') {
        return Err(TransferError::new(
            ERR_PATH_FORBIDDEN,
            format!("path non assoluto (richiesto /...): {}", path),
        ));
    }

    // Rifiuta componenti ".." dopo normalizzazione.
    if contains_parent_component(path) {
        return Err(TransferError::new(
            ERR_PATH_FORBIDDEN,
            format!("path contiene '..' non consentito: {}", path),
        ));
    }

    Ok(())
}

/// Verifica se il path contiene una componente ".." (dopo normalizzazione dei separatori).
/// Usa std::path::Path::components che normalizza sia '/' che '\' su Windows.
/// Pubblica perché riusata da sync.rs (validate_rel_path) e dal server sync.
pub fn contains_parent_component(path: &str) -> bool {
    let p = Path::new(path);
    // Itera sulle componenti normalizzate; Parent == "..".
    for comp in p.components() {
        if comp == std::path::Component::ParentDir {
            return true;
        }
    }
    false
}

/// Verifica che il file sorgente locale (lato client, per `put`) esista.
/// Ritorna `Err(TransferError)` con codice `ERR_FILE_NOT_FOUND` se manca.
pub fn require_local_file_exists(path: &str) -> Result<(), TransferError> {
    let p = Path::new(path);
    if !p.exists() {
        return Err(TransferError::new(
            ERR_FILE_NOT_FOUND,
            format!("file locale non trovato: {}", path),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Estensioni sync (sync-spec §8).
// ---------------------------------------------------------------------------

/// Verifica che una directory locale (lato client, per status/sync) esista
/// e sia una directory. Ritorna `Err(TransferError)` con codice `ERR_FILE_NOT_FOUND`
/// (sync-spec §13: ERR 2 = local_dir non esiste o non è una directory).
pub fn require_local_dir_exists(path: &str) -> Result<(), TransferError> {
    let p = Path::new(path);
    if !p.exists() {
        return Err(TransferError::new(
            ERR_FILE_NOT_FOUND,
            format!("directory locale non trovata: {}", path),
        ));
    }
    if !p.is_dir() {
        return Err(TransferError::new(
            ERR_FILE_NOT_FOUND,
            format!("path locale non è una directory: {}", path),
        ));
    }
    Ok(())
}

/// Valida un rel_path (path relativo normalizzato con '/') restituito da LIST_RES
/// o costruito dal walk locale, per prevenire escape `..` quando il server lo joina
/// al remote_dir. sync-spec §8: un rel_path malevolo come `../../etc/passwd` non
/// deve escapare dal remote_dir.
///
/// Ritorna `Err(TransferError)` con codice `ERR_PATH_FORBIDDEN` se il rel_path
/// contiene una componente `..`.
pub fn validate_rel_path(rel_path: &str) -> Result<(), TransferError> {
    // Un rel_path vuoto è valido (rappresenta la dir base stessa).
    if rel_path.is_empty() {
        return Ok(());
    }
    // Il rel_path usa '/' come separatore (protocollo), ma contains_parent_component
    // normalizza entrambi '/' e '\' via Path::components, quindi è robusto.
    if contains_parent_component(rel_path) {
        return Err(TransferError::new(
            ERR_PATH_FORBIDDEN,
            format!("rel_path contiene '..' non consentito: {}", rel_path),
        ));
    }
    Ok(())
}

/// Verifica se una componente di nome file/directory è un nome riservato Windows
/// o ha trailing '.' / spazio che Windows striperebbe (causando collisioni).
/// sync-spec §8.3: CON, PRN, AUX, NUL, COM1-COM9, LPT1-LPT9 (case-insensitive),
/// più trailing '.' o spazio.
///
/// Restituisce `Some(motivo)` se il nome è invalido su Windows, `None` se ok.
/// Il motivo è una descrizione statica utile per il report (SKIP ...).
pub fn is_windows_reserved_name(name: &str) -> Option<&'static str> {
    // Trailing '.' o spazio: Windows li strip -> "file.txt." diventa "file.txt"
    // e collide silenziosamente con un eventuale "file.txt" già presente.
    if name.ends_with('.') {
        return Some("trailing . non valido su Windows");
    }
    if name.ends_with(' ') {
        return Some("trailing spazio non valido su Windows");
    }
    // Per i nomi riservati Windows considera la parte prima del primo '.':
    // "CON.txt" è riservato come "CON" (device name). Estrae lo stem.
    let stem = match name.find('.') {
        Some(pos) => &name[..pos],
        None => name,
    };
    let upper = stem.to_ascii_uppercase();
    // Lista nomi riservati (sync-spec §8.3).
    let reserved = [
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    for r in reserved {
        if upper == *r {
            return Some("nome riservato Windows");
        }
    }
    None
}

/// Verifica che ogni componente di un rel_path sia un nome valido su Windows.
/// Ritorna `Some((componente, motivo))` alla prima componente invalida, `None` se ok.
/// Usato dal walk locale per skippare file con nomi non validi su Windows.
pub fn rel_path_windows_invalid(rel_path: &str) -> Option<(String, &'static str)> {
    // Split sul separatore '/' del protocollo.
    let parts = rel_path.split('/');
    for part in parts {
        if part.is_empty() {
            // Componente vuota (es. path che inizia con '/' o '//') -> skip.
            continue;
        }
        let invalid = is_windows_reserved_name(part);
        if let Some(reason) = invalid {
            return Some((part.to_string(), reason));
        }
    }
    None
}

/// Verifica che un path joinato (remote_dir + rel_path) resti contenuto in
/// remote_dir dopo canonicalizzazione, prevenendo escape via reparse point /
/// junction / symlink. sync-spec §8.2.
///
/// Fasi:
/// 1. Canonicalizza la porzione più lunga del path che esiste su disco.
///    Verifica che il prefisso canonicalizzato inizi con remote_dir canonicalizzato.
/// 2. Sulle componenti non ancora esistenti (suffisso), applica contains_parent_component.
///
/// Motivo: `std::fs::canonicalize` fallisce su path non esistenti. MKDIR_BATCH
/// crea directory nuove che non esistono ancora — canonicalizzare il path
/// completo darebbe errore su ogni mkdir nuovo. Canonicalizzare solo gli antenati
/// esistenti + check `..` sul resto risolve sia "path già esiste con junction"
/// sia "path nuovo da creare".
///
/// Ritorna `Ok(())` se contenuto, `Err(TransferError)` (ERR_PATH_FORBIDDEN) se escape.
pub fn canonicalize_under(remote_dir: &Path, joined: &Path) -> Result<(), TransferError> {
    // Canonicalizza remote_dir (deve esistere per LIST/DELETE; per MKDIR su dest
    // nuovo può non esistere, in quel caso il chiamante gestisce la creazione).
    let canon_base_result = std::fs::canonicalize(remote_dir);
    let canon_base = match canon_base_result {
        Ok(p) => p,
        Err(_) => {
            // remote_dir non esiste: non possiamo canonicalizzare il base.
            // Ci affidiamo solo al check '..' sul joined (le componenti nuove
            // non possono essere junction perché non esistono ancora).
            let joined_str = joined.to_string_lossy().into_owned();
            if contains_parent_component(&joined_str) {
                return Err(TransferError::new(
                    ERR_PATH_FORBIDDEN,
                    format!("path contiene '..' non consentito: {}", joined.display()),
                ));
            }
            return Ok(());
        }
    };

    // Trova l'antenato più lungo di `joined` che esiste su disco.
    // Risale da `joined` verso l'alto finché trova un path esistente.
    let existing_ancestor = find_longest_existing_ancestor(joined);

    let canon_existing = match existing_ancestor {
        Some(ancestor) => {
            // Canonicalizza l'antenato esistente (può risolvere junction/symlink).
            let canon_result = std::fs::canonicalize(&ancestor);
            match canon_result {
                Ok(p) => p,
                Err(_) => {
                    // Non riusciamo a canonicalizzare: fallback al check '..'.
                    let joined_str = joined.to_string_lossy().into_owned();
                    if contains_parent_component(&joined_str) {
                        return Err(TransferError::new(
                            ERR_PATH_FORBIDDEN,
                            format!("path contiene '..' non consentito: {}", joined.display()),
                        ));
                    }
                    return Ok(());
                }
            }
        }
        None => {
            // Nessun antenato esiste (nemmeno la root?): fallback check '..'.
            let joined_str = joined.to_string_lossy().into_owned();
            if contains_parent_component(&joined_str) {
                return Err(TransferError::new(
                    ERR_PATH_FORBIDDEN,
                    format!("path contiene '..' non consentito: {}", joined.display()),
                ));
            }
            return Ok(());
        }
    };

    // Verifica che l'antenato canonicalizzato sia sotto canon_base.
    if !is_under(&canon_existing, &canon_base) {
        return Err(TransferError::new(
            ERR_PATH_FORBIDDEN,
            format!(
                "path canonicalizzato fuori da remote_dir: {} non è sotto {}",
                canon_existing.display(),
                canon_base.display()
            ),
        ));
    }

    // Suffisso non esistente: le componenti tra canon_existing e joined.
    // Check '..' su queste componenti (una junction non può esistere su path
    // non ancora creati, ma '..' sì se malevolo).
    let suffix = match canon_existing.strip_prefix(&canon_base) {
        Ok(rel) => rel.to_path_buf(),
        Err(_) => PathBuf::new(),
    };
    // Costruisce il path relativo completo dal base al joined e verifica '..'.
    // Usiamo la rappresentazione stringa del joined per il check finale.
    let joined_str = joined.to_string_lossy().into_owned();
    if contains_parent_component(&joined_str) {
        return Err(TransferError::new(
            ERR_PATH_FORBIDDEN,
            format!("path contiene '..' non consentito: {}", joined.display()),
        ));
    }

    // Debug: il suffix è stato calcolato per tracciabilità (best-practice: log).
    eprintln!(
        "[DEBUG] canonicalize_under: base={} canon_existing={} suffix={} -> ok",
        canon_base.display(),
        canon_existing.display(),
        suffix.display()
    );
    Ok(())
}

/// Trova l'antenato più lungo (partendo dal path stesso) che esiste su disco.
/// Ritorna None se nemmeno la root esiste (caso patologico).
fn find_longest_existing_ancestor(path: &Path) -> Option<PathBuf> {
    let mut current = path.to_path_buf();
    loop {
        if current.exists() {
            return Some(current);
        }
        match current.parent() {
            Some(parent) => current = parent.to_path_buf(),
            None => return None, // raggiunta la root senza trovare nulla.
        }
    }
}

/// Verifica che `child` sia contenuto in `parent` (o uguale).
/// Confronto path-based (componenti), non string-based.
fn is_under(child: &Path, parent: &Path) -> bool {
    // Se child == parent, è contenuto (la dir base stessa).
    if child == parent {
        return true;
    }
    // strip_prefix ritorna Ok(rel) se child inizia con parent.
    let stripped = child.strip_prefix(parent);
    stripped.is_ok()
}

// ---------------------------------------------------------------------------
// Test (spec §17 passo 3).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn server_linux_absolute_ok() {
        assert!(validate_server_path("/tmp/remote.bin").is_ok());
        assert!(validate_server_path("/var/log/app.log").is_ok());
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn server_linux_relative_rejected() {
        let err = validate_server_path("relative/path.bin").unwrap_err();
        assert_eq!(err.code, ERR_PATH_FORBIDDEN);
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn server_linux_parent_rejected() {
        // /tmp/../remote.bin deve essere rifiutato (spec test 7).
        let err = validate_server_path("/tmp/../remote.bin").unwrap_err();
        assert_eq!(err.code, ERR_PATH_FORBIDDEN);
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn server_linux_empty_rejected() {
        let err = validate_server_path("").unwrap_err();
        assert_eq!(err.code, ERR_PATH_FORBIDDEN);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn server_windows_absolute_ok() {
        assert!(validate_server_path(r"C:\ci\app.exe").is_ok());
        assert!(validate_server_path(r"D:\logs\app.log").is_ok());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn server_windows_relative_rejected() {
        let err = validate_server_path(r"relative\path.bin").unwrap_err();
        assert_eq!(err.code, ERR_PATH_FORBIDDEN);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn server_windows_parent_rejected() {
        let err = validate_server_path(r"C:\ci\..\app.exe").unwrap_err();
        assert_eq!(err.code, ERR_PATH_FORBIDDEN);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn server_windows_unc_rejected() {
        let err = validate_server_path(r"\\host\share\app.exe").unwrap_err();
        assert_eq!(err.code, ERR_PATH_FORBIDDEN);
    }

    #[test]
    fn local_file_missing_rejected() {
        let err = require_local_file_exists("/non/esiste/qui/12345.bin").unwrap_err();
        assert_eq!(err.code, ERR_FILE_NOT_FOUND);
    }

    #[test]
    fn local_file_existing_ok() {
        // Un file che esiste sempre: il binario del test stesso non è garantito,
        // ma /tmp di solito esiste come directory. Usiamo Cargo.toml relativo al crate.
        let path = env!("CARGO_MANIFEST_DIR").to_string() + "/Cargo.toml";
        assert!(require_local_file_exists(&path).is_ok());
    }

    // --- Test sync (sync-spec §15 passo 2) --------------------------------

    #[test]
    fn validate_rel_path_ok() {
        assert!(validate_rel_path("").is_ok());
        assert!(validate_rel_path("app.exe").is_ok());
        assert!(validate_rel_path("lib/core.dll").is_ok());
        assert!(validate_rel_path("a/b/c/d.txt").is_ok());
    }

    #[test]
    fn validate_rel_path_rejects_parent() {
        // sync-spec §14 test 11: rel_path malevolo ../../etc/passwd -> ERR 1.
        let err = validate_rel_path("../../etc/passwd").unwrap_err();
        assert_eq!(err.code, ERR_PATH_FORBIDDEN);
        let err = validate_rel_path("a/../../b").unwrap_err();
        assert_eq!(err.code, ERR_PATH_FORBIDDEN);
        let err = validate_rel_path("../escape").unwrap_err();
        assert_eq!(err.code, ERR_PATH_FORBIDDEN);
    }

    #[test]
    fn require_local_dir_exists_ok() {
        // CARGO_MANIFEST_DIR è sempre una directory esistente durante i test.
        let dir = env!("CARGO_MANIFEST_DIR").to_string();
        assert!(require_local_dir_exists(&dir).is_ok());
    }

    #[test]
    fn require_local_dir_missing_rejected() {
        let err = require_local_dir_exists("/non/esiste/questa/dir/12345").unwrap_err();
        assert_eq!(err.code, ERR_FILE_NOT_FOUND);
    }

    #[test]
    fn require_local_dir_rejects_file() {
        // Un file (non directory) -> ERR 2.
        let file_path = env!("CARGO_MANIFEST_DIR").to_string() + "/Cargo.toml";
        let err = require_local_dir_exists(&file_path).unwrap_err();
        assert_eq!(err.code, ERR_FILE_NOT_FOUND);
    }

    #[test]
    fn windows_reserved_names_detected() {
        // Nomi riservati base (case-insensitive).
        assert!(is_windows_reserved_name("CON").is_some());
        assert!(is_windows_reserved_name("con").is_some());
        assert!(is_windows_reserved_name("PRN").is_some());
        assert!(is_windows_reserved_name("AUX").is_some());
        assert!(is_windows_reserved_name("NUL").is_some());
        assert!(is_windows_reserved_name("COM1").is_some());
        assert!(is_windows_reserved_name("lpt9").is_some());
        // CON.txt è riservato (Windows considera lo stem).
        assert!(is_windows_reserved_name("CON.txt").is_some());
        assert!(is_windows_reserved_name("LPT1.log").is_some());
    }

    #[test]
    fn windows_reserved_names_trailing_dot_space() {
        // sync-spec §8.3: trailing '.' o spazio.
        assert!(is_windows_reserved_name("old.").is_some());
        assert!(is_windows_reserved_name("file ").is_some());
        assert!(is_windows_reserved_name("file.txt.").is_some());
    }

    #[test]
    fn windows_reserved_names_normal_ok() {
        // Nomi normali non sono riservati.
        assert!(is_windows_reserved_name("app.exe").is_none());
        assert!(is_windows_reserved_name("README.md").is_none());
        assert!(is_windows_reserved_name("lib").is_none());
        assert!(is_windows_reserved_name("COM10").is_none()); // COM10 non è riservato
        assert!(is_windows_reserved_name("config.json").is_none());
    }

    #[test]
    fn rel_path_windows_invalid_detects_component() {
        // sync-spec §14 test 20: nome riservato nel source -> rilevato.
        let res = rel_path_windows_invalid("artifacts/CON.txt");
        assert!(res.is_some());
        let (comp, reason) = res.unwrap();
        assert_eq!(comp, "CON.txt");
        assert!(reason.contains("riservato"));

        let res = rel_path_windows_invalid("artifacts/old.");
        assert!(res.is_some());
        let (comp, _reason) = res.unwrap();
        assert_eq!(comp, "old.");
    }

    #[test]
    fn rel_path_windows_invalid_normal_ok() {
        assert!(rel_path_windows_invalid("artifacts/app.exe").is_none());
        assert!(rel_path_windows_invalid("a/b/c").is_none());
    }

    #[test]
    fn canonicalize_under_ok_for_existing() {
        // Crea una dir temporanea e un file dentro: canonicalize_under ok.
        let base = std::env::temp_dir().join("crosspilot_canon_under_test");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let inner = base.join("sub");
        std::fs::create_dir_all(&inner).unwrap();
        // Path esistente sotto base -> ok.
        let result = canonicalize_under(&base, &inner);
        assert!(result.is_ok());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn canonicalize_under_ok_for_new_path() {
        // Path non ancora esistente sotto base -> ok (no junction possibile).
        let base = std::env::temp_dir().join("crosspilot_canon_under_new");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let new_path = base.join("new").join("deeper").join("file.txt");
        let result = canonicalize_under(&base, &new_path);
        assert!(result.is_ok());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn canonicalize_under_detects_symlink_escape() {
        // sync-spec §14 test 19: symlink che punta fuori da remote_dir.
        let base = std::env::temp_dir().join("crosspilot_canon_symlink_test");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        // Crea un symlink dentro base che punta a /etc (fuori da base).
        let link = base.join("escape");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink("/etc", &link).unwrap();
        // canonicalize_under dovrebbe rilevare l'escape.
        let result = canonicalize_under(&base, &link);
        assert!(result.is_err(), "symlink escape non rilevato");
        let err = result.unwrap_err();
        assert_eq!(err.code, ERR_PATH_FORBIDDEN);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn canonicalize_under_rejects_parent_component() {
        let base = std::env::temp_dir().join("crosspilot_canon_parent_test");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        // Path con '..' che escaperebbe.
        let escape = base.join("..").join("..").join("etc").join("passwd");
        let result = canonicalize_under(&base, &escape);
        assert!(result.is_err());
        let _ = std::fs::remove_dir_all(&base);
    }
}
