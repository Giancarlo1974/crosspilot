//! Validazione dei path per il transfer file (spec §12).
//!
//! Regole:
//! - **Server (Windows):** solo path assoluti con lettera di unità (`C:\...`).
//!   Rifiuta path relativi, `..` (dopo normalizzazione), UNC (`\\host`).
//! - **Server (Linux, per test locali):** path assoluto (`/...`), niente `..`.
//! - **Client (Linux):** path locale normale; `..` consentito (macchina dell'utente).
//!   `local_src` per `put` deve esistere.

use std::path::Path;

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
fn contains_parent_component(path: &str) -> bool {
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
}
