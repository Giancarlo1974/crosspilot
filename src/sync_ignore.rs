//! File `.crosspilotignore` nella directory sorgente di sync/status.
//!
//! Pattern glob di esclusione caricati automaticamente accanto al source,
//! con la stessa sintassi di `--exclude` (una riga = un pattern, `#` =
//! commento, righe vuote ignorate). E' l'alternativa generale all'idea di
//! un `--exclude-defaults` hardcoded (suggerimento utente: saltare sempre
//! `certs/`, `data/`, `logs/`, `www/` sui deploy docker): ogni progetto
//! dichiara i propri esclusi nel file, senza flag ripetitivi e senza
//! nomi di directory fissi nel tool.
//!
//! Il file ignore e' metadato client-side: il suo rel_path viene
//! aggiunto automaticamente ai pattern — non e' mai trasferito ne'
//! candidato a delete (come `.gitignore` non e' parte del sync rsync).

use std::path::Path;

/// Nome del file ignore cercato nella radice del source.
pub const IGNORE_FILE: &str = ".crosspilotignore";

/// Legge i pattern da `<local_dir>/.crosspilotignore`.
/// File assente o illeggibile -> solo il pattern del file stesso
/// (nessun errore: l'ignore e' opzionale).
pub fn load_ignore_patterns(local_dir: &Path) -> Vec<String> {
    let mut patterns: Vec<String> = Vec::new();
    let ignore_path = local_dir.join(IGNORE_FILE);
    let content = std::fs::read_to_string(&ignore_path);
    match content {
        Ok(text) => {
            for line in text.lines() {
                let pat = line.trim();
                if pat.is_empty() || pat.starts_with('#') {
                    continue;
                }
                patterns.push(pat.to_string());
            }
            crate::qprintln!(
                "[DEBUG] {}: {} pattern di esclusione caricati",
                ignore_path.display(),
                patterns.len()
            );
        }
        Err(_) => {
            // Assente/illeggibile: nessun pattern dal file (opzionale).
            crate::qprintln!("[DEBUG] {}: assente, nessuna esclusione da file", IGNORE_FILE);
        }
    }
    // Il file ignore stesso non entra mai nel sync (metadato, non payload).
    patterns.push(IGNORE_FILE.to_string());
    patterns
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn ignore_file_loaded_and_self_excluded() {
        let root = std::env::temp_dir().join("crosspilot_ignore_test");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join(IGNORE_FILE),
            "# commento\ncerts/\ndata/\n\n*.log\n",
        )
        .unwrap();

        let pats = load_ignore_patterns(&root);
        // 3 pattern dal file + il file stesso auto-escluso.
        assert!(pats.contains(&"certs/".to_string()));
        assert!(pats.contains(&"data/".to_string()));
        assert!(pats.contains(&"*.log".to_string()));
        assert!(pats.contains(&IGNORE_FILE.to_string()));
        assert_eq!(pats.len(), 4);
        // Il pattern "certs/" deve matchare il subtree (stessa semantica
        // di --exclude): verifica rapida con is_excluded di sync.rs.
        assert!(crate::sync::is_excluded("certs/ca.pem", &pats));
        assert!(crate::sync::is_excluded("x/debug.log", &pats));
        assert!(!crate::sync::is_excluded("app.conf", &pats));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn ignore_file_absent_is_noop() {
        let root = std::env::temp_dir().join("crosspilot_ignore_absent");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let pats = load_ignore_patterns(&root);
        assert_eq!(pats, vec![IGNORE_FILE.to_string()]);
        let _ = fs::remove_dir_all(&root);
    }
}
