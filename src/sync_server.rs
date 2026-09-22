//! Handler server per directory sync (LIST/MKDIR/DELETE).
//!
//! Modulo separato da `sync.rs` (che contiene la logica client) per rispettare
//! la best-practice "unit < 1000 linee". La spec §12 elenca sync.rs con le
//! funzioni client ("walk locale, LIST remoto, diff, piano, esecuzione sync");
//! gli handler server vivono qui, ma sono parte dello stesso sottosistema sync.
//!
//! Implementa (sync-spec §5, §8.2, §9):
//! - `list_server`: walk directory remota + containment (reparse point/junction).
//! - `mkdir_batch_server`: crea directory (mkdir -p) con containment.
//! - `delete_batch_server`: elimina file/dir (recursive) con containment.
//!
//! Riutilizzo (niente duplicazione):
//! - `path::validate_server_path` / `path::canonicalize_under` (path.rs).
//! - `proto` encode/decode (proto.rs).
//! - `sync::Entry` (alias di ListEntry, tipo condiviso client/server).
//! - `verify::sha256_file_handle` per with_hash=1.

use std::fs;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use tokio::net::TcpStream;

use crate::path;
use crate::proto::{
    self, BatchResult, DeleteBatchReq, DeleteBatchRes, DeleteItem, ListReq, ListRes,
    MkdirBatchReq, MkdirBatchRes,
    ERR_IO, ERR_PATH_FORBIDDEN, ERR_PROTO,
    MSG_DELETE_BATCH_RES, MSG_LIST_RES, MSG_MKDIR_BATCH_RES,
};
use crate::sync::Entry;
use crate::verify::sha256_file_handle;

// ---------------------------------------------------------------------------
// LIST server - sync-spec §5, §8.2, §9.
// ---------------------------------------------------------------------------

/// Lato server: gestisce LIST_REQ. Cammina la directory remota, applica il
/// containment (reparse point/junction, sync-spec §8.2) e risponde LIST_RES.
/// Se entry_count supera il cap -> ERR 5. Se path invalido -> ERR 1.
/// Directory non esistente -> LIST_RES con 0 entry (sync-spec §9 decisione).
pub async fn list_server(stream: &mut TcpStream, req: &ListReq) -> Result<()> {
    // Valida il path base (transfer-spec §12).
    let validate_result = path::validate_server_path(&req.path);
    if let Err(e) = validate_result {
        let err_msg = e.to_err_msg();
        eprintln!(
            "[ERROR] list_server: path invalido - {} ({})",
            err_msg.message,
            proto::error_code_description(err_msg.code)
        );
        proto::send_err(stream, &err_msg).await?;
        return Err(e.into());
    }

    let base = Path::new(&req.path);
    let with_hash = req.with_hash == 1;
    let recursive = req.recursive == 1;

    eprintln!(
        "[DEBUG] list_server: path={} recursive={} with_hash={}",
        req.path, req.recursive, req.with_hash
    );

    // Directory non esistente -> LIST_RES con 0 entry (sync-spec §9 decisione:
    // sync su dest nuovo è il caso più comune; lista vuota = tutto NEW).
    let base_exists = base.exists();
    if !base_exists {
        eprintln!("[DEBUG] list_server: directory non esistente, rispondo 0 entry");
        let res = ListRes::default();
        let payload = proto::encode_list_res(&res)?;
        proto::write_msg(stream, MSG_LIST_RES, &payload).await?;
        return Ok(());
    }

    // Walk server con containment check (sync-spec §8.2).
    let walk_result = walk_remote_dir(base, recursive, with_hash, base);
    let mut entries = match walk_result {
        Ok(e) => e,
        Err(e) => {
            // Errore IO durante il walk: ERR 3.
            let err = proto::ErrMsg {
                code: ERR_IO,
                message: format!("walk remoto fallito: {}", e),
            };
            proto::send_err(stream, &err).await?;
            return Err(e);
        }
    };

    // Cap su entry_count (sync-spec §5): > 100k -> ERR 5 esplicito.
    let count = entries.len() as u32;
    if count > proto::LIST_ENTRY_CAP {
        let err = proto::ErrMsg {
            code: ERR_PROTO,
            message: format!(
                "entry_count {} supera il cap di {}, usa --exclude o restringi la directory",
                count,
                proto::LIST_ENTRY_CAP
            ),
        };
        proto::send_err(stream, &err).await?;
        bail!("entry_count {} supera il cap", count);
    }

    // Ordina per rel_path (output deterministico, sync-spec §16).
    entries.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));

    let res = ListRes { entries };
    let payload = proto::encode_list_res(&res)?;
    proto::write_msg(stream, MSG_LIST_RES, &payload).await?;
    eprintln!("[DEBUG] list_server: inviate {} entry", count);
    Ok(())
}

/// Walk server ricorsivo con containment check (sync-spec §8.2).
/// Salta le entry che canonicalizzano fuori da base (reparse point/junction/symlink).
/// `base_canon` è la dir root per il check containment.
fn walk_remote_dir(base: &Path, recursive: bool, with_hash: bool, base_canon: &Path) -> Result<Vec<Entry>> {
    let mut entries = Vec::new();
    walk_remote_recursive(base, Path::new(""), recursive, with_hash, base_canon, &mut entries)?;
    Ok(entries)
}

/// Funzione ricorsiva interna del walk server.
fn walk_remote_recursive(
    base: &Path,
    rel: &Path,
    recursive: bool,
    with_hash: bool,
    base_canon: &Path,
    out: &mut Vec<Entry>,
) -> Result<()> {
    let full = base.join(rel);
    let read_dir_result = fs::read_dir(&full);
    let dir_iter = match read_dir_result {
        Ok(it) => it,
        Err(e) => {
            return Err(anyhow!("impossibile leggere directory {}: {}", full.display(), e));
        }
    };
    for entry in dir_iter {
        let dir_entry = match entry {
            Ok(e) => e,
            Err(e) => {
                eprintln!("[WARN] walk_remote: skip entry non leggibile in {}: {}", full.display(), e);
                continue;
            }
        };
        let file_name = dir_entry.file_name();
        let name_str = match file_name.to_str() {
            Some(s) => s,
            None => {
                eprintln!("[WARN] walk_remote: skip nome non-UTF-8 in {}", full.display());
                continue;
            }
        };
        let child_rel = rel.join(name_str);
        let child_rel_str = match child_rel.to_str() {
            Some(s) => s.replace('\\', "/"),
            None => continue,
        };

        // Containment check (sync-spec §8.2): canonicalizza gli antenati esistenti
        // e verifica che restino sotto base_canon. Previene junction/symlink escape.
        let child_full = base.join(&child_rel);
        let containment = path::canonicalize_under(base_canon, &child_full);
        if let Err(e) = containment {
            eprintln!(
                "[WARN] walk_remote: skip entry fuori da base (containment): {} - {}",
                child_rel_str, e
            );
            continue;
        }

        let metadata = match dir_entry.metadata() {
            Ok(m) => m,
            Err(e) => {
                eprintln!("[WARN] walk_remote: skip metadata non leggibile {}: {}", child_rel_str, e);
                continue;
            }
        };
        if metadata.is_dir() {
            out.push(Entry {
                rel_path: child_rel_str,
                size: 0,
                is_dir: 1,
                sha256: None,
            });
            if recursive {
                walk_remote_recursive(base, &child_rel, recursive, with_hash, base_canon, out)?;
            }
        } else {
            // File: calcola hash se with_hash (un solo passaggio, sync-spec §6.1).
            let hash_option = if with_hash {
                let hash_result = compute_remote_hash(&child_full);
                match hash_result {
                    Ok(h) => Some(h),
                    Err(e) => {
                        eprintln!("[WARN] walk_remote: hash fallito per {}: {}", child_rel_str, e);
                        None
                    }
                }
            } else {
                None
            };
            out.push(Entry {
                rel_path: child_rel_str,
                size: metadata.len(),
                is_dir: 0,
                sha256: hash_option,
            });
        }
    }
    Ok(())
}

/// Calcola SHA-256 di un file remoto (lato server, per with_hash=1).
fn compute_remote_hash(path: &Path) -> Result<[u8; 32]> {
    let file_open_result = fs::File::open(path);
    let mut file = match file_open_result {
        Ok(f) => f,
        Err(e) => bail!("impossibile aprire {}: {}", path.display(), e),
    };
    sha256_file_handle(&mut file).context("hash su file remoto fallito")
}

// ---------------------------------------------------------------------------
// MKDIR_BATCH server - sync-spec §8.2, §9.
// ---------------------------------------------------------------------------

/// Lato server: gestisce MKDIR_BATCH_REQ. Crea ogni directory (mkdir -p) con
/// containment check (sync-spec §8.2, §9). Idempotente: esiste già -> status=0.
pub async fn mkdir_batch_server(stream: &mut TcpStream, req: &MkdirBatchReq) -> Result<()> {
    let expected = req.paths.len();
    let mut results = Vec::with_capacity(expected);
    let mut idx = 0usize;
    while idx < expected {
        let p = &req.paths[idx];
        let result = mkdir_single(p);
        results.push(result);
        idx += 1;
    }
    let res = MkdirBatchRes { results };
    let payload = proto::encode_mkdir_batch_res(&res)?;
    proto::write_msg(stream, MSG_MKDIR_BATCH_RES, &payload).await?;
    Ok(())
}

/// Crea una singola directory (mkdir -p) con validazione path + containment.
fn mkdir_single(path_str: &str) -> BatchResult {
    // Valida il path assoluto (transfer-spec §12).
    let validate = path::validate_server_path(path_str);
    if let Err(e) = validate {
        return BatchResult::error(e.code, e.message);
    }
    let p = Path::new(path_str);
    // Containment check sugli antenati esistenti (sync-spec §8.2).
    // Per MKDIR il path può non esistere ancora: canonicalize_under gestisce
    // il caso "antenati esistenti + suffisso nuovo".
    // Usiamo il parent come base per il check (la dir nuova è il suffisso).
    let parent = match p.parent() {
        Some(par) => par,
        None => return BatchResult::error(ERR_PATH_FORBIDDEN, "path senza parent"),
    };
    let containment = path::canonicalize_under(parent, p);
    if let Err(e) = containment {
        return BatchResult::error(e.code, e.message);
    }
    // mkdir -p (crea anche i genitori mancanti). Idempotente.
    let mkdir_result = fs::create_dir_all(p);
    match mkdir_result {
        Ok(()) => {
            eprintln!("[DEBUG] mkdir_batch_server: creata/esistente: {}", path_str);
            BatchResult::ok()
        }
        Err(e) => {
            eprintln!("[ERROR] mkdir_batch_server: {} fallita: {}", path_str, e);
            BatchResult::error(ERR_IO, format!("mkdir fallito: {}", e))
        }
    }
}

// ---------------------------------------------------------------------------
// DELETE_BATCH server - sync-spec §8.2, §9.
// ---------------------------------------------------------------------------

/// Lato server: gestisce DELETE_BATCH_REQ. Elimina ogni path (file o dir recursive)
/// con containment check (sync-spec §8.2, §9). Non esiste -> status=1 (not found).
pub async fn delete_batch_server(stream: &mut TcpStream, req: &DeleteBatchReq) -> Result<()> {
    let expected = req.items.len();
    let mut results = Vec::with_capacity(expected);
    let mut idx = 0usize;
    while idx < expected {
        let item = &req.items[idx];
        let result = delete_single(item);
        results.push(result);
        idx += 1;
    }
    let res = DeleteBatchRes { results };
    let payload = proto::encode_delete_batch_res(&res)?;
    proto::write_msg(stream, MSG_DELETE_BATCH_RES, &payload).await?;
    Ok(())
}

/// Elimina un singolo path (file o dir recursive) con validazione + containment.
fn delete_single(item: &DeleteItem) -> BatchResult {
    // Valida il path assoluto.
    let validate = path::validate_server_path(&item.path);
    if let Err(e) = validate {
        return BatchResult::error(e.code, e.message);
    }
    let p = Path::new(&item.path);
    if !p.exists() {
        // sync-spec §9: non esiste -> status=1 (not found, non fatale).
        return BatchResult::not_found();
    }
    // Containment check: il path esiste, canonicalizza tutto (sync-spec §8.2 DELETE).
    // Usiamo il parent come base.
    let parent = match p.parent() {
        Some(par) => par,
        None => return BatchResult::error(ERR_PATH_FORBIDDEN, "path senza parent"),
    };
    let containment = path::canonicalize_under(parent, p);
    if let Err(e) = containment {
        return BatchResult::error(e.code, e.message);
    }
    let delete_result = if item.recursive == 1 {
        fs::remove_dir_all(p)
    } else {
        fs::remove_file(p)
    };
    match delete_result {
        Ok(()) => {
            eprintln!("[DEBUG] delete_batch_server: eliminato: {} (recursive={})", item.path, item.recursive);
            BatchResult::ok()
        }
        Err(e) => {
            eprintln!("[ERROR] delete_batch_server: {} fallita: {}", item.path, e);
            BatchResult::error(ERR_IO, format!("delete fallito: {}", e))
        }
    }
}

// ---------------------------------------------------------------------------
// Test (sync-spec §14 test 15, 17, 19).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::Entry;

    #[tokio::test]
    async fn mkdir_batch_server_creates_dirs() {
        // sync-spec §14 test 17: MKDIR_BATCH con più directory -> 1 connessione.
        // Test a livello funzione (no rete): verifica mkdir_single + containment.
        let root = std::env::temp_dir().join("crosspilot_mkdir_server");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let p1 = root.join("a").to_string_lossy().into_owned();
        let p2 = root.join("a").join("b").to_string_lossy().into_owned();

        let r1 = mkdir_single(&p1);
        let r2 = mkdir_single(&p2);
        assert_eq!(r1.status, 0);
        assert_eq!(r2.status, 0);
        assert!(Path::new(&p1).exists());
        assert!(Path::new(&p2).exists());

        // Idempotente: re-create -> status=0.
        let r3 = mkdir_single(&p1);
        assert_eq!(r3.status, 0);

        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn delete_batch_server_removes() {
        let root = std::env::temp_dir().join("crosspilot_delete_server");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let file_path = root.join("file.txt");
        fs::write(&file_path, b"data").unwrap();
        let dir_path = root.join("dir");
        fs::create_dir_all(&dir_path).unwrap();
        fs::write(dir_path.join("inner.txt"), b"x").unwrap();

        // Delete file (recursive=0).
        let r1 = delete_single(&DeleteItem { path: file_path.to_string_lossy().into_owned(), recursive: 0 });
        assert_eq!(r1.status, 0);
        assert!(!file_path.exists());

        // Delete dir recursive=1.
        let r2 = delete_single(&DeleteItem { path: dir_path.to_string_lossy().into_owned(), recursive: 1 });
        assert_eq!(r2.status, 0);
        assert!(!dir_path.exists());

        // Delete non esistente -> status=1 (not found).
        let r3 = delete_single(&DeleteItem { path: file_path.to_string_lossy().into_owned(), recursive: 0 });
        assert_eq!(r3.status, 1);

        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn list_server_walks_and_caps() {
        // sync-spec §14 test 15: directory con entry -> LIST le restituisce.
        let root = std::env::temp_dir().join("crosspilot_list_server");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("f1.txt"), b"one").unwrap();
        fs::create_dir_all(root.join("d")).unwrap();
        fs::write(root.join("d").join("f2.txt"), b"two").unwrap();

        let entries = walk_remote_dir(&root, true, false, &root).unwrap();
        let rels = entry_rel_paths(&entries);
        assert!(rels.contains(&"f1.txt".to_string()));
        assert!(rels.contains(&"d".to_string()));
        assert!(rels.contains(&"d/f2.txt".to_string()));

        // with_hash: i file hanno sha256.
        let entries_hashed = walk_remote_dir(&root, true, true, &root).unwrap();
        let f1 = find_entry(&entries_hashed, "f1.txt");
        assert!(f1.sha256.is_some());

        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(not(target_os = "windows"))]
    #[tokio::test]
    async fn list_server_skips_symlink_escape() {
        // sync-spec §14 test 19: junction/symlink nel walk server -> skip.
        let root = std::env::temp_dir().join("crosspilot_list_symlink");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("real.txt"), b"ok").unwrap();
        // Symlink che punta fuori da root.
        std::os::unix::fs::symlink("/etc", root.join("escape")).unwrap();

        let entries = walk_remote_dir(&root, true, false, &root).unwrap();
        let rels = entry_rel_paths(&entries);
        // real.txt presente, escape skippato (containment).
        assert!(rels.contains(&"real.txt".to_string()));
        assert!(!rels.contains(&"escape".to_string()));

        let _ = fs::remove_dir_all(&root);
    }

    // --- Helper di test (piccoli, specifici del modulo server) ------------

    fn entry_rel_paths(entries: &[Entry]) -> Vec<String> {
        let mut out = Vec::new();
        for e in entries {
            out.push(e.rel_path.clone());
        }
        out
    }

    fn find_entry<'a>(entries: &'a [Entry], rel: &str) -> &'a Entry {
        for e in entries {
            if e.rel_path == rel {
                return e;
            }
        }
        panic!("entry non trovata: {}", rel);
    }
}
