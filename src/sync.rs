//! Directory sync (mirror one-way) e status (diff read-only).
//!
//! Implementa `docs/sync-spec.md`:
//! - `status`: diff read-only tra directory locale e remota (new/changed/missing/identical/conflict).
//! - `sync`: mirror one-way (source -> dest) che trasferisce solo i file nuovi/modificati
//!   via delta rsync (riutilizza `put_client`) e opzionalmente cancella i file extra sul dest.
//!
//! Una connessione = una operazione (come put/get). Sync orchestra connessioni sequenziali:
//! 1 connessione per LIST, 1 per ogni put, 1 per MKDIR_BATCH, 1 per DELETE_BATCH file,
//! 1 per DELETE_BATCH dir. Niente connessioni parallele (best-practice).
//!
//! Riutilizzo (niente duplicazione):
//! - `put_client` (transfer.rs): chiamato per ogni file da trasferire. Invariato.
//! - `connect_and_handshake` (main.rs): chiamato per ogni connessione.
//! - `validate_server_path` / `canonicalize_under` (path.rs): validazione remote_dir.
//! - `sha256_file_handle` (verify.rs): per `--checksum` lato client.

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use tokio::net::TcpStream;

use crate::path;
use crate::proto::{
    self, DeleteBatchReq, DeleteItem, ListEntry, ListReq,
    MkdirBatchReq,
    MSG_DELETE_BATCH_RES, MSG_ERR, MSG_LIST_RES, MSG_MKDIR_BATCH_RES,
};
use crate::verify::sha256_file_handle;

// ---------------------------------------------------------------------------
// Tipi dati condivisi.
// ---------------------------------------------------------------------------

/// Entry di filesystem (locale o remoto). Riutilizza ListEntry del protocollo
/// per evitare duplicazione: rel_path + size + is_dir + sha256 opzionale.
pub type Entry = ListEntry;

/// Risultato del walk locale: entry valide + entry skippate (non-UTF8, riservate Windows).
#[derive(Debug, Default)]
pub struct WalkResult {
    /// Entry valide (file e directory), ordinate per rel_path.
    pub entries: Vec<Entry>,
    /// Path skippati perché il nome non è UTF-8 valido (sync-spec §16).
    pub skipped_non_utf8: Vec<String>,
    /// Path skippati perché contengono nomi riservati Windows (sync-spec §8.3).
    pub skipped_reserved: Vec<(String, &'static str)>,
}

/// Stato di una entry nel diff (sync-spec §6, §10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryStatus {
    /// In local, non in remote.
    New,
    /// In entrambi, size diversa (o hash diverso con --checksum).
    Changed,
    /// In remote, non in local.
    Missing,
    /// In entrambi, size uguale (e hash uguale con --checksum).
    Identical,
    /// is_dir diverso (file vs dir) o case collision Windows (sync-spec §8.1).
    Conflict,
}

/// Singola entry del diff con stato e riferimenti locale/remoto.
#[derive(Debug, Clone)]
pub struct DiffEntry {
    pub rel_path: String,
    pub status: EntryStatus,
    pub local: Option<Entry>,
    pub remote: Option<Entry>,
    /// Motivo del conflict (vuoto se non conflict).
    pub conflict_reason: String,
}

/// Diff completo tra locale e remoto (output di compute_diff, usato da status e sync).
#[derive(Debug, Default)]
pub struct Diff {
    /// Entry ordinate per rel_path.
    pub entries: Vec<DiffEntry>,
    pub skipped_non_utf8: Vec<String>,
    pub skipped_reserved: Vec<(String, &'static str)>,
}

impl Diff {
    /// Conta le entry per stato (per il riepilogo numerico).
    pub fn counts(&self) -> DiffCounts {
        let mut counts = DiffCounts::default();
        for e in &self.entries {
            match e.status {
                EntryStatus::New => counts.new += 1,
                EntryStatus::Changed => counts.changed += 1,
                EntryStatus::Missing => counts.missing += 1,
                EntryStatus::Identical => counts.identical += 1,
                EntryStatus::Conflict => counts.conflict += 1,
            }
        }
        counts
    }
}

/// Conteggi per stato (per riepilogo output).
#[derive(Debug, Default, Clone, Copy)]
pub struct DiffCounts {
    pub new: u32,
    pub changed: u32,
    pub missing: u32,
    pub identical: u32,
    pub conflict: u32,
}

/// Piano di sync ricavato dal diff (sync-spec §7).
#[derive(Debug, Default)]
pub struct Plan {
    /// Directory da creare (rel_path), ordinate per profondità crescente (genitori prima).
    pub dirs_to_create: Vec<String>,
    /// File da trasferire via put (rel_path).
    pub files_to_put: Vec<String>,
    /// File extra da cancellare (rel_path), solo con --delete.
    pub files_to_delete: Vec<String>,
    /// Directory extra da cancellare (rel_path), ordinate per profondità decrescente,
    /// solo con --delete.
    pub dirs_to_delete: Vec<String>,
    /// Conflict (rel_path, motivo): abort di quel path, errore parziale.
    pub conflicts: Vec<(String, String)>,
    /// File identici skippati (rel_path).
    pub skipped_identical: Vec<String>,
    /// Path skippati non-UTF8.
    pub skipped_non_utf8: Vec<String>,
    /// Path skippati nomi riservati Windows.
    pub skipped_reserved: Vec<(String, &'static str)>,
}

/// Report finale di sync (sync-spec §11).
#[derive(Debug, Default)]
pub struct SyncReport {
    pub put_count: u32,
    pub delete_count: u32,
    pub skip_count: u32,
    pub error_count: u32,
    pub bytes_total: u64,
    pub delta_bytes: u64,
    pub elapsed: Duration,
    /// Messaggi di errore dettagliati (per report non-quiet).
    pub errors: Vec<String>,
}

// ---------------------------------------------------------------------------
// Walk locale (Linux) - sync-spec §16.
// ---------------------------------------------------------------------------

/// Cammina ricorsivamente una directory locale e enumera file e sottodirectory.
/// Salta i nomi non-UTF8 (skip + errore parziale) e i nomi riservati Windows.
/// Ritorna WalkResult con entry ordinate per rel_path (output deterministico).
pub fn walk_local_dir(dir: &Path) -> Result<WalkResult> {
    let mut entries = Vec::new();
    let mut skipped_non_utf8 = Vec::new();
    let mut skipped_reserved = Vec::<(String, &'static str)>::new();
    walk_recursive(dir, Path::new(""), &mut entries, &mut skipped_non_utf8, &mut skipped_reserved)?;
    // Ordina per rel_path per output deterministico (sync-spec §16).
    entries.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
    Ok(WalkResult { entries, skipped_non_utf8, skipped_reserved })
}

/// Funzione ricorsiva interna del walk. `base` è la dir root, `rel` è il path
/// relativo corrente (vuoto alla radice).
fn walk_recursive(
    base: &Path,
    rel: &Path,
    out: &mut Vec<Entry>,
    skipped_non_utf8: &mut Vec<String>,
    skipped_reserved: &mut Vec<(String, &'static str)>,
) -> Result<()> {
    let full = base.join(rel);
    let read_dir_result = fs::read_dir(&full);
    let dir_iter = match read_dir_result {
        Ok(it) => it,
        Err(e) => {
            // Errore di lettura directory: propaga (sync-spec §13 ERR 3 IO).
            return Err(anyhow!("impossibile leggere directory {}: {}", full.display(), e));
        }
    };
    for entry in dir_iter {
        let dir_entry = match entry {
            Ok(e) => e,
            Err(e) => {
                // Entry singola non leggibile: skip + log, non abortire tutto il walk.
                eprintln!("[WARN] walk: skip entry non leggibile in {}: {}", full.display(), e);
                continue;
            }
        };
        let file_name = dir_entry.file_name();
        // Bug evitato (sync-spec §16): to_string_lossy corrompe i nomi non-UTF-8
        // sostituendoli con U+FFFD, creando path sbagliati sul server. Usiamo to_str
        // (Option<&str>): se non è UTF-8 valido, skip + errore parziale, non un path
        // silenziosamente errato.
        let name_str = match file_name.to_str() {
            Some(s) => s,
            None => {
                let display = full.join(&file_name).to_string_lossy().into_owned();
                eprintln!("[WARN] walk: skip nome non-UTF-8: {}", display);
                skipped_non_utf8.push(display);
                continue;
            }
        };
        let child_rel = rel.join(name_str);
        // child_rel è costruito da name_str (già verificato UTF-8): to_str().unwrap() è sicuro.
        // Normalizza il separatore a '/' nel rel_path (sempre '/' nel protocollo, sync-spec §5).
        let child_rel_str = match child_rel.to_str() {
            Some(s) => s.replace('\\', "/"),
            None => {
                // Non dovrebbe succedere dato che name_str è UTF-8, ma difensivo.
                eprintln!("[WARN] walk: skip rel_path non-UTF-8: {}", child_rel.display());
                continue;
            }
        };
        // Check nomi riservati Windows su ogni componente (sync-spec §8.3).
        // Il check è lato client: skip del file + errore parziale, nessun put tentato.
        let reserved_check = path::rel_path_windows_invalid(&child_rel_str);
        if let Some((component, reason)) = reserved_check {
            eprintln!(
                "[WARN] walk: skip nome non valido su Windows: {} ({})",
                child_rel_str, reason
            );
            skipped_reserved.push((child_rel_str.clone(), reason));
            // Non scendiamo nelle directory riservate: i figli avrebbero lo stesso
            // problema di percorso e non sarebbero trasferibili su Windows.
            let _ = component; // component è solo informativo (già nel rel_path).
            continue;
        }
        let metadata = match dir_entry.metadata() {
            Ok(m) => m,
            Err(e) => {
                eprintln!("[WARN] walk: skip metadata non leggibile {}: {}", child_rel_str, e);
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
            // Ricorsione nella sottodirectory.
            walk_recursive(base, &child_rel, out, skipped_non_utf8, skipped_reserved)?;
        } else {
            out.push(Entry {
                rel_path: child_rel_str,
                size: metadata.len(),
                is_dir: 0,
                sha256: None,
            });
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// LIST remoto (lato client) - sync-spec §6, §9.
// ---------------------------------------------------------------------------

/// Lato client: invia LIST_REQ e legge LIST_RES (o ERR).
/// Ritorna la lista di entry remote. `with_hash` controlla se il server include
/// SHA-256 per i file (un solo passaggio sul filesystem remoto, sync-spec §6.1).
pub async fn list_remote_dir(
    stream: &mut TcpStream,
    remote_dir: &str,
    with_hash: bool,
) -> Result<Vec<Entry>> {
    // Costruisce la ListReq: recursive=1 (tutto l'albero), with_hash dal flag.
    let req = ListReq {
        path: remote_dir.to_string(),
        recursive: 1,
        with_hash: if with_hash { 1 } else { 0 },
    };
    eprintln!(
        "[DEBUG] list_remote_dir: LIST_REQ path={} recursive=1 with_hash={}",
        remote_dir, req.with_hash
    );
    proto::send_list_req(stream, &req).await?;

    // Legge la risposta: LIST_RES o ERR.
    let (msg_type, payload) = proto::read_msg(stream).await?;
    if msg_type == MSG_ERR {
        let err = proto::decode_err(&payload)?;
        // ERR 1 = path invalido, ERR 5 = cap superato / proto.
        bail!("LIST_REQ rifiutata dal server: ERR {}: {}", err.code, err.message);
    }
    if msg_type != MSG_LIST_RES {
        bail!(
            "list_remote_dir: atteso LIST_RES (tipo {}), ricevuto tipo {}",
            MSG_LIST_RES,
            msg_type
        );
    }
    // Decodifica con il flag with_hash coerente con la richiesta.
    let res = proto::decode_list_res(&payload, with_hash)?;
    eprintln!("[DEBUG] list_remote_dir: ricevute {} entry", res.entries.len());

    // Validazione difensiva (sync-spec §8): ogni rel_path ricevuto dal server
    // non deve contenere '..' (un server malevolo/buggato non deve far escapare
    // il client). Le entry invalide sono skippate + log.
    let mut clean = Vec::with_capacity(res.entries.len());
    for entry in &res.entries {
        let validate = path::validate_rel_path(&entry.rel_path);
        if let Err(e) = validate {
            eprintln!(
                "[WARN] list_remote_dir: skip entry con rel_path invalido '{}': {}",
                entry.rel_path, e
            );
            continue;
        }
        clean.push(entry.clone());
    }
    Ok(clean)
}

// ---------------------------------------------------------------------------
// Diff (compute_diff) - sync-spec §6, §7, §8.1.
// ---------------------------------------------------------------------------

/// Calcola il diff tra entry locali e remote.
///
/// Regole (sync-spec §6):
/// - rel_path in local non in remote -> NEW
/// - rel_path in remote non in local -> MISSING
/// - rel_path in entrambi:
///   - is_dir diverso -> CONFLICT (file vs dir)
///   - size diversa -> CHANGED
///   - size uguale e --checksum -> hash locale vs hash remoto (CHANGED se diversi)
///   - size uguale (senza --checksum) -> IDENTICAL
///
/// Case-insensitivity Windows (sync-spec §8.1): le chiavi remote sono normalizzate
/// in lowercase per il confronto. Se due rel_path locali collidono dopo lowercase,
/// entrambi sono CONFLICT (case collision). I path in conflicts non compaiono in
/// nessun altro set.
///
/// `local_dir` serve per calcolare gli hash locali quando `checksum=true`.
pub fn compute_diff(local: &WalkResult, remote: &[Entry], checksum: bool, local_dir: &Path) -> Diff {
    // Mappa remote per lowercase rel_path (Windows case-insensitive, sync-spec §8.1).
    let mut remote_by_lower: HashMap<String, &Entry> = HashMap::new();
    for r in remote {
        let lower = r.rel_path.to_lowercase();
        // Su Windows non dovrebbero esserci duplicati case-insensitive, ma se ci sono
        // l'ultimo vince (difensivo). Loggiamo per tracciabilità.
        if remote_by_lower.contains_key(&lower) {
            eprintln!(
                "[WARN] compute_diff: remote ha duplicato case-insensitive: {} (già presente)",
                r.rel_path
            );
        }
        remote_by_lower.insert(lower, r);
    }

    // Mappa local per lowercase rel_path per rilevare case collision (sync-spec §8.1).
    let mut local_lower_groups: HashMap<String, Vec<&Entry>> = HashMap::new();
    for l in &local.entries {
        let lower = l.rel_path.to_lowercase();
        let group = local_lower_groups.entry(lower).or_default();
        group.push(l);
    }

    let mut entries = Vec::new();
    // Traccia i rel_path remote già "consumati" da un match locale, per calcolare MISSING.
    let mut matched_remote_lower: std::collections::HashSet<String> = std::collections::HashSet::new();

    for l in &local.entries {
        let lower = l.rel_path.to_lowercase();
        // Case collision: se più entry locali share lo stesso lowercase -> CONFLICT.
        let group = match local_lower_groups.get(&lower) {
            Some(g) => g,
            None => continue,
        };
        if group.len() > 1 {
            // sync-spec §8.1: case collision, entrambi CONFLICT.
            // Trova gli "altri" rel_path che collidono per il messaggio.
            let others = build_case_collision_others(group, &l.rel_path);
            let reason = format!("case collision con {} su Windows", others);
            entries.push(DiffEntry {
                rel_path: l.rel_path.clone(),
                status: EntryStatus::Conflict,
                local: Some(l.clone()),
                remote: None,
                conflict_reason: reason,
            });
            // Non consuma remote: il path è in conflict, non entra in altri set.
            continue;
        }

        // Cerca il match remoto (case-insensitive).
        let remote_match = remote_by_lower.get(&lower);
        match remote_match {
            None => {
                // Non in remote -> NEW.
                entries.push(DiffEntry {
                    rel_path: l.rel_path.clone(),
                    status: EntryStatus::New,
                    local: Some(l.clone()),
                    remote: None,
                    conflict_reason: String::new(),
                });
            }
            Some(r) => {
                matched_remote_lower.insert(lower.clone());
                // is_dir diverso -> CONFLICT (file vs dir).
                let local_is_dir = l.is_dir == 1;
                let remote_is_dir = r.is_dir == 1;
                if local_is_dir != remote_is_dir {
                    let kind_local = if local_is_dir { "dir" } else { "file" };
                    let kind_remote = if remote_is_dir { "dir" } else { "file" };
                    let reason = format!("file vs dir (locale {}, remoto {})", kind_local, kind_remote);
                    entries.push(DiffEntry {
                        rel_path: l.rel_path.clone(),
                        status: EntryStatus::Conflict,
                        local: Some(l.clone()),
                        remote: Some((*r).clone()),
                        conflict_reason: reason,
                    });
                    continue;
                }
                // Entrambi file o entrambi dir.
                if local_is_dir {
                    // Directory: non ha size/hash significativi. Se presente in entrambi
                    // come dir -> IDENTICAL (la creazione è idempotente, sync-spec §9 MKDIR).
                    entries.push(DiffEntry {
                        rel_path: l.rel_path.clone(),
                        status: EntryStatus::Identical,
                        local: Some(l.clone()),
                        remote: Some((*r).clone()),
                        conflict_reason: String::new(),
                    });
                    continue;
                }
                // Entrambi file: confronta size.
                if l.size != r.size {
                    entries.push(DiffEntry {
                        rel_path: l.rel_path.clone(),
                        status: EntryStatus::Changed,
                        local: Some(l.clone()),
                        remote: Some((*r).clone()),
                        conflict_reason: String::new(),
                    });
                    continue;
                }
                // Size uguale.
                if checksum {
                    // sync-spec §6.1: confronta hash locale vs hash remoto.
                    let local_hash_result = compute_local_hash(local_dir, &l.rel_path);
                    match local_hash_result {
                        Ok(local_hash) => {
                            let remote_hash = r.sha256;
                            match remote_hash {
                                Some(rh) => {
                                    if local_hash != rh {
                                        entries.push(DiffEntry {
                                            rel_path: l.rel_path.clone(),
                                            status: EntryStatus::Changed,
                                            local: Some(l.clone()),
                                            remote: Some((*r).clone()),
                                            conflict_reason: String::new(),
                                        });
                                    } else {
                                        entries.push(DiffEntry {
                                            rel_path: l.rel_path.clone(),
                                            status: EntryStatus::Identical,
                                            local: Some(l.clone()),
                                            remote: Some((*r).clone()),
                                            conflict_reason: String::new(),
                                        });
                                    }
                                }
                                None => {
                                    // Il server non ha restituito l'hash nonostante with_hash=1:
                                    // bug di protocollo. Tratta come CHANGED (cauto).
                                    eprintln!(
                                        "[WARN] compute_diff: remote senza hash per {} nonostante --checksum",
                                        l.rel_path
                                    );
                                    entries.push(DiffEntry {
                                        rel_path: l.rel_path.clone(),
                                        status: EntryStatus::Changed,
                                        local: Some(l.clone()),
                                        remote: Some((*r).clone()),
                                        conflict_reason: String::new(),
                                    });
                                }
                            }
                        }
                        Err(e) => {
                            // Hash locale non calcolabile: skip + errore parziale.
                            eprintln!(
                                "[WARN] compute_diff: hash locale non calcolabile per {}: {}",
                                l.rel_path, e
                            );
                            entries.push(DiffEntry {
                                rel_path: l.rel_path.clone(),
                                status: EntryStatus::Changed,
                                local: Some(l.clone()),
                                remote: Some((*r).clone()),
                                conflict_reason: format!("hash locale non calcolabile: {}", e),
                            });
                        }
                    }
                } else {
                    // Size uguale senza --checksum -> IDENTICAL (sync-spec §6).
                    entries.push(DiffEntry {
                        rel_path: l.rel_path.clone(),
                        status: EntryStatus::Identical,
                        local: Some(l.clone()),
                        remote: Some((*r).clone()),
                        conflict_reason: String::new(),
                    });
                }
            }
        }
    }

    // MISSING: entry remote non matchate da nessun locale.
    for r in remote {
        let lower = r.rel_path.to_lowercase();
        if !matched_remote_lower.contains(&lower) {
            entries.push(DiffEntry {
                rel_path: r.rel_path.clone(),
                status: EntryStatus::Missing,
                local: None,
                remote: Some(r.clone()),
                conflict_reason: String::new(),
            });
        }
    }

    // Ordina per rel_path (output deterministico).
    entries.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));

    Diff {
        entries,
        skipped_non_utf8: local.skipped_non_utf8.clone(),
        skipped_reserved: local.skipped_reserved.clone(),
    }
}

/// Costruisce la lista degli "altri" rel_path che collidono (case collision)
/// con quello dato, per il messaggio di conflict.
fn build_case_collision_others(group: &[&Entry], current: &str) -> String {
    let mut others = Vec::new();
    for e in group {
        if e.rel_path != current {
            others.push(e.rel_path.clone());
        }
    }
    others.join(", ")
}

/// Calcola SHA-256 di un file locale (rel_path sotto local_dir).
/// Usato da compute_diff con --checksum.
fn compute_local_hash(local_dir: &Path, rel_path: &str) -> Result<[u8; 32]> {
    let full = local_dir.join(rel_path);
    let file_open_result = fs::File::open(&full);
    let mut file = match file_open_result {
        Ok(f) => f,
        Err(e) => bail!("impossibile aprire {}: {}", full.display(), e),
    };
    sha256_file_handle(&mut file).context("hash su file locale fallito")
}

// ---------------------------------------------------------------------------
// Piano di sync (build_plan) - sync-spec §7.
// ---------------------------------------------------------------------------

/// Converte un Diff in un Plan di sync. `delete` controlla se i file/dir extra
/// vengono messi nei set di cancellazione (sync-spec §7: --delete default OFF).
pub fn build_plan(diff: &Diff, delete: bool) -> Plan {
    let mut dirs_to_create = Vec::new();
    let mut files_to_put = Vec::new();
    let mut files_to_delete = Vec::new();
    let mut dirs_to_delete = Vec::new();
    let mut conflicts = Vec::new();
    let mut skipped_identical = Vec::new();

    for e in &diff.entries {
        match e.status {
            EntryStatus::New => {
                // NEW: se è dir -> dirs_to_create, se file -> files_to_put.
                let is_dir = match &e.local {
                    Some(l) => l.is_dir == 1,
                    None => false,
                };
                if is_dir {
                    dirs_to_create.push(e.rel_path.clone());
                } else {
                    files_to_put.push(e.rel_path.clone());
                }
            }
            EntryStatus::Changed => {
                // CHANGED: solo i file vanno in put (le dir non si trasferiscono).
                let is_dir = match &e.local {
                    Some(l) => l.is_dir == 1,
                    None => false,
                };
                if !is_dir {
                    files_to_put.push(e.rel_path.clone());
                }
            }
            EntryStatus::Missing => {
                // MISSING: solo con --delete va in cancellazione.
                if delete {
                    let is_dir = match &e.remote {
                        Some(r) => r.is_dir == 1,
                        None => false,
                    };
                    if is_dir {
                        dirs_to_delete.push(e.rel_path.clone());
                    } else {
                        files_to_delete.push(e.rel_path.clone());
                    }
                }
            }
            EntryStatus::Identical => {
                skipped_identical.push(e.rel_path.clone());
            }
            EntryStatus::Conflict => {
                conflicts.push((e.rel_path.clone(), e.conflict_reason.clone()));
            }
        }
    }

    // Ordine di esecuzione (sync-spec §7 "Ordine di esecuzione"):
    // 1. Directory prima, profondità crescente (genitori prima dei figli).
    sort_by_depth_ascending(&mut dirs_to_create);
    // 2. File dopo (sequenziali, 1 connessione per file).
    // files_to_put mantiene l'ordine per rel_path (deterministico).
    // 4. Cancellazione per ultima: file prima, poi dir profondità decrescente
    //    (figli prima dei genitori, altrimenti DELETE fallisce su dir non vuote).
    files_to_delete.sort();
    sort_by_depth_descending(&mut dirs_to_delete);

    Plan {
        dirs_to_create,
        files_to_put,
        files_to_delete,
        dirs_to_delete,
        conflicts,
        skipped_identical,
        skipped_non_utf8: diff.skipped_non_utf8.clone(),
        skipped_reserved: diff.skipped_reserved.clone(),
    }
}

/// Ordina i rel_path per profondità crescente (meno componenti = più in alto).
/// Genitori prima dei figli (sync-spec §7: MKDIR_BATCH in ordine profondità crescente).
fn sort_by_depth_ascending(paths: &mut [String]) {
    paths.sort_by(|a, b| {
        let depth_a = rel_path_depth(a);
        let depth_b = rel_path_depth(b);
        depth_a.cmp(&depth_b).then_with(|| a.cmp(b))
    });
}

/// Ordina i rel_path per profondità decrescente (più componenti = più in profondità prima).
/// Figli prima dei genitori (sync-spec §7: DELETE_BATCH dir in profondità decrescente).
fn sort_by_depth_descending(paths: &mut [String]) {
    paths.sort_by(|a, b| {
        let depth_a = rel_path_depth(a);
        let depth_b = rel_path_depth(b);
        depth_b.cmp(&depth_a).then_with(|| a.cmp(b))
    });
}

/// Profondità di un rel_path = numero di componenti (separatore '/').
/// Usata da sort_by_depth_ascending/descending per un confronto deterministico.
fn rel_path_depth(rel_path: &str) -> usize {
    if rel_path.is_empty() {
        return 0;
    }
    rel_path.matches('/').count() + 1
}

// ---------------------------------------------------------------------------
// Join path cross-OS - sync-spec §16.
// ---------------------------------------------------------------------------

/// Costruisce il path remoto completo joinando remote_dir + rel_path.
/// Sostituisce '/' con il separatore dell'OS del server ('\su Windows, / su Linux).
/// Su Linux (test locali) è diretto; su Windows il client non gira ma il path
/// remoto va costruito con '\'.
pub fn join_remote_path(remote_dir: &str, rel_path: &str) -> String {
    if rel_path.is_empty() {
        return remote_dir.to_string();
    }
    // Sostituisce '/' con '\' per Windows. Su Linux i test usano '/' e la
    // sostituzione è un no-op se remote_dir usa già '/'.
    #[cfg(target_os = "windows")]
    {
        let rel_win = rel_path.replace('/', "\\");
        // Evita doppi separatori se remote_dir finisce già con '\'.
        if remote_dir.ends_with('\\') || remote_dir.ends_with('/') {
            format!("{}{}", remote_dir, rel_win)
        } else {
            format!("{}\\{}", remote_dir, rel_win)
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        if remote_dir.ends_with('/') {
            format!("{}{}", remote_dir, rel_path)
        } else {
            format!("{}/{}", remote_dir, rel_path)
        }
    }
}

// ---------------------------------------------------------------------------
// Output testuale - sync-spec §10 (status), §11 (sync).
// ---------------------------------------------------------------------------

/// Stampa il report di status su stdout (una riga per entry) + riepilogo su stderr.
/// Con `quiet`: solo riepilogo numerico su stderr (machine-readable per CI).
pub fn print_status(diff: &Diff, quiet: bool) {
    if !quiet {
        for e in &diff.entries {
            let label = status_label(&e.status);
            let suffix = if e.conflict_reason.is_empty() {
                String::new()
            } else {
                format!(" ({})", e.conflict_reason)
            };
            println!("{:<9} {}{}", label, e.rel_path, suffix);
        }
    }
    let counts = diff.counts();
    if quiet {
        eprintln!(
            "[status] new={} changed={} missing={} identical={} conflict={}",
            counts.new, counts.changed, counts.missing, counts.identical, counts.conflict
        );
    } else {
        eprintln!(
            "[status] {} new, {} changed, {} missing, {} identical, {} conflict",
            counts.new, counts.changed, counts.missing, counts.identical, counts.conflict
        );
    }
}

/// Etichetta di stato per l'output testuale (sync-spec §10).
fn status_label(status: &EntryStatus) -> &'static str {
    match status {
        EntryStatus::New => "NEW",
        EntryStatus::Changed => "CHANGED",
        EntryStatus::Missing => "MISSING",
        EntryStatus::Identical => "IDENTICAL",
        EntryStatus::Conflict => "CONFLICT",
    }
}

/// Stampa il piano di sync (formato dry-run, sync-spec §11).
pub fn print_plan(plan: &Plan) {
    // MKDIR: directory da creare.
    for d in &plan.dirs_to_create {
        println!("MKDIR     {}", d);
    }
    // PUT: file da trasferire.
    for f in &plan.files_to_put {
        println!("PUT       {}", f);
    }
    // DELETE file.
    for f in &plan.files_to_delete {
        println!("DELETE    {}", f);
    }
    // DELETE dir (recursive).
    for d in &plan.dirs_to_delete {
        println!("DELETE    {}/  (recursive)", d);
    }
    // SKIP identical.
    for s in &plan.skipped_identical {
        println!("SKIP      {} (identical)", s);
    }
    // CONFLICT -> ABORT.
    for (p, reason) in &plan.conflicts {
        println!("CONFLICT  {} ({}) -> ABORT path", p, reason);
    }
    // SKIP non-UTF8.
    for s in &plan.skipped_non_utf8 {
        println!("SKIP      {} (non-UTF-8)", s);
    }
    // SKIP riservati Windows.
    for (s, reason) in &plan.skipped_reserved {
        println!("SKIP      {} ({})", s, reason);
    }
}

/// Stampa il riepilogo finale di sync (sync-spec §11).
pub fn print_sync_report(report: &SyncReport, quiet: bool) {
    if quiet {
        eprintln!(
            "[sync] put={} delete={} skip={} errors={} bytes={} delta={} time={:.1}s",
            report.put_count,
            report.delete_count,
            report.skip_count,
            report.error_count,
            report.bytes_total,
            report.delta_bytes,
            report.elapsed.as_secs_f64()
        );
    } else {
        // Stampa gli errori dettagliati prima del riepilogo.
        for err in &report.errors {
            eprintln!("[sync] ERRORE {}", err);
        }
        eprintln!(
            "[sync] completato: {} trasferiti ({} byte totali, delta {} byte), {} cancellati, {} saltati, {} errori, {:.1}s",
            report.put_count,
            report.bytes_total,
            report.delta_bytes,
            report.delete_count,
            report.skip_count,
            report.error_count,
            report.elapsed.as_secs_f64()
        );
    }
}

// ---------------------------------------------------------------------------
// Esecuzione sync (execute_sync) - sync-spec §7.
// ---------------------------------------------------------------------------

/// Parametri per execute_sync (raggruppati per leggibilità, < 6 arg).
#[derive(Debug, Clone)]
pub struct SyncParams {
    pub local_dir: String,
    pub remote_dir: String,
    pub delete: bool,
    pub dry_run: bool,
    pub quiet: bool,
}

/// Esegue il piano di sync: MKDIR_BATCH + put per-file + DELETE_BATCH.
/// Gestisce CONFLICT (abort di quel path, errore parziale), --dry-run, --quiet.
/// Niente connessioni parallele (best-practice): ogni operazione è sequenziale.
///
/// `connect` è una callback che stabilisce una nuova connessione+handshake per
/// ogni operazione (riutilizza connect_and_handshake di main.rs, invariata).
pub async fn execute_sync<F, Fut>(
    plan: &Plan,
    params: &SyncParams,
    connect: F,
) -> Result<SyncReport>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<TcpStream>>,
{
    let start = Instant::now();
    let mut report = SyncReport::default();
    let local_dir = Path::new(&params.local_dir);

    // --dry-run: stampa il piano ed esci (sync-spec §7 passo 4, §14 test 8).
    if params.dry_run {
        print_plan(plan);
        report.elapsed = start.elapsed();
        return Ok(report);
    }

    // --- Passo 5: MKDIR_BATCH (1 connessione, tutte le dirs_to_create) ---
    if !plan.dirs_to_create.is_empty() {
        let mkdir_result = run_mkdir_batch(plan, params, &connect).await;
        match mkdir_result {
            Ok(mkdir_errors) => {
                // Conta gli errori di mkdir (status=2).
                for err in &mkdir_errors {
                    report.errors.push(err.clone());
                    report.error_count += 1;
                }
                if !params.quiet {
                    eprintln!(
                        "[sync] MKDIR  {} directory create",
                        plan.dirs_to_create.len()
                    );
                }
            }
            Err(e) => {
                // Errore fatale di protocollo sulla connessione MKDIR: logga e continua
                // con i put (i file nelle dir non create falliranno a loro volta, ma
                // sync completa i file possibili, sync-spec §11).
                let msg = format!("MKDIR_BATCH: {}", e);
                eprintln!("[sync] ERRORE {}", msg);
                report.errors.push(msg);
                report.error_count += 1;
            }
        }
    }

    // --- Passo 6: put per-file (sequenziale, 1 connessione per file) ---
    for rel_path in &plan.files_to_put {
        let local_full = local_dir.join(rel_path);
        let local_str = match local_full.to_str() {
            Some(s) => s.to_string(),
            None => {
                let msg = format!("path locale non UTF-8: {}", local_full.display());
                eprintln!("[sync] ERRORE {}", msg);
                report.errors.push(msg);
                report.error_count += 1;
                continue;
            }
        };
        let remote_full = join_remote_path(&params.remote_dir, rel_path);

        // Dimensione file per il report byte totali.
        let file_size = match fs::metadata(&local_full) {
            Ok(m) => m.len(),
            Err(e) => {
                let msg = format!("{}: metadata fallito: {}", rel_path, e);
                eprintln!("[sync] ERRORE {}", msg);
                report.errors.push(msg);
                report.error_count += 1;
                continue;
            }
        };

        // Nuova connessione per ogni put (riutilizza put_client, sync-spec §7).
        let connect_result = connect().await;
        let mut socket = match connect_result {
            Ok(s) => s,
            Err(e) => {
                let msg = format!("{}: connessione fallita: {}", rel_path, e);
                eprintln!("[sync] ERRORE {}", msg);
                report.errors.push(msg);
                report.error_count += 1;
                continue;
            }
        };

        let put_result = crate::transfer::put_client(&mut socket, &local_str, &remote_full).await;
        match put_result {
            Ok(()) => {
                report.put_count += 1;
                report.bytes_total += file_size;
                if !params.quiet {
                    eprintln!("[sync] PUT    {} ({} byte)", rel_path, file_size);
                }
            }
            Err(e) => {
                let msg = format!("{}: {}", rel_path, e);
                eprintln!("[sync] ERRORE {}", msg);
                report.errors.push(msg);
                report.error_count += 1;
            }
        }
    }

    // --- Passo 7: CONFLICT abort (errore parziale, continua con gli altri) ---
    for (rel_path, reason) in &plan.conflicts {
        let msg = format!("{} (conflict: {})", rel_path, reason);
        eprintln!("[sync] ABORT  {}", msg);
        report.errors.push(msg);
        report.error_count += 1;
    }

    // --- Passo 8: DELETE (solo con --delete) ---
    if params.delete {
        // 8a: DELETE_BATCH file (1 connessione, recursive=0).
        if !plan.files_to_delete.is_empty() {
            let del_result = run_delete_batch_files(plan, params, &connect).await;
            match del_result {
                Ok(del_errors) => {
                    for err in &del_errors {
                        report.errors.push(err.clone());
                        report.error_count += 1;
                    }
                    report.delete_count += plan.files_to_delete.len() as u32;
                    if !params.quiet {
                        eprintln!("[sync] DELETE {} file", plan.files_to_delete.len());
                    }
                }
                Err(e) => {
                    let msg = format!("DELETE_BATCH file: {}", e);
                    eprintln!("[sync] ERRORE {}", msg);
                    report.errors.push(msg);
                    report.error_count += 1;
                }
            }
        }
        // 8b: DELETE_BATCH dir (1 connessione distinta, recursive=1, profondità decrescente).
        if !plan.dirs_to_delete.is_empty() {
            let del_result = run_delete_batch_dirs(plan, params, &connect).await;
            match del_result {
                Ok(del_errors) => {
                    for err in &del_errors {
                        report.errors.push(err.clone());
                        report.error_count += 1;
                    }
                    report.delete_count += plan.dirs_to_delete.len() as u32;
                    if !params.quiet {
                        eprintln!("[sync] DELETE {} dir (recursive)", plan.dirs_to_delete.len());
                    }
                }
                Err(e) => {
                    let msg = format!("DELETE_BATCH dir: {}", e);
                    eprintln!("[sync] ERRORE {}", msg);
                    report.errors.push(msg);
                    report.error_count += 1;
                }
            }
        }
    }

    // Skip identical (conteggio per report).
    report.skip_count = plan.skipped_identical.len() as u32;

    report.elapsed = start.elapsed();
    Ok(report)
}

/// Esegue MKDIR_BATCH_REQ su una nuova connessione. Ritorna la lista di messaggi
/// di errore per-path (status=2). Count mismatch -> errore fatale propagato.
async fn run_mkdir_batch<F, Fut>(plan: &Plan, params: &SyncParams, connect: &F) -> Result<Vec<String>>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<TcpStream>>,
{
    let mut paths = Vec::with_capacity(plan.dirs_to_create.len());
    for rel in &plan.dirs_to_create {
        let full = join_remote_path(&params.remote_dir, rel);
        paths.push(full);
    }
    let req = MkdirBatchReq { paths };
    let expected = plan.dirs_to_create.len();

    let connect_result = connect().await;
    let mut socket = connect_result?;
    proto::send_mkdir_batch_req(&mut socket, &req).await?;

    let (msg_type, payload) = proto::read_msg(&mut socket).await?;
    if msg_type == MSG_ERR {
        let err = proto::decode_err(&payload)?;
        bail!("MKDIR_BATCH rifiutato: ERR {}: {}", err.code, err.message);
    }
    if msg_type != MSG_MKDIR_BATCH_RES {
        bail!(
            "MKDIR_BATCH: atteso MKDIR_BATCH_RES (tipo {}), ricevuto tipo {}",
            MSG_MKDIR_BATCH_RES,
            msg_type
        );
    }
    // Count mismatch -> ERR 5 (sync-spec §9): decode restituisce Err.
    let res = proto::decode_mkdir_batch_res(&payload, expected)?;
    let mut errors = Vec::new();
    let mut idx = 0usize;
    while idx < res.results.len() {
        let r = &res.results[idx];
        if r.status == 2 {
            let rel = &plan.dirs_to_create[idx];
            errors.push(format!("{}: server ERR {}: {}", rel, r.code, r.message));
        }
        idx += 1;
    }
    Ok(errors)
}

/// Esegue DELETE_BATCH_REQ per i file (recursive=0) su una nuova connessione.
async fn run_delete_batch_files<F, Fut>(
    plan: &Plan,
    params: &SyncParams,
    connect: &F,
) -> Result<Vec<String>>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<TcpStream>>,
{
    let mut items = Vec::with_capacity(plan.files_to_delete.len());
    for rel in &plan.files_to_delete {
        let full = join_remote_path(&params.remote_dir, rel);
        items.push(DeleteItem { path: full, recursive: 0 });
    }
    run_delete_batch(plan, &plan.files_to_delete, items, connect).await
}

/// Esegue DELETE_BATCH_REQ per le directory (recursive=1) su una nuova connessione.
async fn run_delete_batch_dirs<F, Fut>(
    plan: &Plan,
    params: &SyncParams,
    connect: &F,
) -> Result<Vec<String>>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<TcpStream>>,
{
    let mut items = Vec::with_capacity(plan.dirs_to_delete.len());
    for rel in &plan.dirs_to_delete {
        let full = join_remote_path(&params.remote_dir, rel);
        items.push(DeleteItem { path: full, recursive: 1 });
    }
    run_delete_batch(plan, &plan.dirs_to_delete, items, connect).await
}

/// Helper comune per DELETE_BATCH (file o dir). `rels` serve per mappare gli
/// errori per-path al rel_path (per il report).
async fn run_delete_batch<F, Fut>(
    _plan: &Plan,
    rels: &[String],
    items: Vec<DeleteItem>,
    connect: &F,
) -> Result<Vec<String>>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<TcpStream>>,
{
    let expected = items.len();
    let req = DeleteBatchReq { items };

    let connect_result = connect().await;
    let mut socket = connect_result?;
    proto::send_delete_batch_req(&mut socket, &req).await?;

    let (msg_type, payload) = proto::read_msg(&mut socket).await?;
    if msg_type == MSG_ERR {
        let err = proto::decode_err(&payload)?;
        bail!("DELETE_BATCH rifiutato: ERR {}: {}", err.code, err.message);
    }
    if msg_type != MSG_DELETE_BATCH_RES {
        bail!(
            "DELETE_BATCH: atteso DELETE_BATCH_RES (tipo {}), ricevuto tipo {}",
            MSG_DELETE_BATCH_RES,
            msg_type
        );
    }
    let res = proto::decode_delete_batch_res(&payload, expected)?;
    let mut errors = Vec::new();
    let mut idx = 0usize;
    while idx < res.results.len() {
        let r = &res.results[idx];
        // status=2 = error (status=1 = not found, non fatale, non loggato come errore).
        if r.status == 2 {
            let rel = &rels[idx];
            errors.push(format!("{}: server ERR {}: {}", rel, r.code, r.message));
        }
        idx += 1;
    }
    Ok(errors)
}

// ---------------------------------------------------------------------------
// Test (sync-spec §15 passi 3-6, §14 criteri 1-21).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Walk locale (sync-spec §15 passo 3, §14 test 14) -----------------

    #[test]
    fn walk_local_dir_basic() {
        // Crea una dir temporanea con file, subdir, file in subdir.
        let root = std::env::temp_dir().join("crosspilot_walk_basic");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("a.txt"), b"hello").unwrap();
        fs::write(root.join("b.bin"), [0u8; 100]).unwrap();
        fs::create_dir_all(root.join("sub")).unwrap();
        fs::write(root.join("sub").join("c.txt"), b"world").unwrap();

        let result = walk_local_dir(&root).unwrap();
        // 4 entry: a.txt, b.bin, sub, sub/c.txt.
        assert_eq!(result.entries.len(), 4);
        // Ordinate per rel_path.
        let rels = entry_rel_paths(&result.entries);
        assert!(rels.contains(&"a.txt".to_string()));
        assert!(rels.contains(&"b.bin".to_string()));
        assert!(rels.contains(&"sub".to_string()));
        assert!(rels.contains(&"sub/c.txt".to_string()));
        // Verifica size e is_dir.
        let a = find_entry(&result.entries, "a.txt");
        assert_eq!(a.size, 5);
        assert_eq!(a.is_dir, 0);
        let sub = find_entry(&result.entries, "sub");
        assert_eq!(sub.is_dir, 1);
        assert_eq!(sub.size, 0);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn walk_local_dir_empty() {
        let root = std::env::temp_dir().join("crosspilot_walk_empty");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let result = walk_local_dir(&root).unwrap();
        assert!(result.entries.is_empty());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn walk_local_dir_skips_windows_reserved() {
        // sync-spec §14 test 20: nome riservato Windows nel source -> skip.
        let root = std::env::temp_dir().join("crosspilot_walk_reserved");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("CON.txt"), b"device").unwrap();
        fs::write(root.join("normal.txt"), b"ok").unwrap();
        fs::write(root.join("old."), b"trailing dot").unwrap();

        let result = walk_local_dir(&root).unwrap();
        let rels = entry_rel_paths(&result.entries);
        // normal.txt è presente, CON.txt e old. sono skippati.
        assert!(rels.contains(&"normal.txt".to_string()));
        assert!(!rels.contains(&"CON.txt".to_string()));
        assert!(!rels.contains(&"old.".to_string()));
        // Skipped reserved riporta i due path.
        assert_eq!(result.skipped_reserved.len(), 2);

        let _ = fs::remove_dir_all(&root);
    }

    // --- compute_diff (sync-spec §15 passo 5, §14 test 1-3, 18) -----------

    #[test]
    fn diff_all_identical() {
        // sync-spec §14 test 1: due directory identiche -> tutto IDENTICAL.
        let local = WalkResult {
            entries: vec![
                Entry { rel_path: "a.txt".into(), size: 5, is_dir: 0, sha256: None },
                Entry { rel_path: "sub".into(), size: 0, is_dir: 1, sha256: None },
            ],
            ..Default::default()
        };
        let remote = vec![
            Entry { rel_path: "a.txt".into(), size: 5, is_dir: 0, sha256: None },
            Entry { rel_path: "sub".into(), size: 0, is_dir: 1, sha256: None },
        ];
        let dir = Path::new("/tmp");
        let diff = compute_diff(&local, &remote, false, dir);
        let counts = diff.counts();
        assert_eq!(counts.identical, 2);
        assert_eq!(counts.new, 0);
        assert_eq!(counts.changed, 0);
        assert_eq!(counts.missing, 0);
        assert_eq!(counts.conflict, 0);
    }

    #[test]
    fn diff_new_changed_missing() {
        // sync-spec §14 test 2: file nuovo locale -> NEW; solo remoto -> MISSING;
        // size diversa -> CHANGED.
        let local = WalkResult {
            entries: vec![
                Entry { rel_path: "new.txt".into(), size: 3, is_dir: 0, sha256: None },
                Entry { rel_path: "changed.txt".into(), size: 10, is_dir: 0, sha256: None },
                Entry { rel_path: "same.txt".into(), size: 5, is_dir: 0, sha256: None },
            ],
            ..Default::default()
        };
        let remote = vec![
            Entry { rel_path: "changed.txt".into(), size: 7, is_dir: 0, sha256: None },
            Entry { rel_path: "same.txt".into(), size: 5, is_dir: 0, sha256: None },
            Entry { rel_path: "missing.txt".into(), size: 8, is_dir: 0, sha256: None },
        ];
        let dir = Path::new("/tmp");
        let diff = compute_diff(&local, &remote, false, dir);
        let counts = diff.counts();
        assert_eq!(counts.new, 1);
        assert_eq!(counts.changed, 1);
        assert_eq!(counts.missing, 1);
        assert_eq!(counts.identical, 1);
        // Verifica per-entry.
        assert_eq!(find_diff(&diff.entries, "new.txt").status, EntryStatus::New);
        assert_eq!(find_diff(&diff.entries, "changed.txt").status, EntryStatus::Changed);
        assert_eq!(find_diff(&diff.entries, "missing.txt").status, EntryStatus::Missing);
        assert_eq!(find_diff(&diff.entries, "same.txt").status, EntryStatus::Identical);
    }

    #[test]
    fn diff_conflict_file_vs_dir() {
        // sync-spec §14 test 13: file vs dir sullo stesso rel_path -> CONFLICT.
        let local = WalkResult {
            entries: vec![
                Entry { rel_path: "data".into(), size: 100, is_dir: 0, sha256: None },
            ],
            ..Default::default()
        };
        let remote = vec![
            Entry { rel_path: "data".into(), size: 0, is_dir: 1, sha256: None },
        ];
        let dir = Path::new("/tmp");
        let diff = compute_diff(&local, &remote, false, dir);
        let counts = diff.counts();
        assert_eq!(counts.conflict, 1);
        assert_eq!(find_diff(&diff.entries, "data").status, EntryStatus::Conflict);
    }

    #[test]
    fn diff_case_collision() {
        // sync-spec §14 test 18: source con a.txt + A.txt -> entrambi CONFLICT.
        let local = WalkResult {
            entries: vec![
                Entry { rel_path: "a.txt".into(), size: 3, is_dir: 0, sha256: None },
                Entry { rel_path: "A.txt".into(), size: 4, is_dir: 0, sha256: None },
            ],
            ..Default::default()
        };
        let remote = vec![];
        let dir = Path::new("/tmp");
        let diff = compute_diff(&local, &remote, false, dir);
        let counts = diff.counts();
        // sync-spec §8.1: entrambi CONFLICT, nessun put.
        assert_eq!(counts.conflict, 2);
        assert_eq!(counts.new, 0);
    }

    #[test]
    fn diff_checksum_detects_corruption() {
        // sync-spec §14 test 3: stessa size, contenuto diverso -> CHANGED con --checksum.
        // Crea file locali reali per calcolare l'hash.
        let root = std::env::temp_dir().join("crosspilot_diff_checksum");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("same_size.txt"), b"AAAA").unwrap();
        let local_hash = {
            let mut f = fs::File::open(root.join("same_size.txt")).unwrap();
            sha256_file_handle(&mut f).unwrap()
        };
        // Hash "diverso" (simula file remoto corrotto con stessa size).
        let mut fake_remote_hash = [0u8; 32];
        fake_remote_hash[0] = 0xFF;

        let local = WalkResult {
            entries: vec![
                Entry { rel_path: "same_size.txt".into(), size: 4, is_dir: 0, sha256: None },
            ],
            ..Default::default()
        };
        let remote = vec![
            Entry { rel_path: "same_size.txt".into(), size: 4, is_dir: 0, sha256: Some(fake_remote_hash) },
        ];
        let diff = compute_diff(&local, &remote, true, &root);
        // size uguale ma hash diverso -> CHANGED.
        assert_eq!(find_diff(&diff.entries, "same_size.txt").status, EntryStatus::Changed);

        // Ora con hash uguale -> IDENTICAL.
        let remote_ok = vec![
            Entry { rel_path: "same_size.txt".into(), size: 4, is_dir: 0, sha256: Some(local_hash) },
        ];
        let diff2 = compute_diff(&local, &remote_ok, true, &root);
        assert_eq!(find_diff(&diff2.entries, "same_size.txt").status, EntryStatus::Identical);

        let _ = fs::remove_dir_all(&root);
    }

    // --- build_plan (sync-spec §15 passo 6, §14 test 4-8) -----------------

    #[test]
    fn plan_dirs_sorted_by_depth_ascending() {
        // sync-spec §7: MKDIR in ordine profondità crescente (genitori prima).
        let diff = Diff {
            entries: vec![
                DiffEntry { rel_path: "a/b/c/d".into(), status: EntryStatus::New, local: Some(Entry { rel_path: "a/b/c/d".into(), size: 0, is_dir: 1, sha256: None }), remote: None, conflict_reason: String::new() },
                DiffEntry { rel_path: "a".into(), status: EntryStatus::New, local: Some(Entry { rel_path: "a".into(), size: 0, is_dir: 1, sha256: None }), remote: None, conflict_reason: String::new() },
                DiffEntry { rel_path: "a/b".into(), status: EntryStatus::New, local: Some(Entry { rel_path: "a/b".into(), size: 0, is_dir: 1, sha256: None }), remote: None, conflict_reason: String::new() },
            ],
            ..Default::default()
        };
        let plan = build_plan(&diff, false);
        assert_eq!(plan.dirs_to_create, vec!["a", "a/b", "a/b/c/d"]);
    }

    #[test]
    fn plan_dirs_delete_sorted_by_depth_descending() {
        // sync-spec §7: DELETE dir in profondità decrescente (figli prima).
        let diff = Diff {
            entries: vec![
                DiffEntry { rel_path: "x".into(), status: EntryStatus::Missing, local: None, remote: Some(Entry { rel_path: "x".into(), size: 0, is_dir: 1, sha256: None }), conflict_reason: String::new() },
                DiffEntry { rel_path: "x/y/z".into(), status: EntryStatus::Missing, local: None, remote: Some(Entry { rel_path: "x/y/z".into(), size: 0, is_dir: 1, sha256: None }), conflict_reason: String::new() },
                DiffEntry { rel_path: "x/y".into(), status: EntryStatus::Missing, local: None, remote: Some(Entry { rel_path: "x/y".into(), size: 0, is_dir: 1, sha256: None }), conflict_reason: String::new() },
            ],
            ..Default::default()
        };
        let plan = build_plan(&diff, true);
        // Profondità decrescente: x/y/z (3), x/y (2), x (1).
        assert_eq!(plan.dirs_to_delete, vec!["x/y/z", "x/y", "x"]);
    }

    #[test]
    fn plan_delete_off_without_flag() {
        // sync-spec §14 test 7: senza --delete -> tutto lasciato (niente delete set).
        let diff = Diff {
            entries: vec![
                DiffEntry { rel_path: "extra.txt".into(), status: EntryStatus::Missing, local: None, remote: Some(Entry { rel_path: "extra.txt".into(), size: 5, is_dir: 0, sha256: None }), conflict_reason: String::new() },
            ],
            ..Default::default()
        };
        let plan = build_plan(&diff, false);
        assert!(plan.files_to_delete.is_empty());
        assert!(plan.dirs_to_delete.is_empty());
    }

    #[test]
    fn plan_conflicts_excluded_from_other_sets() {
        // sync-spec §7: i path in conflicts NON compaiono in nessun altro set.
        let diff = Diff {
            entries: vec![
                DiffEntry { rel_path: "conf".into(), status: EntryStatus::Conflict, local: Some(Entry { rel_path: "conf".into(), size: 1, is_dir: 0, sha256: None }), remote: Some(Entry { rel_path: "conf".into(), size: 0, is_dir: 1, sha256: None }), conflict_reason: "file vs dir".into() },
                DiffEntry { rel_path: "ok.txt".into(), status: EntryStatus::New, local: Some(Entry { rel_path: "ok.txt".into(), size: 1, is_dir: 0, sha256: None }), remote: None, conflict_reason: String::new() },
            ],
            ..Default::default()
        };
        let plan = build_plan(&diff, true);
        assert_eq!(plan.conflicts.len(), 1);
        assert!(!plan.files_to_put.contains(&"conf".to_string()));
        assert!(!plan.files_to_delete.contains(&"conf".to_string()));
        assert!(plan.files_to_put.contains(&"ok.txt".to_string()));
    }

    // --- join_remote_path (sync-spec §16) ---------------------------------

    #[test]
    fn join_remote_path_linux() {
        // Su Linux (test): join con '/'.
        let joined = join_remote_path("/tmp/remote", "sub/file.txt");
        assert_eq!(joined, "/tmp/remote/sub/file.txt");
        // rel_path vuoto -> solo remote_dir.
        let joined_empty = join_remote_path("/tmp/remote", "");
        assert_eq!(joined_empty, "/tmp/remote");
        // remote_dir con trailing '/'.
        let joined_slash = join_remote_path("/tmp/remote/", "file.txt");
        assert_eq!(joined_slash, "/tmp/remote/file.txt");
    }

    // --- Helper di test ----------------------------------------------------

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

    fn find_diff<'a>(entries: &'a [DiffEntry], rel: &str) -> &'a DiffEntry {
        for e in entries {
            if e.rel_path == rel {
                return e;
            }
        }
        panic!("diff entry non trovata: {}", rel);
    }
}
