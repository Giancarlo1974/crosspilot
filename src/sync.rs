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

use crate::tls::Link;
use anyhow::{anyhow, bail, Context, Result};

use crate::path;
use crate::proto::{
    self, DeleteBatchReq, DeleteItem, ListEntry, ListReq, MkdirBatchReq, MSG_DELETE_BATCH_RES,
    MSG_ERR, MSG_LIST_RES, MSG_MKDIR_BATCH_RES,
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
    /// Sotto-directory locali non leggibili (es. Permission denied): il walk
    /// continua, ma il contenuto e' sconosciuto — con --delete la fase di
    /// cancellazione va sospesa (semantica rsync: IO error -> niente delete).
    /// La radice illeggibile resta invece fatale (walk vuoto = niente sync).
    pub skipped_unreadable: Vec<String>,
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
    /// Sotto-directory LOCALI non leggibili (dal walk): contenuto ignoto.
    pub skipped_unreadable: Vec<String>,
    /// Sotto-directory REMOTE non leggibili (trailer LIST_RES; vuoto su
    /// server pre-feature): contenuto ignoto. Riempito dal caller dopo
    /// compute_diff (list_remote_dir lo restituisce a parte).
    pub skipped_remote: Vec<String>,
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
    /// Sotto-directory locali non leggibili: se non vuoto, la fase DELETE
    /// va sospesa (contenuto sorgente potenzialmente sotto-enumerato).
    pub skipped_unreadable: Vec<String>,
    /// Sotto-directory remote non leggibili (da LIST_RES skipped): se non
    /// vuoto, la fase DELETE va sospesa (contenuto dest sconosciuto).
    pub skipped_remote: Vec<String>,
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
    let mut skipped_unreadable = Vec::new();
    walk_recursive(
        dir,
        Path::new(""),
        &mut entries,
        &mut skipped_non_utf8,
        &mut skipped_reserved,
        &mut skipped_unreadable,
    )?;
    // Ordina per rel_path per output deterministico (sync-spec §16).
    entries.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
    Ok(WalkResult {
        entries,
        skipped_non_utf8,
        skipped_reserved,
        skipped_unreadable,
    })
}

/// Funzione ricorsiva interna del walk. `base` è la dir root, `rel` è il path
/// relativo corrente (vuoto alla radice).
fn walk_recursive(
    base: &Path,
    rel: &Path,
    out: &mut Vec<Entry>,
    skipped_non_utf8: &mut Vec<String>,
    skipped_reserved: &mut Vec<(String, &'static str)>,
    skipped_unreadable: &mut Vec<String>,
) -> Result<()> {
    let full = base.join(rel);
    let read_dir_result = fs::read_dir(&full);
    let dir_iter = match read_dir_result {
        Ok(it) => it,
        Err(e) => {
            // Radice illeggibile -> fatale. Sotto-directory illeggibile ->
            // warning + skip (bugfix: una dir root-only abortiva l'intero
            // sync; ora il walk continua come rsync). La dir e' comunque
            // gia' enumerata come entry dal chiamante: con --delete il
            // contenuto mancante non va cancellato (vedi execute_sync).
            if rel.as_os_str().is_empty() {
                return Err(anyhow!(
                    "impossibile leggere directory {}: {}",
                    full.display(),
                    e
                ));
            }
            let rel_str = rel.to_string_lossy().replace('\\', "/");
            eprintln!(
                "[WARN] walk: directory non leggibile, skip contenuto: {} ({})",
                rel_str, e
            );
            skipped_unreadable.push(rel_str);
            return Ok(());
        }
    };
    for entry in dir_iter {
        let dir_entry = match entry {
            Ok(e) => e,
            Err(e) => {
                // Entry singola non leggibile: skip + log, non abortire tutto il walk.
                eprintln!(
                    "[WARN] walk: skip entry non leggibile in {}: {}",
                    full.display(),
                    e
                );
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
                eprintln!(
                    "[WARN] walk: skip rel_path non-UTF-8: {}",
                    child_rel.display()
                );
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
                eprintln!(
                    "[WARN] walk: skip metadata non leggibile {}: {}",
                    child_rel_str, e
                );
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
            walk_recursive(
                base,
                &child_rel,
                out,
                skipped_non_utf8,
                skipped_reserved,
                skipped_unreadable,
            )?;
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

/// Esito di LIST remoto: entry enumerate + directory remote non leggibili
/// (trailer opzionale di LIST_RES — vuoto su server pre-feature).
#[derive(Debug, Default)]
pub struct ListOutcome {
    pub entries: Vec<Entry>,
    /// rel_path delle sotto-dir remote illeggibili (walk continuato):
    /// il loro contenuto e' sconosciuto — vedi delete-guard in execute_sync.
    pub skipped: Vec<String>,
}

/// Lato client: invia LIST_REQ e legge LIST_RES (o ERR).
/// Ritorna entry remote + skipped. `with_hash` controlla se il server include
/// SHA-256 per i file (un solo passaggio sul filesystem remoto, sync-spec §6.1).
/// `recursive` = false lista solo il livello top della directory (probe
/// poco costosi, es. resolve_remote_file_dest).
pub async fn list_remote_dir(
    stream: &mut Link,
    remote_dir: &str,
    with_hash: bool,
    recursive: bool,
) -> Result<ListOutcome> {
    // Costruisce la ListReq: recursive dal flag, with_hash dal flag.
    let req = ListReq {
        path: remote_dir.to_string(),
        recursive: if recursive { 1 } else { 0 },
        with_hash: if with_hash { 1 } else { 0 },
    };
    crate::qprintln!(
        "[DEBUG] list_remote_dir: LIST_REQ path={} recursive={} with_hash={}",
        remote_dir,
        req.recursive,
        req.with_hash
    );
    proto::send_list_req(stream, &req).await?;

    // Legge la risposta: LIST_RES o ERR.
    let (msg_type, payload) = proto::read_msg(stream).await?;
    if msg_type == MSG_ERR {
        let err = proto::decode_err(&payload)?;
        // ERR 1 = path invalido, ERR 5 = cap superato / proto.
        bail!(
            "LIST_REQ rifiutata dal server: ERR {}: {}",
            err.code,
            err.message
        );
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
    crate::qprintln!(
        "[DEBUG] list_remote_dir: ricevute {} entry",
        res.entries.len()
    );

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
    // Skipped remoti (trailer opzionale): le dir qui elencate esistono ma
    // non sono leggibili dal server — il loro contenuto e' sconosciuto.
    if !res.skipped.is_empty() {
        eprintln!(
            "[WARN] list_remote_dir: {} directory remote non leggibili (contenuto ignoto)",
            res.skipped.len()
        );
    }
    Ok(ListOutcome {
        entries: clean,
        skipped: res.skipped,
    })
}

// ---------------------------------------------------------------------------
// Esclusioni (--exclude <pattern>) - glob semplice su rel_path.
// ---------------------------------------------------------------------------

/// Match glob minimale: '*' = qualunque sequenza (incl. '/', vuota),
/// '?' = un carattere. Ricorsione su '*' con backtracking.
/// (Niente dipendenze esterne: la sintassi resta volutamente essenziale.)
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let pat: Vec<char> = pattern.chars().collect();
    let txt: Vec<char> = text.chars().collect();
    glob_match_rec(&pat, 0, &txt, 0)
}

/// Cuore ricorsivo del match glob con backtracking su '*'.
fn glob_match_rec(pat: &[char], pi: usize, txt: &[char], ti: usize) -> bool {
    if pi == pat.len() {
        return ti == txt.len();
    }
    match pat[pi] {
        '*' => {
            // '*' matcha zero o piu' caratteri qualsiasi (anche '/').
            let mut k = ti;
            while k <= txt.len() {
                if glob_match_rec(pat, pi + 1, txt, k) {
                    return true;
                }
                k += 1;
            }
            false
        }
        '?' => ti < txt.len() && glob_match_rec(pat, pi + 1, txt, ti + 1),
        c => ti < txt.len() && txt[ti] == c && glob_match_rec(pat, pi + 1, txt, ti + 1),
    }
}

/// True se `rel_path` e' escluso da `patterns` (semantica --exclude stile
/// rsync, semplificata):
/// - pattern con '/'  -> match sul rel_path intero E su ogni antenato
///   (escludere "a/b" esclude anche il subtree "a/b/c");
/// - pattern senza '/' -> match sul basename di ogni componente del path
///   (escludere "*.log" esclude "sub/x.log"; escludere "cache" esclude
///   "a/cache/b" perche' il componente dir "cache" matcha).
pub fn is_excluded(rel_path: &str, patterns: &[String]) -> bool {
    if patterns.is_empty() {
        return false;
    }
    // Candidati: il rel_path stesso + ogni antenato (componente a prefisso).
    // Es: "a/b/c" -> ["a/b/c", "a/b", "a"].
    let mut candidates: Vec<&str> = Vec::new();
    candidates.push(rel_path);
    let bytes = rel_path.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'/' {
            let ancestor = &rel_path[..i];
            candidates.push(ancestor);
        }
        i += 1;
    }
    for pat in patterns {
        let pat = pat.trim_matches('/');
        if pat.is_empty() {
            continue;
        }
        let has_slash = pat.contains('/');
        for cand in &candidates {
            if has_slash {
                if glob_match(pat, cand) {
                    return true;
                }
            } else {
                // Pattern basename-only: confronta col nome del componente.
                let base = cand.rsplit('/').next().unwrap_or(cand);
                if glob_match(pat, base) {
                    return true;
                }
            }
        }
    }
    false
}

/// Filtra le entry locali e remote secondo le esclusioni --exclude.
/// Entrambi i lati: un path escluso non e' ne' trasferito ne' cancellato
/// (esattamente come rsync --exclude).
pub fn apply_exclusions(local: &mut WalkResult, remote: &mut Vec<Entry>, patterns: &[String]) {
    if patterns.is_empty() {
        return;
    }
    // Locale: le entry escluse spariscono dal source (non vanno in NEW).
    let mut kept_local: Vec<Entry> = Vec::with_capacity(local.entries.len());
    let mut excluded_count = 0usize;
    let mut idx = 0usize;
    while idx < local.entries.len() {
        let e = &local.entries[idx];
        if is_excluded(&e.rel_path, patterns) {
            excluded_count += 1;
        } else {
            kept_local.push(e.clone());
        }
        idx += 1;
    }
    local.entries = kept_local;
    // Remoto: le entry escluse spariscono dalla vista -> non MISSING ->
    // non cancellabili con --delete (rsync: l'esclusione protegge anche
    // dalla cancellazione, non solo dal trasferimento).
    let mut kept_remote: Vec<Entry> = Vec::with_capacity(remote.len());
    let mut j = 0usize;
    while j < remote.len() {
        let e = &remote[j];
        if is_excluded(&e.rel_path, patterns) {
            excluded_count += 1;
        } else {
            kept_remote.push(e.clone());
        }
        j += 1;
    }
    *remote = kept_remote;
    if excluded_count > 0 {
        crate::qprintln!(
            "[sync] --exclude: {} path esclusi (pattern: {})",
            excluded_count,
            patterns.join(", ")
        );
    }
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
pub fn compute_diff(
    local: &WalkResult,
    remote: &[Entry],
    checksum: bool,
    local_dir: &Path,
) -> Diff {
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
    let mut matched_remote_lower: std::collections::HashSet<String> =
        std::collections::HashSet::new();

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
                    let reason = format!(
                        "file vs dir (locale {}, remoto {})",
                        kind_local, kind_remote
                    );
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
        skipped_unreadable: local.skipped_unreadable.clone(),
        skipped_remote: Vec::new(),
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
        skipped_unreadable: diff.skipped_unreadable.clone(),
        skipped_remote: diff.skipped_remote.clone(),
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
// Destinazione di `sync <file> <remote>` - risoluzione file vs directory.
// ---------------------------------------------------------------------------

/// Esito della risoluzione di `remote_dir` quando il source e' un FILE singolo.
#[derive(Debug)]
pub enum RemoteFileDest {
    /// Il remote e' una directory (esistente, o '/' finale): il file va
    /// in `<dir>/<basename>`.
    Dir(String),
    /// Il remote e' il path FILE completo di destinazione (rename supportato).
    File(String),
}

/// Risolve `remote_dir` per `sync <file> <remote>`.
///
/// Bug report: il remote era SEMPRE trattato come directory, quindi
/// `sync default.conf /var/docker/.../default.conf` produceva
/// `.../default.conf/default.conf` e falliva con `ERR 3: impossibile
/// creare .part`. Ora la semantica e' quella di rsync:
/// - '/' (o '\') finale -> directory esplicita;
/// - path esistente come DIRECTORY sul remote -> directory;
/// - qualunque altro caso (file esistente, path mancante) -> il remote
///   arg E' il path file di destinazione (rename incluso).
///
/// Il tipo remoto si scopre con UNA LIST non-ricorsiva della directory
/// PADRE: LIST sul path stesso non distingue "dir vuota" da "inesistente"
/// (entrambe rispondono 0 entry), mentre il parent dice se il basename
/// esiste ed e' una directory.
pub async fn resolve_remote_file_dest(
    stream: &mut Link,
    remote_dir: &str,
) -> Result<RemoteFileDest> {
    // '/' o '\' finale = intento directory esplicito (la creazione se
    // mancante e' demandata a ensure_remote_dir dal caller).
    let stripped = remote_dir.trim_end_matches(['/', '\\']);
    if stripped.len() < remote_dir.len() {
        // Root secche da NON "snudare": "/" -> stripped "" e "C:\" ->
        // stripped "C:" (drive-relative, non la root). In quei casi il
        // remote e' gia' la directory.
        let is_bare_root = stripped.is_empty()
            || (stripped.len() == 2 && stripped.ends_with(':'));
        let dir = if is_bare_root {
            remote_dir.to_string()
        } else {
            stripped.to_string()
        };
        crate::qprintln!(
            "[DEBUG] sync file: remote '{}' -> directory (separatore finale)",
            remote_dir
        );
        return Ok(RemoteFileDest::Dir(dir));
    }

    // Scomposizione parent/basename sul separatore finale ('/' o '\'):
    // senza separatore non c'e' parent da ispezionare -> path file.
    let split = remote_parent_and_base(remote_dir);
    let (parent, remote_base) = match split {
        Some(pb) => pb,
        None => {
            crate::qprintln!(
                "[DEBUG] sync file: remote '{}' senza separatore -> path file",
                remote_dir
            );
            return Ok(RemoteFileDest::File(remote_dir.to_string()));
        }
    };

    // Probe: LIST del parent (NON ricorsiva — serve solo il tipo del
    // basename, non il contenuto). Il confronto e' case-insensitive come
    // il diff (sync-spec §8.1): su Windows "Conf.d" == "conf.d".
    let probe = list_remote_dir(stream, &parent, false, false).await;
    let base_lower = remote_base.to_lowercase();
    match probe {
        Ok(outcome) => {
            for entry in &outcome.entries {
                let entry_lower = entry.rel_path.to_lowercase();
                if entry_lower == base_lower && entry.is_dir == 1 {
                    crate::qprintln!(
                        "[DEBUG] sync file: remote '{}' e' una directory esistente",
                        remote_dir
                    );
                    return Ok(RemoteFileDest::Dir(remote_dir.to_string()));
                }
            }
            crate::qprintln!(
                "[DEBUG] sync file: remote '{}' non e' directory esistente -> path file",
                remote_dir
            );
        }
        Err(e) => {
            // Probe fallito (parent invalido/illeggibile): il dest resta il
            // path file — un eventuale errore reale emerga al PUT, non qui.
            crate::qprintln!(
                "[DEBUG] sync file: probe parent '{}' fallita ({}) -> dest come path file",
                parent,
                e
            );
        }
    }
    Ok(RemoteFileDest::File(remote_dir.to_string()))
}

/// Scompone un remote path in (parent, basename) sull'ULTIMO separatore
/// ('/' o '\'). Casi limite: "/x" -> parent "/" (non ""); "C:\x" ->
/// parent "C:\" (non "C:", che sarebbe drive-relative). Senza separatore
/// -> None (nessun parent da ispezionare). Funzione pura (testabile
/// senza rete, best-practice: logica separata dal probe).
fn remote_parent_and_base(remote_dir: &str) -> Option<(String, String)> {
    let pos = remote_dir.rfind(['/', '\\'])?;
    let base = remote_dir[pos + 1..].to_string();
    if base.is_empty() {
        return None;
    }
    let parent_slice = &remote_dir[..pos];
    let mut parent = if parent_slice.is_empty() {
        remote_dir[..=pos].to_string()
    } else {
        parent_slice.to_string()
    };
    if parent.ends_with(':') {
        parent.push('\\');
    }
    Some((parent, base))
}

/// Crea una directory remota (mkdir -p idempotente) via MKDIR_BATCH.
/// Usata quando il dest di un sync-file e' dichiarato directory ('/'
/// finale) ma potrebbe non esistere ancora sul remote.
pub async fn ensure_remote_dir(stream: &mut Link, dir: &str) -> Result<()> {
    let req = MkdirBatchReq {
        paths: vec![dir.to_string()],
    };
    proto::send_mkdir_batch_req(stream, &req).await?;
    let (msg_type, payload) = proto::read_msg(stream).await?;
    if msg_type == MSG_ERR {
        let err = proto::decode_err(&payload)?;
        bail!("MKDIR rifiutato: ERR {}: {}", err.code, err.message);
    }
    if msg_type != MSG_MKDIR_BATCH_RES {
        bail!(
            "ensure_remote_dir: atteso MKDIR_BATCH_RES (tipo {}), ricevuto tipo {}",
            MSG_MKDIR_BATCH_RES,
            msg_type
        );
    }
    let res = proto::decode_mkdir_batch_res(&payload, 1)?;
    for r in &res.results {
        if r.status == 2 {
            bail!("mkdir remoto '{}' fallito: ERR {}: {}", dir, r.code, r.message);
        }
    }
    Ok(())
}

/// Conta i FILE marcati Identical nel diff (le directory non contano: per
/// loro "identical" significa solo presente su entrambi i lati). Usato dal
/// warning "confronto per sola dimensione" quando --checksum non e' attivo.
pub fn count_identical_files(diff: &Diff) -> usize {
    let mut n = 0usize;
    for e in &diff.entries {
        if e.status != EntryStatus::Identical {
            continue;
        }
        let local_is_dir = match &e.local {
            Some(l) => l.is_dir == 1,
            None => false,
        };
        if !local_is_dir {
            n += 1;
        }
    }
    n
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
    // Walk incompleti: directory non leggibili (il contenuto e' sconosciuto,
    // non "identico" — un sync --delete le proteggerebbe comunque).
    for s in &diff.skipped_unreadable {
        eprintln!("[status] WARN directory locale non leggibile: {}", s);
    }
    for s in &diff.skipped_remote {
        eprintln!("[status] WARN directory remota non leggibile: {}", s);
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
    // SKIP directory locali illeggibili (walk sorgente incompleto).
    for s in &plan.skipped_unreadable {
        println!("SKIP      {} (directory locale non leggibile)", s);
    }
    // SKIP directory remote illeggibili (walk dest incompleto).
    for s in &plan.skipped_remote {
        println!("SKIP      {} (directory remota non leggibile)", s);
    }
}

/// Stampa il riepilogo finale di sync (sync-spec §11).
/// Con `dry_run` i contatori riflettono il PIANO (nessuna op eseguita):
/// il testo lo dice esplicitamente — prima stampava "0 trasferiti" anche
/// con un piano pieno e l'utente doveva contare le righe PUT a mano
/// (bug report sul riepilogo fuorviante).
pub fn print_sync_report(report: &SyncReport, quiet: bool, dry_run: bool) {
    if quiet {
        let dry_tag = if dry_run { "dry_run=1 " } else { "" };
        eprintln!(
            "[sync] {}put={} delete={} skip={} errors={} bytes={} delta={} time={:.1}s",
            dry_tag,
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
        if dry_run {
            eprintln!(
                "[sync] dry-run (nessuna modifica remota): {} da trasferire ({} byte totali), {} da cancellare, {} saltati, {} conflict/errori",
                report.put_count,
                report.bytes_total,
                report.delete_count,
                report.skip_count,
                report.error_count
            );
        } else {
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

/// Connessione persistente riusabile per tutte le operazioni di un sync.
///
/// Prima ogni operazione apriva una connessione nuova (spec §5 "una
/// connessione = una operazione"): handshake TCP+TLS ripetuto per OGNI
/// file (report utente: sync lento e rumoroso). I server nuovi tengono
/// la connessione file-mode aperta in un loop di messaggi, quindi una
/// sola sessione serve tutto il sync.
///
/// Compatibilita' con i server vecchi (che chiudono dopo UNA operazione):
/// il primo fallimento di trasporto su una connessione gia' usata marca
/// `single_shot` — da quel punto si riapre una connessione fresca per
/// ogni op, riproducendo il comportamento legacy senza round-trip sprecati.
/// Qualunque drop di trasporto causa UNA riconnessione+retry (tutte le
/// operazioni sync — LIST, PUT, MKDIR_BATCH, DELETE_BATCH — sono
/// idempotenti); gli errori di protocollo non si ritentano mai.
/// Futuro boxed della connect callback (alias per type_complexity).
type ConnectFut = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Link>> + Send>>;
/// Callback boxed che apre connessione+handshake+reconcile.
type ConnectFn = Box<dyn FnMut() -> ConnectFut + Send>;

pub struct SyncSession {
    /// Connessione corrente (None = da (ri)aprire prima della prossima op).
    link: Option<Link>,
    /// Callback che apre connessione+handshake+reconcile (connect_and_handshake).
    connect: ConnectFn,
    /// Il link corrente ha gia' completato almeno un'op: se ora muore il
    /// server e' "one-shot" (chiude dopo ogni operazione = pre-sessione
    /// persistente) — si passa a conn fresca per op senza altri fallimenti.
    served_on_link: bool,
    /// Server "one-shot" rilevato: conn fresca per op (comportamento legacy).
    single_shot: bool,
    /// Contatore riconnessioni (diagnostica/report).
    pub reconnects: u32,
}

impl SyncSession {
    /// Avvolge la callback di connessione (es. `|| connect_and_handshake().await`).
    pub fn new<F, Fut>(mut connect: F) -> Self
    where
        F: FnMut() -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<Link>> + Send + 'static,
    {
        Self {
            link: None,
            connect: Box::new(move || Box::pin(connect())),
            served_on_link: false,
            single_shot: false,
            reconnects: 0,
        }
    }

    /// Come `new()`, ma parte da una connessione GIA' aperta (es. quella
    /// appena usata per il probe LIST del tipo remoto): evita una
    /// ri-handshake. `served_on_link` e' pre-marcato true: se il link
    /// risulta gia' chiuso (server one-shot che chiude dopo ogni op) la
    /// prima op fa reconnect e marca single_shot, come da protocollo.
    pub fn new_with_link<F, Fut>(link: Link, connect: F) -> Self
    where
        F: FnMut() -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<Link>> + Send + 'static,
    {
        let mut session = Self::new(connect);
        session.link = Some(link);
        session.served_on_link = true;
        session
    }

    /// Esegue un'operazione framed sulla connessione corrente.
    /// Su drop di trasporto: una riconnessione + retry (le op sync sono
    /// idempotenti). Errori di protocollo: propagati subito, mai ritentati.
    pub async fn op<T>(&mut self, mut f: impl AsyncFnMut(&mut Link) -> Result<T>) -> Result<T> {
        let mut attempt = 0u32;
        loop {
            if self.link.is_none() {
                let conn = (self.connect)().await?;
                self.link = Some(conn);
                self.served_on_link = false;
            }
            attempt += 1;
            // take() del link: libera il borrow su self durante l'await.
            let mut link = self.link.take().unwrap();
            let was_used = self.served_on_link;
            let result = f(&mut link).await;
            match result {
                Ok(v) => {
                    if self.single_shot {
                        // Server one-shot: la connessione e' comunque morta
                        // dopo l'op — si butta subito (prossima op riapre).
                        self.link = None;
                        self.served_on_link = false;
                    } else {
                        self.link = Some(link);
                        self.served_on_link = true;
                    }
                    return Ok(v);
                }
                Err(e) => {
                    self.link = None;
                    self.served_on_link = false;
                    if attempt >= 2 || !is_transport_drop(&e) {
                        return Err(e);
                    }
                    if was_used {
                        // Morta DOPO un'op riuscita -> chiusura-per-op del
                        // server legacy, non un problema di rete.
                        self.single_shot = true;
                    }
                    self.reconnects += 1;
                    crate::qprintln!("[sync] connessione remota chiusa, riconnessione e retry...");
                }
            }
        }
    }
}

/// True se l'errore e' un drop di trasporto (connessione chiusa/reset/eof):
/// unico caso in cui riconnettere+riprovare ha senso. Gli errori di
/// protocollo ("rifiutata", "atteso X ricevuto Y", ERR server) non sono
/// ritentabili: su una connessione fresca fallirebbero identici.
fn is_transport_drop(e: &anyhow::Error) -> bool {
    // io::Error in catena: UnexpectedEof/ConnectionReset/BrokenPipe di
    // read_exact/write_all, o errori TLS incapsulati come io::Error.
    for cause in e.chain() {
        if cause.is::<std::io::Error>() {
            return true;
        }
    }
    // Fallback testuale per errori anyhow senza io::Error nella catena
    // (es. "early eof" sollevato come bail! testuale dal reader TLS).
    let msg = format!("{:#}", e).to_lowercase();
    msg.contains("eof")
        || msg.contains("closed")
        || msg.contains("reset by peer")
        || msg.contains("broken pipe")
}

/// Esegue il piano di sync: MKDIR_BATCH + put per-file + DELETE_BATCH.
/// Gestisce CONFLICT (abort di quel path, errore parziale), --dry-run, --quiet.
/// Niente connessioni parallele (best-practice): ogni operazione è sequenziale.
///
/// Tutte le operazioni vanno su UNA SyncSession (connessione persistente
/// riusata con reconnect-on-drop); su server pre-sessione il fallback
/// "una connessione per op" e' automatico (vedi SyncSession).
///
/// `connect` è una callback che stabilisce una nuova connessione+handshake
/// (riutilizza connect_and_handshake di main.rs, invariata).
pub async fn execute_sync<F, Fut>(
    plan: &Plan,
    params: &SyncParams,
    connect: F,
) -> Result<SyncReport>
where
    F: FnMut() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<Link>> + Send + 'static,
{
    let start = Instant::now();
    let mut report = SyncReport::default();
    let local_dir = Path::new(&params.local_dir);

    // Walk incompleto (dir locali o remote illeggibili): i contenuti
    // sotto-enumerati rendono la fase DELETE pericolosa (file esistenti
    // ma non visti apparirebbero "extra" -> cancellati). Semantica rsync:
    // "IO error encountered -- skipping file deletion". Warning esplicito
    // + skip di TUTTA la fase delete, anche in dry-run... no: in dry-run
    // il piano si mostra comunque com'e' (nessun effetto collaterale).
    let delete_guard =
        params.delete && (!plan.skipped_unreadable.is_empty() || !plan.skipped_remote.is_empty());
    if delete_guard {
        eprintln!(
            "[WARN] sync: --delete sospeso: {} dir locali e {} dir remote non leggibili \
             (contenuto ignoto — nessuna cancellazione per sicurezza)",
            plan.skipped_unreadable.len(),
            plan.skipped_remote.len()
        );
    }

    // --dry-run: stampa il piano ed esci (sync-spec §7 passo 4, §14 test 8).
    // Bug fix (report utente): i contatori del riepilogo contavano solo le
    // operazioni ESEGUITE -> in dry-run stampavano sempre 0/0/0 anche con
    // un piano pieno, e l'utente doveva fare grep manuale sulle righe PUT.
    // Ora il report riflette il piano: files_to_put -> put_count, i set di
    // cancellazione -> delete_count, tutte le categorie SKIP stampate da
    // print_plan -> skip_count, i conflict -> error_count.
    if params.dry_run {
        print_plan(plan);
        report.put_count = plan.files_to_put.len() as u32;
        let del_files = plan.files_to_delete.len() as u32;
        let del_dirs = plan.dirs_to_delete.len() as u32;
        report.delete_count = del_files + del_dirs;
        let mut skip_total = plan.skipped_identical.len();
        skip_total += plan.skipped_non_utf8.len();
        skip_total += plan.skipped_reserved.len();
        skip_total += plan.skipped_unreadable.len();
        skip_total += plan.skipped_remote.len();
        report.skip_count = skip_total as u32;
        report.error_count = plan.conflicts.len() as u32;
        // bytes_total: somma delle dimensioni locali dei file da trasferire
        // (stat locale, nessuna op remota). delta_bytes resta 0: il delta
        // reale e' calcolabile solo trasferendo.
        for rel in &plan.files_to_put {
            let full = local_dir.join(rel);
            let meta = fs::metadata(&full);
            if let Ok(m) = meta {
                report.bytes_total += m.len();
            }
        }
        report.elapsed = start.elapsed();
        return Ok(report);
    }

    // Sessione persistente: una connessione serve tutte le operazioni
    // (reconnect-on-drop + fallback one-shot su server legacy).
    let mut session = SyncSession::new(connect);

    // --- Passo 5: MKDIR_BATCH (remote_dir + tutte le dirs_to_create) ---
    // Il batch si manda anche quando dirs_to_create e' vuoto ma ci sono
    // file da trasferire: il remote_dir stesso e' il primo path del batch
    // (mkdir -p idempotente). Senza questo, sync su root remota NUOVA con
    // sorgente piatto (solo file top-level) falliva al primo PUT con
    // ERR 3 su .part — nessun MKDIR creava la root (bug latente: la spec
    // §9 presuppone "dest nuovo = caso comune" ma la root non era mai
    // creata esplicitamente).
    if !plan.dirs_to_create.is_empty() || !plan.files_to_put.is_empty() {
        let mkdir_result = run_mkdir_batch(plan, params, &mut session).await;
        match mkdir_result {
            Ok(mkdir_errors) => {
                // Conta gli errori di mkdir (status=2).
                for err in &mkdir_errors {
                    report.errors.push(err.clone());
                    report.error_count += 1;
                }
                if !params.quiet {
                    crate::qprintln!(
                        "[sync] MKDIR  {} directory create (root inclusa)",
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

    // --- Passo 6: put per-file (sequenziale sulla sessione) ---
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

        // PUT sulla connessione della sessione (riusata; reconnect+retry
        // automatico su drop — put e' idempotente, sync-spec §7).
        let local_ref = local_str.as_str();
        let remote_ref = remote_full.as_str();
        let put_result = session
            .op(async |socket: &mut Link| {
                crate::transfer::put_client(socket, local_ref, remote_ref).await
            })
            .await;
        match put_result {
            Ok(()) => {
                report.put_count += 1;
                report.bytes_total += file_size;
                if !params.quiet {
                    crate::qprintln!("[sync] PUT    {} ({} byte)", rel_path, file_size);
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

    // --- Passo 8: DELETE (solo con --delete E walk completo) ---
    // delete_guard: se il walk ha saltato directory illeggibili (locale o
    // remote) la fase delete e' sospesa — il warning e' gia' stato emesso.
    if params.delete && !delete_guard {
        // 8a: DELETE_BATCH file (recursive=0).
        if !plan.files_to_delete.is_empty() {
            let del_result = run_delete_batch_files(plan, params, &mut session).await;
            match del_result {
                Ok(del_errors) => {
                    for err in &del_errors {
                        report.errors.push(err.clone());
                        report.error_count += 1;
                    }
                    report.delete_count += plan.files_to_delete.len() as u32;
                    if !params.quiet {
                        crate::qprintln!("[sync] DELETE {} file", plan.files_to_delete.len());
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
        // 8b: DELETE_BATCH dir (recursive=1, profondità decrescente).
        if !plan.dirs_to_delete.is_empty() {
            let del_result = run_delete_batch_dirs(plan, params, &mut session).await;
            match del_result {
                Ok(del_errors) => {
                    for err in &del_errors {
                        report.errors.push(err.clone());
                        report.error_count += 1;
                    }
                    report.delete_count += plan.dirs_to_delete.len() as u32;
                    if !params.quiet {
                        crate::qprintln!(
                            "[sync] DELETE {} dir (recursive)",
                            plan.dirs_to_delete.len()
                        );
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

    // Diagnostica sessione: quante riconnessioni sono servite (drop di
    // rete o fallback one-shot su server legacy).
    if session.reconnects > 0 {
        crate::qprintln!("[sync] riconnessioni effettuate: {}", session.reconnects);
    }

    report.elapsed = start.elapsed();
    Ok(report)
}

/// Esegue MKDIR_BATCH_REQ sulla connessione della sessione. Ritorna la lista
/// di messaggi di errore per-path (status=2). Count mismatch -> errore fatale.
/// Il primo path del batch e' sempre il remote_dir stesso (mkdir -p
/// idempotente): garantisce la root di destinazione anche quando non ci
/// sono sotto-directory da creare (sync su dest nuovo con source piatto).
async fn run_mkdir_batch(
    plan: &Plan,
    params: &SyncParams,
    session: &mut SyncSession,
) -> Result<Vec<String>> {
    let mut paths = Vec::with_capacity(plan.dirs_to_create.len() + 1);
    // Root remota per prima: i genitori vengono sempre prima dei figli
    // (mkdir -p la creerebbe comunque, ma esplicitarla rende l'errore di
    // validazione/containment della ROOT diagnosticabile subito).
    paths.push(params.remote_dir.clone());
    for rel in &plan.dirs_to_create {
        let full = join_remote_path(&params.remote_dir, rel);
        paths.push(full);
    }
    let req = MkdirBatchReq { paths };
    let expected = req.paths.len();

    let payload = session
        .op(async |socket: &mut Link| {
            proto::send_mkdir_batch_req(socket, &req).await?;
            let (msg_type, payload) = proto::read_msg(socket).await?;
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
            Ok(payload)
        })
        .await?;
    // Count mismatch -> ERR 5 (sync-spec §9): decode restituisce Err.
    let res = proto::decode_mkdir_batch_res(&payload, expected)?;
    let mut errors = Vec::new();
    let mut idx = 0usize;
    while idx < res.results.len() {
        let r = &res.results[idx];
        if r.status == 2 {
            // Il primo risultato riguarda il remote_dir (root), i successivi
            // seguono l'ordine di dirs_to_create.
            let rel = if idx == 0 {
                params.remote_dir.as_str()
            } else {
                plan.dirs_to_create[idx - 1].as_str()
            };
            errors.push(format!("{}: server ERR {}: {}", rel, r.code, r.message));
        }
        idx += 1;
    }
    Ok(errors)
}

/// Esegue DELETE_BATCH_REQ per i file (recursive=0) sulla connessione della sessione.
async fn run_delete_batch_files(
    plan: &Plan,
    params: &SyncParams,
    session: &mut SyncSession,
) -> Result<Vec<String>> {
    let mut items = Vec::with_capacity(plan.files_to_delete.len());
    for rel in &plan.files_to_delete {
        let full = join_remote_path(&params.remote_dir, rel);
        items.push(DeleteItem {
            path: full,
            recursive: 0,
        });
    }
    run_delete_batch(&plan.files_to_delete, items, session).await
}

/// Esegue DELETE_BATCH_REQ per le directory (recursive=1) sulla connessione della sessione.
async fn run_delete_batch_dirs(
    plan: &Plan,
    params: &SyncParams,
    session: &mut SyncSession,
) -> Result<Vec<String>> {
    let mut items = Vec::with_capacity(plan.dirs_to_delete.len());
    for rel in &plan.dirs_to_delete {
        let full = join_remote_path(&params.remote_dir, rel);
        items.push(DeleteItem {
            path: full,
            recursive: 1,
        });
    }
    run_delete_batch(&plan.dirs_to_delete, items, session).await
}

/// Helper comune per DELETE_BATCH (file o dir). `rels` serve per mappare gli
/// errori per-path al rel_path (per il report).
async fn run_delete_batch(
    rels: &[String],
    items: Vec<DeleteItem>,
    session: &mut SyncSession,
) -> Result<Vec<String>> {
    let expected = items.len();
    let req = DeleteBatchReq { items };

    let payload = session
        .op(async |socket: &mut Link| {
            proto::send_delete_batch_req(socket, &req).await?;
            let (msg_type, payload) = proto::read_msg(socket).await?;
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
            Ok(payload)
        })
        .await?;
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
                Entry {
                    rel_path: "a.txt".into(),
                    size: 5,
                    is_dir: 0,
                    sha256: None,
                },
                Entry {
                    rel_path: "sub".into(),
                    size: 0,
                    is_dir: 1,
                    sha256: None,
                },
            ],
            ..Default::default()
        };
        let remote = vec![
            Entry {
                rel_path: "a.txt".into(),
                size: 5,
                is_dir: 0,
                sha256: None,
            },
            Entry {
                rel_path: "sub".into(),
                size: 0,
                is_dir: 1,
                sha256: None,
            },
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
                Entry {
                    rel_path: "new.txt".into(),
                    size: 3,
                    is_dir: 0,
                    sha256: None,
                },
                Entry {
                    rel_path: "changed.txt".into(),
                    size: 10,
                    is_dir: 0,
                    sha256: None,
                },
                Entry {
                    rel_path: "same.txt".into(),
                    size: 5,
                    is_dir: 0,
                    sha256: None,
                },
            ],
            ..Default::default()
        };
        let remote = vec![
            Entry {
                rel_path: "changed.txt".into(),
                size: 7,
                is_dir: 0,
                sha256: None,
            },
            Entry {
                rel_path: "same.txt".into(),
                size: 5,
                is_dir: 0,
                sha256: None,
            },
            Entry {
                rel_path: "missing.txt".into(),
                size: 8,
                is_dir: 0,
                sha256: None,
            },
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
        assert_eq!(
            find_diff(&diff.entries, "changed.txt").status,
            EntryStatus::Changed
        );
        assert_eq!(
            find_diff(&diff.entries, "missing.txt").status,
            EntryStatus::Missing
        );
        assert_eq!(
            find_diff(&diff.entries, "same.txt").status,
            EntryStatus::Identical
        );
    }

    #[test]
    fn diff_conflict_file_vs_dir() {
        // sync-spec §14 test 13: file vs dir sullo stesso rel_path -> CONFLICT.
        let local = WalkResult {
            entries: vec![Entry {
                rel_path: "data".into(),
                size: 100,
                is_dir: 0,
                sha256: None,
            }],
            ..Default::default()
        };
        let remote = vec![Entry {
            rel_path: "data".into(),
            size: 0,
            is_dir: 1,
            sha256: None,
        }];
        let dir = Path::new("/tmp");
        let diff = compute_diff(&local, &remote, false, dir);
        let counts = diff.counts();
        assert_eq!(counts.conflict, 1);
        assert_eq!(
            find_diff(&diff.entries, "data").status,
            EntryStatus::Conflict
        );
    }

    #[test]
    fn diff_case_collision() {
        // sync-spec §14 test 18: source con a.txt + A.txt -> entrambi CONFLICT.
        let local = WalkResult {
            entries: vec![
                Entry {
                    rel_path: "a.txt".into(),
                    size: 3,
                    is_dir: 0,
                    sha256: None,
                },
                Entry {
                    rel_path: "A.txt".into(),
                    size: 4,
                    is_dir: 0,
                    sha256: None,
                },
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
            entries: vec![Entry {
                rel_path: "same_size.txt".into(),
                size: 4,
                is_dir: 0,
                sha256: None,
            }],
            ..Default::default()
        };
        let remote = vec![Entry {
            rel_path: "same_size.txt".into(),
            size: 4,
            is_dir: 0,
            sha256: Some(fake_remote_hash),
        }];
        let diff = compute_diff(&local, &remote, true, &root);
        // size uguale ma hash diverso -> CHANGED.
        assert_eq!(
            find_diff(&diff.entries, "same_size.txt").status,
            EntryStatus::Changed
        );

        // Ora con hash uguale -> IDENTICAL.
        let remote_ok = vec![Entry {
            rel_path: "same_size.txt".into(),
            size: 4,
            is_dir: 0,
            sha256: Some(local_hash),
        }];
        let diff2 = compute_diff(&local, &remote_ok, true, &root);
        assert_eq!(
            find_diff(&diff2.entries, "same_size.txt").status,
            EntryStatus::Identical
        );

        let _ = fs::remove_dir_all(&root);
    }

    // --- build_plan (sync-spec §15 passo 6, §14 test 4-8) -----------------

    #[test]
    fn plan_dirs_sorted_by_depth_ascending() {
        // sync-spec §7: MKDIR in ordine profondità crescente (genitori prima).
        let diff = Diff {
            entries: vec![
                DiffEntry {
                    rel_path: "a/b/c/d".into(),
                    status: EntryStatus::New,
                    local: Some(Entry {
                        rel_path: "a/b/c/d".into(),
                        size: 0,
                        is_dir: 1,
                        sha256: None,
                    }),
                    remote: None,
                    conflict_reason: String::new(),
                },
                DiffEntry {
                    rel_path: "a".into(),
                    status: EntryStatus::New,
                    local: Some(Entry {
                        rel_path: "a".into(),
                        size: 0,
                        is_dir: 1,
                        sha256: None,
                    }),
                    remote: None,
                    conflict_reason: String::new(),
                },
                DiffEntry {
                    rel_path: "a/b".into(),
                    status: EntryStatus::New,
                    local: Some(Entry {
                        rel_path: "a/b".into(),
                        size: 0,
                        is_dir: 1,
                        sha256: None,
                    }),
                    remote: None,
                    conflict_reason: String::new(),
                },
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
                DiffEntry {
                    rel_path: "x".into(),
                    status: EntryStatus::Missing,
                    local: None,
                    remote: Some(Entry {
                        rel_path: "x".into(),
                        size: 0,
                        is_dir: 1,
                        sha256: None,
                    }),
                    conflict_reason: String::new(),
                },
                DiffEntry {
                    rel_path: "x/y/z".into(),
                    status: EntryStatus::Missing,
                    local: None,
                    remote: Some(Entry {
                        rel_path: "x/y/z".into(),
                        size: 0,
                        is_dir: 1,
                        sha256: None,
                    }),
                    conflict_reason: String::new(),
                },
                DiffEntry {
                    rel_path: "x/y".into(),
                    status: EntryStatus::Missing,
                    local: None,
                    remote: Some(Entry {
                        rel_path: "x/y".into(),
                        size: 0,
                        is_dir: 1,
                        sha256: None,
                    }),
                    conflict_reason: String::new(),
                },
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
            entries: vec![DiffEntry {
                rel_path: "extra.txt".into(),
                status: EntryStatus::Missing,
                local: None,
                remote: Some(Entry {
                    rel_path: "extra.txt".into(),
                    size: 5,
                    is_dir: 0,
                    sha256: None,
                }),
                conflict_reason: String::new(),
            }],
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
                DiffEntry {
                    rel_path: "conf".into(),
                    status: EntryStatus::Conflict,
                    local: Some(Entry {
                        rel_path: "conf".into(),
                        size: 1,
                        is_dir: 0,
                        sha256: None,
                    }),
                    remote: Some(Entry {
                        rel_path: "conf".into(),
                        size: 0,
                        is_dir: 1,
                        sha256: None,
                    }),
                    conflict_reason: "file vs dir".into(),
                },
                DiffEntry {
                    rel_path: "ok.txt".into(),
                    status: EntryStatus::New,
                    local: Some(Entry {
                        rel_path: "ok.txt".into(),
                        size: 1,
                        is_dir: 0,
                        sha256: None,
                    }),
                    remote: None,
                    conflict_reason: String::new(),
                },
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

    // --- remote_parent_and_base (risoluzione dest file singolo) ---------

    #[test]
    fn remote_parent_and_base_splits() {
        // Unix: split sull'ultimo '/'.
        let (p, b) = remote_parent_and_base("/var/docker/nginx/conf.d/default.conf").unwrap();
        assert_eq!(p, "/var/docker/nginx/conf.d");
        assert_eq!(b, "default.conf");
        // Root unix: il parent di "/x" e' "/" non "".
        let (p2, b2) = remote_parent_and_base("/x").unwrap();
        assert_eq!(p2, "/");
        assert_eq!(b2, "x");
        // Windows: split su '\'; il parent di "C:\x" e' "C:\" non "C:".
        let (p3, b3) = remote_parent_and_base("C:\\ci\\conf\\app.conf").unwrap();
        assert_eq!(p3, "C:\\ci\\conf");
        assert_eq!(b3, "app.conf");
        let (p4, b4) = remote_parent_and_base("C:\\x").unwrap();
        assert_eq!(p4, "C:\\");
        assert_eq!(b4, "x");
        // Senza separatore -> None (nessun parent).
        assert!(remote_parent_and_base("app.conf").is_none());
        // Basename vuoto (trailing sep non gestito qui) -> None.
        assert!(remote_parent_and_base("/dir/").is_none());
    }

    // --- Esclusioni --exclude (glob semplice) -------------------------------

    #[test]
    fn exclude_basename_and_path_patterns() {
        let pats = vec![
            "*.log".to_string(),
            "data/postgres".to_string(),
            "cache".to_string(),
        ];
        // Pattern basename-only: matcha ovunque nel path.
        assert!(is_excluded("sub/debug.log", &pats));
        assert!(is_excluded("debug.log", &pats));
        // Pattern con '/': match sul rel_path e sul subtree.
        assert!(is_excluded("data/postgres", &pats));
        assert!(is_excluded("data/postgres/base/PG_VERSION", &pats));
        // Componente dir esclusa -> subtree escluso.
        assert!(is_excluded("a/cache/b/c.txt", &pats));
        // Non esclusi.
        assert!(!is_excluded("src/main.rs", &pats));
        assert!(!is_excluded("data/postgres2/x", &pats));
        assert!(!is_excluded("cached/file", &pats));
    }

    #[test]
    fn glob_match_basics() {
        assert!(glob_match("*.log", "a.log"));
        assert!(glob_match("*.log", "a/b.log"));
        assert!(glob_match("a/*/c", "a/b/c"));
        assert!(glob_match("a?c", "abc"));
        assert!(!glob_match("a?c", "ac"));
        assert!(glob_match("x", "x"));
        assert!(!glob_match("x", "xy"));
        assert!(glob_match("", ""));
    }

    // --- execute_sync --dry-run (bug report: riepilogo sempre 0/0/0) -----

    #[tokio::test]
    async fn dry_run_report_reflects_plan() {
        // Bug report: --dry-run stampava "0 trasferiti, 0 saltati, 0 errori"
        // anche con un piano pieno — i contatori ignoravano il dry-run.
        // Ora il report riflette il piano (PUT/DELETE/SKIP/CONFLICT).
        let root = std::env::temp_dir().join("crosspilot_dry_run_report");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("a.txt"), b"hello").unwrap();

        let plan = Plan {
            files_to_put: vec!["a.txt".to_string()],
            files_to_delete: vec!["gone.txt".to_string()],
            dirs_to_delete: vec!["old".to_string()],
            skipped_identical: vec!["same.txt".to_string()],
            skipped_remote: vec!["denied".to_string()],
            conflicts: vec![("conf".to_string(), "file vs dir".to_string())],
            ..Default::default()
        };
        let params = SyncParams {
            local_dir: root.to_string_lossy().into_owned(),
            remote_dir: "/remote".to_string(),
            delete: true,
            dry_run: true,
            quiet: false,
        };
        // Connect callback che fallirebbe se chiamata: prova che il
        // dry-run non tocca la rete.
        let connect = || async {
            Err::<Link, anyhow::Error>(anyhow!("dry-run non deve connettersi"))
        };
        let report = execute_sync(&plan, &params, connect).await.unwrap();
        assert_eq!(report.put_count, 1);
        assert_eq!(report.delete_count, 2);
        // skipped_identical + skipped_remote = 2 righe SKIP stampate.
        assert_eq!(report.skip_count, 2);
        assert_eq!(report.error_count, 1);
        assert_eq!(report.bytes_total, 5);

        let _ = fs::remove_dir_all(&root);
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
