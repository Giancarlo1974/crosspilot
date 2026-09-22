//! Transfer file delta (stile rsync) tra client e server (spec docs/transfer-spec.md).
//!
//! Implementa upload (`put`) e download (`get`) con:
//! - Algoritmo rsync via `fast_rsync` (rolling checksum + strong hash + delta).
//! - SHA-256 whole-file per integrità end-to-end (fast_rsync usa MD4, insicuro).
//! - Chunking sequenziale per file di qualsiasi dimensione (memoria costante).
//! - Applicazione atomica su file `.part` + rename.
//!
//! Ruoli:
//! - PUT: client = sender (file nuovo = local_src), server = receiver (base = dest).
//! - GET: server = sender (file nuovo = remote_src), client = receiver (base = local_dst).

use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use fast_rsync::{Signature, SignatureOptions};
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;

use crate::path;
use crate::proto::{
    self, Ack, Delta, ErrMsg, GetReq, Meta, PutReq, Signature as SigMsg, TransferError,
    MSG_ACK, MSG_DELTA, MSG_ERR, MSG_META, MSG_SIGNATURE,
    ERR_CHECKSUM_MISMATCH, ERR_IO, ERR_PROTO,
};
use crate::verify::{sha256_bytes, sha256_file_handle};

// ---------------------------------------------------------------------------
// Costanti di configurazione (spec §6, §13).
// ---------------------------------------------------------------------------

/// Dimensione default del segmento: 64 MB.
/// Default basso per container CI con poca RAM (peak receiver ~192 MB a 64 MB).
pub const DEFAULT_SEGMENT_SIZE: u64 = 67_108_864;

/// Dimensione minima del segmento: 1 MB.
const MIN_SEGMENT_SIZE: u64 = 1_048_576;

/// Dimensione massima del segmento: 256 MB.
const MAX_SEGMENT_SIZE: u64 = 268_435_456;

/// Block size minimo per la signature rsync.
const MIN_BLOCK_SIZE: u32 = 2048;

/// Block size massimo per la signature rsync.
const MAX_BLOCK_SIZE: u32 = 65_536;

/// crypto_hash_size per SignatureOptions: 16 byte (MD4, massimo).
const CRYPTO_HASH_SIZE: u32 = 16;

/// Suffisso del file temporaneo di lavoro (scritto segmento per segmento).
const PART_SUFFIX: &str = ".part";

// ---------------------------------------------------------------------------
// Config helpers.
// ---------------------------------------------------------------------------

/// Legge la dimensione del segmento da env `CROSSPILOT_SEGMENT_SIZE` (in byte).
/// Risoluzione via envs: CROSSPILOT_<ENV>_SEGMENT_SIZE -> CROSSPILOT_SEGMENT_SIZE.
/// Se non impostata usa il default 64 MB. Valida il range [1 MB, 256 MB].
pub fn read_segment_size_env() -> Result<u64> {
    let raw = crate::envs::var("SEGMENT_SIZE");
    let value = match raw {
        Some(s) => {
            let parsed = s
                .parse::<u64>()
                .with_context(|| format!("CROSSPILOT_SEGMENT_SIZE non è un numero valido: {}", s))?;
            eprintln!(
                "[DEBUG] transfer: CROSSPILOT_SEGMENT_SIZE override = {} byte",
                parsed
            );
            parsed
        }
        None => DEFAULT_SEGMENT_SIZE,
    };

    if value < MIN_SEGMENT_SIZE || value > MAX_SEGMENT_SIZE {
        bail!(
            "CROSSPILOT_SEGMENT_SIZE {} fuori range (min {}, max {})",
            value,
            MIN_SEGMENT_SIZE,
            MAX_SEGMENT_SIZE
        );
    }
    Ok(value)
}

/// Calcola il block_size ottimale per la signature rsync.
/// Formula spec: clamp(round(sqrt(file_size)), 2048, 65536).
/// fast_rsync non richiede potenze di due.
pub fn compute_block_size(file_size: u64) -> u32 {
    // sqrt della dimensione; per file_size 0 usiamo il minimo.
    let sqrt_val = if file_size == 0 {
        MIN_BLOCK_SIZE as f64
    } else {
        (file_size as f64).sqrt()
    };
    let rounded = sqrt_val.round() as u64;
    let clamped = rounded.clamp(MIN_BLOCK_SIZE as u64, MAX_BLOCK_SIZE as u64);
    clamped as u32
}

/// Valida che block_size sia nel range [2048, 65536]. Ritorna TransferError ERR_PROTO se fuori.
fn validate_block_size(block_size: u32) -> Result<(), TransferError> {
    if block_size < MIN_BLOCK_SIZE || block_size > MAX_BLOCK_SIZE {
        return Err(TransferError::new(
            ERR_PROTO,
            format!(
                "block_size {} fuori range [{}, {}]",
                block_size, MIN_BLOCK_SIZE, MAX_BLOCK_SIZE
            ),
        ));
    }
    Ok(())
}

/// Valida che segment_size sia nel range [1 MB, 256 MB]. Ritorna TransferError ERR_PROTO se fuori.
fn validate_segment_size(segment_size: u64) -> Result<(), TransferError> {
    if segment_size < MIN_SEGMENT_SIZE || segment_size > MAX_SEGMENT_SIZE {
        return Err(TransferError::new(
            ERR_PROTO,
            format!(
                "segment_size {} fuori range [{}, {}]",
                segment_size, MIN_SEGMENT_SIZE, MAX_SEGMENT_SIZE
            ),
        ));
    }
    Ok(())
}

/// Costruisce le SignatureOptions standard (block_size + crypto_hash_size = 16).
fn make_sig_options(block_size: u32) -> SignatureOptions {
    SignatureOptions {
        block_size,
        crypto_hash_size: CRYPTO_HASH_SIZE,
    }
}

/// Calcola il numero di segmenti = ceil(total_new_size / segment_size).
fn segment_count(total_new_size: u64, segment_size: u64) -> u64 {
    (total_new_size + segment_size - 1) / segment_size
}

// ---------------------------------------------------------------------------
// Helper I/O su file (sync, memoria contante per segmento).
// ---------------------------------------------------------------------------

/// Legge un segmento [start, end) dal file. Ritorna un Vec<u8> di (end-start) byte.
fn read_segment(file: &mut File, start: u64, end: u64) -> Result<Vec<u8>> {
    let len = (end - start) as usize;
    let mut buf = vec![0u8; len];
    file.seek(SeekFrom::Start(start))
        .with_context(|| format!("seek fallito a offset {}", start))?;
    file.read_exact(&mut buf)
        .with_context(|| format!("lettura segmento [{}, {}) fallita", start, end))?;
    Ok(buf)
}

/// Apre il file base (se esiste) e ritorna (Option<File>, base_size).
/// Se il file non esiste, ritorna (None, 0).
fn open_base_file(base_path: &Path) -> (Option<File>, u64) {
    let metadata = match fs::metadata(base_path) {
        Ok(m) => m,
        Err(_) => return (None, 0),
    };
    let size = metadata.len();
    let file = match File::open(base_path) {
        Ok(f) => f,
        Err(_) => return (None, size),
    };
    (Some(file), size)
}

/// Pre-alloca il file .part a total_new_size e lo apre in lettura+scrittura.
///
/// Bug trovato: `File::create` apre in O_WRONLY (write-only). Dopo aver scritto i
/// segmenti, `sha256_file_handle` tenta di leggere il file per l'hash whole-file,
/// ma la read su un fd write-only fallisce con EBADF (errore IO).
/// Fix: apriamo in read+write (OpenOptions read+write+create+truncate) così possiamo
/// sia scrivere i segmenti sia leggere per l'hash senza riaprire il file.
fn create_part_file(part_path: &Path, total_new_size: u64) -> Result<File> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(part_path)
        .with_context(|| format!("impossibile creare il file .part: {}", part_path.display()))?;
    if total_new_size > 0 {
        file.set_len(total_new_size).with_context(|| {
            format!(
                "pre-allocazione .part a {} byte fallita",
                total_new_size
            )
        })?;
    }
    Ok(file)
}

/// Sostituisce atomicamente dest_path con part_path.
/// Su Windows usa MoveFileExW(MOVEFILE_REPLACE_EXISTING); su Linux fs::rename (sovrascrive).
fn atomic_replace(part_path: &Path, dest_path: &Path) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        atomic_replace_windows(part_path, dest_path)
    }
    #[cfg(not(target_os = "windows"))]
    {
        fs::rename(part_path, dest_path).with_context(|| {
            format!(
                "rename atomico fallito: {} -> {}",
                part_path.display(),
                dest_path.display()
            )
        })?;
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn atomic_replace_windows(part_path: &Path, dest_path: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use winapi::um::winbase::MoveFileExW;
    use winapi::um::winbase::MOVEFILE_REPLACE_EXISTING;

    // Converte i path in stringhe wide (UTF-16) terminate da null per l'API Win32.
    let mut part_wide: Vec<u16> = part_path.as_os_str().encode_wide().collect();
    part_wide.push(0);
    let mut dest_wide: Vec<u16> = dest_path.as_os_str().encode_wide().collect();
    dest_wide.push(0);

    let ok = unsafe {
        MoveFileExW(
            part_wide.as_ptr(),
            dest_wide.as_ptr(),
            MOVEFILE_REPLACE_EXISTING,
        )
    };
    if ok == 0 {
        bail!(
            "MoveFileExW fallito: {} -> {}",
            part_path.display(),
            dest_path.display()
        );
    }
    Ok(())
}

/// Elimina il file .part se esiste (best-effort, errori ignorati).
fn cleanup_part_file(part_path: &Path) {
    if part_path.exists() {
        let _ = fs::remove_file(part_path);
    }
}

// ---------------------------------------------------------------------------
// Helper di protocollo: invio/ricezione conferma whole-file.
// ---------------------------------------------------------------------------

/// Lato sender: dopo aver ricevuto l'ACK del receiver, confronta l'hash del file
/// nuovo (calcolato localmente) con l'hash del .part (inviato dal receiver).
/// Se coincidono, invia ACK(status 0) come conferma. Se mismatch, invia ERR 4.
async fn send_confirmation(
    stream: &mut TcpStream,
    source_hash: [u8; 32],
    ack: &Ack,
) -> Result<()> {
    if ack.sha256_whole_file == source_hash {
        // Hash coincidono: il transfer è integro. Conferma al receiver.
        let confirm = Ack {
            status: 0,
            total_bytes_written: ack.total_bytes_written,
            sha256_whole_file: source_hash,
        };
        proto::send_ack(stream, &confirm).await?;
        Ok(())
    } else {
        // Mismatch whole-file: il delta ha corrotto il file. Segnala ERR 4.
        eprintln!(
            "[ERROR] transfer: checksum whole-file mismatch. atteso={}, ricevuto={}",
            hex(&source_hash),
            hex(&ack.sha256_whole_file)
        );
        let err = ErrMsg {
            code: ERR_CHECKSUM_MISMATCH,
            message: "checksum whole-file mismatch".to_string(),
        };
        proto::send_err(stream, &err).await?;
        bail!("checksum whole-file mismatch");
    }
}

/// Lato receiver: dopo aver inviato l'ACK, attende la conferma del sender.
/// Ritorna Ok(()) se il sender conferma (ACK status 0), Err se il sender invia ERR.
async fn wait_for_confirmation(stream: &mut TcpStream) -> Result<()> {
    let (msg_type, payload) = proto::read_msg(stream).await?;
    if msg_type == MSG_ACK {
        let ack = proto::decode_ack(&payload)?;
        if ack.status == 0 {
            Ok(())
        } else {
            bail!("il sender ha segnalato errore (status {})", ack.status);
        }
    } else if msg_type == MSG_ERR {
        let err = proto::decode_err(&payload)?;
        bail!("il sender ha segnalato ERR {}: {}", err.code, err.message);
    } else {
        bail!(
            "messaggio inatteso in attesa conferma: tipo {}",
            msg_type
        );
    }
}

/// Converte 32 byte in stringa esadecimale (per log di debug).
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

// ---------------------------------------------------------------------------
// Loop segmenti lato SENDER (ha il file nuovo, calcola delta).
// ---------------------------------------------------------------------------

/// Esegue il loop segmenti lato sender. Per ogni segmento:
/// 1. Riceve SIGNATURE del segmento base dal receiver.
/// 2. Legge il segmento nuovo dal file.
/// 3. Calcola il delta via fast_rsync::diff.
/// 4. Invia DELTA (blob + sha256_segment + segment_new_size).
///
/// Calcola anche SHA-256 whole-file del file nuovo in streaming (un solo passaggio).
/// Ritorna l'hash whole-file del file nuovo.
async fn sender_segment_loop(
    stream: &mut TcpStream,
    new_file: &mut File,
    block_size: u32,
    segment_size: u64,
    total_new_size: u64,
) -> Result<[u8; 32]> {
    let opts = make_sig_options(block_size);
    // Signature di base vuota: usata quando il receiver invia blob vuoto (base assente).
    // fast_rsync::diff con 0 blocchi produce un delta tutto literal (copia i byte nuovi).
    let empty_sig = Signature::calculate(&[], opts);
    let count = segment_count(total_new_size, segment_size);

    let mut hasher = Sha256::new();

    for i in 0..count {
        // 1. Riceve la SIGNATURE del segmento base i.
        let (msg_type, payload) = proto::read_msg(stream).await?;
        // Se il server invia ERR (es. path invalido, file non trovato), propaga il messaggio.
        if msg_type == MSG_ERR {
            let err = proto::decode_err(&payload)?;
            bail!("server ha segnalato ERR {}: {}", err.code, err.message);
        }
        if msg_type != MSG_SIGNATURE {
            bail!(
                "sender: atteso SIGNATURE (tipo {}), ricevuto tipo {}",
                MSG_SIGNATURE,
                msg_type
            );
        }
        let sig_msg = proto::decode_signature(&payload)?;
        if sig_msg.segment_index != i as u32 {
            bail!(
                "sender: segment_index atteso {}, ricevuto {}",
                i,
                sig_msg.segment_index
            );
        }

        // 2. Legge il segmento nuovo [start, end).
        let start = i * segment_size;
        let end = std::cmp::min((i + 1) * segment_size, total_new_size);
        let new_segment = read_segment(new_file, start, end)
            .context("sender: lettura segmento nuovo fallita")?;
        // Aggiorna l'hash whole-file in streaming (un solo passaggio sul file).
        hasher.update(&new_segment);

        // 3. Calcola il delta. Se il blob signature è vuoto (base assente), usa la
        //    signature di base vuota -> delta tutto literal.
        let mut delta_blob = Vec::new();
        if sig_msg.blob.is_empty() {
            let indexed = empty_sig.index();
            fast_rsync::diff(&indexed, &new_segment, &mut delta_blob)
                .context("sender: diff su signature vuota fallita")?;
        } else {
            let sig = Signature::deserialize(sig_msg.blob)
                .context("sender: deserializzazione signature fallita")?;
            let indexed = sig.index();
            fast_rsync::diff(&indexed, &new_segment, &mut delta_blob)
                .context("sender: diff fallita")?;
        }

        // 4. Hash del segmento nuovo (verifica per-segmento lato receiver).
        let seg_hash = sha256_bytes(&new_segment);
        let delta_msg = Delta {
            segment_index: i as u32,
            blob: delta_blob,
            sha256_segment: seg_hash,
            segment_new_size: new_segment.len() as u64,
        };
        proto::send_delta(stream, &delta_msg).await?;

        eprintln!(
            "[DEBUG] transfer sender: segmento {}/{} ({} byte), delta {} byte",
            i + 1,
            count,
            new_segment.len(),
            delta_msg.blob.len()
        );
    }

    // Finalizza l'hash whole-file del file nuovo.
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Loop segmenti lato RECEIVER (ha il file base, applica delta su .part).
// ---------------------------------------------------------------------------

/// Esegue il loop segmenti lato receiver. Per ogni segmento:
/// 1. Legge il segmento base (se esiste) e calcola la signature.
/// 2. Invia SIGNATURE al sender.
/// 3. Riceve DELTA dal sender.
/// 4. Applica il delta sul segmento base -> output.
/// 5. Verifica SHA-256 del segmento ricostruito.
/// 6. Scrive l'output su .part all'offset start.
///
/// Ritorna (total_bytes_written, sha256_whole_file del .part).
async fn receiver_segment_loop(
    stream: &mut TcpStream,
    base_path: Option<&Path>,
    part_file: &mut File,
    block_size: u32,
    segment_size: u64,
    total_new_size: u64,
) -> Result<(u64, [u8; 32])> {
    let opts = make_sig_options(block_size);
    let count = segment_count(total_new_size, segment_size);

    // Apre il file base se esiste; base_size = dimensione del base (0 se assente).
    let base_path_owned = base_path.map(|p| p.to_path_buf());
    let (mut base_file_opt, base_size) = match &base_path_owned {
        Some(p) => open_base_file(p),
        None => (None, 0),
    };

    let mut total_written: u64 = 0;

    for i in 0..count {
        let start = i * segment_size;
        let end = std::cmp::min((i + 1) * segment_size, total_new_size);

        // 1. Legge il segmento base [start, min(end, base_size)). Vuoto se base assente
        //    o start >= base_size (segmento oltre la fine del base).
        let base_seg: Vec<u8> = if start < base_size {
            let base_end = std::cmp::min(end, base_size);
            match base_file_opt.as_mut() {
                Some(f) => read_segment(f, start, base_end)
                    .context("receiver: lettura segmento base fallita")?,
                None => Vec::new(),
            }
        } else {
            Vec::new()
        };

        // 2. Calcola la signature del segmento base. Blob vuoto se base_seg è vuoto.
        let sig_blob: Vec<u8> = if base_seg.is_empty() {
            Vec::new()
        } else {
            let sig = Signature::calculate(&base_seg, opts);
            sig.serialized().to_vec()
        };
        let sig_msg = SigMsg {
            segment_index: i as u32,
            blob: sig_blob,
        };
        proto::send_signature(stream, &sig_msg).await?;

        // 3. Riceve il DELTA dal sender.
        let (msg_type, payload) = proto::read_msg(stream).await?;
        if msg_type != MSG_DELTA {
            bail!(
                "receiver: atteso DELTA (tipo {}), ricevuto tipo {}",
                MSG_DELTA,
                msg_type
            );
        }
        let delta_msg = proto::decode_delta(&payload)?;
        if delta_msg.segment_index != i as u32 {
            bail!(
                "receiver: segment_index atteso {}, ricevuto {}",
                i,
                delta_msg.segment_index
            );
        }

        // 4. Applica il delta sul segmento base. apply_limited bounda l'output
        //    a segment_new_size (sicurezza contro delta malevoli/corrotti).
        let limit = delta_msg.segment_new_size as usize;
        let mut output = Vec::with_capacity(limit);
        fast_rsync::apply_limited(&base_seg, &delta_msg.blob, &mut output, limit)
            .context("receiver: apply delta fallita")?;

        // 5. Verifica SHA-256 del segmento ricostruito (integrità per-segmento).
        let computed_hash = sha256_bytes(&output);
        if computed_hash != delta_msg.sha256_segment {
            // Bug trovato: il delta ricostruito non corrisponde all'hash dichiarato.
            // Questo cattura corruzione del blob delta in transito o bug in fast_rsync.
            eprintln!(
                "[ERROR] transfer receiver: checksum segmento {} mismatch (atteso={}, calcolato={})",
                i,
                hex(&delta_msg.sha256_segment),
                hex(&computed_hash)
            );
            return Err(TransferError::new(
                ERR_CHECKSUM_MISMATCH,
                format!("checksum mismatch sul segmento {}", i),
            )
            .into());
        }

        // 6. Scrive l'output su .part all'offset start (seek + write).
        part_file
            .seek(SeekFrom::Start(start))
            .with_context(|| format!("receiver: seek .part a {} fallito", start))?;
        part_file
            .write_all(&output)
            .context("receiver: scrittura segmento su .part fallita")?;
        total_written += output.len() as u64;

        eprintln!(
            "[DEBUG] transfer receiver: segmento {}/{} ({} byte scritti a offset {})",
            i + 1,
            count,
            output.len(),
            start
        );
    }

    // Calcola SHA-256 whole-file del .part (verifica end-to-end).
    let whole_hash = sha256_file_handle(part_file).context("receiver: hash .part fallito")?;
    Ok((total_written, whole_hash))
}

// ---------------------------------------------------------------------------
// Entry point: PUT (upload). Client = sender, Server = receiver.
// ---------------------------------------------------------------------------

/// Lato client PUT (upload): client = sender del file local_src verso remote_dst.
///
/// Flusso: PUT_REQ -> loop segmenti (sender) -> riceve ACK -> verifica -> conferma.
pub async fn put_client(stream: &mut TcpStream, local_src: &str, remote_dst: &str) -> Result<()> {
    // Valida che il file sorgente locale esista.
    path::require_local_file_exists(local_src)?;

    // Apri il file nuovo (sorgente) e leggi la dimensione.
    let src_path = Path::new(local_src);
    let mut new_file = File::open(src_path)
        .with_context(|| format!("impossibile aprire il file sorgente: {}", local_src))?;
    let total_new_size = new_file
        .metadata()
        .with_context(|| format!("impossibile leggere metadata di {}", local_src))?
        .len();

    // Calcola i parametri di chunking.
    let block_size = compute_block_size(total_new_size);
    let segment_size = read_segment_size_env()?;

    eprintln!(
        "[DEBUG] transfer put_client: src={} ({} byte), dst={}, block_size={}, segment_size={}",
        local_src, total_new_size, remote_dst, block_size, segment_size
    );

    // Invia PUT_REQ.
    let req = PutReq {
        path: remote_dst.to_string(),
        block_size,
        segment_size,
        total_new_size,
    };
    proto::send_put_req(stream, &req).await?;

    // Loop segmenti lato sender; ritorna l'hash whole-file del file nuovo.
    let source_hash = sender_segment_loop(stream, &mut new_file, block_size, segment_size, total_new_size)
        .await?;

    // Riceve ACK dal receiver (server).
    let (msg_type, payload) = proto::read_msg(stream).await?;
    if msg_type == MSG_ERR {
        let err = proto::decode_err(&payload)?;
        bail!("server ha segnalato ERR {}: {}", err.code, err.message);
    }
    if msg_type != MSG_ACK {
        bail!("put_client: atteso ACK (tipo {}), ricevuto tipo {}", MSG_ACK, msg_type);
    }
    let ack = proto::decode_ack(&payload)?;

    // Verifica whole-file e invia conferma al server (che farà il rename).
    send_confirmation(stream, source_hash, &ack).await?;

    eprintln!(
        "[DEBUG] transfer put_client: completato. {} byte, hash={}",
        ack.total_bytes_written,
        hex(&source_hash)
    );
    Ok(())
}

/// Lato server PUT (upload): server = receiver. Scrive su .part, poi rename atomico.
///
/// Flusso: riceve PUT_REQ -> valida -> loop segmenti (receiver) -> ACK -> attende conferma -> rename.
pub async fn put_server(stream: &mut TcpStream, req: PutReq) -> Result<()> {
    // Valida il path di destinazione (server-side).
    if let Err(e) = path::validate_server_path(&req.path) {
        let err_msg = e.to_err_msg();
        eprintln!(
            "[ERROR] transfer put_server: path invalido - {} ({})",
            err_msg.message,
            proto::error_code_description(err_msg.code)
        );
        proto::send_err(stream, &err_msg).await?;
        return Err(e.into());
    }

    // Valida block_size e segment_size (range protocollo).
    if let Err(e) = validate_block_size(req.block_size) {
        proto::send_err(stream, &e.to_err_msg()).await?;
        return Err(e.into());
    }
    if let Err(e) = validate_segment_size(req.segment_size) {
        proto::send_err(stream, &e.to_err_msg()).await?;
        return Err(e.into());
    }

    let dest_path = Path::new(&req.path);
    // Costruisce il path .part in modo robusto: <dest>.part
    let part_path = make_part_path(dest_path);

    eprintln!(
        "[DEBUG] transfer put_server: dst={} ({} byte), block_size={}, segment_size={}",
        req.path, req.total_new_size, req.block_size, req.segment_size
    );

    // Crea e pre-alloca il file .part.
    let part_file = match create_part_file(&part_path, req.total_new_size) {
        Ok(f) => f,
        Err(e) => {
            let err_msg = ErrMsg {
                code: ERR_IO,
                message: format!("impossibile creare .part: {}", e),
            };
            proto::send_err(stream, &err_msg).await?;
            return Err(e);
        }
    };
    let mut part_file = part_file;

    // Loop segmenti lato receiver. base = file dest esistente (se presente).
    let base_path = if dest_path.exists() {
        Some(dest_path)
    } else {
        None
    };
    let loop_result = receiver_segment_loop(
        stream,
        base_path,
        &mut part_file,
        req.block_size,
        req.segment_size,
        req.total_new_size,
    )
    .await;

    let (total_bytes, whole_hash) = match loop_result {
        Ok(v) => v,
        Err(e) => {
            // Errore durante il loop: invia ERR, elimina .part, propaga.
            let err_msg = match e.downcast_ref::<TransferError>() {
                Some(te) => te.to_err_msg(),
                None => ErrMsg {
                    code: ERR_IO,
                    message: format!("errore transfer: {}", e),
                },
            };
            eprintln!("[ERROR] transfer put_server: loop fallito - {}", err_msg.message);
            let _ = proto::send_err(stream, &err_msg).await;
            cleanup_part_file(&part_path);
            return Err(e);
        }
    };

    // Invia ACK con l'hash whole-file del .part.
    let ack = Ack {
        status: 0,
        total_bytes_written: total_bytes,
        sha256_whole_file: whole_hash,
    };
    proto::send_ack(stream, &ack).await?;

    // Attende la conferma del client (verifica whole-file lato sender).
    if let Err(e) = wait_for_confirmation(stream).await {
        eprintln!("[ERROR] transfer put_server: conferma fallita - {}", e);
        cleanup_part_file(&part_path);
        return Err(e);
    }

    // Conferma ricevuta: rename atomico .part -> dest.
    if let Err(e) = atomic_replace(&part_path, dest_path) {
        cleanup_part_file(&part_path);
        return Err(e);
    }

    eprintln!(
        "[DEBUG] transfer put_server: completato. {} byte scritti in {}",
        total_bytes,
        req.path
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Entry point: GET (download). Server = sender, Client = receiver.
// ---------------------------------------------------------------------------

/// Lato client GET (download): client = receiver del file remote_src verso local_dst.
///
/// Flusso: GET_REQ -> riceve META -> loop segmenti (receiver) -> ACK -> attende conferma -> rename.
pub async fn get_client(
    stream: &mut TcpStream,
    remote_src: &str,
    local_dst: &str,
) -> Result<()> {
    let segment_size = read_segment_size_env()?;
    // block_size nel GET_REQ: placeholder valido (il client ricalcola dopo META).
    let placeholder_block_size: u32 = 8192;

    eprintln!(
        "[DEBUG] transfer get_client: src={}, dst={}, segment_size={}",
        remote_src, local_dst, segment_size
    );

    // Invia GET_REQ.
    let req = GetReq {
        path: remote_src.to_string(),
        block_size: placeholder_block_size,
        segment_size,
    };
    proto::send_get_req(stream, &req).await?;

    // Riceve META (total_new_size) dal server.
    let (msg_type, payload) = proto::read_msg(stream).await?;
    if msg_type == MSG_ERR {
        let err = proto::decode_err(&payload)?;
        bail!("server ha segnalato ERR {}: {}", err.code, err.message);
    }
    if msg_type != MSG_META {
        bail!("get_client: atteso META (tipo {}), ricevuto tipo {}", MSG_META, msg_type);
    }
    let meta = proto::decode_meta(&payload)?;
    let total_new_size = meta.total_new_size;

    // Ricalcola block_size ottimale ora che conosciamo total_new_size.
    let block_size = compute_block_size(total_new_size);

    eprintln!(
        "[DEBUG] transfer get_client: total_new_size={} byte, block_size={}",
        total_new_size, block_size
    );

    // Crea e pre-alloca il file .part locale.
    let dest_path = Path::new(local_dst);
    let part_path = make_part_path(dest_path);
    let mut part_file = create_part_file(&part_path, total_new_size)
        .with_context(|| format!("impossibile creare .part locale: {}", part_path.display()))?;

    // base = file local_dst esistente (se presente).
    let base_path = if dest_path.exists() {
        Some(dest_path)
    } else {
        None
    };
    let loop_result = receiver_segment_loop(
        stream,
        base_path,
        &mut part_file,
        block_size,
        segment_size,
        total_new_size,
    )
    .await;

    let (total_bytes, whole_hash) = match loop_result {
        Ok(v) => v,
        Err(e) => {
            // Errore: invia ERR/ACK di errore, elimina .part, propaga.
            let err_msg = match e.downcast_ref::<TransferError>() {
                Some(te) => te.to_err_msg(),
                None => ErrMsg {
                    code: ERR_IO,
                    message: format!("errore transfer: {}", e),
                },
            };
            eprintln!("[ERROR] transfer get_client: loop fallito - {}", err_msg.message);
            let _ = proto::send_err(stream, &err_msg).await;
            cleanup_part_file(&part_path);
            return Err(e);
        }
    };

    // Invia ACK con l'hash whole-file del .part.
    let ack = Ack {
        status: 0,
        total_bytes_written: total_bytes,
        sha256_whole_file: whole_hash,
    };
    proto::send_ack(stream, &ack).await?;

    // Attende la conferma del server (verifica whole-file lato sender).
    if let Err(e) = wait_for_confirmation(stream).await {
        eprintln!("[ERROR] transfer get_client: conferma fallita - {}", e);
        cleanup_part_file(&part_path);
        return Err(e);
    }

    // Conferma ricevuta: rename atomico .part -> local_dst.
    if let Err(e) = atomic_replace(&part_path, dest_path) {
        cleanup_part_file(&part_path);
        return Err(e);
    }

    eprintln!(
        "[DEBUG] transfer get_client: completato. {} byte scritti in {}",
        total_bytes, local_dst
    );
    Ok(())
}

/// Lato server GET (download): server = sender del file remote_src.
///
/// Flusso: riceve GET_REQ -> valida -> META -> loop segmenti (sender) -> riceve ACK -> verifica -> conferma.
pub async fn get_server(stream: &mut TcpStream, req: GetReq) -> Result<()> {
    // Valida il path sorgente (server-side).
    if let Err(e) = path::validate_server_path(&req.path) {
        let err_msg = e.to_err_msg();
        eprintln!(
            "[ERROR] transfer get_server: path invalido - {} ({})",
            err_msg.message,
            proto::error_code_description(err_msg.code)
        );
        proto::send_err(stream, &err_msg).await?;
        return Err(e.into());
    }

    // Valida block_size e segment_size.
    if let Err(e) = validate_block_size(req.block_size) {
        proto::send_err(stream, &e.to_err_msg()).await?;
        return Err(e.into());
    }
    if let Err(e) = validate_segment_size(req.segment_size) {
        proto::send_err(stream, &e.to_err_msg()).await?;
        return Err(e.into());
    }

    // Apre il file sorgente (remoto). Deve esistere.
    let src_path = Path::new(&req.path);
    let mut new_file = match File::open(src_path) {
        Ok(f) => f,
        Err(_) => {
            let err_msg = ErrMsg {
                code: proto::ERR_FILE_NOT_FOUND,
                message: format!("file non trovato: {}", req.path),
            };
            proto::send_err(stream, &err_msg).await?;
            return Err(anyhow!("file non trovato: {}", req.path));
        }
    };
    let total_new_size = new_file
        .metadata()
        .with_context(|| format!("impossibile leggere metadata di {}", req.path))?
        .len();

    eprintln!(
        "[DEBUG] transfer get_server: src={} ({} byte), segment_size={}",
        req.path, total_new_size, req.segment_size
    );

    // Invia META con la dimensione del file remoto.
    let meta = Meta { total_new_size };
    proto::send_meta(stream, &meta).await?;

    // block_size: usa quello del client (validato) o ricalcola? Il sender non
    // calcola signature (le calcola il receiver), quindi usa il block_size del
    // client per coerenza. Il receiver userà il proprio block_size (nel signature).
    // Qui usiamo req.block_size solo per costruire le SignatureOptions del sender
    // per la signature vuota (base assente). In GET il sender non calcola signature
    // del base, ma sender_segment_loop usa empty_sig per segmenti senza base.
    let block_size = req.block_size;

    // Loop segmenti lato sender; ritorna l'hash whole-file del file nuovo.
    let source_hash = sender_segment_loop(
        stream,
        &mut new_file,
        block_size,
        req.segment_size,
        total_new_size,
    )
    .await?;

    // Riceve ACK dal receiver (client).
    let (msg_type, payload) = proto::read_msg(stream).await?;
    if msg_type == MSG_ERR {
        let err = proto::decode_err(&payload)?;
        bail!("client ha segnalato ERR {}: {}", err.code, err.message);
    }
    if msg_type != MSG_ACK {
        bail!("get_server: atteso ACK (tipo {}), ricevuto tipo {}", MSG_ACK, msg_type);
    }
    let ack = proto::decode_ack(&payload)?;

    // Verifica whole-file e invia conferma al client (che farà il rename).
    send_confirmation(stream, source_hash, &ack).await?;

    eprintln!(
        "[DEBUG] transfer get_server: completato. {} byte, hash={}",
        ack.total_bytes_written,
        hex(&source_hash)
    );
    Ok(())
}

/// Costruisce il path .part accanto al path di destinazione: <dest>.part
fn make_part_path(dest_path: &Path) -> std::path::PathBuf {
    // Aggiunge il suffisso .part al path (come stringa) per gestire correttamente
    // i path Windows (C:\...\app.exe -> C:\...\app.exe.part).
    let dest_str = dest_path.to_string_lossy().into_owned();
    let part_str = format!("{}{}", dest_str, PART_SUFFIX);
    std::path::PathBuf::from(part_str)
}

// ---------------------------------------------------------------------------
// Test (spec §17 passo 1: roundtrip algoritmo fast_rsync in memoria).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Roundtrip base: file identici -> delta mostly copy, apply ricostruisce identico.
    #[test]
    fn rsync_roundtrip_identical() {
        let data = vec![0x42u8; 100_000];
        let opts = make_sig_options(2048);

        let sig = Signature::calculate(&data, opts);
        let sig_blob = sig.serialized().to_vec();

        let sig2 = Signature::deserialize(sig_blob).unwrap();
        let indexed = sig2.index();
        let mut delta = Vec::new();
        fast_rsync::diff(&indexed, &data, &mut delta).unwrap();

        let mut output = Vec::new();
        fast_rsync::apply_limited(&data, &delta, &mut output, data.len()).unwrap();
        assert_eq!(output, data);
        // File identici: delta deve essere piccolo (mostly copy).
        assert!(delta.len() < data.len() / 10, "delta troppo grande per file identici");
    }

    /// Prepend 1 byte: il rolling checksum deve trovare i match shiftati (mostly copy).
    #[test]
    fn rsync_roundtrip_prepend_one_byte() {
        let base = vec![0x42u8; 100_000];
        let mut new_data = Vec::with_capacity(base.len() + 1);
        new_data.push(0x99);
        new_data.extend_from_slice(&base);

        let opts = make_sig_options(2048);
        let sig = Signature::calculate(&base, opts);
        let indexed = sig.index();
        let mut delta = Vec::new();
        fast_rsync::diff(&indexed, &new_data, &mut delta).unwrap();

        let mut output = Vec::new();
        fast_rsync::apply_limited(&base, &delta, &mut output, new_data.len()).unwrap();
        assert_eq!(output, new_data);
        // Prepend 1 byte: delta deve essere mostly copy (criterio spec §16: delta < new/10).
        // Il delta contiene i comandi COPY + 1 byte literal; molto più piccolo del file.
        assert!(
            delta.len() < new_data.len() / 10,
            "delta troppo grande per prepend 1 byte: {} (criterio < {})",
            delta.len(),
            new_data.len() / 10
        );
    }

    /// Append 100 byte: la maggior parte è copy, solo la coda è literal.
    #[test]
    fn rsync_roundtrip_append_bytes() {
        let base = vec![0x42u8; 100_000];
        let mut new_data = base.clone();
        new_data.extend_from_slice(&vec![0x77u8; 100]);

        let opts = make_sig_options(2048);
        let sig = Signature::calculate(&base, opts);
        let indexed = sig.index();
        let mut delta = Vec::new();
        fast_rsync::diff(&indexed, &new_data, &mut delta).unwrap();

        let mut output = Vec::new();
        fast_rsync::apply_limited(&base, &delta, &mut output, new_data.len()).unwrap();
        assert_eq!(output, new_data);
    }

    /// File vuoto: signature su base vuota, delta vuoto, output vuoto.
    #[test]
    fn rsync_roundtrip_empty_file() {
        let base: Vec<u8> = Vec::new();
        let new_data: Vec<u8> = Vec::new();

        let opts = make_sig_options(2048);
        // Base vuota: usiamo Signature::calculate(&[]).
        let sig = Signature::calculate(&base, opts);
        let indexed = sig.index();
        let mut delta = Vec::new();
        fast_rsync::diff(&indexed, &new_data, &mut delta).unwrap();

        let mut output = Vec::new();
        fast_rsync::apply_limited(&base, &delta, &mut output, 0).unwrap();
        assert_eq!(output, new_data);
    }

    /// Base assente (blob signature vuoto): il sender usa empty_sig, delta tutto literal.
    /// Verifica che apply con base vuota ricostruisce il segmento nuovo.
    #[test]
    fn rsync_roundtrip_base_absent() {
        let new_data = vec![0x55u8; 50_000];

        let opts = make_sig_options(2048);
        // Simula il receiver che invia blob vuoto (base assente).
        let empty_sig = Signature::calculate(&[], opts);
        let indexed = empty_sig.index();
        let mut delta = Vec::new();
        fast_rsync::diff(&indexed, &new_data, &mut delta).unwrap();

        // Receiver applica con base vuota.
        let base: Vec<u8> = Vec::new();
        let mut output = Vec::new();
        fast_rsync::apply_limited(&base, &delta, &mut output, new_data.len()).unwrap();
        assert_eq!(output, new_data);
    }

    /// Verifica compute_block_size rispetta la formula clamp(round(sqrt(size))).
    #[test]
    fn block_size_formula() {
        // 10 MB: sqrt(10485760) ≈ 3238.17 -> round 3238.
        assert_eq!(compute_block_size(10 * 1024 * 1024), 3238);
        // 1 GB: sqrt(1073741824) = 32768 esatto.
        assert_eq!(compute_block_size(1024 * 1024 * 1024), 32768);
        // File piccolo: sqrt < 2048 -> clamp a 2048.
        assert_eq!(compute_block_size(100), 2048);
        // 10 GB: sqrt(10737418240) ≈ 103625 -> clamp a 65536.
        assert_eq!(compute_block_size(10 * 1024 * 1024 * 1024), 65536);
        // File vuoto: 2048.
        assert_eq!(compute_block_size(0), 2048);
    }

    /// Verifica segment_count = ceil(total/segment).
    #[test]
    fn segment_count_formula() {
        assert_eq!(segment_count(0, 1024), 0);
        assert_eq!(segment_count(1, 1024), 1);
        assert_eq!(segment_count(1024, 1024), 1);
        assert_eq!(segment_count(1025, 1024), 2);
        assert_eq!(segment_count(2048, 1024), 2);
    }

    /// Verifica validazione block_size.
    #[test]
    fn block_size_validation() {
        assert!(validate_block_size(2048).is_ok());
        assert!(validate_block_size(65536).is_ok());
        assert!(validate_block_size(3238).is_ok()); // non potenza di due
        assert!(validate_block_size(2047).is_err());
        assert!(validate_block_size(65537).is_err());
    }

    /// Verifica validazione segment_size.
    #[test]
    fn segment_size_validation() {
        assert!(validate_segment_size(MIN_SEGMENT_SIZE).is_ok());
        assert!(validate_segment_size(MAX_SEGMENT_SIZE).is_ok());
        assert!(validate_segment_size(MIN_SEGMENT_SIZE - 1).is_err());
        assert!(validate_segment_size(MAX_SEGMENT_SIZE + 1).is_err());
    }

    /// Verifica make_part_path.
    #[test]
    fn part_path_construction() {
        let p = make_part_path(Path::new("/tmp/file.bin"));
        assert_eq!(p.to_string_lossy(), "/tmp/file.bin.part");

        let p2 = make_part_path(Path::new(r"C:\ci\app.exe"));
        assert_eq!(p2.to_string_lossy(), r"C:\ci\app.exe.part");
    }
}
