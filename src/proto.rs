//! Protocollo di transfer file (framing length-prefixed, little-endian).
//!
//! Ogni messaggio in wire ha questo header:
//! ```text
//! u32 LE  magic       = 0x3142_4644   // "DFB1"
//! u8      version     = 2
//! u8      msg_type
//! u32 LE  payload_len
//! [u8;N]  payload
//! ```
//!
//! I messaggi sono: PUT_REQ(1), GET_REQ(2), META(7), SIGNATURE(3),
//! DELTA(4), ACK(5), ERR(6). Vedi `docs/transfer-spec.md` sezione 6.
//!
//! Messaggi directory sync (vedi `docs/sync-spec.md` sezione 5):
//! LIST_REQ(8), LIST_RES(9), MKDIR_BATCH_REQ(10), MKDIR_BATCH_RES(11),
//! DELETE_BATCH_REQ(12), DELETE_BATCH_RES(13).

use anyhow::{anyhow, bail, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Magic word del protocollo file transfer: byte "DFB1" letti little-endian.
/// Usato dal server per distinguere la modalità file dalla modalità shell (peek 4 byte).
pub const MAGIC: u32 = 0x3142_4644;

/// Versione del protocollo (unica, copre file transfer + directory sync +
/// update). RESTA 1 per compatibilita' con i server legacy (winboat-bridge):
/// il framing v1/v2 era identico (il bump era cosmetico nel rename) e un
/// client v2 verrebbe rifiutato dai server v1 ("versione non supportata")
/// rendendo impossibile anche il PUT dell'auto-update. I messaggi nuovi
/// (UPDATE_REQ/RES) sono distinti per msg_type, non per versione: i server
/// legacy li rifiutano e il client usa il fallback WMI/setsid.
pub const VERSION: u8 = 1;

// Identificatori dei tipi di messaggio (msg_type).
pub const MSG_PUT_REQ: u8 = 1;
pub const MSG_GET_REQ: u8 = 2;
pub const MSG_SIGNATURE: u8 = 3;
pub const MSG_DELTA: u8 = 4;
pub const MSG_ACK: u8 = 5;
pub const MSG_ERR: u8 = 6;
pub const MSG_META: u8 = 7;

// Messaggi directory sync (sync-spec §5).
pub const MSG_LIST_REQ: u8 = 8;
pub const MSG_LIST_RES: u8 = 9;
pub const MSG_MKDIR_BATCH_REQ: u8 = 10;
pub const MSG_MKDIR_BATCH_RES: u8 = 11;
pub const MSG_DELETE_BATCH_REQ: u8 = 12;
pub const MSG_DELETE_BATCH_RES: u8 = 13;

// Messaggi self-update via TCP (update-spec): il client chiede al server di
// spawnare l'updater staged e uscire. Inviati solo a server che dichiarano
// un BUILD_TS nell'handshake "READY <ts>" (i server legacy mandano "READY"
// secco e non ricevono mai UPDATE_REQ: per loro c'e' il path WMI/setsid).
pub const MSG_UPDATE_REQ: u8 = 14;
pub const MSG_UPDATE_RES: u8 = 15;

/// Cap massimo sul numero di entry restituite da LIST_RES (sync-spec §5).
/// Oltre questo limite il server risponde ERR 5 esplicito (non payload da 1 GB).
pub const LIST_ENTRY_CAP: u32 = 100_000;

/// Dimensione fissa dell'header: magic(4) + version(1) + msg_type(1) + payload_len(4) = 10 byte.
const HEADER_LEN: usize = 10;

/// Limite massimo del payload per un singolo messaggio.
/// Un segmento da 256 MB + delta + overhead può arrivare a ~512 MB; usiamo 1 GB come tetto assoluto.
const MAX_PAYLOAD_LEN: usize = 1024 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Codici di errore del protocollo (vedi spec sezione 14).
// ---------------------------------------------------------------------------

pub const ERR_PATH_FORBIDDEN: u16 = 1;
pub const ERR_FILE_NOT_FOUND: u16 = 2;
pub const ERR_IO: u16 = 3;
pub const ERR_CHECKSUM_MISMATCH: u16 = 4;
pub const ERR_PROTO: u16 = 5;
/// Riservato, non usato.
pub const ERR_RESERVED: u16 = 6;

/// Restituisce una descrizione umana del codice di errore (per log server/client).
/// Referenzia tutti i codici definiti, incluso ERR_RESERVED (documentato ma non usato).
pub fn error_code_description(code: u16) -> &'static str {
    match code {
        ERR_PATH_FORBIDDEN => "path vietato",
        ERR_FILE_NOT_FOUND => "file non trovato",
        ERR_IO => "errore di I/O",
        ERR_CHECKSUM_MISMATCH => "checksum mismatch",
        ERR_PROTO => "errore di protocollo (magic/version/parametri invalidi)",
        ERR_RESERVED => "riservato (non usato)",
        _ => "codice errore sconosciuto",
    }
}

// ---------------------------------------------------------------------------
// Tipo di errore del transfer: porta il codice di protocollo (ERR_*).
// Usato da path.rs e transfer.rs; convertito in messaggio ERR sul wire.
// ---------------------------------------------------------------------------

/// Errore del transfer file. `code` è uno dei codici ERR_* definiti sopra.
#[derive(Debug)]
pub struct TransferError {
    /// Codice di errore del protocollo (vedi costanti ERR_*).
    pub code: u16,
    /// Messaggio descrittivo.
    pub message: String,
}

impl TransferError {
    /// Crea un nuovo TransferError con codice e messaggio.
    pub fn new(code: u16, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// Converte in un messaggio ERR del protocollo.
    pub fn to_err_msg(&self) -> ErrMsg {
        ErrMsg {
            code: self.code,
            message: self.message.clone(),
        }
    }
}

impl std::fmt::Display for TransferError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[ERR {}] {}", self.code, self.message)
    }
}

impl std::error::Error for TransferError {}

// ---------------------------------------------------------------------------
// Strutture messaggi.
// ---------------------------------------------------------------------------

/// Richiesta di upload (C→S). path dst + parametri di chunking.
#[derive(Debug, Clone)]
pub struct PutReq {
    /// Path di destinazione sul server (UTF-8, senza null).
    pub path: String,
    /// Dimensione del blocco per la signature rsync.
    pub block_size: u32,
    /// Dimensione del segmento per il chunking sequenziale.
    pub segment_size: u64,
    /// Dimensione totale del file nuovo da trasferire.
    pub total_new_size: u64,
}

/// Richiesta di download (C→S). path src + parametri di chunking.
#[derive(Debug, Clone)]
pub struct GetReq {
    /// Path sorgente sul server (UTF-8, senza null).
    pub path: String,
    /// Dimensione del blocco per la signature rsync.
    pub block_size: u32,
    /// Dimensione del segmento per il chunking sequenziale.
    pub segment_size: u64,
}

/// Metadati inviati dal server durante il GET (S→C): dimensione del file remoto.
#[derive(Debug, Clone)]
pub struct Meta {
    /// Dimensione totale del file nuovo (remoto) da trasferire.
    pub total_new_size: u64,
}

/// Signature rsync di un segmento base (receiver→sender).
/// Se il segmento base è assente o troppo corto, `blob` è vuoto.
#[derive(Debug, Clone)]
pub struct Signature {
    /// Indice del segmento a cui si riferisce la signature.
    pub segment_index: u32,
    /// Blob opaco = `fast_rsync::Signature::serialized()`. Vuoto se base assente.
    pub blob: Vec<u8>,
}

/// Delta rsync di un segmento (sender→receiver) + hash di integrità.
#[derive(Debug, Clone)]
pub struct Delta {
    /// Indice del segmento a cui si riferisce il delta.
    pub segment_index: u32,
    /// Blob opaco = output di `fast_rsync::diff()`.
    pub blob: Vec<u8>,
    /// SHA-256 del segmento nuovo (per verifica integrità per-segmento).
    pub sha256_segment: [u8; 32],
    /// Numero di byte del segmento nuovo.
    pub segment_new_size: u64,
}

/// Ack finale del receiver: stato + byte scritti + hash whole-file.
#[derive(Debug, Clone)]
pub struct Ack {
    /// Stato: 0 = ok, altro = errore.
    pub status: u8,
    /// Byte totali scritti sul file .part.
    pub total_bytes_written: u64,
    /// SHA-256 del file ricostruito (whole-file).
    pub sha256_whole_file: [u8; 32],
}

/// Messaggio di errore: codice + descrizione UTF-8.
#[derive(Debug, Clone)]
pub struct ErrMsg {
    /// Codice di errore (vedi costanti ERR_*).
    pub code: u16,
    /// Messaggio descrittivo UTF-8.
    pub message: String,
}

/// Richiesta di self-update del server (C→S): path assoluto del binario
/// staged (`crosspilot-<ts>.exe` nella stessa dir dell'exe in esecuzione).
/// Il server lo spawnza detached con `update --target <self_exe>
/// --wait-pid <self_pid> --port <porta_locale>`, risponde UPDATE_RES ed esce.
#[derive(Debug, Clone)]
pub struct UpdateReq {
    /// Path assoluto del binario staged (UTF-8, senza null).
    pub staged_path: String,
}

/// Risposta del server a UPDATE_REQ (S→C).
#[derive(Debug, Clone)]
pub struct UpdateRes {
    /// Stato: 0 = updater spawnato (il server sta uscendo), altro = errore.
    pub status: u8,
    /// Messaggio descrittivo UTF-8.
    pub message: String,
}

// ---------------------------------------------------------------------------
// Framing di basso livello: read_msg / write_msg.
// Usano read_exact (niente read() singolo: insicuro per binario framed).
// ---------------------------------------------------------------------------

/// Legge un messaggio framed dal reader async.
/// Ritorna (msg_type, payload). Verifica magic e version.
pub async fn read_msg<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<(u8, Vec<u8>)> {
    // Legge l'header per intero: read_exact garantisce tutti i byte o errore.
    let mut header = [0u8; HEADER_LEN];
    reader.read_exact(&mut header).await?;

    // Estrae il magic dai primi 4 byte little-endian.
    let magic = u32::from_le_bytes([
        header[0],
        header[1],
        header[2],
        header[3],
    ]);
    if magic != MAGIC {
        bail!("Magic non valido: atteso 0x{:08X}, ricevuto 0x{:08X}", MAGIC, magic);
    }

    // Verifica la versione del protocollo.
    let version = header[4];
    if version != VERSION {
        bail!("Versione protocollo non supportata: attesa {}, ricevuta {}", VERSION, version);
    }

    // Estrae il tipo di messaggio.
    let msg_type = header[5];

    // Estrae la lunghezza del payload (little-endian).
    let payload_len = u32::from_le_bytes([
        header[6],
        header[7],
        header[8],
        header[9],
    ]) as usize;

    if payload_len > MAX_PAYLOAD_LEN {
        bail!("Payload troppo grande: {} byte (max {})", payload_len, MAX_PAYLOAD_LEN);
    }

    // Legge il payload per intero.
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        reader.read_exact(&mut payload).await?;
    }

    Ok((msg_type, payload))
}

/// Scrive un messaggio framed sul writer async.
/// `payload` è il contenuto; `msg_type` identifica il tipo di messaggio.
pub async fn write_msg<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    msg_type: u8,
    payload: &[u8],
) -> Result<()> {
    let mut header = [0u8; HEADER_LEN];

    // Magic little-endian.
    let magic_bytes = MAGIC.to_le_bytes();
    header[0] = magic_bytes[0];
    header[1] = magic_bytes[1];
    header[2] = magic_bytes[2];
    header[3] = magic_bytes[3];

    // Versione.
    header[4] = VERSION;

    // Tipo di messaggio.
    header[5] = msg_type;

    // Lunghezza payload little-endian (u32).
    let payload_len = payload.len() as u32;
    let len_bytes = payload_len.to_le_bytes();
    header[6] = len_bytes[0];
    header[7] = len_bytes[1];
    header[8] = len_bytes[2];
    header[9] = len_bytes[3];

    // Scrive header e payload (due write distinte per tracciabilità).
    writer.write_all(&header).await?;
    if !payload.is_empty() {
        writer.write_all(payload).await?;
    }
    writer.flush().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Encode/decode dei singoli messaggi.
// ---------------------------------------------------------------------------

/// Codifica una PutReq in payload (path\0 + block_size u32 + segment_size u64 + total_new_size u64).
pub fn encode_put_req(req: &PutReq) -> Result<Vec<u8>> {
    if req.path.contains('\0') {
        bail!("Path di destinazione contiene null");
    }
    let path_bytes = req.path.as_bytes();
    let mut payload = Vec::with_capacity(path_bytes.len() + 1 + 4 + 8 + 8);

    // Path UTF-8 + terminatore null.
    payload.extend_from_slice(path_bytes);
    payload.push(0);

    // block_size u32 LE.
    let bs_bytes = req.block_size.to_le_bytes();
    payload.extend_from_slice(&bs_bytes);

    // segment_size u64 LE.
    let ss_bytes = req.segment_size.to_le_bytes();
    payload.extend_from_slice(&ss_bytes);

    // total_new_size u64 LE.
    let tns_bytes = req.total_new_size.to_le_bytes();
    payload.extend_from_slice(&tns_bytes);

    Ok(payload)
}

/// Decodifica una PutReq dal payload.
pub fn decode_put_req(payload: &[u8]) -> Result<PutReq> {
    // Trova il terminatore null del path.
    let null_pos = payload
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| anyhow!("PutReq: terminatore null mancante"))?;

    // Estrae il path come stringa UTF-8.
    let path_bytes = &payload[..null_pos];
    let path = String::from_utf8(path_bytes.to_vec())
        .map_err(|e| anyhow!("PutReq: path non UTF-8 valido: {}", e))?;

    // Dopo il null: block_size(4) + segment_size(8) + total_new_size(8) = 20 byte.
    let rest = &payload[null_pos + 1..];
    if rest.len() < 20 {
        bail!("PutReq: payload troppo corto dopo il path ({} byte, attesi 20)", rest.len());
    }

    let block_size = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]);
    let segment_size = u64::from_le_bytes([
        rest[4], rest[5], rest[6], rest[7], rest[8], rest[9], rest[10], rest[11],
    ]);
    let total_new_size = u64::from_le_bytes([
        rest[12], rest[13], rest[14], rest[15], rest[16], rest[17], rest[18], rest[19],
    ]);

    Ok(PutReq {
        path,
        block_size,
        segment_size,
        total_new_size,
    })
}

/// Codifica una GetReq in payload (path\0 + block_size u32 + segment_size u64).
pub fn encode_get_req(req: &GetReq) -> Result<Vec<u8>> {
    if req.path.contains('\0') {
        bail!("Path sorgente contiene null");
    }
    let path_bytes = req.path.as_bytes();
    let mut payload = Vec::with_capacity(path_bytes.len() + 1 + 4 + 8);

    payload.extend_from_slice(path_bytes);
    payload.push(0);

    let bs_bytes = req.block_size.to_le_bytes();
    payload.extend_from_slice(&bs_bytes);

    let ss_bytes = req.segment_size.to_le_bytes();
    payload.extend_from_slice(&ss_bytes);

    Ok(payload)
}

/// Decodifica una GetReq dal payload.
pub fn decode_get_req(payload: &[u8]) -> Result<GetReq> {
    let null_pos = payload
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| anyhow!("GetReq: terminatore null mancante"))?;

    let path_bytes = &payload[..null_pos];
    let path = String::from_utf8(path_bytes.to_vec())
        .map_err(|e| anyhow!("GetReq: path non UTF-8 valido: {}", e))?;

    // Dopo il null: block_size(4) + segment_size(8) = 12 byte.
    let rest = &payload[null_pos + 1..];
    if rest.len() < 12 {
        bail!("GetReq: payload troppo corto dopo il path ({} byte, attesi 12)", rest.len());
    }

    let block_size = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]);
    let segment_size = u64::from_le_bytes([
        rest[4], rest[5], rest[6], rest[7], rest[8], rest[9], rest[10], rest[11],
    ]);

    Ok(GetReq {
        path,
        block_size,
        segment_size,
    })
}

/// Codifica un Meta in payload (u64 LE total_new_size).
pub fn encode_meta(meta: &Meta) -> Vec<u8> {
    meta.total_new_size.to_le_bytes().to_vec()
}

/// Decodifica un Meta dal payload.
pub fn decode_meta(payload: &[u8]) -> Result<Meta> {
    if payload.len() < 8 {
        bail!("Meta: payload troppo corto ({} byte, attesi 8)", payload.len());
    }
    let total_new_size = u64::from_le_bytes([
        payload[0], payload[1], payload[2], payload[3],
        payload[4], payload[5], payload[6], payload[7],
    ]);
    Ok(Meta { total_new_size })
}

/// Codifica una Signature in payload (u32 LE segment_index + blob).
pub fn encode_signature(sig: &Signature) -> Vec<u8> {
    let mut payload = Vec::with_capacity(4 + sig.blob.len());
    let idx_bytes = sig.segment_index.to_le_bytes();
    payload.extend_from_slice(&idx_bytes);
    payload.extend_from_slice(&sig.blob);
    payload
}

/// Decodifica una Signature dal payload.
pub fn decode_signature(payload: &[u8]) -> Result<Signature> {
    if payload.len() < 4 {
        bail!("Signature: payload troppo corto ({} byte, attesi almeno 4)", payload.len());
    }
    let segment_index = u32::from_le_bytes([
        payload[0], payload[1], payload[2], payload[3],
    ]);
    let blob = payload[4..].to_vec();
    Ok(Signature { segment_index, blob })
}

/// Codifica un Delta in payload (u32 LE segment_index + blob + [u8;32] sha256 + u64 LE segment_new_size).
pub fn encode_delta(delta: &Delta) -> Vec<u8> {
    let mut payload = Vec::with_capacity(4 + delta.blob.len() + 32 + 8);
    let idx_bytes = delta.segment_index.to_le_bytes();
    payload.extend_from_slice(&idx_bytes);
    payload.extend_from_slice(&delta.blob);
    payload.extend_from_slice(&delta.sha256_segment);
    let size_bytes = delta.segment_new_size.to_le_bytes();
    payload.extend_from_slice(&size_bytes);
    payload
}

/// Decodifica un Delta dal payload.
pub fn decode_delta(payload: &[u8]) -> Result<Delta> {
    // Struttura: segment_index(4) + blob(variabile) + sha256(32) + segment_new_size(8).
    // Il blob ha lunghezza = payload.len() - 4 - 32 - 8.
    let min_len = 4 + 32 + 8;
    if payload.len() < min_len {
        bail!("Delta: payload troppo corto ({} byte, attesi almeno {}", payload.len(), min_len);
    }

    let segment_index = u32::from_le_bytes([
        payload[0], payload[1], payload[2], payload[3],
    ]);

    // Il blob sta tra offset 4 e (len - 40).
    let blob_end = payload.len() - 40;
    let blob = payload[4..blob_end].to_vec();

    // SHA-256 del segmento: 32 byte dopo il blob.
    let mut sha256_segment = [0u8; 32];
    sha256_segment.copy_from_slice(&payload[blob_end..blob_end + 32]);

    // segment_new_size: ultimi 8 byte.
    let size_start = blob_end + 32;
    let segment_new_size = u64::from_le_bytes([
        payload[size_start], payload[size_start + 1],
        payload[size_start + 2], payload[size_start + 3],
        payload[size_start + 4], payload[size_start + 5],
        payload[size_start + 6], payload[size_start + 7],
    ]);

    Ok(Delta {
        segment_index,
        blob,
        sha256_segment,
        segment_new_size,
    })
}

/// Codifica un Ack in payload (u8 status + u64 LE total_bytes + [u8;32] sha256).
pub fn encode_ack(ack: &Ack) -> Vec<u8> {
    let mut payload = Vec::with_capacity(1 + 8 + 32);
    payload.push(ack.status);
    let tb_bytes = ack.total_bytes_written.to_le_bytes();
    payload.extend_from_slice(&tb_bytes);
    payload.extend_from_slice(&ack.sha256_whole_file);
    payload
}

/// Decodifica un Ack dal payload.
pub fn decode_ack(payload: &[u8]) -> Result<Ack> {
    if payload.len() < 41 {
        bail!("Ack: payload troppo corto ({} byte, attesi 41)", payload.len());
    }
    let status = payload[0];
    let total_bytes_written = u64::from_le_bytes([
        payload[1], payload[2], payload[3], payload[4],
        payload[5], payload[6], payload[7], payload[8],
    ]);
    let mut sha256_whole_file = [0u8; 32];
    sha256_whole_file.copy_from_slice(&payload[9..41]);
    Ok(Ack {
        status,
        total_bytes_written,
        sha256_whole_file,
    })
}

/// Codifica un ErrMsg in payload (u16 LE code + messaggio UTF-8).
pub fn encode_err(err: &ErrMsg) -> Vec<u8> {
    let mut payload = Vec::with_capacity(2 + err.message.len());
    let code_bytes = err.code.to_le_bytes();
    payload.extend_from_slice(&code_bytes);
    let msg_bytes = err.message.as_bytes();
    payload.extend_from_slice(msg_bytes);
    payload
}

/// Decodifica un ErrMsg dal payload.
pub fn decode_err(payload: &[u8]) -> Result<ErrMsg> {
    if payload.len() < 2 {
        bail!("Err: payload troppo corto ({} byte, attesi almeno 2)", payload.len());
    }
    let code = u16::from_le_bytes([payload[0], payload[1]]);
    let msg_bytes = &payload[2..];
    let message = String::from_utf8(msg_bytes.to_vec())
        .unwrap_or_else(|_| "<messaggio non UTF-8>".to_string());
    Ok(ErrMsg { code, message })
}

// ---------------------------------------------------------------------------
// Helper di alto livello: invio/ricezione dei messaggi tipizzati.
// ---------------------------------------------------------------------------

/// Invia una PutReq.
pub async fn send_put_req<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    req: &PutReq,
) -> Result<()> {
    let payload = encode_put_req(req)?;
    write_msg(writer, MSG_PUT_REQ, &payload).await
}

/// Invia una GetReq.
pub async fn send_get_req<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    req: &GetReq,
) -> Result<()> {
    let payload = encode_get_req(req)?;
    write_msg(writer, MSG_GET_REQ, &payload).await
}

/// Invia un Meta.
pub async fn send_meta<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    meta: &Meta,
) -> Result<()> {
    let payload = encode_meta(meta);
    write_msg(writer, MSG_META, &payload).await
}

/// Invia una Signature.
pub async fn send_signature<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    sig: &Signature,
) -> Result<()> {
    let payload = encode_signature(sig);
    write_msg(writer, MSG_SIGNATURE, &payload).await
}

/// Invia un Delta.
pub async fn send_delta<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    delta: &Delta,
) -> Result<()> {
    let payload = encode_delta(delta);
    write_msg(writer, MSG_DELTA, &payload).await
}

/// Invia un Ack.
pub async fn send_ack<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    ack: &Ack,
) -> Result<()> {
    let payload = encode_ack(ack);
    write_msg(writer, MSG_ACK, &payload).await
}

/// Invia un ErrMsg.
pub async fn send_err<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    err: &ErrMsg,
) -> Result<()> {
    let payload = encode_err(err);
    write_msg(writer, MSG_ERR, &payload).await
}

// ---------------------------------------------------------------------------
// Messaggi directory sync (sync-spec §5, §9).
// ---------------------------------------------------------------------------

/// Richiesta LIST (C→S): path assoluto remoto + flag recursive + with_hash.
#[derive(Debug, Clone)]
pub struct ListReq {
    /// Path assoluto della directory da listare (UTF-8, senza null).
    pub path: String,
    /// 1 = ricorsivo (tutto l'albero), 0 = solo top-level.
    pub recursive: u8,
    /// 1 = includi SHA-256 di ogni file nella risposta (un solo passaggio).
    pub with_hash: u8,
}

/// Singola entry di LIST_RES: path relativo + size + tipo + hash opzionale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListEntry {
    /// Path relativo alla dir richiesta, normalizzato con '/' come separatore.
    pub rel_path: String,
    /// Dimensione in byte (0 per directory).
    pub size: u64,
    /// 1 = directory, 0 = file.
    pub is_dir: u8,
    /// SHA-256 del file; presente SOLO se with_hash=1 e is_dir=0.
    pub sha256: Option<[u8; 32]>,
}

/// Risposta LIST (S→C): lista di entry (eventualmente vuota).
#[derive(Debug, Clone, Default)]
pub struct ListRes {
    /// Entry enumerate (entry_count sul wire).
    pub entries: Vec<ListEntry>,
}

/// Singolo item di un batch DELETE: path + flag recursive.
#[derive(Debug, Clone)]
pub struct DeleteItem {
    /// Path assoluto remoto da eliminare.
    pub path: String,
    /// 1 = elimina ricorsivamente (directory), 0 = solo file.
    pub recursive: u8,
}

/// Richiesta MKDIR batch (C→S): lista di path assoluti da creare (mkdir -p).
#[derive(Debug, Clone, Default)]
pub struct MkdirBatchReq {
    /// Path assoluti remoti da creare.
    pub paths: Vec<String>,
}

/// Risposta MKDIR batch (S→C): per-path status.
#[derive(Debug, Clone, Default)]
pub struct MkdirBatchRes {
    /// Risultati per-path, nello stesso ordine della richiesta.
    pub results: Vec<BatchResult>,
}

/// Richiesta DELETE batch (C→S): lista di item (path + recursive).
#[derive(Debug, Clone, Default)]
pub struct DeleteBatchReq {
    /// Item da eliminare.
    pub items: Vec<DeleteItem>,
}

/// Risposta DELETE batch (S→C): per-path status.
#[derive(Debug, Clone, Default)]
pub struct DeleteBatchRes {
    /// Risultati per-path, nello stesso ordine della richiesta.
    pub results: Vec<BatchResult>,
}

/// Risultato per-path di un'operazione batch (MKDIR/DELETE).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchResult {
    /// 0 = ok, 1 = not found (solo DELETE, non fatale), 2 = error.
    pub status: u8,
    /// Codice di errore (0 se ok, ERR_* se errore).
    pub code: u16,
    /// Messaggio descrittivo UTF-8 (vuoto se ok).
    pub message: String,
}

impl BatchResult {
    /// Crea un risultato ok (status=0, code=0, messaggio vuoto).
    pub fn ok() -> Self {
        Self {
            status: 0,
            code: 0,
            message: String::new(),
        }
    }

    /// Crea un risultato di errore (status=2) con codice e messaggio.
    pub fn error(code: u16, message: impl Into<String>) -> Self {
        Self {
            status: 2,
            code,
            message: message.into(),
        }
    }

    /// Crea un risultato "not found" (status=1, non fatale, solo DELETE).
    pub fn not_found() -> Self {
        Self {
            status: 1,
            code: 0,
            message: String::new(),
        }
    }
}

// --- LIST_REQ / LIST_RES ---------------------------------------------------

/// Codifica una ListReq in payload (path\0 + recursive u8 + with_hash u8).
pub fn encode_list_req(req: &ListReq) -> Result<Vec<u8>> {
    if req.path.contains('\0') {
        bail!("ListReq: path contiene null");
    }
    let path_bytes = req.path.as_bytes();
    let mut payload = Vec::with_capacity(path_bytes.len() + 1 + 1 + 1);
    payload.extend_from_slice(path_bytes);
    payload.push(0); // terminatore null del path
    payload.push(req.recursive);
    payload.push(req.with_hash);
    Ok(payload)
}

/// Decodifica una ListReq dal payload.
pub fn decode_list_req(payload: &[u8]) -> Result<ListReq> {
    let null_pos = payload
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| anyhow!("ListReq: terminatore null mancante"))?;
    let path_bytes = &payload[..null_pos];
    let path = String::from_utf8(path_bytes.to_vec())
        .map_err(|e| anyhow!("ListReq: path non UTF-8 valido: {}", e))?;
    let rest = &payload[null_pos + 1..];
    if rest.len() < 2 {
        bail!("ListReq: payload troppo corto dopo il path ({} byte, attesi 2)", rest.len());
    }
    let recursive = rest[0];
    let with_hash = rest[1];
    Ok(ListReq { path, recursive, with_hash })
}

/// Codifica una ListRes in payload (u32 LE entry_count + [entry]×N).
pub fn encode_list_res(res: &ListRes) -> Result<Vec<u8>> {
    let count = res.entries.len() as u32;
    let mut payload = Vec::new();
    let count_bytes = count.to_le_bytes();
    payload.extend_from_slice(&count_bytes);
    for entry in &res.entries {
        encode_list_entry(&mut payload, entry)?;
    }
    Ok(payload)
}

/// Decodifica una ListRes dal payload. Verifica il cap di 100k entry.
/// `with_hash` indica se il server ha incluso SHA-256 per i file (deve
/// corrispondere al flag della ListReq originale): senza di esso il decoder
/// non può distinguere i 32 byte dell'hash dai byte della entry successiva.
pub fn decode_list_res(payload: &[u8], with_hash: bool) -> Result<ListRes> {
    if payload.len() < 4 {
        bail!("ListRes: payload troppo corto ({} byte, attesi almeno 4)", payload.len());
    }
    let count = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
    if count > LIST_ENTRY_CAP {
        bail!(
            "ListRes: entry_count {} supera il cap di {}",
            count,
            LIST_ENTRY_CAP
        );
    }
    let mut offset = 4usize;
    let mut entries = Vec::with_capacity(count as usize);
    let mut i = 0u32;
    while i < count {
        let entry = decode_list_entry(payload, &mut offset, with_hash)?;
        entries.push(entry);
        i += 1;
    }
    Ok(ListRes { entries })
}

/// Codifica una singola entry e l'appende al payload.
/// Formato: u16 LE rel_path_len + rel_path UTF-8 + u64 LE size + u8 is_dir
///          + [u8;32] sha256 (solo se Some).
fn encode_list_entry(out: &mut Vec<u8>, entry: &ListEntry) -> Result<()> {
    let path_bytes = entry.rel_path.as_bytes();
    let path_len = path_bytes.len() as u16;
    let path_len_bytes = path_len.to_le_bytes();
    out.extend_from_slice(&path_len_bytes);
    out.extend_from_slice(path_bytes);
    let size_bytes = entry.size.to_le_bytes();
    out.extend_from_slice(&size_bytes);
    out.push(entry.is_dir);
    if let Some(hash) = &entry.sha256 {
        out.extend_from_slice(hash);
    }
    Ok(())
}

/// Decodifica una singola entry a partire da offset (avanza offset).
/// `with_hash` indica se attenderci i 32 byte di SHA-256 per i file.
fn decode_list_entry(payload: &[u8], offset: &mut usize, with_hash: bool) -> Result<ListEntry> {
    // rel_path_len u16 LE.
    if payload.len() < *offset + 2 {
        bail!("ListRes: payload troncato in rel_path_len");
    }
    let path_len = u16::from_le_bytes([payload[*offset], payload[*offset + 1]]) as usize;
    *offset += 2;
    // rel_path UTF-8.
    if payload.len() < *offset + path_len {
        bail!("ListRes: payload troncato in rel_path");
    }
    let path_bytes = &payload[*offset..*offset + path_len];
    let rel_path = String::from_utf8(path_bytes.to_vec())
        .map_err(|e| anyhow!("ListRes: rel_path non UTF-8 valido: {}", e))?;
    *offset += path_len;
    // size u64 LE.
    if payload.len() < *offset + 8 {
        bail!("ListRes: payload troncato in size");
    }
    let size = u64::from_le_bytes([
        payload[*offset], payload[*offset + 1], payload[*offset + 2], payload[*offset + 3],
        payload[*offset + 4], payload[*offset + 5], payload[*offset + 6], payload[*offset + 7],
    ]);
    *offset += 8;
    // is_dir u8.
    if payload.len() < *offset + 1 {
        bail!("ListRes: payload troncato in is_dir");
    }
    let is_dir = payload[*offset];
    *offset += 1;
    // sha256 opzionale: presente SOLO se with_hash=1 e is_dir=0.
    // Il flag with_hash arriva dal chiamante (corrisponde alla ListReq originale):
    // senza di esso non si potrebbe distinguere l'hash dai byte della entry successiva.
    let sha256 = if with_hash && is_dir == 0 {
        if payload.len() < *offset + 32 {
            bail!("ListRes: payload troncato in sha256");
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[*offset..*offset + 32]);
        *offset += 32;
        Some(hash)
    } else {
        None
    };
    Ok(ListEntry { rel_path, size, is_dir, sha256 })
}

// --- MKDIR_BATCH_REQ / MKDIR_BATCH_RES -------------------------------------

/// Codifica una MkdirBatchReq in payload (u32 LE count + [u16 LE len + path]×N).
pub fn encode_mkdir_batch_req(req: &MkdirBatchReq) -> Result<Vec<u8>> {
    let count = req.paths.len() as u32;
    let mut payload = Vec::new();
    let count_bytes = count.to_le_bytes();
    payload.extend_from_slice(&count_bytes);
    for path in &req.paths {
        if path.contains('\0') {
            bail!("MkdirBatchReq: path contiene null: {}", path);
        }
        let path_bytes = path.as_bytes();
        let path_len = path_bytes.len() as u16;
        let path_len_bytes = path_len.to_le_bytes();
        payload.extend_from_slice(&path_len_bytes);
        payload.extend_from_slice(path_bytes);
    }
    Ok(payload)
}

/// Decodifica una MkdirBatchReq dal payload.
pub fn decode_mkdir_batch_req(payload: &[u8]) -> Result<MkdirBatchReq> {
    if payload.len() < 4 {
        bail!("MkdirBatchReq: payload troppo corto ({} byte, attesi 4)", payload.len());
    }
    let count = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
    let mut offset = 4usize;
    let mut paths = Vec::with_capacity(count);
    let mut i = 0usize;
    while i < count {
        if payload.len() < offset + 2 {
            bail!("MkdirBatchReq: payload troncato in path_len");
        }
        let path_len = u16::from_le_bytes([payload[offset], payload[offset + 1]]) as usize;
        offset += 2;
        if payload.len() < offset + path_len {
            bail!("MkdirBatchReq: payload troncato in path");
        }
        let path_bytes = &payload[offset..offset + path_len];
        let path = String::from_utf8(path_bytes.to_vec())
            .map_err(|e| anyhow!("MkdirBatchReq: path non UTF-8 valido: {}", e))?;
        offset += path_len;
        paths.push(path);
        i += 1;
    }
    Ok(MkdirBatchReq { paths })
}

/// Codifica una MkdirBatchRes in payload (u32 LE count + [status+code+msg]×N).
pub fn encode_mkdir_batch_res(res: &MkdirBatchRes) -> Result<Vec<u8>> {
    encode_batch_res_inner(MSG_MKDIR_BATCH_RES, &res.results)
}

/// Decodifica una MkdirBatchRes dal payload. Verifica count == expected.
pub fn decode_mkdir_batch_res(payload: &[u8], expected: usize) -> Result<MkdirBatchRes> {
    let results = decode_batch_res_inner(payload, "MkdirBatchRes", expected)?;
    Ok(MkdirBatchRes { results })
}

// --- DELETE_BATCH_REQ / DELETE_BATCH_RES -----------------------------------

/// Codifica una DeleteBatchReq in payload
/// (u32 LE count + [u16 LE len + path + u8 recursive]×N).
pub fn encode_delete_batch_req(req: &DeleteBatchReq) -> Result<Vec<u8>> {
    let count = req.items.len() as u32;
    let mut payload = Vec::new();
    let count_bytes = count.to_le_bytes();
    payload.extend_from_slice(&count_bytes);
    for item in &req.items {
        if item.path.contains('\0') {
            bail!("DeleteBatchReq: path contiene null: {}", item.path);
        }
        let path_bytes = item.path.as_bytes();
        let path_len = path_bytes.len() as u16;
        let path_len_bytes = path_len.to_le_bytes();
        payload.extend_from_slice(&path_len_bytes);
        payload.extend_from_slice(path_bytes);
        payload.push(item.recursive);
    }
    Ok(payload)
}

/// Decodifica una DeleteBatchReq dal payload.
pub fn decode_delete_batch_req(payload: &[u8]) -> Result<DeleteBatchReq> {
    if payload.len() < 4 {
        bail!("DeleteBatchReq: payload troppo corto ({} byte, attesi 4)", payload.len());
    }
    let count = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
    let mut offset = 4usize;
    let mut items = Vec::with_capacity(count);
    let mut i = 0usize;
    while i < count {
        if payload.len() < offset + 2 {
            bail!("DeleteBatchReq: payload troncato in path_len");
        }
        let path_len = u16::from_le_bytes([payload[offset], payload[offset + 1]]) as usize;
        offset += 2;
        if payload.len() < offset + path_len + 1 {
            bail!("DeleteBatchReq: payload troncato in path/recursive");
        }
        let path_bytes = &payload[offset..offset + path_len];
        let path = String::from_utf8(path_bytes.to_vec())
            .map_err(|e| anyhow!("DeleteBatchReq: path non UTF-8 valido: {}", e))?;
        offset += path_len;
        let recursive = payload[offset];
        offset += 1;
        items.push(DeleteItem { path, recursive });
        i += 1;
    }
    Ok(DeleteBatchReq { items })
}

/// Codifica una DeleteBatchRes in payload (u32 LE count + [status+code+msg]×N).
pub fn encode_delete_batch_res(res: &DeleteBatchRes) -> Result<Vec<u8>> {
    encode_batch_res_inner(MSG_DELETE_BATCH_RES, &res.results)
}

/// Decodifica una DeleteBatchRes dal payload. Verifica count == expected.
pub fn decode_delete_batch_res(payload: &[u8], expected: usize) -> Result<DeleteBatchRes> {
    let results = decode_batch_res_inner(payload, "DeleteBatchRes", expected)?;
    Ok(DeleteBatchRes { results })
}

/// Codifica la parte comune di MKDIR_BATCH_RES / DELETE_BATCH_RES.
/// Formato: u32 LE count + [u8 status + u16 LE code + u16 LE msg_len + msg]×N.
fn encode_batch_res_inner(_msg_type: u8, results: &[BatchResult]) -> Result<Vec<u8>> {
    let count = results.len() as u32;
    let mut payload = Vec::new();
    let count_bytes = count.to_le_bytes();
    payload.extend_from_slice(&count_bytes);
    for r in results {
        payload.push(r.status);
        let code_bytes = r.code.to_le_bytes();
        payload.extend_from_slice(&code_bytes);
        let msg_bytes = r.message.as_bytes();
        let msg_len = msg_bytes.len() as u16;
        let msg_len_bytes = msg_len.to_le_bytes();
        payload.extend_from_slice(&msg_len_bytes);
        payload.extend_from_slice(msg_bytes);
    }
    Ok(payload)
}

/// Decodifica la parte comune di MKDIR_BATCH_RES / DELETE_BATCH_RES.
/// Verifica che count == expected (sync-spec §9: count mismatch -> ERR 5).
fn decode_batch_res_inner(
    payload: &[u8],
    label: &str,
    expected: usize,
) -> Result<Vec<BatchResult>> {
    if payload.len() < 4 {
        bail!("{}: payload troppo corto ({} byte, attesi 4)", label, payload.len());
    }
    let count = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
    // sync-spec §9: count mismatch -> il client stoppa immediatamente (ERR 5).
    if count != expected {
        bail!(
            "{}: count mismatch (atteso {}, ricevuto {}) - bug di protocollo o troncamento",
            label,
            expected,
            count
        );
    }
    let mut offset = 4usize;
    let mut results = Vec::with_capacity(count);
    let mut i = 0usize;
    while i < count {
        if payload.len() < offset + 1 {
            bail!("{}: payload troncato in status", label);
        }
        let status = payload[offset];
        offset += 1;
        if payload.len() < offset + 2 {
            bail!("{}: payload troncato in code", label);
        }
        let code = u16::from_le_bytes([payload[offset], payload[offset + 1]]);
        offset += 2;
        if payload.len() < offset + 2 {
            bail!("{}: payload troncato in msg_len", label);
        }
        let msg_len = u16::from_le_bytes([payload[offset], payload[offset + 1]]) as usize;
        offset += 2;
        if payload.len() < offset + msg_len {
            bail!("{}: payload troncato in message", label);
        }
        let msg_bytes = &payload[offset..offset + msg_len];
        let message = String::from_utf8(msg_bytes.to_vec())
            .unwrap_or_else(|_| "<messaggio non UTF-8>".to_string());
        offset += msg_len;
        results.push(BatchResult { status, code, message });
        i += 1;
    }
    Ok(results)
}

// --- Helper di alto livello per sync (invio/ricezione tipizzati) -----------

/// Invia una ListReq.
pub async fn send_list_req<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    req: &ListReq,
) -> Result<()> {
    let payload = encode_list_req(req)?;
    write_msg(writer, MSG_LIST_REQ, &payload).await
}

/// Invia una MkdirBatchReq.
pub async fn send_mkdir_batch_req<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    req: &MkdirBatchReq,
) -> Result<()> {
    let payload = encode_mkdir_batch_req(req)?;
    write_msg(writer, MSG_MKDIR_BATCH_REQ, &payload).await
}

/// Invia una DeleteBatchReq.
pub async fn send_delete_batch_req<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    req: &DeleteBatchReq,
) -> Result<()> {
    let payload = encode_delete_batch_req(req)?;
    write_msg(writer, MSG_DELETE_BATCH_REQ, &payload).await
}

// ---------------------------------------------------------------------------
// Messaggi self-update (UPDATE_REQ / UPDATE_RES).
// ---------------------------------------------------------------------------

/// Codifica una UpdateReq in payload (path\0).
pub fn encode_update_req(req: &UpdateReq) -> Result<Vec<u8>> {
    if req.staged_path.contains('\0') {
        bail!("UpdateReq: path contiene null");
    }
    let mut payload = Vec::with_capacity(req.staged_path.len() + 1);
    payload.extend_from_slice(req.staged_path.as_bytes());
    payload.push(0);
    Ok(payload)
}

/// Decodifica una UpdateReq dal payload.
pub fn decode_update_req(payload: &[u8]) -> Result<UpdateReq> {
    let null_pos = payload
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| anyhow!("UpdateReq: terminatore null mancante"))?;
    let path_bytes = &payload[..null_pos];
    let staged_path = String::from_utf8(path_bytes.to_vec())
        .map_err(|e| anyhow!("UpdateReq: path non UTF-8 valido: {}", e))?;
    Ok(UpdateReq { staged_path })
}

/// Codifica una UpdateRes in payload (u8 status + messaggio UTF-8).
pub fn encode_update_res(res: &UpdateRes) -> Vec<u8> {
    let mut payload = Vec::with_capacity(1 + res.message.len());
    payload.push(res.status);
    payload.extend_from_slice(res.message.as_bytes());
    payload
}

/// Decodifica una UpdateRes dal payload.
pub fn decode_update_res(payload: &[u8]) -> Result<UpdateRes> {
    if payload.is_empty() {
        bail!("UpdateRes: payload vuoto (attesi almeno 1 byte)");
    }
    let status = payload[0];
    let message = String::from_utf8(payload[1..].to_vec())
        .unwrap_or_else(|_| "<messaggio non UTF-8>".to_string());
    Ok(UpdateRes { status, message })
}

/// Invia una UpdateReq.
pub async fn send_update_req<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    req: &UpdateReq,
) -> Result<()> {
    let payload = encode_update_req(req)?;
    write_msg(writer, MSG_UPDATE_REQ, &payload).await
}

/// Invia una UpdateRes.
pub async fn send_update_res<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    res: &UpdateRes,
) -> Result<()> {
    let payload = encode_update_res(res);
    write_msg(writer, MSG_UPDATE_RES, &payload).await
}

// ---------------------------------------------------------------------------
// Test di roundtrip encode/decode (spec §17 passo 2).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_put_req() {
        let req = PutReq {
            path: r"C:\ci\app.exe".to_string(),
            block_size: 3238,
            segment_size: 67108864,
            total_new_size: 10485760,
        };
        let payload = encode_put_req(&req).unwrap();
        let decoded = decode_put_req(&payload).unwrap();
        assert_eq!(decoded.path, req.path);
        assert_eq!(decoded.block_size, req.block_size);
        assert_eq!(decoded.segment_size, req.segment_size);
        assert_eq!(decoded.total_new_size, req.total_new_size);
    }

    #[test]
    fn roundtrip_get_req() {
        let req = GetReq {
            path: r"C:\ci\log.txt".to_string(),
            block_size: 2048,
            segment_size: 16777216,
        };
        let payload = encode_get_req(&req).unwrap();
        let decoded = decode_get_req(&payload).unwrap();
        assert_eq!(decoded.path, req.path);
        assert_eq!(decoded.block_size, req.block_size);
        assert_eq!(decoded.segment_size, req.segment_size);
    }

    #[test]
    fn roundtrip_meta() {
        let meta = Meta { total_new_size: 123456789 };
        let payload = encode_meta(&meta);
        let decoded = decode_meta(&payload).unwrap();
        assert_eq!(decoded.total_new_size, meta.total_new_size);
    }

    #[test]
    fn roundtrip_signature_empty_blob() {
        // Segmento base assente: blob vuoto.
        let sig = Signature { segment_index: 0, blob: Vec::new() };
        let payload = encode_signature(&sig);
        let decoded = decode_signature(&payload).unwrap();
        assert_eq!(decoded.segment_index, 0);
        assert!(decoded.blob.is_empty());
    }

    #[test]
    fn roundtrip_signature_with_blob() {
        // Blob opaco simulato (in produzione è fast_rsync::Signature::serialized()).
        let blob = vec![0xAA; 128];
        let sig = Signature { segment_index: 42, blob };
        let payload = encode_signature(&sig);
        let decoded = decode_signature(&payload).unwrap();
        assert_eq!(decoded.segment_index, 42);
        assert_eq!(decoded.blob, sig.blob);
    }

    #[test]
    fn roundtrip_delta() {
        let blob = vec![0xBB; 256];
        let mut sha = [0u8; 32];
        sha[0] = 1;
        sha[31] = 2;
        let delta = Delta {
            segment_index: 7,
            blob,
            sha256_segment: sha,
            segment_new_size: 67108864,
        };
        let payload = encode_delta(&delta);
        let decoded = decode_delta(&payload).unwrap();
        assert_eq!(decoded.segment_index, 7);
        assert_eq!(decoded.blob, delta.blob);
        assert_eq!(decoded.sha256_segment, sha);
        assert_eq!(decoded.segment_new_size, 67108864);
    }

    #[test]
    fn roundtrip_delta_empty_blob() {
        // Delta vuoto (segmento identico al base: mostly copy, nessun literal).
        let delta = Delta {
            segment_index: 0,
            blob: Vec::new(),
            sha256_segment: [0xFF; 32],
            segment_new_size: 0,
        };
        let payload = encode_delta(&delta);
        let decoded = decode_delta(&payload).unwrap();
        assert_eq!(decoded.segment_index, 0);
        assert!(decoded.blob.is_empty());
        assert_eq!(decoded.segment_new_size, 0);
    }

    #[test]
    fn roundtrip_ack() {
        let ack = Ack {
            status: 0,
            total_bytes_written: 10485760,
            sha256_whole_file: [0x42; 32],
        };
        let payload = encode_ack(&ack);
        let decoded = decode_ack(&payload).unwrap();
        assert_eq!(decoded.status, 0);
        assert_eq!(decoded.total_bytes_written, 10485760);
        assert_eq!(decoded.sha256_whole_file, [0x42; 32]);
    }

    #[test]
    fn roundtrip_err() {
        let err = ErrMsg { code: ERR_PATH_FORBIDDEN, message: "path vietato".to_string() };
        let payload = encode_err(&err);
        let decoded = decode_err(&payload).unwrap();
        assert_eq!(decoded.code, ERR_PATH_FORBIDDEN);
        assert_eq!(decoded.message, "path vietato");
    }

    #[test]
    fn put_req_rejects_null_in_path() {
        let req = PutReq {
            path: "bad\0path".to_string(),
            block_size: 2048,
            segment_size: 64 * 1024 * 1024,
            total_new_size: 100,
        };
        assert!(encode_put_req(&req).is_err());
    }

    /// Verifica che i codici di errore del protocollo siano tutti distinti e
    /// che ERR_RESERVED = 6 (spec §14: riservato, non usato).
    #[test]
    fn error_codes_are_distinct_and_reserved_is_6() {
        let codes = [
            ERR_PATH_FORBIDDEN,
            ERR_FILE_NOT_FOUND,
            ERR_IO,
            ERR_CHECKSUM_MISMATCH,
            ERR_PROTO,
            ERR_RESERVED,
        ];
        // Ogni codice deve essere nel range 1..=6 e univoco.
        for (i, &c) in codes.iter().enumerate() {
            assert_eq!(c, (i + 1) as u16, "codice errore alla posizione {} non progressivo", i);
        }
        // ERR_RESERVED è esplicitamente 6 (non usato, ma documentato).
        assert_eq!(ERR_RESERVED, 6);
    }

    /// Verifica che error_code_description mappi tutti i codici noti.
    #[test]
    fn error_code_description_covers_all() {
        assert_eq!(error_code_description(ERR_PATH_FORBIDDEN), "path vietato");
        assert_eq!(error_code_description(ERR_FILE_NOT_FOUND), "file non trovato");
        assert_eq!(error_code_description(ERR_IO), "errore di I/O");
        assert_eq!(error_code_description(ERR_CHECKSUM_MISMATCH), "checksum mismatch");
        assert_eq!(error_code_description(ERR_PROTO), "errore di protocollo (magic/version/parametri invalidi)");
        assert_eq!(error_code_description(ERR_RESERVED), "riservato (non usato)");
        assert_eq!(error_code_description(999), "codice errore sconosciuto");
    }

    /// Test di roundtrip del framing a livello byte: scrive su un Vec e rilegge.
    #[tokio::test]
    async fn framing_roundtrip() {
        let mut buf: Vec<u8> = Vec::new();
        let payload = b"hello world";
        write_msg(&mut buf, MSG_META, payload).await.unwrap();

        // Il buffer ora contiene header(10) + payload(11).
        let mut cursor = std::io::Cursor::new(buf);
        let (msg_type, decoded_payload) = read_msg(&mut cursor).await.unwrap();
        assert_eq!(msg_type, MSG_META);
        assert_eq!(decoded_payload, payload);
    }

    #[tokio::test]
    async fn framing_rejects_bad_magic() {
        let mut bad = [0u8; HEADER_LEN];
        // Magic sbagliato.
        bad[0] = 0;
        bad[1] = 0;
        bad[2] = 0;
        bad[3] = 0;
        bad[4] = VERSION;
        bad[5] = MSG_META;
        let len_bytes = 0u32.to_le_bytes();
        bad[6..10].copy_from_slice(&len_bytes);

        let mut cursor = std::io::Cursor::new(bad);
        let result = read_msg(&mut cursor).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn framing_rejects_bad_version() {
        let mut bad = [0u8; HEADER_LEN];
        let magic_bytes = MAGIC.to_le_bytes();
        bad[0..4].copy_from_slice(&magic_bytes);
        bad[4] = 99; // versione non supportata
        bad[5] = MSG_META;
        let len_bytes = 0u32.to_le_bytes();
        bad[6..10].copy_from_slice(&len_bytes);

        let mut cursor = std::io::Cursor::new(bad);
        let result = read_msg(&mut cursor).await;
        assert!(result.is_err());
    }

    // --- Test directory sync (sync-spec §15 passo 1) ----------------------

    #[test]
    fn roundtrip_list_req() {
        let req = ListReq {
            path: r"C:\ci\artifacts".to_string(),
            recursive: 1,
            with_hash: 1,
        };
        let payload = encode_list_req(&req).unwrap();
        let decoded = decode_list_req(&payload).unwrap();
        assert_eq!(decoded.path, req.path);
        assert_eq!(decoded.recursive, 1);
        assert_eq!(decoded.with_hash, 1);
    }

    #[test]
    fn list_req_rejects_null_in_path() {
        let req = ListReq {
            path: "bad\0path".to_string(),
            recursive: 1,
            with_hash: 0,
        };
        assert!(encode_list_req(&req).is_err());
    }

    #[test]
    fn roundtrip_list_res_without_hash() {
        // with_hash=0: nessun sha256 nelle entry file.
        let entries = vec![
            ListEntry {
                rel_path: "app.exe".to_string(),
                size: 1024,
                is_dir: 0,
                sha256: None,
            },
            ListEntry {
                rel_path: "lib".to_string(),
                size: 0,
                is_dir: 1,
                sha256: None,
            },
            ListEntry {
                rel_path: "lib/core.dll".to_string(),
                size: 2048,
                is_dir: 0,
                sha256: None,
            },
        ];
        let res = ListRes { entries };
        let payload = encode_list_res(&res).unwrap();
        let decoded = decode_list_res(&payload, false).unwrap();
        assert_eq!(decoded.entries.len(), 3);
        assert_eq!(decoded.entries[0].rel_path, "app.exe");
        assert_eq!(decoded.entries[0].size, 1024);
        assert_eq!(decoded.entries[0].is_dir, 0);
        assert!(decoded.entries[0].sha256.is_none());
        assert_eq!(decoded.entries[1].is_dir, 1);
        assert_eq!(decoded.entries[2].rel_path, "lib/core.dll");
    }

    #[test]
    fn roundtrip_list_res_with_hash() {
        // with_hash=1: i file hanno sha256, le directory no.
        let mut hash1 = [0u8; 32];
        hash1[0] = 0xAB;
        let entries = vec![
            ListEntry {
                rel_path: "app.exe".to_string(),
                size: 1024,
                is_dir: 0,
                sha256: Some(hash1),
            },
            ListEntry {
                rel_path: "lib".to_string(),
                size: 0,
                is_dir: 1,
                sha256: None,
            },
        ];
        let res = ListRes { entries };
        let payload = encode_list_res(&res).unwrap();
        let decoded = decode_list_res(&payload, true).unwrap();
        assert_eq!(decoded.entries.len(), 2);
        assert_eq!(decoded.entries[0].sha256, Some(hash1));
        assert!(decoded.entries[1].sha256.is_none());
    }

    #[test]
    fn list_res_empty() {
        // Directory vuota o non esistente -> 0 entry.
        let res = ListRes::default();
        let payload = encode_list_res(&res).unwrap();
        let decoded = decode_list_res(&payload, false).unwrap();
        assert!(decoded.entries.is_empty());
    }

    #[test]
    fn list_res_rejects_cap_exceeded() {
        // entry_count > LIST_ENTRY_CAP -> errore (ERR 5 lato server).
        let mut payload = Vec::new();
        let over_cap = LIST_ENTRY_CAP + 1;
        let count_bytes = over_cap.to_le_bytes();
        payload.extend_from_slice(&count_bytes);
        let result = decode_list_res(&payload, false);
        assert!(result.is_err());
    }

    #[test]
    fn roundtrip_mkdir_batch_req() {
        let paths = vec![
            r"C:\ci\artifacts".to_string(),
            r"C:\ci\artifacts\lib".to_string(),
            r"C:\ci\artifacts\lib\sub".to_string(),
        ];
        let req = MkdirBatchReq { paths };
        let payload = encode_mkdir_batch_req(&req).unwrap();
        let decoded = decode_mkdir_batch_req(&payload).unwrap();
        assert_eq!(decoded.paths.len(), 3);
        assert_eq!(decoded.paths[0], r"C:\ci\artifacts");
        assert_eq!(decoded.paths[2], r"C:\ci\artifacts\lib\sub");
    }

    #[test]
    fn mkdir_batch_req_empty() {
        let req = MkdirBatchReq::default();
        let payload = encode_mkdir_batch_req(&req).unwrap();
        let decoded = decode_mkdir_batch_req(&payload).unwrap();
        assert!(decoded.paths.is_empty());
    }

    #[test]
    fn roundtrip_mkdir_batch_res() {
        let results = vec![
            BatchResult::ok(),
            BatchResult::error(ERR_IO, "permesso negato"),
        ];
        let res = MkdirBatchRes { results };
        let payload = encode_mkdir_batch_res(&res).unwrap();
        let decoded = decode_mkdir_batch_res(&payload, 2).unwrap();
        assert_eq!(decoded.results.len(), 2);
        assert_eq!(decoded.results[0].status, 0);
        assert_eq!(decoded.results[1].status, 2);
        assert_eq!(decoded.results[1].code, ERR_IO);
        assert_eq!(decoded.results[1].message, "permesso negato");
    }

    #[test]
    fn mkdir_batch_res_count_mismatch() {
        // sync-spec §9: count mismatch -> errore (client stoppa).
        let results = vec![BatchResult::ok()];
        let res = MkdirBatchRes { results };
        let payload = encode_mkdir_batch_res(&res).unwrap();
        // expected=3 ma la risposta ne ha 1 -> errore.
        let result = decode_mkdir_batch_res(&payload, 3);
        assert!(result.is_err());
    }

    #[test]
    fn roundtrip_delete_batch_req() {
        let items = vec![
            DeleteItem { path: r"C:\ci\old.dat".to_string(), recursive: 0 },
            DeleteItem { path: r"C:\ci\old_dir".to_string(), recursive: 1 },
        ];
        let req = DeleteBatchReq { items };
        let payload = encode_delete_batch_req(&req).unwrap();
        let decoded = decode_delete_batch_req(&payload).unwrap();
        assert_eq!(decoded.items.len(), 2);
        assert_eq!(decoded.items[0].path, r"C:\ci\old.dat");
        assert_eq!(decoded.items[0].recursive, 0);
        assert_eq!(decoded.items[1].recursive, 1);
    }

    #[test]
    fn roundtrip_delete_batch_res() {
        let results = vec![
            BatchResult::ok(),
            BatchResult::not_found(),
            BatchResult::error(ERR_IO, "busy"),
        ];
        let res = DeleteBatchRes { results };
        let payload = encode_delete_batch_res(&res).unwrap();
        let decoded = decode_delete_batch_res(&payload, 3).unwrap();
        assert_eq!(decoded.results.len(), 3);
        assert_eq!(decoded.results[0].status, 0);
        assert_eq!(decoded.results[1].status, 1); // not found
        assert_eq!(decoded.results[2].status, 2);
        assert_eq!(decoded.results[2].message, "busy");
    }

    #[test]
    fn delete_batch_res_count_mismatch() {
        let results = vec![BatchResult::ok()];
        let res = DeleteBatchRes { results };
        let payload = encode_delete_batch_res(&res).unwrap();
        let result = decode_delete_batch_res(&payload, 5);
        assert!(result.is_err());
    }

    /// Roundtrip framing dei nuovi messaggi sync via write_msg/read_msg.
    #[tokio::test]
    async fn framing_list_req_roundtrip() {
        let mut buf: Vec<u8> = Vec::new();
        let req = ListReq {
            path: r"C:\ci\art".to_string(),
            recursive: 1,
            with_hash: 1,
        };
        send_list_req(&mut buf, &req).await.unwrap();
        let mut cursor = std::io::Cursor::new(buf);
        let (msg_type, payload) = read_msg(&mut cursor).await.unwrap();
        assert_eq!(msg_type, MSG_LIST_REQ);
        let decoded = decode_list_req(&payload).unwrap();
        assert_eq!(decoded.path, req.path);
    }

    // --- Test self-update ---------------------------------------------------

    #[test]
    fn roundtrip_update_req() {
        let req = UpdateReq {
            staged_path: r"C:\ci\crosspilot-1758530400.exe".to_string(),
        };
        let payload = encode_update_req(&req).unwrap();
        let decoded = decode_update_req(&payload).unwrap();
        assert_eq!(decoded.staged_path, req.staged_path);
    }

    #[test]
    fn update_req_rejects_null_in_path() {
        let req = UpdateReq {
            staged_path: "bad\0path".to_string(),
        };
        assert!(encode_update_req(&req).is_err());
    }

    #[test]
    fn roundtrip_update_res() {
        let res = UpdateRes {
            status: 0,
            message: "updater avviato".to_string(),
        };
        let payload = encode_update_res(&res);
        let decoded = decode_update_res(&payload).unwrap();
        assert_eq!(decoded.status, 0);
        assert_eq!(decoded.message, "updater avviato");
    }
}
