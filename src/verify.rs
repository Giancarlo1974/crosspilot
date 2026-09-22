//! Helper SHA-256 per integrità end-to-end (spec §8, §10).
//!
//! fast_rsync usa MD4 (insicuro) come strong hash per-blocco. SHA-256 sul file
//! ricostruito garantisce integrità: delta sbagliato -> mismatch -> ERR 4, zero corruzione.
//!
//! Fornisce:
//! - `sha256_bytes`: hash di un buffer in memoria (segmenti).
//! - `sha256_file`: hash streaming di un file su disco (whole-file).

use std::fs::File;
use std::io::{Read, Seek};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

/// Calcola SHA-256 di un buffer in memoria (usato per i segmenti).
/// Ritorna i 32 byte del digest.
pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Calcola SHA-256 di un file già aperto, leggendo dall'inizio alla fine.
/// Memoria costante (streaming a chunk da 64 KB). Utile per verificare il file
/// .part prima del rename atomico.
///
/// Il file deve essere aperto in lettura (read+write o read-only). Legge direttamente
/// dal file (niente try_clone: dup() condivide l'offset e crea confusione dopo seek).
pub fn sha256_file_handle(file: &mut File) -> Result<[u8; 32]> {
    // Riavvolge all'inizio per leggere tutto il file.
    file.seek(std::io::SeekFrom::Start(0))
        .context("impossibile seek all'inizio del file per hash")?;

    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .context("errore lettura durante hash su handle")?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Test (spec §17 passo 4).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn sha256_known_vector() {
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let data = b"abc";
        let hash = sha256_bytes(data);
        let expected: [u8; 32] = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn sha256_empty() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let hash = sha256_bytes(b"");
        let expected: [u8; 32] = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn sha256_file_matches_bytes() {
        // Scrive un file temporaneo e verifica che l'hash su file == hash in memoria.
        let dir = std::env::temp_dir();
        let path = dir.join("crosspilot_verify_test.bin");
        let content = b"contenuto di prova per sha256 streaming su file";
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(content).unwrap();
        }
        let mut f = std::fs::File::open(&path).unwrap();
        let hash_file = sha256_file_handle(&mut f).unwrap();
        let hash_mem = sha256_bytes(content);
        assert_eq!(hash_file, hash_mem);

        // Pulizia.
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn sha256_large_file_streaming() {
        // File da ~1 MB per verificare che lo streaming legge più chunk.
        let dir = std::env::temp_dir();
        let path = dir.join("crosspilot_verify_large.bin");
        let mut content = Vec::with_capacity(1024 * 1024);
        // Pattern ripetuto: riempie 1 MB con byte ciclici.
        for i in 0..(1024 * 1024) {
            content.push((i % 251) as u8);
        }
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(&content).unwrap();
        }
        let mut f = std::fs::File::open(&path).unwrap();
        let hash_file = sha256_file_handle(&mut f).unwrap();
        let hash_mem = sha256_bytes(&content);
        assert_eq!(hash_file, hash_mem);

        let _ = std::fs::remove_file(&path);
    }
}
