// Modulo deploy: sincronizzazione degli artefatti sul target via WinRM.
// Separato da bootstrap.rs per rispettare la best-practice < 1000 righe.
//
// Artefatti gestiti (tutti nella directory di EXE_PATH sul remote):
//   crosspilot.exe    — server Windows (embeddato via include_bytes!)
//   crosspilot.linux  — binario Linux musl statico, sidecar per il
//                           self-update dei client piu' vecchi (embeddato
//                           solo nei build fatti con build-release.sh)
//   crosspilot.ver    — metadati BUILD_TS / EXE_SHA256 / LINUX_SHA256
//   .env                  — CROSSPILOT_SERVER_PORT per il server remoto
//
// AUTO-UPDATE BIDIREZIONALE ("il piu' vecchio si aggiorna da solo"):
// il confronto avviene su BUILD_TS (unix timestamp condiviso da tutti gli
// artefatti della stessa release via build-release.sh), non sull'hash:
// SHA-256 dice solo "diverso", non "piu' nuovo". Se il remote e' piu'
// nuovo, bootstrap chiama self_update (download del sidecar linux) e NON
// deploya mai: mai fare downgrade.
//
// DEPLOY STAGED (mai sovrascrivere un exe potenzialmente in esecuzione):
//   1. upload base64 chunked via send_input -> <file>.b64
//   2. decode -> <file>.new (NON in-place: il file originale resta intatto)
//   3. verifica SHA-256 del .new
//   4. functional check (solo exe): '<exe>.new' --version deve uscire 0 e
//      stampare il build_ts atteso — prova che il PE e' integro ed
//      eseguibile su quel Windows
//   5. swap atomico-ish: exe -> exe.old (rename consentito anche su exe
//      running), exe.new -> exe. Se un check fallisce: .new eliminato e
//      l'originale non e' stato toccato.
//
// Strategia upload invariata: Shell API (open_shell -> start_command ->
// send_input -> receive_next) per inviare byte binari via stdin (WinRM
// Send), bypassando il limite command-line di 8191 char.

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::time::Duration;
use winrm_rs::WinrmClient;

use crate::envs;
use crate::version::{self, RemoteBuildInfo};

/// Binario Windows embeddato (compilato con scripts/build-release.sh).
/// Se questo file manca, il build fallisce. Esegui:
///   ./scripts/build-release.sh
///
/// NOTA: gli embed sono attivi SOLO sui client non-Windows. Senza il cfg,
/// l'exe Windows embedderebbe a sua volta l'asset della build precedente
/// e il sidecar musl embedderebbe il nuovo exe: dimensioni che crescono
//  esponenzialmente ad ogni build-release (exe 67MB -> 141MB -> ...).
/// Il server Windows non deploya mai: per lui gli asset sono vuoti.
#[cfg(not(target_os = "windows"))]
const WINDOWS_EXE: &[u8] = include_bytes!("../assets/crosspilot.exe");
#[cfg(target_os = "windows")]
const WINDOWS_EXE: &[u8] = b"";

/// Binario Linux musl statico embeddato (sidecar per il self-update).
/// Il path arriva da build.rs (CROSSPILOT_LINUX_ASSET): se
/// assets/crosspilot.linux manca (build dev senza build-release.sh)
/// e' uno stub vuoto e l'upload del sidecar viene skippato con warning.
/// Come WINDOWS_EXE: vuoto su target Windows (nessun deploy da server).
#[cfg(not(target_os = "windows"))]
const LINUX_BIN: &[u8] = include_bytes!(env!("CROSSPILOT_LINUX_ASSET"));
#[cfg(target_os = "windows")]
const LINUX_BIN: &[u8] = b"";

/// Dimensione chunk per send_input (byte di base64).
/// WinRM Send message non ha il limite command-line, ma l'envelope SOAP ha
/// comunque un limite (~500KB). 100KB base64 è sicuro.
const CHUNK_B64_SIZE: usize = 100_000;

/// Directory remota che contiene l'exe (tutto prima dell'ultimo '\').
pub(crate) fn remote_dir_of(remote_exe_path: &str) -> &str {
    remote_exe_path
        .rfind('\\')
        .map(|i| &remote_exe_path[..i])
        .unwrap_or("C:\\")
}

/// Path remoto del sidecar linux (accanto all'exe).
fn linux_sidecar_path(remote_exe_path: &str) -> String {
    format!("{}\\{}", remote_dir_of(remote_exe_path), version::LINUX_SIDECAR_NAME)
}

/// Path remoto del file metadati .ver (accanto all'exe).
fn ver_file_path(remote_exe_path: &str) -> String {
    format!("{}\\{}", remote_dir_of(remote_exe_path), version::VER_FILE_NAME)
}

/// Legge lo stato della build deployata sul remote con UNA sola chiamata
/// WinRM: presenza exe + hash exe + presenza sidecar + contenuto .ver.
///
/// Output dello script (righe CHIAVE=valore, parsate da version::parse_remote_info):
///   EXE=True|False
///   EXE_HASH=<sha256>            (solo se exe presente)
///   LINUX_PRESENT=True|False
///   <righe grezze di crosspilot.ver, se esiste>
///
/// Il .ver viene letto come file (Get-Content), non eseguendo l'exe:
/// funziona anche se l'exe e' locked o in scansione AV. Un remote legacy
/// (deploy pre auto-update) non ha .ver -> build_ts=None -> ts effettivo 0
/// -> trattato come "piu' vecchio di qualsiasi build versionato".
/// Nota: ritorna WinrmError (non anyhow) perche' bootstrap deve
/// distinguere gli errori deterministici (endpoint morto / auth
/// rifiutata) con report_winrm_error.
pub async fn remote_build_info(
    client: &WinrmClient,
    host: &str,
    remote_exe_path: &str,
) -> std::result::Result<RemoteBuildInfo, winrm_rs::WinrmError> {
    let ver_path = ver_file_path(remote_exe_path);
    let linux_path = linux_sidecar_path(remote_exe_path);

    // Get-Content del .ver emette le sue righe grezze (BUILD_TS=...,
    // EXE_SHA256=..., LINUX_SHA256=...) che il parser riconosce direttamente.
    let script = format!(
        "Write-Output \"EXE=$(Test-Path '{}')\"; \
         if (Test-Path '{}') {{ Write-Output \"EXE_HASH=$((Get-FileHash '{}' -Algorithm SHA256).Hash)\" }}; \
         Write-Output \"LINUX_PRESENT=$(Test-Path '{}')\"; \
         if (Test-Path '{}') {{ Get-Content '{}' }}",
        remote_exe_path, remote_exe_path, remote_exe_path, linux_path, ver_path, ver_path
    );

    let out = client.run_powershell(host, &script).await?;

    let stdout = String::from_utf8_lossy(&out.stdout);
    let info = version::parse_remote_info(&stdout);

    eprintln!(
        "[DEBUG] remote_build_info: exe_present={} ts={:?} linux_present={} exit_code={}",
        info.exe_present, info.build_ts, info.linux_present, out.exit_code
    );
    if let Some(h) = &info.exe_sha256 {
        eprintln!("[DEBUG] remote_build_info: exe_sha256={}", &h[..16.min(h.len())]);
    }

    Ok(info)
}

/// Deploy completo e idempotente degli artefatti sul target.
///
/// `info` e' lo stato remoto gia' letto da bootstrap (evita una seconda
/// chiamata WinRM). Per ogni artefatto: se l'hash remoto coincide, skip;
//  altrimenti upload staged + verifica + swap. Alla fine .ver e .env
/// vengono sempre (ri)scritti con i valori correnti.
///
/// Ritorna Ok(()) se gli artefatti remoti sono allineati al build locale.
pub async fn deploy_exe(
    client: &WinrmClient,
    host: &str,
    remote_exe_path: &str,
    info: &RemoteBuildInfo,
) -> Result<()> {
    // --- Hash locali degli artefatti embeddati ---
    let exe_data = WINDOWS_EXE;
    // Su target Windows entrambi gli embed sono vuoti (il server non
    // deploya): niente da uploadare, errore esplicito invece di un
    // .ver con hash dell'exe vuoto.
    if exe_data.is_empty() && LINUX_BIN.is_empty() {
        anyhow::bail!(
            "nessun artefatto embeddato (build Windows o dev senza build-release.sh): \
             deploy non supportato"
        );
    }
    let local_exe_hash = sha256_bytes(exe_data).to_uppercase();
    eprintln!(
        "[deploy] build locale: ts={} exe={} byte sha256={}",
        version::BUILD_TS,
        exe_data.len(),
        &local_exe_hash[..16]
    );

    let linux_data = LINUX_BIN;
    let local_linux_hash = if linux_data.is_empty() {
        eprintln!(
            "[deploy] WARNING: asset linux non embeddato (build senza build-release.sh): \
             sidecar self-update non deployabile"
        );
        None
    } else {
        Some(sha256_bytes(linux_data).to_uppercase())
    };
    if let Some(h) = &local_linux_hash {
        eprintln!(
            "[deploy] sidecar linux embeddato: {} byte sha256={}",
            linux_data.len(),
            &h[..16]
        );
    }

    // --- Step 1: exe Windows (staged + functional check + swap) ---
    if exe_data.is_empty() {
        // Target Windows: nessun asset embeddato (il server non deploya).
        eprintln!(
            "[deploy] WARNING: asset exe non embeddato (build Windows/dev): \
             upload exe skippato"
        );
    } else if info.exe_present && info.exe_sha256.as_deref() == Some(local_exe_hash.as_str()) {
        eprintln!("[deploy] exe remoto gia' allineato (hash match). Skip upload exe.");
    } else {
        eprintln!(
            "[deploy] exe remoto {}: upload staged di {} byte...",
            if info.exe_present { "obsoleto/assente" } else { "mancante" },
            exe_data.len()
        );
        ensure_remote_dir(client, host, remote_exe_path).await?;
        upload_artifact(client, host, exe_data, remote_exe_path, true).await?;
    }

    // --- Step 2: sidecar linux (staged + swap, niente functional check:
    // non e' eseguibile su Windows; l'hash e' la garanzia) ---
    if let Some(linux_hash) = &local_linux_hash {
        let linux_path = linux_sidecar_path(remote_exe_path);
        let remote_linux_hash = remote_file_hash(client, host, &linux_path).await?;
        let aligned = remote_linux_hash.as_deref() == Some(linux_hash.as_str());
        eprintln!(
            "[DEBUG] deploy: sidecar linux remoto hash={:?} atteso={}",
            remote_linux_hash.as_deref().map(|h| &h[..16.min(h.len())]),
            &linux_hash[..16]
        );
        if aligned {
            eprintln!("[deploy] sidecar linux gia' allineato. Skip.");
        } else {
            eprintln!("[deploy] upload staged sidecar linux ({} byte)...", linux_data.len());
            upload_artifact(client, host, linux_data, &linux_path, false).await?;
        }
    }

    // --- Step 3: file .ver (metadati per i prossimi bootstrap/self-update) ---
    let ver_content = version::render_ver_file(
        version::BUILD_TS,
        &local_exe_hash,
        local_linux_hash.as_deref(),
    );
    let ver_path = ver_file_path(remote_exe_path);
    // WriteAllLines con array di stringhe: evita l'escape ambiguo dei
    // newline (in una stringa PS single-quoted "\n" resterebbe letterale).
    // Le righe non contengono quote singole; replace() e' comunque difesa.
    let mut ver_script = String::from("[IO.File]::WriteAllLines('");
    ver_script.push_str(&ver_path);
    ver_script.push_str("', @(");
    let mut first = true;
    for line in ver_content.lines() {
        if !first {
            ver_script.push(',');
        }
        first = false;
        ver_script.push('\'');
        ver_script.push_str(&line.replace('\'', "''"));
        ver_script.push('\'');
    }
    ver_script.push_str("))");
    let out = client
        .run_powershell(host, &ver_script)
        .await
        .context("write .ver remoto")?;
    if out.exit_code != 0 {
        eprintln!(
            "[deploy] WARNING: scrittura .ver fallita: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    } else {
        eprintln!("[deploy] .ver scritto: {} (ts={})", ver_path, version::BUILD_TS);
    }

    // --- Step 4: .env minimale per il server (invariato) ---
    // Il server remoto ha bisogno solo di CROSSPILOT_SERVER_PORT; gli altri
    // parametri servono al client Linux. Niente "\n" nel contenuto.
    let server_port = envs::var("SERVER_PORT").unwrap_or_else(|| "5330".to_string());
    let env_content = format!("CROSSPILOT_SERVER_PORT={}", server_port);
    let env_remote = format!("{}\\.env", remote_dir_of(remote_exe_path));
    let env_script = format!("[IO.File]::WriteAllText('{}', '{}')", env_remote, env_content);
    let out = client
        .run_powershell(host, &env_script)
        .await
        .context("write .env remoto")?;
    if out.exit_code != 0 {
        eprintln!(
            "[deploy] WARNING: scrittura .env fallita: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    } else {
        eprintln!("[deploy] .env scritto: {}", env_remote);
    }

    eprintln!("[deploy] artefatti remoti allineati al build locale (ts={})", version::BUILD_TS);
    Ok(())
}

/// Crea la directory remota che contiene l'exe (idempotente).
async fn ensure_remote_dir(client: &WinrmClient, host: &str, remote_exe_path: &str) -> Result<()> {
    let remote_dir = remote_dir_of(remote_exe_path);
    let mkdir_script = format!(
        "New-Item -ItemType Directory -Force -Path '{}' | Out-Null; Test-Path '{}'",
        remote_dir, remote_dir
    );
    let out = client
        .run_powershell(host, &mkdir_script)
        .await
        .context("mkdir remoto")?;
    eprintln!("[deploy] dir target: {}", String::from_utf8_lossy(&out.stdout).trim());
    Ok(())
}

/// Hash SHA-256 (uppercase) di un file remoto, o None se mancante.
async fn remote_file_hash(
    client: &WinrmClient,
    host: &str,
    remote_path: &str,
) -> Result<Option<String>> {
    let script = format!(
        "if (Test-Path '{}') {{ (Get-FileHash '{}' -Algorithm SHA256).Hash }} else {{ 'MISSING' }}",
        remote_path, remote_path
    );
    let out = client
        .run_powershell(host, &script)
        .await
        .context("remote_file_hash")?;
    let value = String::from_utf8_lossy(&out.stdout).trim().to_uppercase();
    if value.is_empty() || value == "MISSING" {
        return Ok(None);
    }
    Ok(Some(value))
}

/// Upload staged generico di un artefatto:
///   <path>.b64 (stdin chunked) -> decode -> <staged> -> verifica hash
///   -> [se check_version] '<staged>' --version deve stampare il ts
///   -> swap: <path> -> <path>.old, <staged> -> <path>
///
/// Il file originale viene toccato SOLO nell'ultimo passo e solo dopo
/// che lo staged ha superato tutte le verifiche.
///
/// NOTA sul nome staged: per check_version deve finire in `.exe`.
/// PowerShell `& 'file.new'` rifiuta di eseguire file con estensione
/// non eseguibile ("not recognized"): il functional check su
/// `crosspilot.exe.new` fallirebbe sempre. `crosspilot.new.exe`
/// invece e' un nome .exe valido e l'invoke nativo funziona.
async fn upload_artifact(
    client: &WinrmClient,
    host: &str,
    data: &[u8],
    remote_path: &str,
    check_version: bool,
) -> Result<()> {
    let local_hash = sha256_bytes(data).to_uppercase();
    let temp_b64 = format!("{}.b64", remote_path);
    // Staged eseguibile: <stem>.new.exe per i check_version, <path>.new
    // per gli artefatti non eseguibili (sidecar linux).
    let staged = if check_version {
        let stem = remote_path.strip_suffix(".exe").unwrap_or(remote_path);
        format!("{}.new.exe", stem)
    } else {
        format!("{}.new", remote_path)
    };

    // --- Upload base64 chunked via send_input (stdin) ---
    eprintln!(
        "[deploy] '{}' upload chunked ({} byte, chunk={} base64)...",
        remote_path,
        data.len(),
        CHUNK_B64_SIZE
    );
    let b64 = base64_encode(data);
    let total_chunks = b64.len().div_ceil(CHUNK_B64_SIZE);
    eprintln!(
        "[deploy] totale: {} byte -> {} base64 -> {} chunk",
        data.len(),
        b64.len(),
        total_chunks
    );

    // Pulisce un eventuale .b64 residuo di un upload precedente interrotto.
    let cleanup_script = format!(
        "if (Test-Path '{}') {{ Remove-Item '{}' -Force }}",
        temp_b64, temp_b64
    );
    let _ = client.run_powershell(host, &cleanup_script).await;

    // Shell remota: powershell legge stdin e appende al file .b64.
    let shell = client.open_shell(host).await.context("open_shell")?;
    eprintln!("[deploy] shell_id={}", shell.shell_id());

    let ps_command = format!(
        "$in = [Console]::In.ReadToEnd(); [IO.File]::AppendAllText('{}', $in)",
        temp_b64
    );
    let cmd_id = shell
        .start_command(
            "powershell.exe",
            &["-NoProfile", "-NonInteractive", "-Command", &ps_command],
        )
        .await
        .context("start_command")?;
    eprintln!("[deploy] command_id={}", cmd_id);

    let b64_bytes = b64.as_bytes();
    for (i, chunk) in b64_bytes.chunks(CHUNK_B64_SIZE).enumerate() {
        let is_last = i + 1 == total_chunks;
        shell
            .send_input(&cmd_id, chunk, is_last)
            .await
            .with_context(|| format!("send_input chunk {}/{}", i + 1, total_chunks))?;
        if (i + 1) % 10 == 0 || is_last {
            eprintln!(
                "[deploy] chunk {}/{} ({}%)",
                i + 1,
                total_chunks,
                (i + 1) * 100 / total_chunks
            );
        }
    }

    // Poll per completion del comando remoto (append su file).
    let mut done = false;
    for _ in 0..30 {
        let recv = shell.receive_next(&cmd_id).await.context("receive_next")?;
        if recv.done {
            done = true;
            if !recv.stderr.is_empty() {
                eprintln!("[deploy] stderr: {}", String::from_utf8_lossy(&recv.stderr).trim());
            }
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    let _ = shell.close().await;
    if !done {
        anyhow::bail!("comando upload non completato entro 30s");
    }
    eprintln!("[deploy] upload base64 completato.");

    // --- Decode .b64 -> .new + verifica hash dello staged ---
    // Il decode avviene su un FILE NUOVO (.new): l'originale resta intatto
    // fino allo swap finale.
    let decode_script = format!(
        "$b64 = Get-Content '{}' -Raw -Encoding ASCII; \
         $bytes = [Convert]::FromBase64String($b64); \
         [IO.File]::WriteAllBytes('{}', $bytes); \
         Remove-Item '{}' -Force; \
         Write-Output \"HASH=$((Get-FileHash '{}' -Algorithm SHA256).Hash)\"",
        temp_b64, staged, temp_b64, staged
    );
    let out = client
        .run_powershell(host, &decode_script)
        .await
        .context("decode base64 -> .new")?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let staged_hash = stdout
        .lines()
        .find_map(|l| l.trim().strip_prefix("HASH="))
        .unwrap_or("")
        .to_uppercase();
    eprintln!(
        "[deploy] hash staged: {}",
        if staged_hash.is_empty() { "(vuoto)" } else { &staged_hash[..16.min(staged_hash.len())] }
    );
    if staged_hash != local_hash {
        // Pulizia best-effort dello staged corrotto.
        let rm = format!("if (Test-Path '{}') {{ Remove-Item '{}' -Force }}", staged, staged);
        let _ = client.run_powershell(host, &rm).await;
        anyhow::bail!(
            "SHA-256 MISMATCH staged '{}': atteso {} remoto {}",
            staged,
            &local_hash[..16],
            &staged_hash[..16.min(staged_hash.len())]
        );
    }

    // --- Functional check (solo exe Windows): lo staged deve eseguire ---
    // '<path>.new' --version deve uscire 0 e stampare il build_ts atteso.
    // Prova che il PE e' integro (non troncato, non corrotto) PRIMA di
    // sostituire l'exe in produzione. Per il sidecar linux non e'
    // eseguibile su Windows: check_version=false, basta l'hash.
    if check_version {
        let ver_script = format!(
            "$o = & '{}' --version 2>&1 | Out-String; \
             Write-Output \"EXIT=$LASTEXITCODE\"; \
             Write-Output \"VER=$($o.Trim())\"",
            staged
        );
        let out = client
            .run_powershell(host, &ver_script)
            .await
            .context("functional check --version staged")?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        let mut exit_ok = false;
        let mut remote_ts: Option<u64> = None;
        for line in stdout.lines() {
            let line = line.trim();
            if let Some(v) = line.strip_prefix("EXIT=") {
                exit_ok = v == "0";
            }
            if let Some(v) = line.strip_prefix("VER=") {
                remote_ts = version::parse_version_ts(v);
            }
        }
        eprintln!(
            "[DEBUG] functional check staged: exit_ok={} ts={:?} atteso={}",
            exit_ok, remote_ts, version::BUILD_TS
        );
        if !exit_ok || remote_ts != Some(version::BUILD_TS) {
            let rm = format!("if (Test-Path '{}') {{ Remove-Item '{}' -Force }}", staged, staged);
            let _ = client.run_powershell(host, &rm).await;
            anyhow::bail!(
                "functional check fallito su '{}': exit_ok={} ts={:?} (atteso {}). \
                 Exe originale NON toccato.",
                staged,
                exit_ok,
                remote_ts,
                version::BUILD_TS
            );
        }
        eprintln!("[deploy] functional check OK: staged esegue e riporta ts={}", version::BUILD_TS);
    }

    // --- Swap atomico-ish: <path> -> <path>.old, <staged> -> <path> ---
    // Windows consente la RINOMINA di un exe in esecuzione (no overwrite):
    // questo rende il deploy sicuro anche se il server sta girando.
    let swap_script = format!(
        "if (Test-Path '{0}.old') {{ Remove-Item '{0}.old' -Force }}; \
         if (Test-Path '{0}') {{ Move-Item '{0}' '{0}.old' -Force }}; \
         Move-Item '{1}' '{0}' -Force; \
         Write-Output \"FINAL_HASH=$((Get-FileHash '{0}' -Algorithm SHA256).Hash)\"",
        remote_path, staged
    );
    let out = client
        .run_powershell(host, &swap_script)
        .await
        .context("swap .new -> finale")?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let final_hash = stdout
        .lines()
        .find_map(|l| l.trim().strip_prefix("FINAL_HASH="))
        .unwrap_or("")
        .to_uppercase();
    eprintln!(
        "[deploy] hash post-swap '{}': {}",
        remote_path,
        &final_hash[..16.min(final_hash.len())]
    );
    if final_hash != local_hash {
        anyhow::bail!(
            "SHA-256 MISMATCH post-swap '{}': atteso {} remoto {}",
            remote_path,
            &local_hash[..16],
            &final_hash[..16.min(final_hash.len())]
        );
    }
    eprintln!("[deploy] '{}' aggiornato e verificato (backup in .old).", remote_path);
    Ok(())
}

/// Calcola SHA-256 di byte in memoria.
fn sha256_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Base64 encode standard (con padding).
pub(crate) fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | (data[i + 2] as u32);
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(TABLE[((n >> 6) & 63) as usize] as char);
        out.push(TABLE[(n & 63) as usize] as char);
        i += 3;
    }
    let rem = data.len() - i;
    if rem == 1 {
        let n = (data[i] as u32) << 16;
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rem == 2 {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8);
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(TABLE[((n >> 6) & 63) as usize] as char);
        out.push('=');
    }
    out
}

/// Base64 decode standard. Ignora whitespace (WinRM puo' intercalare
/// CRLF nello stdout del comando remoto). Usato da self_update per il
/// download del sidecar linux.
pub(crate) fn base64_decode(input: &str) -> Result<Vec<u8>> {
    fn val(c: u8) -> Result<u32> {
        match c {
            b'A'..=b'Z' => Ok((c - b'A') as u32),
            b'a'..=b'z' => Ok((c - b'a' + 26) as u32),
            b'0'..=b'9' => Ok((c - b'0' + 52) as u32),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => anyhow::bail!("carattere base64 invalido: {:?}", c as char),
        }
    }
    let clean: Vec<u8> = input
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    let mut out = Vec::with_capacity(clean.len() / 4 * 3);
    for chunk in clean.chunks(4) {
        if chunk.len() < 4 {
            anyhow::bail!("base64 troncato: chunk finale di {} byte", chunk.len());
        }
        let pad = chunk.iter().filter(|&&c| c == b'=').count();
        let mut n: u32 = 0;
        for (idx, &c) in chunk.iter().enumerate() {
            let v = if c == b'=' { 0 } else { val(c)? };
            n |= v << (18 - idx * 6);
        }
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_roundtrip() {
        let data = b"crosspilot self-update test \x00\x01\x02\xff";
        let enc = base64_encode(data);
        let dec = base64_decode(&enc).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn base64_roundtrip_padding() {
        for len in 0..7usize {
            let data: Vec<u8> = (0..len).map(|i| i as u8 + 1).collect();
            let enc = base64_encode(&data);
            let dec = base64_decode(&enc).unwrap();
            assert_eq!(dec, data, "len={}", len);
        }
    }

    #[test]
    fn base64_decode_ignora_whitespace() {
        // WinRM puo' frammentare lo stdout con CRLF.
        let dec = base64_decode("aGVs\r\nbG8=\r\n").unwrap();
        assert_eq!(dec, b"hello");
    }

    #[test]
    fn base64_decode_rifiuta_input_invalido() {
        assert!(base64_decode("aGV").is_err()); // troncato
        assert!(base64_decode("aGVsbG8!").is_err()); // carattere invalido
    }
}
