// Modulo deploy: upload del binario Windows cross-compilato sul target via WinRM.
// Separato da bootstrap.rs per rispettare la best-practice < 1000 righe.
//
// Il binario Windows è embeddato nel binario Linux via include_bytes!
// (vedi scripts/build-release.sh per la procedura di compilazione).
// Questo garantisce che il client Linux sia autonomo: non serve il codice
// sorgente né una cross-toolchain sul machine di esecuzione.
//
// Strategia: usa l'API shell di basso livello (open_shell → start_command →
// send_input → receive_next → close) per inviare i byte binari via stdin
// (WinRM Send message), bypassando il limite command-line di 8191 char.
//
// Il comando remoto è:
//   powershell.exe -NoProfile -Command "$in=[Console]::In.ReadToEnd(); [IO.File]::AppendAllText('file.b64',$in)"
// I chunk base64 vengono inviati via send_input (stdin), poi decodificati in exe.

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::time::Duration;
use winrm_rs::WinrmClient;

use crate::envs;

/// Binario Windows embeddato (compilato con scripts/build-release.sh).
/// Se questo file manca, il build fallisce. Esegui:
///   ./scripts/build-release.sh
const WINDOWS_EXE: &[u8] = include_bytes!("../assets/winboat-bridge.exe");

/// Dimensione chunk per send_input (byte di base64).
/// WinRM Send message non ha il limite command-line, ma l'envelope SOAP ha
/// comunque un limite (~500KB). 100KB base64 è sicuro.
const CHUNK_B64_SIZE: usize = 100_000;

/// Esegue il deploy completo del binario Windows sul target:
/// 1. Verifica se l'exe remoto esiste già con stesso hash (skip se match)
/// 2. Crea la directory target
/// 3. Upload chunked base64 via send_input (stdin)
/// 4. Decode base64 → exe + verifica hash
/// 5. Deploya il .env minimale per il server
///
/// Ritorna Ok(()) se l'exe remoto è pronto e valido dopo il deploy.
pub async fn deploy_exe(
    client: &WinrmClient,
    host: &str,
    remote_exe_path: &str,
) -> Result<()> {
    // --- Binario Windows embeddato ---
    let exe_data = WINDOWS_EXE;
    let local_hash = sha256_bytes(exe_data);
    let local_hash_upper = local_hash.to_uppercase();
    eprintln!(
        "[deploy] Binario embeddato: {} byte (sha256={})",
        exe_data.len(),
        &local_hash_upper[..16]
    );

    // --- Step 1: verifica se il file esiste già con stesso hash ---
    let check_script = format!(
        "if (Test-Path '{}') {{ (Get-FileHash '{}' -Algorithm SHA256).Hash }} else {{ 'MISSING' }}",
        remote_exe_path, remote_exe_path
    );
    let out = client.run_powershell(host, &check_script)
        .await
        .context("check hash remoto")?;
    let remote_hash = String::from_utf8_lossy(&out.stdout).trim().to_uppercase();
    eprintln!("[deploy] hash remoto: {}", if remote_hash.is_empty() { "(vuoto)" } else { &remote_hash[..16.min(remote_hash.len())] });

    if remote_hash == local_hash_upper {
        eprintln!("[deploy] File già presente con stesso hash. Skip upload.");
    } else {
        // --- Step 2: crea directory target se non esiste ---
        let remote_dir = remote_exe_path.rfind('\\').map(|i| &remote_exe_path[..i]).unwrap_or("C:\\");
        let mkdir_script = format!(
            "New-Item -ItemType Directory -Force -Path '{}' | Out-Null; Test-Path '{}'",
            remote_dir, remote_dir
        );
        let out = client.run_powershell(host, &mkdir_script)
            .await
            .context("mkdir remoto")?;
        eprintln!("[deploy] dir creata: {}", String::from_utf8_lossy(&out.stdout).trim());

        // --- Step 3: upload chunked via send_input (stdin) ---
        eprintln!("[deploy] Upload chunked via send_input (chunk={} byte base64)...", CHUNK_B64_SIZE);
        let b64 = base64_encode(exe_data);
        let total_chunks = (b64.len() + CHUNK_B64_SIZE - 1) / CHUNK_B64_SIZE;
        eprintln!("[deploy] totale: {} byte → {} base64 → {} chunk", exe_data.len(), b64.len(), total_chunks);

        let temp_b64 = format!("{}.b64", remote_exe_path);

        // Pulisce file temp esistente
        let cleanup_script = format!("if (Test-Path '{}') {{ Remove-Item '{}' -Force }}", temp_b64, temp_b64);
        let _ = client.run_powershell(host, &cleanup_script).await;

        // Crea shell remota (Shell API: start_command + send_input + receive_next)
        let shell = client.open_shell(host).await.context("open_shell")?;
        eprintln!("[deploy] shell_id={}", shell.shell_id());

        // Esegue powershell che legge stdin e appende al file
        let ps_command = format!(
            "$in = [Console]::In.ReadToEnd(); [IO.File]::AppendAllText('{}', $in)",
            temp_b64
        );
        let cmd_id = shell.start_command(
            "powershell.exe",
            &["-NoProfile", "-NonInteractive", "-Command", &ps_command],
        ).await.context("start_command")?;
        eprintln!("[deploy] command_id={}", cmd_id);

        // Invia i chunk base64 via send_input (stdin)
        let b64_bytes = b64.as_bytes();
        for (i, chunk) in b64_bytes.chunks(CHUNK_B64_SIZE).enumerate() {
            let is_last = i + 1 == total_chunks;
            shell.send_input(&cmd_id, chunk, is_last)
                .await
                .with_context(|| format!("send_input chunk {}/{}", i + 1, total_chunks))?;
            if (i + 1) % 10 == 0 || is_last {
                eprintln!("[deploy] chunk {}/{} ({}%)", i + 1, total_chunks, (i + 1) * 100 / total_chunks);
            }
        }

        // Poll per output/completion
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
        eprintln!("[deploy] Upload base64 completato.");

        // --- Step 4: decode base64 → exe + verifica hash ---
        let decode_script = format!(
            "$b64 = Get-Content '{}' -Raw -Encoding ASCII; \
             $bytes = [Convert]::FromBase64String($b64); \
             [IO.File]::WriteAllBytes('{}', $bytes); \
             Remove-Item '{}' -Force; \
             (Get-FileHash '{}' -Algorithm SHA256).Hash",
            temp_b64, remote_exe_path, temp_b64, remote_exe_path
        );
        let out = client.run_powershell(host, &decode_script)
            .await
            .context("decode base64")?;
        let remote_hash_after = String::from_utf8_lossy(&out.stdout).trim().to_uppercase();
        eprintln!("[deploy] hash remoto dopo upload: {}", &remote_hash_after[..16.min(remote_hash_after.len())]);
        if remote_hash_after != local_hash_upper {
            anyhow::bail!(
                "SHA-256 MISMATCH dopo upload! locale={} remoto={}",
                &local_hash_upper[..16],
                &remote_hash_after[..16.min(remote_hash_after.len())]
            );
        }
        eprintln!("[deploy] SHA-256 match! Upload riuscito.");
    }

    // --- Step 5: deploya il .env minimale per il server ---
    // Il server remoto ha bisogno di WINBOAT_SERVER_PORT per sapere su quale
    // porta ascoltare. Gli altri parametri (WINBOAT_HOST, WINBOAT_USER, ecc.)
    // servono solo al client Linux e non sono necessari sul server.
    // La porta viene dalla config attiva (WINBOAT_<ENV>_SERVER_PORT ->
    // fallback WINBOAT_SERVER_PORT -> 5330).
    // Nota: niente "\n" nel contenuto: la stringa PowerShell e' single-quoted
    // e "\n" resterebbe letterale nel file .env remoto.
    let server_port = envs::var("SERVER_PORT")
        .unwrap_or_else(|| "5330".to_string());
    let env_content = format!("WINBOAT_SERVER_PORT={}", server_port);
    let env_remote = format!(
        "{}\\.env",
        remote_exe_path.rfind('\\').map(|i| &remote_exe_path[..i]).unwrap_or("C:\\")
    );
    let env_script = format!(
        "[IO.File]::WriteAllText('{}', '{}')",
        env_remote, env_content
    );
    let out = client.run_powershell(host, &env_script)
        .await
        .context("write .env remoto")?;
    if out.exit_code != 0 {
        eprintln!("[deploy] WARNING: scrittura .env fallita: {}", String::from_utf8_lossy(&out.stderr).trim());
    } else {
        eprintln!("[deploy] .env scritto: {}", env_remote);
    }

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
fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
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
