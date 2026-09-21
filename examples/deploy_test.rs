// Test di deploy: upload del binario Windows cross-compilato sul target via WinRM.
//
// Strategia: usa l'API shell di basso livello (create_shell → execute_command →
// send_input → receive_output → signal → delete) per inviare i byte binari via
// stdin (WinRM Send message), bypassando il limite command-line di 8191 char.
//
// Il comando remoto è: powershell.exe -NoProfile -Command "$in=[Console]::In.ReadToEnd(); [IO.File]::AppendAllText('file.b64',$in)"
// I chunk base64 vengono inviati via send_input (stdin), poi decodificati in exe.

use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;
use winrm_rs::{WinrmClient, WinrmConfig, WinrmCredentials};

/// Carica il .env da percorsi multipli (stessa logica di main.rs).
fn load_dotenv() {
    if let Ok(cwd) = env::current_dir() {
        let p = cwd.join(".env");
        if p.exists() {
            let _ = dotenvy::from_path(&p);
            return;
        }
    }
    if let Ok(cwd) = env::current_dir() {
        let p = cwd.join("target/release/.env");
        if p.exists() {
            let _ = dotenvy::from_path(&p);
        }
    }
}

/// Legge le credenziali WinRM dal .env.
fn load_env() -> (String, String, String, String, String) {
    let host = env::var("WINBOAT_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = env::var("WINBOAT_PORT").unwrap_or_else(|_| "5985".to_string());
    let user = env::var("WINBOAT_USER").unwrap_or_else(|_| "gianca".to_string());
    let pass = env::var("WINBOAT_PASS").unwrap_or_else(|_| "gianca".to_string());
    let exe_path = env::var("WINBOAT_EXE_PATH")
        .unwrap_or_else(|_| r"C:\Users\giancarloalbanese\repos\winboat-bridge\target\release\winboat-bridge.exe".to_string());
    (host, port, user, pass, exe_path)
}

/// Split UPN user@domain in (user, domain).
fn split_user(user_raw: &str) -> (String, String) {
    if let Some(pos) = user_raw.rfind('@') {
        (user_raw[..pos].to_string(), String::new())
    } else if let Some(pos) = user_raw.rfind('\\') {
        (user_raw[pos + 1..].to_string(), user_raw[..pos].to_string())
    } else {
        (user_raw.to_string(), String::new())
    }
}

/// Calcola SHA-256 di un file locale.
fn sha256_file(path: &PathBuf) -> Result<String, String> {
    let data = fs::read(path).map_err(|e| format!("read failed: {e}"))?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let hash = hasher.finalize();
    Ok(hash.iter().map(|b| format!("{:02x}", b)).collect())
}

/// Dimensione chunk per send_input (byte di base64).
/// WinRM Send message non ha il limite command-line, ma l'envelope SOAP ha
/// comunque un limite (~500KB). 100KB base64 è sicuro.
const CHUNK_B64_SIZE: usize = 100_000;

#[tokio::main]
async fn main() {
    load_dotenv();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn".into()),
        )
        .init();

    // --- Carica config ---
    let (host, port_str, user_raw, pass, remote_exe_path) = load_env();
    let port: u16 = port_str.parse().unwrap_or(5985);
    let (user, domain) = split_user(&user_raw);

    // --- Path locale del binario cross-compilato ---
    let local_exe: PathBuf = env::current_dir()
        .unwrap()
        .join("target/x86_64-pc-windows-gnu/release/winboat-bridge.exe");

    if !local_exe.exists() {
        eprintln!("ERRORE: binario locale non trovato: {}", local_exe.display());
        eprintln!("Esegui prima: cargo build --release --target x86_64-pc-windows-gnu --bin winboat-bridge");
        std::process::exit(1);
    }

    let local_size = fs::metadata(&local_exe).unwrap().len();
    let local_hash = sha256_file(&local_exe).expect("sha256 locale");
    println!("Binario locale: {} ({} byte, sha256={})", local_exe.display(), local_size, &local_hash[..16]);
    println!("Target remoto: {}:{} -> {}", host, port, remote_exe_path);

    // --- Crea client WinRM ---
    let config = WinrmConfig {
        port,
        use_tls: false,
        ..Default::default()
    };
    let creds = WinrmCredentials::new(&user, &pass, &domain);
    let client = WinrmClient::new(config, creds).expect("client WinRM");

    // --- Step 1: verifica se il file esiste già con stesso hash ---
    println!("\n[1/5] Verifica file remoto esistente...");
    let check_script = format!(
        "if (Test-Path '{}') {{ (Get-FileHash '{}' -Algorithm SHA256).Hash }} else {{ 'MISSING' }}",
        remote_exe_path, remote_exe_path
    );
    let out = client.run_powershell(&host, &check_script).await.expect("check");
    let remote_hash = String::from_utf8_lossy(&out.stdout).trim().to_uppercase();
    let local_hash_upper = local_hash.to_uppercase();
    println!("  hash remoto: {}", if remote_hash.is_empty() { "(vuoto)" } else { &remote_hash[..16.min(remote_hash.len())] });
    println!("  hash locale: {}", &local_hash_upper[..16]);

    if remote_hash == local_hash_upper {
        println!("  → File già presente con stesso hash. Skip upload exe.");
    } else {
        // --- Step 2: crea directory target se non esiste ---
        println!("\n[2/5] Creazione directory target...");
        let remote_dir = remote_exe_path.rfind('\\').map(|i| &remote_exe_path[..i]).unwrap_or("C:\\");
        let mkdir_script = format!(
            "New-Item -ItemType Directory -Force -Path '{}' | Out-Null; Test-Path '{}'",
            remote_dir, remote_dir
        );
        let out = client.run_powershell(&host, &mkdir_script).await.expect("mkdir");
        println!("  dir creata: {}", String::from_utf8_lossy(&out.stdout).trim());

        // --- Step 3: upload chunked via send_input (stdin) ---
        println!("\n[3/5] Upload chunked via send_input (chunk={} byte base64)...", CHUNK_B64_SIZE);
        let exe_data = fs::read(&local_exe).expect("read exe");
        let b64 = base64_encode(&exe_data);
        let total_chunks = (b64.len() + CHUNK_B64_SIZE - 1) / CHUNK_B64_SIZE;
        println!("  totale: {} byte → {} base64 → {} chunk", exe_data.len(), b64.len(), total_chunks);

        let temp_b64 = format!("{}.b64", remote_exe_path);

        // Pulisce file temp esistente
        let cleanup_script = format!("if (Test-Path '{}') {{ Remove-Item '{}' -Force }}", temp_b64, temp_b64);
        let _ = client.run_powershell(&host, &cleanup_script).await;

        // Crea shell remota (Shell API: start_command + send_input + receive_next)
        println!("  Creazione shell remota...");
        let shell = client.open_shell(&host).await.expect("open_shell");
        println!("  shell_id={}", shell.shell_id());

        // Esegue powershell che legge stdin e appende al file
        let ps_command = format!(
            "$in = [Console]::In.ReadToEnd(); [IO.File]::AppendAllText('{}', $in)",
            temp_b64
        );
        let cmd_id = shell.start_command(
            "powershell.exe",
            &["-NoProfile", "-NonInteractive", "-Command", &ps_command],
        ).await.expect("start_command");
        println!("  command_id={}", cmd_id);

        // Invia i chunk base64 via send_input (stdin)
        let b64_bytes = b64.as_bytes();
        for (i, chunk) in b64_bytes.chunks(CHUNK_B64_SIZE).enumerate() {
            let is_last = i + 1 == total_chunks;
            shell.send_input(&cmd_id, chunk, is_last).await
                .unwrap_or_else(|e| panic!("send_input chunk {}/{} failed: {e}", i + 1, total_chunks));
            if (i + 1) % 10 == 0 || is_last {
                println!("  chunk {}/{} ({}%)", i + 1, total_chunks, (i + 1) * 100 / total_chunks);
            }
        }

        // Poll per output/completion
        println!("  Attesa completamento comando...");
        let mut done = false;
        for _ in 0..30 {
            let recv = shell.receive_next(&cmd_id).await.expect("receive_next");
            if recv.done {
                done = true;
                if !recv.stderr.is_empty() {
                    eprintln!("  stderr: {}", String::from_utf8_lossy(&recv.stderr).trim());
                }
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        let _ = shell.close().await;
        if !done {
            eprintln!("  ERRORE: comando non completato entro 30s");
            std::process::exit(1);
        }
        println!("  Upload base64 completato.");

        // --- Step 4: decode base64 → exe + verifica hash ---
        println!("\n[4/5] Decode base64 → exe + verifica hash...");
        let decode_script = format!(
            "$b64 = Get-Content '{}' -Raw -Encoding ASCII; \
             $bytes = [Convert]::FromBase64String($b64); \
             [IO.File]::WriteAllBytes('{}', $bytes); \
             Remove-Item '{}' -Force; \
             (Get-FileHash '{}' -Algorithm SHA256).Hash",
            temp_b64, remote_exe_path, temp_b64, remote_exe_path
        );
        let out = client.run_powershell(&host, &decode_script).await.expect("decode");
        let remote_hash_after = String::from_utf8_lossy(&out.stdout).trim().to_uppercase();
        println!("  hash remoto dopo upload: {}", &remote_hash_after[..16.min(remote_hash_after.len())]);
        println!("  hash locale:              {}", &local_hash_upper[..16]);
        if remote_hash_after == local_hash_upper {
            println!("  → SHA-256 match! Upload riuscito.");
        } else {
            eprintln!("  → SHA-256 MISMATCH! Upload fallito.");
            eprintln!("  stderr: {}", String::from_utf8_lossy(&out.stderr).trim());
            std::process::exit(1);
        }
    }

    // --- Step 5: deploya anche il .env minimale per il server ---
    println!("\n[5/6] Deploy .env per il server remoto...");
    let env_content = "WINBOAT_SERVER_PORT=5330\n";
    let env_remote = format!(
        "{}\\.env",
        remote_exe_path.rfind('\\').map(|i| &remote_exe_path[..i]).unwrap_or("C:\\")
    );
    let env_script = format!(
        "[IO.File]::WriteAllText('{}', '{}')",
        env_remote, env_content
    );
    let out = client.run_powershell(&host, &env_script).await.expect("write .env");
    if out.exit_code == 0 {
        println!("  .env scritto: {}", env_remote);
    } else {
        eprintln!("  ERRORE scrittura .env: {}", String::from_utf8_lossy(&out.stderr).trim());
    }

    // --- Step 6: test esecuzione remota (--help) ---
    println!("\n[6/6] Test esecuzione remota (--help)...");
    test_remote_run(&client, &host, &remote_exe_path).await;
}

/// Test: esegue `winboat-bridge.exe --help` sul target via WinRM.
/// Verifica che il binario giri (mcfgthread.dll presente, ecc.).
async fn test_remote_run(client: &WinrmClient, host: &str, exe_path: &str) {
    let script = format!("& '{}' --help", exe_path);
    match client.run_powershell(&host, &script).await {
        Ok(out) => {
            println!("  exit_code={}", out.exit_code);
            let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            if !stdout.is_empty() {
                // Mostra solo le prime 5 righe per non spammatizzare
                let lines: Vec<&str> = stdout.lines().take(5).collect();
                println!("  stdout: {}", lines.join("\n          "));
            }
            if !stderr.is_empty() {
                eprintln!("  stderr: {}", stderr);
            }
            if out.exit_code == 0 {
                println!("  → Binario esegue correttamente sul target!");
            } else {
                eprintln!("  → Binario NON esegue (exit_code={}).", out.exit_code);
            }
        }
        Err(e) => {
            eprintln!("  → Esecuzione remota fallita: {}", e);
        }
    }
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
