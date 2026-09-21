// Modulo bootstrap: avvia il server remoto su Windows via WinRM.
// Separato da main.rs per rispettare la best-practice < 1000 righe.

use anyhow::{Context, Result};
use tokio::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use winrm_rs::WinrmError;

use crate::deploy;
use crate::envs;

/// Settato quando l'endpoint WinRM risulta irraggiungibile a livello TCP
/// (connect refused/timeout = servizio non attivo o firewall che droppa).
/// Letto dal chiamante per arricchire l'errore finale con il remediation.
static WINRM_UNREACHABLE: AtomicBool = AtomicBool::new(false);

/// Dedup del messaggio di remediation: bootstrap_server viene chiamata nel
/// retry loop (fino a 4 volte) e ogni chiamata puo' fallire 2 volte
/// (Test-Path + schtasks). L'hint va stampato una sola volta per processo.
static HINT_PRINTED: AtomicBool = AtomicBool::new(false);

/// True se il bootstrap ha rilevato l'endpoint WinRM irraggiungibile.
pub fn winrm_unreachable() -> bool {
    WINRM_UNREACHABLE.load(Ordering::Relaxed)
}

/// Stampa una volta il remediation per WinRM non abilitato sull'host remoto.
fn print_psremoting_hint(host: &str, port: u16) {
    if HINT_PRINTED.swap(true, Ordering::Relaxed) {
        return;
    }
    eprintln!();
    eprintln!("[HINT] Endpoint WinRM {}:{} non raggiungibile (servizio non attivo o firewall).", host, port);
    eprintln!("       Sulla macchina Windows remota, da PowerShell come amministratore:");
    eprintln!();
    eprintln!("         Enable-PSRemoting -Force");
    eprintln!();
    eprintln!("       (crea il listener 5985 e le regole firewall; alternativa: winrm quickconfig)");
    eprintln!();
}

/// Logga l'errore WinRM e stampa il remediation appropriato.
/// Ritorna true se l'errore e' deterministico (endpoint morto o auth rifiutata):
/// in quel caso ogni ulteriore chiamata WinRM fallirebbe identicamente, quindi
/// il chiamante puo' saltare i tentativi successivi e passare al polling.
/// Il transport ritenta gia' internamente gli errori HTTP transitori
/// (send_soap_with_retry): un Http surfato qui e' quindi un fallimento reale.
fn report_winrm_error(ctx: &str, e: &WinrmError, host: &str, port: u16) -> bool {
    eprintln!("[ERROR] bootstrap_server: {} fallito: {}", ctx, e);
    match e {
        WinrmError::Http(err) => {
            if err.is_connect() || err.is_timeout() {
                WINRM_UNREACHABLE.store(true, Ordering::Relaxed);
                print_psremoting_hint(host, port);
            }
            true
        }
        WinrmError::AuthFailed(_) => {
            if !HINT_PRINTED.swap(true, Ordering::Relaxed) {
                eprintln!();
                eprintln!("[HINT] Autenticazione WinRM rifiutata da {}:{}.", host, port);
                eprintln!("       Verificare USER/PASS dell'ambiente attivo: winboat-bridge env show <nome>");
                eprintln!();
            }
            true
        }
        _ => false,
    }
}

/// Avvia il server remoto su Windows via WinRM.
///
/// BUG (risolto): la versione precedente usava evil-winrm, una shell Ruby
/// interattiva che non gestisce lo stdin piped in modo deterministico.
/// Il comando PowerShell veniva inviato tramite pipe su stdin insieme a
/// "exit\n", ma evil-winrm poteva:
///   1. andare in timeout (15s) senza processare il comando → kill locale,
///      "assuming remote started" senza alcuna verifica;
///   2. processare "exit" prima del comando → il comando non veniva eseguito;
///   3. dichiarare successo in base all'exit code del processo *locale*
///      (sempre 0 se evil-winrm riceveva "exit"), ignorando completamente
///      l'output del comando PowerShell remoto.
///
/// Risultato: il server non partiva mai, ma il client ritentava 5 volte
/// (ogni volta 15s di timeout evil-winrm + 30s di polling = 225s totali).
///
/// FIX: sostituito evil-winrm con winrm-rs (puro Rust, async, NTLMv2).
/// winrm-rs esegue il comando PowerShell via protocollo WinRM nativo e
/// ritorna immediatamente con stdout/stderr/exit_code del comando remoto.
/// Inoltre run_powershell codifica lo script come UTF-16LE base64
/// (-EncodedCommand), eliminando i problemi di quoting/escaping.
pub async fn bootstrap_server() -> Result<()> {
    // --- Path del server remoto (da .env) ---
    // Risoluzione via envs: WINBOAT_<ENV>_EXE_PATH -> fallback WINBOAT_EXE_PATH.
    let exe_path = envs::var("EXE_PATH")
        .context("WINBOAT_EXE_PATH (o WINBOAT_<ENV>_EXE_PATH) must be set in the .env file")?;

    // --- Credenziali e endpoint WinRM (da .env) ---
    let host = envs::var("HOST")
        .unwrap_or_else(|| "127.0.0.1".to_string());
    let winrm_port_str = envs::var("PORT")
        .unwrap_or_else(|| "47320".to_string());
    let winrm_user_raw = envs::var("USER")
        .unwrap_or_else(|| "gianca".to_string());
    let winrm_pass = envs::var("PASS")
        .unwrap_or_else(|| "gianca".to_string());

    // Split dello username UPN (user@domain) in username + dominio NetBIOS.
    // NTLM usa il dominio NetBIOS (es. AC-S-SRL), non il DNS (es. ac-s-srl.it):
    // il suffisso @ va rimosso dal campo username dell'autenticazione.
    let (winrm_user, winrm_domain) = if let Some(pos) = winrm_user_raw.rfind('@') {
        let user_part = winrm_user_raw[..pos].to_string();
        // Il dominio NTLM viene comunque auto-rilevato dal challenge Type 2:
        // non serve convertire il DNS domain in NetBIOS.
        let _domain_dns = winrm_user_raw[pos + 1..].to_string();
        eprintln!("[DEBUG] bootstrap_server: split UPN user={} domain_dns={}", user_part, _domain_dns);
        (user_part, String::new())
    } else if let Some(pos) = winrm_user_raw.rfind('\\') {
        // Formato DOMAIN\user.
        let domain_part = winrm_user_raw[..pos].to_string();
        let user_part = winrm_user_raw[pos + 1..].to_string();
        eprintln!("[DEBUG] bootstrap_server: split DOMAIN\\user user={} domain={}", user_part, domain_part);
        (user_part, domain_part)
    } else {
        (winrm_user_raw, String::new())
    };

    // Parsing della porta WinRM (default 5985 per HTTP).
    let winrm_port = winrm_port_str.parse::<u16>()
        .unwrap_or(5985);
    eprintln!("[DEBUG] bootstrap_server: endpoint WinRM = {}:{} (HTTP, NTLMv2)", host, winrm_port);

    // --- Costruzione client WinRM ---
    // HTTP (use_tls = false), NTLMv2 (default). Il dominio è lasciato vuoto:
    // winrm-rs lo auto-rileva dal challenge NTLM Type 2 del server.
    let config = winrm_rs::WinrmConfig {
        port: winrm_port,
        use_tls: false,
        ..Default::default()
    };

    let credentials = winrm_rs::WinrmCredentials::new(
        winrm_user,
        winrm_pass,
        winrm_domain, // dominio: auto-rilevato dal challenge NTLM se vuoto
    );

    let client = winrm_rs::WinrmClient::new(config, credentials)
        .context("Impossibile creare il client WinRM")?;

    // --- Pre-check: verifica che il binario esista prima di avviare ---
    // Se manca, esegue l'auto-deploy del binario cross-compilato.
    // Distingue "file missing" (bug 3.6) da fallimento WinRM/protocollo.
    let check_script = format!("Test-Path '{}'", exe_path);
    let check_result = client.run_powershell(&host, &check_script).await;
    // winrm_dead: errore deterministico (endpoint morto / auth rifiutata).
    // In quel caso deploy e schtasks fallirebbero identicamente: si salta
    // direttamente al polling (il server potrebbe comunque essere attivo).
    let mut winrm_dead = false;
    let need_deploy = match check_result {
        Ok(out) => {
            let result_str = String::from_utf8_lossy(&out.stdout).trim().to_string();
            eprintln!("[DEBUG] bootstrap_server: Test-Path '{}' = {}", exe_path, result_str);
            result_str.eq_ignore_ascii_case("false")
        }
        Err(e) => {
            winrm_dead = report_winrm_error("Test-Path", &e, &host, winrm_port);
            // Se non riusciamo a verificare, proviamo ad avviare comunque
            // (il server potrebbe essere già in esecuzione).
            false
        }
    };

    if need_deploy {
        eprintln!("[bootstrap] Exe remoto mancante. Avvio auto-deploy...");
        if let Err(e) = deploy::deploy_exe(&client, &host, &exe_path).await {
            eprintln!("[ERROR] bootstrap_server: auto-deploy fallito: {}", e);
            // Non ritorniamo errore: il server potrebbe essere già in
            // esecuzione da un bootstrap precedente. Il polling deciderà.
        }
    }

    // --- Avvio server remoto via schtasks ---
    // Avvio detached: usiamo schtasks (Task Scheduler) invece di Start-Process.
    // Start-Process con -RedirectStandardOutput/-RedirectStandardError attende
    // che il processo figlio chiuda gli handle → OperationTimeout 60s.
    // Start-Process senza redirect: il processo figlio viene killato quando
    // la shell WinRM termina (perde gli handle stdout/stderr).
    // WScript.Shell.Run: il processo figlio crasha entro pochi secondi.
    // Start-Job: il job viene killato quando la shell WinRM chiude.
    // schtasks: il processo è gestito dal Task Scheduler di Windows e
    // sopravvive alla chiusura della shell WinRM. È l'unico modo affidabile
    // per avviare un processo persistente via WinRM.
    let ps_script = format!(
        "schtasks /Create /TN winboat-server /TR '\"{}\" --server' /SC ONCE /ST 00:00 /F | Out-Null; \
         schtasks /Run /TN winboat-server | Out-Null",
        exe_path
    );
    eprintln!("[DEBUG] bootstrap_server: script PowerShell = {}", ps_script);

    // --- Esecuzione comando remoto ---
    // Skip se WinRM e' deterministicamente non utilizzabile: la chiamata
    // fallirebbe identica dopo ~30s di connect timeout. Il polling resta:
    // il server potrebbe essere gia' in esecuzione da un avvio precedente.
    if winrm_dead {
        eprintln!("[bootstrap] WinRM non utilizzabile: skip avvio schtasks remoto.");
    } else {
        eprintln!("Bootstrapping server via WinRM...");
        let ps_result = client.run_powershell(&host, &ps_script).await;

    // Verifica del risultato: il bug precedente ignorava completamente
    // l'output del comando remoto. Ora controlliamo exit_code e stderr.
    match ps_result {
        Ok(output) => {
            eprintln!("[DEBUG] bootstrap_server: exit_code={}", output.exit_code);

            let stdout_str = String::from_utf8_lossy(&output.stdout);
            let stderr_str = String::from_utf8_lossy(&output.stderr);

            if !stdout_str.trim().is_empty() {
                eprintln!("[DEBUG] bootstrap_server: stdout={}", stdout_str.trim());
            }
            if !stderr_str.trim().is_empty() {
                eprintln!("[DEBUG] bootstrap_server: stderr={}", stderr_str.trim());
            }

            if output.exit_code != 0 {
                // Start-Process fallito (es. exe inesistente, permessi).
                // Non ritorniamo errore: il server potrebbe essere già in
                // esecuzione da un bootstrap precedente. Il polling deciderà.
                eprintln!(
                    "[ERROR] bootstrap_server: Start-Process fallito (exit_code={}): {}",
                    output.exit_code, stderr_str.trim()
                );
            } else {
                println!("Bootstrap command executed successfully.");
            }
        }
        Err(e) => {
            // Connessione WinRM fallita (rete, credenziali, servizio non attivo).
            // Non ritorniamo errore: il server potrebbe essere già in esecuzione.
            // Il chiamante ritenterà la connessione TCP fino a max_attempts.
            report_winrm_error("comando WinRM", &e, &host, winrm_port);
        }
    }
    }

    // --- Polling: verifica che il server TCP sia effettivamente partito ---
    // Il processo remoto può richiedere più tempo su dischi lenti, AV scan,
    // o primo avvio. Tenta la connessione TCP ogni 2s per un massimo di 30s.
    poll_server_startup().await;

    Ok(())
}

/// Polling dell'endpoint TCP del server: tenta la connessione ogni 2s
/// per un massimo di 30s. Non ritorna errore — il chiamante gestisce i retry.
async fn poll_server_startup() {
    println!("Waiting for server to start...");
    let host = envs::var("HOST")
        .unwrap_or_else(|| "127.0.0.1".to_string());
    let client_port = envs::var("CLIENT_PORT")
        .unwrap_or_else(|| "47330".to_string());
    let addr = format!("{}:{}", host, client_port);

    let mut connected = false;
    for i in 1..=15 {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            TcpStream::connect(addr.as_str())
        ).await;
        if let Ok(Ok(_)) = result {
            println!("Server is up (after {}s).", i * 2);
            connected = true;
            break;
        }
        println!("Server not ready yet, retrying ({}s elapsed)...", i * 2);
    }
    if !connected {
        eprintln!("Warning: server did not come up within 30s after bootstrap.");
    }
}
