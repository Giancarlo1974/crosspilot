// Modulo bootstrap: avvia il server remoto su Windows via WinRM.
// Separato da main.rs per rispettare la best-practice < 1000 righe.

use anyhow::{Context, Result};
use tokio::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use winrm_rs::WinrmError;

use crate::deploy;
use crate::envs;
use crate::self_update;
use crate::version;

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
                eprintln!("       Verificare USER/PASS dell'ambiente attivo: crosspilot env show <nome>");
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
/// Contesto WinRM condiviso: client costruito + host + porta + utente
/// raw (per schtasks /RU). Estratto da bootstrap_server per essere
/// riutilizzato dal preflight del fallback di update::reconcile.
struct WinrmCtx {
    client: winrm_rs::WinrmClient,
    host: String,
    port: u16,
    /// Utente raw come configurato (UPN o DOMAIN\user): schtasks /RU lo
    /// accetta in entrambi i formati.
    schtasks_user: String,
}

/// Risolve le credenziali/endpoint WinRM dal .env (catena ambienti) e
/// costruisce il client. Condiviso da bootstrap_server e winrm_probe.
fn winrm_context() -> Result<WinrmCtx> {
    let host = envs::var("HOST").unwrap_or_else(|| "127.0.0.1".to_string());
    let winrm_port_str = envs::var("PORT").unwrap_or_else(|| "47320".to_string());
    let winrm_user_raw = envs::var("USER").unwrap_or_else(|| "gianca".to_string());
    let winrm_pass = envs::var("PASS").unwrap_or_else(|| "gianca".to_string());

    // Split dello username UPN (user@domain) in username + dominio NetBIOS.
    // NTLM usa il dominio NetBIOS (es. AC-S-SRL), non il DNS (es. ac-s-srl.it):
    // il suffisso @ va rimosso dal campo username dell'autenticazione.
    let (winrm_user, winrm_domain) = if let Some(pos) = winrm_user_raw.rfind('@') {
        let user_part = winrm_user_raw[..pos].to_string();
        // Il dominio NTLM viene comunque auto-rilevato dal challenge Type 2:
        // non serve convertire il DNS domain in NetBIOS.
        let _domain_dns = winrm_user_raw[pos + 1..].to_string();
        eprintln!("[DEBUG] winrm_context: split UPN user={} domain_dns={}", user_part, _domain_dns);
        (user_part, String::new())
    } else if let Some(pos) = winrm_user_raw.rfind('\\') {
        // Formato DOMAIN\user.
        let domain_part = winrm_user_raw[..pos].to_string();
        let user_part = winrm_user_raw[pos + 1..].to_string();
        eprintln!("[DEBUG] winrm_context: split DOMAIN\\user user={} domain={}", user_part, domain_part);
        (user_part, domain_part)
    } else {
        (winrm_user_raw.clone(), String::new())
    };

    // Parsing della porta WinRM (default 5985 per HTTP).
    let port = winrm_port_str.parse::<u16>().unwrap_or(5985);
    eprintln!("[DEBUG] winrm_context: endpoint WinRM = {}:{} (HTTP, NTLMv2)", host, port);

    // --- Costruzione client WinRM ---
    // HTTP (use_tls = false), NTLMv2 (default). Il dominio è lasciato vuoto:
    // winrm-rs lo auto-rileva dal challenge NTLM Type 2 del server.
    let config = winrm_rs::WinrmConfig {
        port,
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
    Ok(WinrmCtx {
        client,
        host,
        port,
        schtasks_user: winrm_user_raw,
    })
}

/// Preflight WinRM per il fallback di update::reconcile: verifica che il
/// canale WinRM sia VIVO prima di fermare un server funzionante.
///
/// PERCHE': quando l'update via TCP fallisce (es. server zombificato con
/// versione protocollo incompatibile — il caso H101, build intermedia con
/// VERSION=2 che chiude il socket su ogni messaggio framed), l'unica via
/// di recovery e' il deploy via WinRM. Ma il deploy richiede di fermare
/// il vecchio server (`quit` in shell-mode) PRIMA del riavvio: farlo con
/// WinRM morto lascerebbe il remote senza server e senza via d'uscita
/// (brick volontario). Questo preflight risponde alla domanda "posso
/// permettermi di fermare il server?".
///
/// Ritorna Some(info) se remote_build_info risponde (deploy possibile),
/// None se WinRM non e' utilizzabile.
pub async fn winrm_probe() -> Option<version::RemoteBuildInfo> {
    let ctx = match winrm_context() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[update-fallback] preflight: configurazione WinRM non valida: {}", e);
            return None;
        }
    };
    let exe_path = match envs::var("EXE_PATH") {
        Some(p) => p,
        None => {
            eprintln!("[update-fallback] preflight: EXE_PATH non configurato");
            return None;
        }
    };
    match deploy::remote_build_info(&ctx.client, &ctx.host, &exe_path).await {
        Ok(info) => {
            eprintln!(
                "[update-fallback] preflight WinRM OK: ts remoto={:?} locale={} exe_present={}",
                info.build_ts, version::BUILD_TS, info.exe_present
            );
            Some(info)
        }
        Err(e) => {
            eprintln!("[update-fallback] preflight WinRM fallito: {}", e);
            None
        }
    }
}

/// FIX: sostituito evil-winrm con winrm-rs (puro Rust, async, NTLMv2).
/// winrm-rs esegue il comando PowerShell via protocollo WinRM nativo e
/// ritorna immediatamente con stdout/stderr/exit_code del comando remoto.
/// Inoltre run_powershell codifica lo script come UTF-16LE base64
/// (-EncodedCommand), eliminando i problemi di quoting/escaping.
pub async fn bootstrap_server() -> Result<()> {
    // --- Path del server remoto (da .env) ---
    // Risoluzione via envs: CROSSPILOT_<ENV>_EXE_PATH -> fallback CROSSPILOT_EXE_PATH.
    let exe_path = envs::var("EXE_PATH")
        .context("CROSSPILOT_EXE_PATH (o CROSSPILOT_<ENV>_EXE_PATH) must be set in the .env file")?;

    // --- Credenziali e endpoint WinRM (da .env) ---
    let ctx = winrm_context()?;

    // Split dello username UPN (user@domain) in username + dominio NetBIOS.
    // NTLM usa il dominio NetBIOS (es. AC-S-SRL), non il DNS (es. ac-s-srl.it):
    // il suffisso @ va rimosso dal campo username dell'autenticazione.
    // Copia per schtasks /RU (tentativo S4U): il raw viene mosso dallo
    // split qui sotto. Formati accettati da /RU: user, DOMAIN\user, UPN.
    let schtasks_user = ctx.schtasks_user.clone();
    let host = ctx.host.clone();
    let client = ctx.client;
    let winrm_port = ctx.port;

    // --- Pre-check: stato build remoto + auto-update bidirezionale ---
    // remote_build_info sostituisce il vecchio Test-Path: oltre alla
    // presenza dell'exe legge il .ver (BUILD_TS) per il confronto di
    // versione. Il confronto usa il timestamp, non l'hash: SHA-256 dice
    // solo "diverso", non "piu' nuovo/piu' vecchio".
    //
    //   remote assente o ts_remoto < ts_locale -> deploy (upload staged)
    //   ts_remoto == ts_locale                 -> deploy idempotente
    //                                             (hash check, skip)
    //   ts_remoto > ts_locale                  -> SELF-UPDATE del client:
    //                                             scarica il sidecar linux
    //                                             e re-exec. MAI downgrade.
    //
    // winrm_dead: errore deterministico (endpoint morto / auth rifiutata).
    // In quel caso deploy e schtasks fallirebbero identicamente: si salta
    // direttamente al polling (il server potrebbe comunque essere attivo).
    let mut winrm_dead = false;
    match deploy::remote_build_info(&client, &host, &exe_path).await {
        Ok(info) => {
            eprintln!(
                "[DEBUG] bootstrap_server: ts remoto={:?} locale={} exe_present={} linux_present={}",
                info.build_ts, version::BUILD_TS, info.exe_present, info.linux_present
            );

            if !info.exe_present {
                // Exe mancante (bug 3.6): deploy completo.
                eprintln!("[bootstrap] Exe remoto mancante. Avvio auto-deploy...");
                if let Err(e) = deploy::deploy_exe(&client, &host, &exe_path, &info).await {
                    eprintln!("[ERROR] bootstrap_server: auto-deploy fallito: {}", e);
                    // Non ritorniamo errore: il server potrebbe essere già in
                    // esecuzione da un bootstrap precedente. Il polling deciderà.
                }
            } else if info.is_newer_than_local() {
                // Remote PIU' NUOVO del client: il "piu' vecchio" siamo noi.
                // Escape hatch per lo sviluppo: CROSSPILOT_NO_SELF_UPDATE=1
                // evita che un binario compilato a mano (cargo build dev)
                // venga rimpiazzato dall'artefatto musl del remote.
                let self_update_disabled = envs::var("NO_SELF_UPDATE")
                    .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false);
                if self_update_disabled {
                    eprintln!(
                        "[self-update] remote piu' nuovo (ts={} > {}) ma \
                         CROSSPILOT_NO_SELF_UPDATE attivo: proseguo senza aggiornare.",
                        info.effective_ts(),
                        version::BUILD_TS
                    );
                } else {
                    // self_update scarica il sidecar linux, verifica,
                    // sostituisce l'exe corrente e fa re-exec: su successo
                    // NON ritorna. Su errore: warning e si prosegue col
                    // binario corrente, SENZA deployare (mai downgrade).
                    let remote_dir = deploy::remote_dir_of(&exe_path);
                    let update_result = self_update::run(
                        &client,
                        &host,
                        remote_dir,
                        info.effective_ts(),
                        info.linux_sha256.as_deref(),
                    )
                    .await;
                    match update_result {
                        Ok(()) => {
                            // Iraggiungibile su Unix (exec sostituisce il
                            // processo); il log copre piattaforme senza exec.
                            eprintln!("[self-update] re-exec completato senza sostituzione processo?");
                        }
                        Err(e) => {
                            eprintln!(
                                "[WARNING] Remote piu' nuovo (ts={}) ma self-update fallito: {}",
                                info.effective_ts(),
                                e
                            );
                            eprintln!(
                                "          Proseguo col binario locale (ts={}) senza toccare il remote. \
                                 Aggiornare il client manualmente.",
                                version::BUILD_TS
                            );
                        }
                    }
                }
            } else {
                // Remote piu' vecchio o uguale: deploy idempotente. Se gli
                // hash coincidono gia', deploy_exe skippa l'upload (costo:
                // le verifiche .ver/.env, pochi ms di WinRM).
                if let Err(e) = deploy::deploy_exe(&client, &host, &exe_path, &info).await {
                    eprintln!("[ERROR] bootstrap_server: auto-deploy fallito: {}", e);
                }
            }
        }
        Err(e) => {
            winrm_dead = report_winrm_error("remote_build_info", &e, &host, winrm_port);
            // Se non riusciamo a verificare, proviamo ad avviare comunque
            // (il server potrebbe essere già in esecuzione).
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
    //
    // Catena di tentativi per privilegi massimi + esecuzione nascosta.
    // Un task configurato "run whether user is logged on or not" (SYSTEM,
    // S4U o con password) gira in sessione 0 non interattiva: nessuna
    // finestra cmd visibile. Il task interattivo (default storico) gira
    // invece nella sessione utente e mostra la console.
    //   1) /RU SYSTEM /RL HIGHEST: gira come SYSTEM (privilegi massimi,
    //      piu' di Administrator) in sessione 0 → hidden. Creare un task
    //      SYSTEM e' privilegio amministrativo: se l'utente WinRM non e'
    //      admin, schtasks fallisce con Access Denied → tentativo 2.
    //   2) /RU <utente> /NP /RL HIGHEST: logon S4U ("run whether user is
    //      logged on or not" senza password memorizzata): gira come
    //      l'utente WinRM con token elevato (se admin), sessione 0 →
    //      hidden. Limite S4U: niente credenziali di rete in uscita
    //      (bind TCP locale e file locali funzionano).
    //   3) fallback storico: task interattivo — finestra visibile e token
    //      non elevato, ma meglio un server visibile che nessun server.
    // Lo script stampa RUNAS=<mode> per permettere al client di loggare
    // la modalita' effettivamente selezionata.
    let ps_script = format!(
        "$tn='crosspilot-server'; $tr='\"{}\" --server'; $mode='FAILED'; \
         schtasks /Create /TN $tn /TR $tr /SC ONCE /ST 00:00 /RU SYSTEM /RL HIGHEST /F | Out-Null; \
         if ($LASTEXITCODE -eq 0) {{ $mode='SYSTEM' }} else {{ \
         schtasks /Create /TN $tn /TR $tr /SC ONCE /ST 00:00 /RU '{}' /NP /RL HIGHEST /F | Out-Null; \
         if ($LASTEXITCODE -eq 0) {{ $mode='USER_S4U' }} else {{ \
         schtasks /Create /TN $tn /TR $tr /SC ONCE /ST 00:00 /F | Out-Null; \
         if ($LASTEXITCODE -eq 0) {{ $mode='INTERACTIVE' }} \
         }} }}; \
         Write-Output \"RUNAS=$mode\"; \
         schtasks /Run /TN $tn | Out-Null",
        exe_path, schtasks_user
    );
    eprintln!("[DEBUG] bootstrap_server: script PowerShell = {}", ps_script);

    // --- Esecuzione comando remoto ---
    // Skip se WinRM e' deterministicamente non utilizzabile: la chiamata
    // fallirebbe identica dopo ~30s di connect timeout. Il polling resta:
    // il server potrebbe essere gia' in esecuzione da un avvio precedente.
    if winrm_dead {
        eprintln!("[bootstrap] WinRM non utilizzabile: skip avvio schtasks remoto.");
    } else {
        // Regola firewall inbound per la porta del server: senza di essa
        // un server vivo e' indistinguibile da uno spento visto dal client
        // (SYN droppato). Idempotente: creata solo se manca.
        ensure_firewall_rule(&client, &host).await;
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

            // Individua la modalita' di avvio scelta dalla catena di
            // fallback nello script (RUNAS=SYSTEM|USER_S4U|INTERACTIVE|FAILED).
            let mut runas_mode = "";
            for line in stdout_str.lines() {
                let trimmed = line.trim();
                if let Some(mode) = trimmed.strip_prefix("RUNAS=") {
                    runas_mode = mode;
                }
            }
            match runas_mode {
                "SYSTEM" => {
                    println!("Remote server scheduled as SYSTEM (elevated, hidden).");
                }
                "USER_S4U" => {
                    println!("Remote server scheduled as {} (elevated if admin, hidden).", schtasks_user);
                }
                "INTERACTIVE" => {
                    eprintln!("[WARNING] Server avviato in sessione interattiva: finestra cmd visibile e privilegi non elevati.");
                    eprintln!("          Per privilegi admin + esecuzione nascosta servono diritti admin sull'account WinRM.");
                }
                "FAILED" => {
                    eprintln!("[ERROR] bootstrap_server: creazione task fallita in tutte le modalita'.");
                }
                _ => {}
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
    let up = poll_server_startup().await;
    if !up && !winrm_dead {
        // Il server non risponde: prima di dichiarare fallimento chiediamo
        // AL REMOTO (via WinRM, canale indipendente) cosa sta succedendo.
        // Distingue i tre casi: processo morto / porta non bindata /
        // firewall che droppa l'inbound (il caso H102: server VIVO e in
        // ascolto, ma SYN droppato => "connect timeout" indistinguibile
        // dal "server spento" visto da fuori).
        remote_startup_diag(&client, &host).await;
    }

    Ok(())
}

/// Porta TCP del server remoto vista dal client (CLIENT_PORT nel .env,
/// coerente con poll_server_startup e con la regola firewall creata).
fn server_tcp_port() -> u16 {
    envs::var("CLIENT_PORT")
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(5330)
}

/// Crea (una sola volta) la regola firewall inbound per la porta TCP del
/// server. Senza di essa il server puo' essere VIVO e in ascolto ma
/// irraggiungibile dai client: il SYN viene droppato dal Windows Firewall
/// e l'esterno vede solo "connect timeout" — identico a un server spento
/// (caso reale H102). Nome regola `crosspilot-server-<porta>`: distinta
/// per porta, idempotente via check Get-NetFirewallRule.
async fn ensure_firewall_rule(client: &winrm_rs::WinrmClient, host: &str) {
    let port = server_tcp_port();
    let script = format!(
        "$p={p}; $n='crosspilot-server-' + $p; \
         if (Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue) {{ \
         Write-Output 'FIREWALL=PRESENT' \
         }} else {{ \
         netsh advfirewall firewall add rule name=$n dir=in action=allow protocol=TCP localport=$p | Out-Null; \
         if ($LASTEXITCODE -eq 0) {{ Write-Output 'FIREWALL=ADDED' }} else {{ Write-Output 'FIREWALL=FAILED' }} \
         }}",
        p = port
    );
    match client.run_powershell(host, &script).await {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
            match stdout.as_str() {
                "FIREWALL=ADDED" => println!("[bootstrap] regola firewall inbound creata (TCP/{}, nome crosspilot-server-{}).", port, port),
                "FIREWALL=PRESENT" => println!("[bootstrap] regola firewall inbound gia' presente (TCP/{}, nome crosspilot-server-{}).", port, port),
                "FIREWALL=FAILED" => eprintln!(
                    "[WARNING] bootstrap: creazione regola firewall TCP/{} fallita (serve admin): \
                     se il server non risponde ma il processo vive, questo e' il motivo.",
                    port
                ),
                other => eprintln!("[WARNING] bootstrap: esito firewall inatteso: {:?}", other),
            }
        }
        Err(e) => eprintln!("[WARNING] bootstrap: check regola firewall fallito: {}", e),
    }
}

/// Diagnostica post-bootstrap-fallito, eseguita via WinRM sul remote.
/// Riporta: processo crosspilot attivo (PID), porta in ascolto LOCALE,
/// regola firewall. Con questi tre dati il fallimento e' classificabile:
///   PROC vuoto          -> il task non ha avviato il processo (crash?)
///   PROC pieno, LISTEN vuoto -> processo vivo ma bind fallito
///   PROC+LISTEN pieni   -> server OK: e' il FIREWALL/inbound a bloccare
async fn remote_startup_diag(client: &winrm_rs::WinrmClient, host: &str) {
    let port = server_tcp_port();
    eprintln!(
        "[bootstrap] server non in ascolto dopo 30s: diagnostica remota via WinRM..."
    );
    let script = format!(
        "$p={p}; \
         $proc = (Get-Process -Name crosspilot -ErrorAction SilentlyContinue | Select-Object -First 1).Id; \
         if (-not $proc) {{ Write-Output 'PROC=' }} else {{ Write-Output \"PROC=$proc\" }}; \
         $l = Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1; \
         if ($l) {{ Write-Output \"LISTEN=$($l.OwningProcess)\" }} else {{ Write-Output 'LISTEN=' }}; \
         $fw = Get-NetFirewallRule -DisplayName (\"crosspilot-server-\" + $p) -ErrorAction SilentlyContinue; \
         if ($fw) {{ Write-Output 'FW=1' }} else {{ Write-Output 'FW=0' }}",
        p = port
    );
    match client.run_powershell(host, &script).await {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
            eprintln!("[bootstrap] diagnostica remota:\n{}", stdout);
            let has_pid = stdout
                .lines()
                .find(|l| l.starts_with("PROC="))
                .map(|l| !l.trim_start_matches("PROC=").trim().is_empty())
                .unwrap_or(false);
            let listen_pid = stdout
                .lines()
                .find(|l| l.starts_with("LISTEN="))
                .map(|l| l.trim_start_matches("LISTEN=").len() > 0)
                .unwrap_or(false);
            let fw = stdout.lines().any(|l| l.trim() == "FW=1");
            if has_pid && listen_pid {
                if fw {
                    eprintln!(
                        "[bootstrap] processo ATTIVO e porta {} in ascolto LOCALE con regola firewall: \
                         il SYN in ingresso e' bloccato altrove (rete/VPN/profilo firewall) — verificare la rete.",
                        port
                    );
                } else {
                    eprintln!(
                        "[bootstrap] processo ATTIVO e porta {} in ascolto LOCALE ma SENZA regola firewall: \
                         e' il Windows Firewall a droppare l'inbound (ritentare: la regola viene creata al prossimo bootstrap).",
                        port
                    );
                }
            } else if has_pid && !listen_pid {
                eprintln!(
                    "[bootstrap] processo ATTIVO ma porta {} NON in ascolto: bind fallito \
                     (porta occupata? configurazione .env?).",
                    port
                );
            } else {
                eprintln!(
                    "[bootstrap] NESSUN processo crosspilot attivo: il task schedulato non ha avviato \
                     il server (crash all'avvio? controllare LOG_PATH/ERR_PATH sul remote)."
                );
            }
        }
        Err(e) => eprintln!("[bootstrap] diagnostica remota non disponibile: {}", e),
    }
}

/// Polling dell'endpoint TCP del server: tenta la connessione ogni 2s
/// per un massimo di 30s. Non ritorna errore — il chiamante gestisce i retry.
async fn poll_server_startup() -> bool {
    println!("Waiting for server to start...");
    let host = envs::var("HOST")
        .unwrap_or_else(|| "127.0.0.1".to_string());
    let client_port = envs::var("CLIENT_PORT")
        .unwrap_or_else(|| "47330".to_string());
    let addr = format!("{}:{}", host, client_port);

    for i in 1..=15 {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            TcpStream::connect(addr.as_str())
        ).await;
        if let Ok(Ok(_)) = result {
            println!("Server is up (after {}s).", i * 2);
            return true;
        }
        println!("Server not ready yet, retrying ({}s elapsed)...", i * 2);
    }
    eprintln!("Warning: server did not come up within 30s after bootstrap.");
    false
}
