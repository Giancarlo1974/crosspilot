// Modulo update: auto-update bidirezionale via TCP, senza WinRM.
// Separato da bootstrap.rs/deploy.rs (WinRM) per rispettare la
// best-practice < 1000 righe.
//
// ARCHITETTURA ("il piu' vecchio si aggiorna da solo", over TCP):
// l'handshake del server e' "READY <BUILD_TS>\n" (i server legacy mandano
// "READY\n" secco -> ts=None -> trattati come i piu' vecchi di tutti).
//
//   remote_ts == locale  -> niente da fare
//   remote_ts >  locale  -> SELF-UPDATE del client: GET del sidecar
//                           crosspilot.linux via TCP (stesso protocollo file
//                           transfer), poi install_staged_file (hash +
//                           --version check + rename + re-exec). Mai downgrade.
//   remote_ts <  locale
//     o None (legacy)    -> UPDATE del server: PUT dell'exe embeddato come
//                           crosspilot-<ts>.exe + PUT del sidecar, poi
//                           trigger:
//                             * server nuovo: MSG_UPDATE_REQ -> il server
//                               spawnza lo staged DETACHED (fuori dal job
//                               object) con `update --target <exe>
//                               --wait-pid <pid> --port <porta>` ed esce.
//                             * server legacy: comando shell WMI
//                               (Win32_Process.Create nasce dal servizio
//                               WMI, fuori dal job) oppure `setsid` su
//                               Linux, poi `quit`.
//                           L'updater attende la morte del server, fa lo
//                           swap rename-first (exe -> exe.old, staged -> exe),
//                           rilancia `exe --server` detached ed esce.
//
// ROBUSTEZZA (post-mortem H166: brick silenzioso del remote — vecchio
// server ucciso, updater mai salito, nessuna traccia diagnostica):
// - functional check pre-trigger: `<staged> --version` via shell-mode;
//   uno staged non eseguibile abortisce l'update PRIMA di uccidere il
//   server (il path WinRM lo faceva gia', qui mancava).
// - marker anti retry-storm: il rollback scrive `crosspilot-<ts>.bad`;
//   il client lo rileva prima del PUT e non ritenta lo stesso build.
// - log su file: l'updater e' detached (stdio nullo) -> ogni passo e'
//   appendato a `crosspilot-update.log` accanto al target.
// - rollback automatico: se il nuovo server non binda la porta entro
//   SERVER_UP_WAIT_SECS, `.old` viene ripristinato e rilanciato.
// - --target esplicito negli spawn WMI/setsid: default_target assume il
//   nome `crosspilot[.exe]`, un EXE_PATH con nome diverso swappava il
//   file sbagliato.
// - PUT con retry: "early eof" intermittenti su upload grossi.
//
// NOTE CHIAVE (motivazioni, non ripetere bug):
// - I figli shell-mode su Windows sono in un Job Object KILL_ON_JOB_CLOSE:
//   un updater spawnato cosi' morirebbe insieme al server. Per questo lo
//   staged va spawnato detached dal server stesso (MSG_UPDATE_REQ) o via
//   WMI/setsid (legacy). CREATE_BREAKAWAY_FROM_JOB non basta: il nostro
//   job non ha JOB_OBJECT_LIMIT_BREAKAWAY_OK -> ERROR_ACCESS_DENIED.
// - Swap rename-first: su Windows un exe running non si sovrascrive ne'
//   cancella, ma si rinomina. .old resta come rollback.
// - WinRM resta SOLO per: cold bootstrap (nessun server in ascolto) e
//   transizione dei client legacy (che leggendo "READY " falliscono
//   l'handshake e ripiegano sul self-update WinRM esistente).

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::{bootstrap, deploy, envs, path, proto, transfer, verify, version};
// self_update e' usato solo nel path unix (install_staged_file);
// su Windows il self-update passa dall'updater (cfg-specific).
#[cfg(not(target_os = "windows"))]
use crate::self_update;

/// Esito del confronto di versione nell'handshake.
#[derive(Debug, PartialEq, Eq)]
pub enum Reconcile {
    /// La connessione e' utilizzabile (versioni allineate, update non
    /// necessario, o update fallito ma si prosegue: mai bloccare il lavoro).
    Proceed,
    /// E' stato triggerato un update del server: chiudere il socket e
    /// riconnettersi (il server sta riavviando col binario nuovo).
    Reconnect,
    /// Riconnessione dopo il fallback WinRM: il vecchio server e' gia'
    /// stato fermato (`quit`) e quello nuovo e' gia' in ascolto (verificato
    /// dal polling di bootstrap_server) — l'attesa della caduta della
    /// porta (wait_remote_restart_begin) e' inutile qui, si riconnette
    /// subito.
    ReconnectNoWait,
}

/// Dedup: un update per processo. Evita retry-storm quando l'update e'
/// fallito ma il server e' comunque raggiungibile (sync apre N connessioni).
static UPDATE_TRIED: AtomicBool = AtomicBool::new(false);

/// Dopo il trigger di update (Reconnect): attende che la porta TCP del
/// vecchio server CADA prima di lasciar riconnettere il client.
///
/// PERCHE': il server esce ~100ms dopo l'ack di UPDATE_REQ (grace per
/// l'ACK); una riconnessione immediata dentro quella finestra parla col
/// VECCHIO binario — il comando girerebbe sulla versione pre-swap e
/// l'handshake riporterebbe il ts vecchio (race osservata nell'e2e
/// localhost). Aspettando la caduta della porta si e' certi che lo swap
/// e' in corso (o gia' avvenuto: il retry loop con deadline gestisce il
/// ritorno in ascolto del binario nuovo).
///
/// Best-effort: se la porta non cade entro 10s (updater lentissimo, o
/// swap+relaunch cosi' veloce da non essere mai visto giu') si prosegue
/// comunque — il comportamento degrada a quello pre-fix, mai peggio.
pub async fn wait_remote_restart_begin(addr: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut polls = 0u32;
    while Instant::now() < deadline {
        match TcpStream::connect(addr).await {
            // Porta ancora aperta: il vecchio server non e' ancora uscito.
            Ok(_) => {}
            Err(_) => {
                eprintln!(
                    "[update] vecchio server uscito (porta caduta dopo {} poll).",
                    polls
                );
                return;
            }
        }
        polls += 1;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    eprintln!(
        "[update] WARNING: porta {} mai caduta entro 10s (swap molto veloce o updater lento): proseguo coi retry.",
        addr
    );
}

// ---------------------------------------------------------------------------
// LATO CLIENT: confronto versione e orchestrazione.
// ---------------------------------------------------------------------------

/// Chiamata dopo l'handshake: decide se procedere, aggiornare il server o
/// il client. Infallibile: ogni fallimento degenera in Proceed con warning
/// (un server disallineato e' comunque utilizzabile, stesso protocollo).
pub async fn reconcile(remote_ts: Option<u64>) -> Reconcile {
    let local = version::BUILD_TS;

    // Kill switch globale (dev/diagnostica).
    let disabled = envs::var("NO_UPDATE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if disabled {
        eprintln!("[update] CROSSPILOT_NO_UPDATE attivo: check versione disabilitato.");
        return Reconcile::Proceed;
    }

    match remote_ts {
        Some(t) if t == local => Reconcile::Proceed,

        Some(t) if t > local => {
            // Remote piu' nuovo: il "piu' vecchio" e' il client.
            let no_self = envs::var("NO_SELF_UPDATE")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            if no_self {
                eprintln!(
                    "[update] remote piu' nuovo (ts={} > {}) ma CROSSPILOT_NO_SELF_UPDATE attivo.",
                    t, local
                );
                return Reconcile::Proceed;
            }
            if UPDATE_TRIED.swap(true, Ordering::Relaxed) {
                eprintln!("[update] self-update gia' tentato: proseguo col binario locale.");
                return Reconcile::Proceed;
            }
            eprintln!("[update] remote piu' nuovo (ts={} > {}): self-update via TCP...", t, local);
            match self_update_tcp(t).await {
                // Su unix non ritorna (exec); su errore: warning e si prosegue.
                Ok(()) => Reconcile::Proceed,
                Err(e) => {
                    eprintln!(
                        "[update] WARNING self-update fallito: {} — proseguo col binario locale (ts={})",
                        e, local
                    );
                    Reconcile::Proceed
                }
            }
        }

        _ => {
            // remote_ts None (server legacy, "READY\n") o piu' vecchio.
            if UPDATE_TRIED.swap(true, Ordering::Relaxed) {
                eprintln!("[update] update remoto gia' tentato: proseguo.");
                return Reconcile::Proceed;
            }
            eprintln!(
                "[update] remote {:?} piu' vecchio del locale (ts={}): update via TCP...",
                remote_ts, local
            );
            match update_remote(remote_ts).await {
                Ok(()) => Reconcile::Reconnect,
                Err(e) => {
                    eprintln!(
                        "[update] WARNING update remoto via TCP fallito: {:#}",
                        e
                    );
                    // --- FALLBACK WINRM ---
                    // Il transfer TCP puo' essere rotto SUL REMOTE (caso
                    // reale H101: server di una build intermedia con
                    // VERSION=2 del protocollo che rifiuta i messaggi framed
                    // dei client v1 chiudendo il socket -> "early eof" su
                    // OGNI put, anche da 1KB). Shell-mode (testo raw) e
                    // handshake continuano pero' a funzionare, quindi il
                    // server e' vivo ma non aggiornabile via TCP.
                    //
                    // Il canale WinRM e' indipendente dal framing TCP:
                    // deploy + riavvio via schtasks. Sequenza SICURA:
                    //   1. preflight WinRM (winrm_probe): se WinRM non
                    //      risponde NON si tocca il server corrente
                    //      (fermarlo senza via di ripristino = brick);
                    //   2. `quit` in shell-mode (raw: funziona anche con
                    //      framing rotto) -> il vecchio server esce pulito,
                    //      niente race col comando client;
                    //   3. bootstrap_server(): deploy staged via WinRM
                    //      (con functional check `--version` + swap .old)
                    //      + schtasks /Run + attesa;
                    //   4. Reconnect: riconnesione e verifica del ts nuovo.
                    if let Some(_info) = bootstrap::winrm_probe().await {
                        eprintln!(
                            "[update] fallback WinRM: fermo il vecchio server via shell-mode (`quit`)..."
                        );
                        let _ = send_shell_and_drain("quit").await;
                        eprintln!("[update] fallback WinRM: vecchio server fermato, deploy + riavvio via WinRM...");
                        match bootstrap::bootstrap_server().await {
                            Ok(()) => {
                                eprintln!(
                                    "[update] fallback WinRM completato: riconnessione al server aggiornato..."
                                );
                                // Il vecchio server e' gia' uscito (quit) e
                                // bootstrap_server ha atteso il nuovo in
                                // ascolto: niente attesa caduta porta.
                                return Reconcile::ReconnectNoWait;
                            }
                            Err(e2) => {
                                eprintln!(
                                    "[update] WARNING fallback WinRM fallito: {:#} — proseguo col server corrente",
                                    e2
                                );
                            }
                        }
                    } else {
                        eprintln!(
                            "[update] WinRM non raggiungibile: nessun fallback disponibile, \
                             proseguo col server corrente (TCP non aggiornabile da questo client)."
                        );
                    }
                    Reconcile::Proceed
                }
            }
        }
    }
}

/// Update del server remoto (client piu' nuovo):
/// PUT exe staged + PUT sidecar + trigger (MSG_UPDATE_REQ su server nuovo,
/// WMI/setsid + quit su server legacy).
async fn update_remote(remote_ts: Option<u64>) -> Result<()> {
    let exe_path =
        envs::var("EXE_PATH").context("CROSSPILOT_EXE_PATH necessario per l'update remoto")?;

    let remote_windows = is_windows_path(&exe_path);
    // PE da caricare: l'embed su build non-Windows; su client Windows il
    // binario stesso (e' gia' un PE — l'embed avrebbe chicken-and-egg).
    let win_exe = deploy::windows_exe_bytes().unwrap_or_default();
    // Binario linux: embed musl preferito; su unix senza embed il self
    // (un client linux/musl e' gia' un binario linux).
    let linux_bin = deploy::linux_bin_bytes().unwrap_or_default();
    // Il payload staged deve matchare l'OS del REMOTE (non quello del
    // client): PE su Windows, binario linux su Linux — altrimenti lo
    // spawn dell'updater fallisce (ENOEXEC).
    let (staged_payload, staged_name): (Vec<u8>, String) = if remote_windows {
        (win_exe.clone(), format!("crosspilot-{}.exe", version::BUILD_TS))
    } else {
        (linux_bin.clone(), format!("crosspilot-{}", version::BUILD_TS))
    };
    if staged_payload.is_empty() {
        bail!(
            "artefatto {} non disponibile (embed vuoto: build senza build-release.sh)",
            if remote_windows { "windows" } else { "linux" }
        );
    }
    let dir = remote_parent(&exe_path).to_string();
    let staged_remote = remote_join(&dir, &staged_name);
    eprintln!(
        "[update] dir remota: {} -> staged: {}",
        dir, staged_remote
    );

    // --- Step 0: marker anti retry-storm ---
    // Il rollback dell'updater lascia `crosspilot-<ts>.bad` nella dir del
    // remote quando un build supera lo swap ma non il rilancio (server
    // mai in ascolto). Senza questo check ogni run del client farebbe:
    // brick -> rollback -> riconnessione -> nuovo tentativo -> brick.
    // Presente => abortisco: serve intervento manuale o un build diverso.
    let bad_marker = remote_join(&dir, &format!("crosspilot-{}.bad", version::BUILD_TS));
    if remote_file_exists(&bad_marker).await {
        bail!(
            "build {} gia' fallito su questo remote (marker {} presente): \
             rollback automatico gia' avvenuto — rimuovere il marker sul remote \
             o distribuire un build con ts diverso",
            version::BUILD_TS,
            bad_marker
        );
    }

    // --- Step 1: PUT exe staged ---
    // put_client richiede un file su disco: l'exe embeddato va prima
    // materializzato in tempdir (nome con pid per evitare collisioni).
    let tmp_exe = std::env::temp_dir().join(format!(
        "crosspilot-{}-{}.exe",
        version::BUILD_TS,
        std::process::id()
    ));
    std::fs::write(&tmp_exe, staged_payload)
        .with_context(|| format!("scrittura {}", tmp_exe.display()))?;
    let tmp_exe_s = tmp_exe.to_string_lossy().to_string();
    let put_res = put_with_retry(&tmp_exe_s, &staged_remote, "exe staged").await;
    let _ = std::fs::remove_file(&tmp_exe);
    put_res.context("upload exe staged")?;
    eprintln!("[update] exe staged uploadato: {}", staged_remote);

    // --- Step 1.5: functional check dello staged PRIMA del trigger ---
    // Il path WinRM prova `'<exe>.new' --version` prima dello swap; qui
    // mancava e uno staged non eseguibile (OS troppo vecchio, AV, upload
    // troncato) brickava il remote: l'updater non partiva e il vecchio
    // server era gia' stato ucciso. Fallire qui abortisce l'update con
    // il server ancora vivo e utilizzabile.
    check_staged_runnable(&staged_remote, remote_windows).await?;

    // --- Step 2: PUT degli artefatti scaricabili (cross-serve) ---
    // Il remote aggiornato serve self-update a client di QUALUNQUE OS:
    // - crosspilot.linux SEMPRE (artefatto per i client linux; su remote
    //   linux e' lo stesso payload dello staged appena swappato);
    // - crosspilot.exe solo su remote unix: su remote Windows e' l'exe
    //   in esecuzione (file locked, lo aggiorna lo swap dell'updater).
    let artifacts: Vec<(&[u8], &str)> = if remote_windows {
        vec![(linux_bin.as_slice(), version::LINUX_SIDECAR_NAME)]
    } else {
        vec![
            (linux_bin.as_slice(), version::LINUX_SIDECAR_NAME),
            (win_exe.as_slice(), "crosspilot.exe"),
        ]
    };
    for (payload, name) in artifacts {
        if payload.is_empty() {
            eprintln!(
                "[update] WARNING: artefatto {} non embeddato (build senza build-release.sh)",
                name
            );
            continue;
        }
        let artifact_remote = remote_join(&dir, name);
        let tmp_art = std::env::temp_dir().join(format!(
            "crosspilot-art-{}-{}",
            version::BUILD_TS,
            std::process::id()
        ));
        std::fs::write(&tmp_art, payload)
            .with_context(|| format!("scrittura {}", tmp_art.display()))?;
        let tmp_art_s = tmp_art.to_string_lossy().to_string();
        let put_res = put_with_retry(&tmp_art_s, &artifact_remote, name).await;
        let _ = std::fs::remove_file(&tmp_art);
        match put_res {
            Ok(()) => eprintln!("[update] artefatto {} uploadato: {}", name, artifact_remote),
            // Non fatale: il remote puo' aggiornare l'exe anche senza
            // l'artefatto cross-OS (servira' solo per self-update futuri).
            Err(e) => eprintln!("[update] WARNING upload {}: {}", name, e),
        }
    }

    // --- Step 2.5: .env minimale per il server rilanciato ---
    // Come nel path WinRM (deploy_exe): il server legge solo
    // CROSSPILOT_SERVER_PORT dalla .env della dir dell'exe. La porta e'
    // quella a cui il client si connette (CLIENT_PORT), non la default.
    // Senza questo file il server aggiornato binderebbe la default 5330
    // o leggerebbe una .env stale (es. WINBOAT_SERVER_PORT ignorata).
    let port = envs::var("CLIENT_PORT")
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(5330);
    let env_content = format!("CROSSPILOT_SERVER_PORT={}\n", port);
    let tmp_env = std::env::temp_dir().join(format!("crosspilot-env-{}", std::process::id()));
    std::fs::write(&tmp_env, &env_content)
        .with_context(|| format!("scrittura {}", tmp_env.display()))?;
    let tmp_env_s = tmp_env.to_string_lossy().to_string();
    let env_remote = remote_join(&dir, ".env");
    let put_res = put_with_retry(&tmp_env_s, &env_remote, ".env").await;
    let _ = std::fs::remove_file(&tmp_env);
    match put_res {
        Ok(()) => eprintln!("[update] .env remoto scritto (porta {})", port),
        Err(e) => eprintln!("[update] WARNING upload .env: {}", e),
    }

    // --- Step 3: trigger dello swap ---
    match remote_ts {
        Some(_) => {
            // Server nuovo (ha mandato "READY <ts>"): capisce MSG_UPDATE_REQ.
            // Va su connessione FRESCA, non su quella dell'handshake: il peek
            // del server ha timeout 2s e dopo i PUT (anche minuti) il socket
            // dell'handshake e' gia' caduto in shell-mode — il frame verrebbe
            // eseguito come comando shell ("early eof" sul client).
            let mut s = open_conn().await?;
            let req = proto::UpdateReq {
                staged_path: staged_remote.clone(),
            };
            proto::send_update_req(&mut s, &req).await?;
            let (msg_type, payload) = proto::read_msg(&mut s).await?;
            if msg_type == proto::MSG_ERR {
                let err = proto::decode_err(&payload)?;
                bail!("UPDATE_REQ rifiutato: ERR {} {}", err.code, err.message);
            }
            if msg_type != proto::MSG_UPDATE_RES {
                bail!("risposta inattesa a UPDATE_REQ (tipo {})", msg_type);
            }
            let res = proto::decode_update_res(&payload)?;
            if res.status != 0 {
                bail!("spawn updater fallito sul remote: {}", res.message);
            }
            eprintln!("[update] updater avviato sul remote: {}", res.message);
        }
        None => {
            // Server legacy ("READY\n"): niente UPDATE_REQ. Si spawnano
            // l'updater via shell (fuori dal job: WMI su Windows, setsid su
            // Linux) e poi si manda `quit` per far uscire il vecchio server.
            // L'updater attende la porta libera, poi swappa e rilancia.
            // --target esplicito: default_target() assumerebbe il nome
            // `crosspilot[.exe]` nella dir dello staged; se EXE_PATH ha
            // un nome diverso (es. deploy rinominato) lo swap colpirebbe
            // il file sbagliato. Meglio dire all'updater qual e' l'exe
            // reale da sostituire.
            let spawn_cmd = if remote_windows {
                wmi_spawn_cmd(&staged_remote, port, &exe_path)
            } else {
                format!(
                    "setsid \"{}\" update --target \"{}\" --port {} >/dev/null 2>&1 &",
                    staged_remote, exe_path, port
                )
            };
            let out = send_shell_and_drain(&spawn_cmd).await?;
            eprintln!("[update] spawn legacy output: {}", out.trim());
            // L'updater e' partito (spawn completato: EOF ricevuto).
            // Ora `quit` fa uscire il vecchio server -> l'updater procede.
            let _ = send_shell_and_drain("quit").await;
            eprintln!("[update] vecchio server terminato; updater in corso sul remote.");
        }
    }
    Ok(())
}

/// Self-update del client (remote piu' nuovo): GET .ver + GET del binario
/// per l'OS del CLIENT via TCP (crosspilot.linux su unix, crosspilot.exe
/// su Windows), poi installazione:
/// - unix: install_staged_file (rename atomico + re-exec)
/// - windows: staged + updater detached (un exe running non si sovrascrive:
///   l'updater fa lo swap dopo la nostra uscita e rilancia gli stessi argv)
async fn self_update_tcp(remote_ts: u64) -> Result<()> {
    let exe_path =
        envs::var("EXE_PATH").context("CROSSPILOT_EXE_PATH necessario per il self-update")?;
    let dir = remote_parent(&exe_path).to_string();
    let info = fetch_remote_ver(&dir).await;
    #[cfg(not(target_os = "windows"))]
    {
        let expected = info.and_then(|i| i.linux_sha256);
        self_update_unix(remote_ts, &dir, expected).await
    }
    #[cfg(target_os = "windows")]
    {
        let expected = info.and_then(|i| i.exe_sha256);
        self_update_windows(remote_ts, &dir, expected).await
    }
}

/// Scarica `crosspilot.ver` dal remote (best-effort) e lo parsa.
async fn fetch_remote_ver(dir: &str) -> Option<version::RemoteBuildInfo> {
    let ver_remote = remote_join(dir, version::VER_FILE_NAME);
    let ver_local = std::env::temp_dir().join(format!("crosspilot-{}.ver", std::process::id()));
    let ver_local_s = ver_local.to_string_lossy().to_string();
    let mut info = None;
    if let Ok(mut s) = open_conn().await {
        if transfer::get_client(&mut s, &ver_remote, &ver_local_s)
            .await
            .is_ok()
        {
            if let Ok(content) = std::fs::read_to_string(&ver_local) {
                let parsed = version::parse_remote_info(&content);
                eprintln!(
                    "[update] .ver remoto: ts={:?} exe_sha256={} linux_sha256={}",
                    parsed.build_ts,
                    parsed
                        .exe_sha256
                        .as_deref()
                        .map(|h| &h[..16.min(h.len())])
                        .unwrap_or("(assente)"),
                    parsed
                        .linux_sha256
                        .as_deref()
                        .map(|h| &h[..16.min(h.len())])
                        .unwrap_or("(assente)"),
                );
                info = Some(parsed);
            }
        } else {
            eprintln!("[update] WARNING: .ver remoto non leggibile; verifica solo funzionale.");
        }
        let _ = std::fs::remove_file(&ver_local);
    }
    info
}

/// Self-update su client Unix: GET sidecar -> install_staged_file
/// (hash + --version check + rename atomico + re-exec).
#[cfg(not(target_os = "windows"))]
async fn self_update_unix(
    remote_ts: u64,
    dir: &str,
    expected_sha: Option<String>,
) -> Result<()> {
    let self_path = std::env::current_exe().context("current_exe")?;
    let staged = self_update::staged_path(&self_path);
    let staged_s = staged.to_string_lossy().to_string();
    let sidecar_remote = remote_join(dir, version::LINUX_SIDECAR_NAME);
    eprintln!("[update] download '{}' -> {}", sidecar_remote, staged_s);
    let mut s = open_conn().await?;
    if let Err(e) = transfer::get_client(&mut s, &sidecar_remote, &staged_s).await {
        let _ = std::fs::remove_file(&staged);
        return Err(e).context("download sidecar via TCP");
    }

    // Installa (verifica, chmod, --version check, swap, re-exec).
    let result = self_update::install_staged_file(&staged, remote_ts, expected_sha.as_deref()).await;
    if result.is_err() {
        let _ = std::fs::remove_file(&staged);
    }
    result
}

/// Self-update su client Windows: l'exe running non si puo' sovrascrivere
/// -> si scarica il PE remoto come staged `crosspilot-<ts>.exe` nella dir
/// del client, si spawnza DETACHED come updater (--wait-pid = noi) e si
/// esce: l'updater swappa e rilancia lo stesso argv (--arg, con console).
#[cfg(target_os = "windows")]
async fn self_update_windows(
    remote_ts: u64,
    dir: &str,
    expected_sha: Option<String>,
) -> Result<()> {
    let self_exe = std::env::current_exe().context("current_exe")?;
    let self_dir = self_exe
        .parent()
        .map(|p| p.to_path_buf())
        .context("exe senza parent dir")?;
    let staged = self_dir.join(format!("crosspilot-{}.exe", remote_ts));
    let staged_s = staged.to_string_lossy().to_string();

    // GET del PE remoto (su remote Windows e' l'exe in esecuzione —
    // lettura consentita; su remote Linux e' l'artefatto materializzato).
    let remote_exe = remote_join(dir, "crosspilot.exe");
    eprintln!("[update] download '{}' -> {}", remote_exe, staged_s);
    let mut s = open_conn().await?;
    if let Err(e) = transfer::get_client(&mut s, &remote_exe, &staged_s).await {
        let _ = std::fs::remove_file(&staged);
        return Err(e).context("download crosspilot.exe via TCP");
    }

    let install = async {
        // Hash check vs .ver (EXE_SHA256).
        if let Some(expected) = &expected_sha {
            let actual = sha256_file_hex(&staged)?;
            if !actual.eq_ignore_ascii_case(expected) {
                bail!(
                    "SHA-256 MISMATCH staged: atteso {} scaricato {}",
                    &expected[..16.min(expected.len())],
                    &actual[..16]
                );
            }
            eprintln!("[update] SHA-256 match con .ver remoto.");
        }
        // Functional check: lo staged deve eseguire --version col ts atteso.
        let out = std::process::Command::new(&staged)
            .arg("--version")
            .output()
            .context("esecuzione staged --version")?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        let staged_ts = version::parse_version_ts(&stdout);
        if !out.status.success() || staged_ts != Some(remote_ts) {
            bail!(
                "staged --version inatteso (ts={:?}, atteso {})",
                staged_ts,
                remote_ts
            );
        }
        eprintln!("[update] staged verificato (ts={})", remote_ts);

        // Spawn updater detached + uscita: l'updater swappa e rilancia
        // lo stesso argv (--arg ripetuto) con console visibile.
        let mut args = vec![
            "update".to_string(),
            "--target".to_string(),
            self_exe.to_string_lossy().to_string(),
            "--wait-pid".to_string(),
            std::process::id().to_string(),
            "--console".to_string(),
        ];
        for a in std::env::args().skip(1) {
            args.push("--arg".to_string());
            args.push(a);
        }
        spawn_detached(&staged, &args, false)?;
        eprintln!("[update] updater spawnato; il client esce per lo swap.");
        Ok(())
    }
    .await;
    if let Err(e) = install {
        let _ = std::fs::remove_file(&staged);
        return Err(e);
    }
    std::process::exit(0);
}

/// Connessione TCP + handshake, SENZA logica di update (uso interno:
/// le connessioni di PUT/GET/shell dell'orchestrazione non devono
/// ri-triggerare il reconcile).
async fn open_conn() -> Result<TcpStream> {
    let host = envs::var("HOST").unwrap_or_else(|| "127.0.0.1".to_string());
    let client_port = envs::var("CLIENT_PORT").unwrap_or_else(|| "47330".to_string());
    let addr = format!("{}:{}", host, client_port);
    let (s, _ts) = crate::connect_raw(&addr).await?;
    Ok(s)
}

/// Invia un comando in shell-mode su una nuova connessione e drena l'output
/// fino a EOF (il server chiude quando il comando termina).
async fn send_shell_and_drain(cmd: &str) -> Result<String> {
    let mut s = open_conn().await?;
    s.write_all(cmd.as_bytes()).await?;
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match tokio::time::timeout_at(deadline.into(), s.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => out.extend_from_slice(&buf[..n]),
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                eprintln!("[update] WARNING: timeout lettura output comando remoto");
                break;
            }
        }
    }
    Ok(String::from_utf8_lossy(&out).to_string())
}

/// True se `remote` esiste sul server (GET di prova su file temp locale).
/// Best-effort: qualunque errore (connessione, file assente, permessi)
/// => false. Usata solo per il probe del marker anti retry-storm.
async fn remote_file_exists(remote: &str) -> bool {
    let tmp = std::env::temp_dir().join(format!("crosspilot-probe-{}", std::process::id()));
    let tmp_s = tmp.to_string_lossy().to_string();
    let res = async {
        let mut s = open_conn().await?;
        transfer::get_client(&mut s, remote, &tmp_s).await
    }
    .await;
    let _ = std::fs::remove_file(&tmp);
    let exists = res.is_ok();
    eprintln!("[update] probe remoto {} -> exists={}", remote, exists);
    exists
}

/// PUT con retry su connessione fresca: l'upload di file grossi (~6.5 MB)
/// ha mostrato "early eof" intermittenti (socket chiuso dal server a meta'
/// stream). PUT e' idempotente — il dst viene riscritto da zero — quindi
/// ritentare e' sicuro; la connessione rotta va comunque buttata e ogni
/// tentativo ne apre una nuova.
async fn put_with_retry(local: &str, remote: &str, what: &str) -> Result<()> {
    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 1..=3u32 {
        let res = async {
            let mut s = open_conn().await?;
            transfer::put_client(&mut s, local, remote).await
        }
        .await;
        match res {
            Ok(()) => {
                if attempt > 1 {
                    eprintln!("[update] PUT {} riuscito al tentativo {}", what, attempt);
                }
                return Ok(());
            }
            Err(e) => {
                eprintln!(
                    "[update] WARNING PUT {} tentativo {}/3 fallito: {}",
                    what, attempt, e
                );
                last_err = Some(e);
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
    Err(last_err
        .map(|e| {
            // Diagnostica mirata: "early eof" dopo PUT_REQ = il server ha
            // chiuso il socket senza rispondere. Il caso reale: server di
            // una build con VERSION protocollo incompatibile che rifiuta
            // i messaggi framed chiudendo la connessione (H101). Senza
            // questo hint l'errore e' criptico e sembra un problema di rete.
            if format!("{:#}", e).contains("early eof") {
                e.context(
                    "il server remoto ha chiuso il socket dopo PUT_REQ: possibile \
                     versione protocollo incompatibile (build intermedia?)",
                )
            } else {
                e
            }
        })
        .unwrap_or_else(|| anyhow::anyhow!("PUT {} fallito", what)))
}

/// Functional check dello staged sul remote: esegue `<staged> --version`
/// in shell-mode e verifica che il build_ts stampato sia quello atteso.
/// Chiamata PRIMA del trigger di swap: se fallisce, il vecchio server
/// resta vivo e il remote non viene brickato (a differenza del bug H166,
/// dove l'updater non e' mai partito e non c'era modo di saperlo).
async fn check_staged_runnable(staged: &str, remote_windows: bool) -> Result<()> {
    // Su unix il file appena uploadato ha permessi 644 (PUT non setta
    // +x): chmod prima dell'esecuzione. Su Windows il bit non esiste.
    let cmd = if remote_windows {
        format!("\"{}\" --version", staged)
    } else {
        format!("chmod 755 \"{}\" && \"{}\" --version", staged, staged)
    };
    eprintln!("[update] functional check staged: {}", cmd);
    let out = send_shell_and_drain(&cmd)
        .await
        .context("esecuzione staged --version sul remote")?;
    eprintln!("[update] staged --version output: {}", out.trim());
    // Il ts viene cercato in QUALUNQUE riga: l'output shell-mode puo'
    // contenere rumore (banner, CLIXML di powershell, echo del tty).
    let staged_ts = out
        .lines()
        .find_map(version::parse_version_ts)
        .with_context(|| format!("output --version senza ts: {}", out.trim()))?;
    if staged_ts != version::BUILD_TS {
        bail!(
            "staged --version riporta ts={} ma il locale e' {}: binario incoerente",
            staged_ts,
            version::BUILD_TS
        );
    }
    eprintln!("[update] staged verificato eseguibile sul remote (ts={})", staged_ts);
    Ok(())
}

/// Comando PowerShell (EncodedCommand, UTF-16LE base64: zero problemi di
/// quoting via cmd /C) che crea il processo updater via WMI.
/// Win32_Process.Create spawna il processo dal servizio WMI: nasce FUORI
/// dal job object del server e sopravvive alla sua terminazione.
fn wmi_spawn_cmd(staged: &str, port: u16, target: &str) -> String {
    let cmdline = format!(
        "\"{}\" update --target \"{}\" --port {}",
        staged, target, port
    );
    let ps = format!(
        "(Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{{CommandLine='{}'}}).ReturnValue",
        cmdline.replace('\'', "''")
    );
    let utf16: Vec<u8> = ps.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    format!(
        "powershell -NoProfile -EncodedCommand {}",
        deploy::base64_encode(&utf16)
    )
}

// ---------------------------------------------------------------------------
// LATO SERVER: gestione MSG_UPDATE_REQ (spawn updater + uscita).
// ---------------------------------------------------------------------------

/// Gestisce MSG_UPDATE_REQ: valida lo staged (stessa dir dell'exe corrente,
/// nome crosspilot-*, esistente), lo spawnza detached con
/// `update --target <self> --wait-pid <pid> --port <porta>`, risponde
/// UPDATE_RES e termina il processo server per consentire lo swap.
pub async fn server_apply_update(socket: &mut TcpStream, req: &proto::UpdateReq) -> Result<()> {
    let staged = PathBuf::from(&req.staged_path);
    let self_exe = std::env::current_exe().context("current_exe")?;

    // Validazione "di forma": path assoluto + stessa dir dell'exe +
    // nome staged + file esistente. (Non e' una barriera di sicurezza:
    // il protocollo TCP e' gia' RCE completo via shell-mode.)
    let same_dir = match (staged.parent(), self_exe.parent()) {
        (Some(a), Some(b)) => {
            let a = a.to_string_lossy().replace('/', "\\").to_lowercase();
            let b = b.to_string_lossy().replace('/', "\\").to_lowercase();
            a.trim_end_matches('\\') == b.trim_end_matches('\\')
        }
        _ => false,
    };
    let staged_ok = path::validate_server_path(&req.staged_path).is_ok()
        && same_dir
        && staged
            .file_name()
            .map(|n| n.to_string_lossy().starts_with("crosspilot-"))
            .unwrap_or(false)
        && staged.is_file();
    if !staged_ok {
        let res = proto::UpdateRes {
            status: 1,
            message: format!("staged path non valido: {}", req.staged_path),
        };
        let _ = proto::send_update_res(socket, &res).await;
        bail!("UPDATE_REQ rifiutato: staged non valido ({})", req.staged_path);
    }

    // Su Unix il file arrivato via PUT ha permessi 644: serve +x per eseguirlo
    // (su Windows il bit non esiste: no-op non applicabile, cfg-gated).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = staged.metadata() {
            let mut perms = meta.permissions();
            perms.set_mode(0o755);
            let _ = std::fs::set_permissions(&staged, perms);
        }
    }

    let pid = std::process::id();
    let port = socket.local_addr().map(|a| a.port()).unwrap_or(0);
    let args = vec![
        "update".to_string(),
        "--target".to_string(),
        self_exe.to_string_lossy().to_string(),
        "--wait-pid".to_string(),
        pid.to_string(),
        "--port".to_string(),
        port.to_string(),
    ];
    match spawn_detached(&staged, &args, false) {
        Ok(()) => {
            let res = proto::UpdateRes {
                status: 0,
                message: format!("updater avviato, server pid {} in uscita", pid),
            };
            let _ = proto::send_update_res(socket, &res).await;
            eprintln!("[update] updater spawnato; il server esce per consentire lo swap.");
            // Breve pausa per dare tempo all'ACK di raggiungere il client.
            tokio::time::sleep(Duration::from_millis(100)).await;
            std::process::exit(0);
        }
        Err(e) => {
            let res = proto::UpdateRes {
                status: 2,
                message: format!("spawn updater fallito: {}", e),
            };
            let _ = proto::send_update_res(socket, &res).await;
            Err(e)
        }
    }
}

// ---------------------------------------------------------------------------
// UPDATER: `crosspilot-<ts> update` — attende la morte del server, swappa,
// rilancia. Esegue detached, fuori dal job object del server.
// ---------------------------------------------------------------------------

/// Finestra di attesa per il bind del server rilanciato, prima di
/// dichiarare fallito l'update e fare rollback a `.old`. Il client
/// polla per 90s: 60s qui lasciano margine per swap+rollback+relisten
/// del vecchio server dentro la stessa finestra.
const SERVER_UP_WAIT_SECS: u64 = 60;

/// Nome del file di log dell'updater, accanto al target dello swap.
/// NON matcha i pattern di sweep_staged (`crosspilot-<digits>`): resta
/// come traccia diagnostica anche dopo il cleanup del server.
const UPDATER_LOG_NAME: &str = "crosspilot-update.log";

/// Logger append-only su file + mirror su stderr.
///
/// PERCHE': l'updater gira DETACHED con stdio nullo (spawn_detached) —
/// senza un log su disco ogni fallimento (wait, swap, relaunch, bind del
/// server rilanciato) e' invisibile: e' esattamente il brick silenzioso
/// visto su H166. Best-effort per contratto: un log mancato non deve MAI
/// interrompere l'update.
struct UpdaterLog {
    path: PathBuf,
}

impl UpdaterLog {
    fn new(dir: &Path) -> Self {
        Self {
            path: dir.join(UPDATER_LOG_NAME),
        }
    }

    /// Appende una riga `[unix_ts] msg`. Rotazione minimale: oltre
    /// 512 KiB il file riparte da zero (e' diagnostica dell'ultimo
    /// update, non uno storico — il file vivrebbe altrimenti per sempre
    /// accumulando update su update).
    fn line(&self, msg: &str) {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if let Ok(meta) = std::fs::metadata(&self.path) {
            if meta.len() > 512 * 1024 {
                let _ = std::fs::remove_file(&self.path);
            }
        }
        let row = format!("[{}] {}\n", ts, msg);
        let res = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .and_then(|mut f| std::io::Write::write_all(&mut f, row.as_bytes()));
        if let Err(e) = res {
            // Nemmeno il log file e' scrivibile: resta solo stderr
            // (visibile se l'updater e' lanciato a mano con console).
            eprintln!("[updater] WARNING log {} non scrivibile: {}", self.path.display(), e);
        }
        eprintln!("[updater] {}", msg);
    }
}

/// Entry point del sottocomando `update` (usato dallo staged binary).
/// `target`: exe da sostituire (default: `crosspilot[.exe]` nella dir dello
/// staged). `wait_pid`/`port`: condizioni di attesa morte server.
/// `relaunch_args`: argv per il rilancio post-swap (default `["--server"]`;
/// il self-update di un client Windows rilancia gli argv originali).
/// `console`: su Windows rilancia con una console nuova (output visibile —
/// usato per i comandi client; i server restano hidden).
///
/// In server-mode (relaunch_args vuoto -> `--server`) dopo il rilancio
/// l'updater VERIFICA che la porta torni in ascolto: se non succede fa
/// rollback a `.old` e rilancia il vecchio binario (meglio un server
/// vecchio che un remote morto), lasciando il marker `crosspilot-<ts>.bad`
/// che impedisce al client di ritentare lo stesso build all'infinito.
pub async fn run_updater(
    target: Option<String>,
    wait_pid: Option<u32>,
    port: Option<u16>,
    wait_secs: u64,
    relaunch_args: Vec<String>,
    console: bool,
) -> Result<()> {
    let self_exe = std::env::current_exe().context("current_exe")?;
    let target_path = match target {
        Some(t) => PathBuf::from(t),
        None => default_target(&self_exe)?,
    };
    if target_path == self_exe {
        bail!("target == exe corrente ({}): niente da fare", target_path.display());
    }
    let port = port
        .or_else(|| envs::var("SERVER_PORT").and_then(|p| p.parse().ok()))
        .unwrap_or(5330);

    let dir = target_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    // Il log file vive accanto al target: dir scrivibile perche' ci e'
    // appena stato fatto un PUT/staged.
    let log = UpdaterLog::new(&dir);
    // Modalita' server = relaunch_args vuoto (default `--server`).
    // Calcolata una volta sola: usata dal rilancio di emergenza (solo i
    // server vanno riportati in vita) e dal check porta post-relaunch
    // (un client Windows rilanciato con --arg non apre listener).
    let server_mode = relaunch_args.is_empty();
    log.line(&format!(
        "=== updater start: self={} target={} wait_pid={:?} port={} wait={}s relaunch_args={:?} console={}",
        self_exe.display(),
        target_path.display(),
        wait_pid,
        port,
        wait_secs,
        relaunch_args,
        console
    ));

    // --- Step 1: attende la morte del vecchio server ---
    wait_server_down(wait_pid, port, wait_secs, &log).await;
    // Grace: rilascio handle file post-mortem (e coda AV).
    tokio::time::sleep(Duration::from_millis(500)).await;
    log.line("vecchio server considerato morto: inizio swap rename-first");

    // --- Step 2: swap rename-first ---
    // target -> target.old (rollback point), poi self -> target.
    // Su Windows il rename di un exe running e' consentito: lo swap
    // funziona anche se il vecchio processo e' ancora in chiusura.
    let mut old_os = target_path.as_os_str().to_owned();
    old_os.push(".old");
    let old_path = PathBuf::from(old_os);
    if target_path.exists() {
        let _ = std::fs::remove_file(&old_path);
        match retry_rename(&target_path, &old_path, 60).await {
            Ok(()) => log.line(&format!("backup: {} -> {}", target_path.display(), old_path.display())),
            Err(e) => {
                // Senza backup non si puo' fare rollback: abortire e'
                // piu' sicuro che proseguire allo swap senza paracadute
                // (il vecchio server e' morto ma il suo exe e' intatto).
                log.line(&format!("FATAL rename target -> .old: {} — abort senza swap", e));
                // Il target e' ANCORA il vecchio binario funzionante (lo
                // swap non e' avvenuto): invece di lasciare il remote
                // morto, si tenta il rilancio di emergenza del vecchio
                // exe. Se riesce l'update e' fallito ma il remote resta
                // operativo (il client ritentera' al prossimo giro).
                if server_mode {
                    log.line("rilancio di emergenza del vecchio binario (intatto)...");
                    match spawn_detached(&target_path, &["--server".to_string()], false) {
                        Ok(()) => {
                            if wait_port_up(port, 30, &log).await {
                                log.line("vecchio server ripartito: update fallito ma remote operativo");
                            } else {
                                log.line("WARNING: vecchio server non in ascolto dopo il rilancio di emergenza");
                            }
                        }
                        Err(e2) => log.line(&format!("FATAL rilancio di emergenza: {}", e2)),
                    }
                }
                return Err(e.context("rename target -> .old"));
            }
        }
    } else {
        log.line("target assente: nessun backup .old necessario");
    }
    match retry_rename(&self_exe, &target_path, 60).await {
        Ok(()) => log.line(&format!("staged -> {} (rename)", target_path.display())),
        Err(e) => {
            // Fallback copy (es. rename cross-volume impossibile — non
            // dovrebbe accadere: staged e target sono nella stessa dir).
            log.line(&format!("rename fallito ({}), fallback copy...", e));
            match std::fs::copy(&self_exe, &target_path) {
                Ok(_) => log.line(&format!(
                    "staged -> {} (copy; lo staged resta su disco, lo sweep pulisce)",
                    target_path.display()
                )),
                Err(e2) => {
                    // Lo swap non e' avvenuto: se il backup .old esiste
                    // ripristiniamolo SUBITO (target potrebbe essere
                    // assente o corrotto a meta').
                    log.line(&format!("FATAL copy staged -> target: {}", e2));
                    if old_path.exists() {
                        match retry_rename(&old_path, &target_path, 30).await {
                            Ok(()) => log.line("ripristino immediato .old -> target OK"),
                            Err(e3) => log.line(&format!("FATAL anche il ripristino .old: {}", e3)),
                        }
                    }
                    return Err(anyhow::Error::from(e2).context(format!(
                        "copy {} -> {}",
                        self_exe.display(),
                        target_path.display()
                    )));
                }
            }
        }
    }

    // Su Unix il rename preserva i permessi dello staged (644 da PUT):
    // il target deve essere eseguibile prima del rilancio.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = target_path.metadata() {
            let mut perms = meta.permissions();
            perms.set_mode(0o755);
            let _ = std::fs::set_permissions(&target_path, perms);
        }
    }

    // --- Step 3: .ver + sweep staged (best-effort) ---
    match write_ver_file(&dir, &target_path) {
        Ok(()) => log.line(&format!(".ver scritto (ts={})", version::BUILD_TS)),
        Err(e) => log.line(&format!("WARNING scrittura .ver: {}", e)),
    }
    sweep_staged(&dir);

    // --- Step 4: rilancio dell'exe aggiornato ---
    // Default: --server (update del server). Il self-update di un client
    // Windows passa gli argv originali via --arg.
    let relaunch = if server_mode {
        vec!["--server".to_string()]
    } else {
        relaunch_args
    };
    match spawn_detached(&target_path, &relaunch, console) {
        Ok(()) => log.line(&format!(
            "rilanciato {} {:?}",
            target_path.display(),
            relaunch
        )),
        Err(e) => {
            // Spawn impossibile (es. exe corrotto nonostante il check):
            // tentativo di ripristino immediato. Il relaunch del rollback
            // usa gli STESSI argv del relaunch fallito (per un client
            // Windows --arg sarebbero gli argv originali, non --server!).
            log.line(&format!("FATAL spawn rilancio: {} — rollback", e));
            let verify_port = if server_mode { Some(port) } else { None };
            rollback_to_old(&dir, &target_path, &old_path, verify_port, &relaunch, console, &log).await;
            return Err(e);
        }
    }

    // --- Step 5: conferma che il server rilanciato binda la porta ---
    // Solo in server-mode: il rilancio di un client Windows (--arg con
    // gli argv originali) non apre listener, non c'e' nulla da verificare.
    if !server_mode {
        log.line("relaunch custom (--arg): skip check porta. Updater terminato OK.");
        return Ok(());
    }
    if wait_port_up(port, SERVER_UP_WAIT_SECS, &log).await {
        log.line(&format!(
            "nuovo server in ascolto su porta {}: update COMPLETATO",
            port
        ));
        return Ok(());
    }

    // --- Step 6: rollback automatico ---
    // Il nuovo exe e' partito (spawn ok) ma la porta non si e' mai aperta:
    // crash post-avvio, bind fallito, AV che lo ammazza dopo lo spawn.
    // Si ripristina .old e si rilancia: il remote torna alla versione
    // precedente invece di restare morto.
    log.line(&format!(
        "nuovo server NON in ascolto dopo {}s: ROLLBACK a {}",
        SERVER_UP_WAIT_SECS,
        old_path.display()
    ));
    rollback_to_old(&dir, &target_path, &old_path, Some(port), &["--server".to_string()], false, &log).await;
    Ok(())
}

/// Poll TCP su 127.0.0.1:port per `secs`: true appena qualcosa accetta.
/// Il connect riuscito viene subito chiuso: il server vedra' un handshake
/// abortito (peek timeout) — rumore innocuo nei suoi log.
async fn wait_port_up(port: u16, secs: u64, log: &UpdaterLog) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut attempt = 0u32;
    while Instant::now() < deadline {
        attempt += 1;
        match TcpStream::connect(format!("127.0.0.1:{}", port)).await {
            Ok(_) => {
                log.line(&format!(
                    "porta {} in ascolto (tentativo {})",
                    port, attempt
                ));
                return true;
            }
            Err(e) => {
                if attempt % 10 == 1 {
                    log.line(&format!(
                        "attesa porta {} (tentativo {}): {}",
                        port, attempt, e
                    ));
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    log.line(&format!("porta {} MAI in ascolto entro {}s", port, secs));
    false
}

/// Ripristino post-fallimento. Sequenza:
/// 1. marker `crosspilot-<ts>.bad` (anti retry-storm: il client lo
///    rileva via GET e non ritenta questo build — vedi update_remote);
/// 2. il binario fallito viene parcheggiato come `crosspilot-<ts>.failed`
///    (evidenza per la diagnosi; il nome NON matcha is_staged_name ->
///    sopravvive allo sweep);
/// 3. `.old` torna target e viene rilanciato con `relaunch` (server:
///    `--server`; client Windows self-update: argv originali);
/// 4. se `port` e' Some (server-mode): attesa bind e log dell'esito.
///
/// Tutto best-effort: se anche il rollback fallisce il remote resta
/// morto e serve intervento manuale (RDP/WinRM) — il log file spiega
/// esattamente dove si e' fermato.
async fn rollback_to_old(
    dir: &Path,
    target: &Path,
    old: &Path,
    port: Option<u16>,
    relaunch: &[String],
    console: bool,
    log: &UpdaterLog,
) {
    log.line("=== ROLLBACK in corso ===");

    // 1) Marker anti retry-storm: piccolo file testo con la ragione.
    //    `crosspilot-<digits>.bad` non matcha is_staged_name (stem non
    //    tutto digit) -> sopravvive a sweep_staged e self_describe.
    let marker = dir.join(format!("crosspilot-{}.bad", version::BUILD_TS));
    let marker_txt = format!(
        "build {} rollback su {}: il binario rilanciato con {:?} non ha aperto la porta {:?} entro {}s\n",
        version::BUILD_TS,
        target.display(),
        relaunch,
        port,
        SERVER_UP_WAIT_SECS
    );
    match std::fs::write(&marker, &marker_txt) {
        Ok(()) => log.line(&format!("marker anti-retry scritto: {}", marker.display())),
        Err(e) => log.line(&format!(
            "WARNING scrittura marker {}: {}",
            marker.display(),
            e
        )),
    }

    // 2) Parcheggio del binario fallito (non cancellare: potrebbe essere
    //    solo un bind fallito, non un exe corrotto).
    let failed = dir.join(format!("crosspilot-{}.failed", version::BUILD_TS));
    if target.exists() {
        match retry_rename(target, &failed, 10).await {
            Ok(()) => log.line(&format!(
                "exe fallito parcheggiato: {} -> {}",
                target.display(),
                failed.display()
            )),
            Err(e) => log.line(&format!("WARNING parcheggio exe fallito: {}", e)),
        }
    }

    // 3) Ripristino .old -> target.
    if !old.exists() {
        log.line("FATAL rollback: .old assente — niente da ripristinare, remote morto");
        return;
    }
    match retry_rename(old, target, 60).await {
        Ok(()) => log.line(&format!("ripristinato {} -> {}", old.display(), target.display())),
        Err(e) => {
            log.line(&format!("FATAL rollback rename .old -> target: {}", e));
            return;
        }
    }

    // 4) Rilancio del binario ripristinato. `console` e' quella del
    // relaunch originario (un client Windows vuole la console visibile).
    match spawn_detached(target, relaunch, console) {
        Ok(()) => log.line(&format!("rollback: binario ripristinato rilanciato {:?}", relaunch)),
        Err(e) => {
            log.line(&format!("FATAL rollback: spawn fallito: {}", e));
            return;
        }
    }
    // 5) Conferma bind: solo in server-mode (client: niente listener).
    let Some(port) = port else {
        log.line("rollback COMPLETATO (client-mode: nessuna porta da verificare)");
        return;
    };
    if wait_port_up(port, 30, log).await {
        log.line("rollback COMPLETATO: vecchio server di nuovo in ascolto");
    } else {
        log.line("FATAL rollback: neanche il vecchio server binda — intervento manuale");
    }
}

/// Attende che il vecchio server muoia: per PID (preciso, path nuovo) o
/// per liberazione della porta TCP (fallback legacy / senza pid).
async fn wait_server_down(wait_pid: Option<u32>, port: u16, wait_secs: u64, log: &UpdaterLog) {
    let deadline = Instant::now() + Duration::from_secs(wait_secs);
    if let Some(pid) = wait_pid {
        while Instant::now() < deadline {
            if !process_alive(pid) {
                log.line(&format!("pid {} terminato.", pid));
                return;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        log.line(&format!("WARNING: pid {} ancora vivo dopo {}s", pid, wait_secs));
    }
    // Porta: attesa che il listener muoia (complementare al pid, o unico
    // segnale quando il pid non e' noto — es. spawn WMI legacy).
    while Instant::now() < deadline {
        if TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .is_err()
        {
            log.line(&format!("porta {} libera.", port));
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    log.line(&format!(
        "WARNING: porta {} ancora occupata dopo {}s",
        port, wait_secs
    ));
    // Ultima spiaggia su Windows: kill diretto dei PID in ascolto
    // (riusa la logica AddrInUse del server).
    #[cfg(target_os = "windows")]
    {
        log.line(&format!("forzo kill listener su porta {}", port));
        let _ = crate::kill_listener_on_port_windows(port).await;
    }
}

/// True se il processo `pid` esiste ancora.
#[cfg(target_os = "windows")]
fn process_alive(pid: u32) -> bool {
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::processthreadsapi::OpenProcess;
    use winapi::um::synchapi::WaitForSingleObject;
    use winapi::um::winbase::WAIT_OBJECT_0;
    use winapi::um::winnt::SYNCHRONIZE;
    unsafe {
        let h = OpenProcess(SYNCHRONIZE, 0, pid);
        if h.is_null() {
            return false;
        }
        let r = WaitForSingleObject(h, 0);
        CloseHandle(h);
        r != WAIT_OBJECT_0
    }
}

/// True se il processo `pid` esiste ancora (via /proc).
#[cfg(not(target_os = "windows"))]
fn process_alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{}", pid)).exists()
}

/// Spawna un processo detached: niente job object, console separata su
/// Windows (DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW),
/// nuovo process group su Unix. Con `console=true` su Windows usa invece
/// CREATE_NEW_CONSOLE (finestra nuova con output visibile — per rilanciare
/// comandi client dopo il self-update) e stdio ereditato.
/// Il figlio sopravvive alla morte del parent — e' il punto del design:
/// i figli shell-mode invece muoiono col server (job + kill_notify).
fn spawn_detached(program: &Path, args: &[String], console: bool) -> Result<()> {
    let mut cmd = std::process::Command::new(program);
    cmd.args(args);
    if !console {
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        let flags = if console {
            // CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP: finestra
            // propria con output visibile, fuori dal job del parent.
            0x00000010 | 0x00000200
        } else {
            0x00000008 | 0x00000200 | 0x08000000
        };
        cmd.creation_flags(flags);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let child = cmd
        .spawn()
        .with_context(|| format!("spawn detached {}", program.display()))?;
    eprintln!(
        "[update] spawn detached pid={} {} {:?}",
        child.id(),
        program.display(),
        args
    );
    Ok(())
}

/// Rinomina `from -> to` con retry (handle file rilasciati in ritardo,
/// interferenza AV). Ritorna l'ultimo errore dopo `attempts` tentativi.
async fn retry_rename(from: &Path, to: &Path, attempts: u32) -> Result<()> {
    let mut last_err = None;
    for _ in 0..attempts {
        match std::fs::rename(from, to) {
            Ok(()) => return Ok(()),
            Err(e) => {
                last_err = Some(e);
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }
    Err(anyhow::anyhow!(
        "rename {} -> {} fallito dopo {} tentativi: {:?}",
        from.display(),
        to.display(),
        attempts,
        last_err
    ))
}

/// Target default dello swap: `crosspilot[.exe]` nella dir dello staged.
/// Richiede che l'exe corrente abbia nome `crosspilot-<ts>[.exe]`.
fn default_target(self_exe: &Path) -> Result<PathBuf> {
    let name = self_exe
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    if !is_staged_name(&name) {
        bail!(
            "--target richiesto: l'exe corrente ({}) non e' un binario staged crosspilot-<ts>",
            name
        );
    }
    let dir = self_exe
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let mut target = dir.join("crosspilot");
    if let Some(ext) = self_exe.extension() {
        target.set_extension(ext);
    }
    Ok(target)
}

/// True se `name` matcha il pattern staged `crosspilot-<digits>[.exe]`.
fn is_staged_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("crosspilot-") else {
        return false;
    };
    let stem = rest.strip_suffix(".exe").unwrap_or(rest);
    !stem.is_empty() && stem.chars().all(|c| c.is_ascii_digit())
}

/// Scrive `crosspilot.ver` in `dir`: BUILD_TS + EXE_SHA256 + LINUX_SHA256.
/// EXE_SHA256 descrive l'artefatto WINDOWS scaricabile (`crosspilot.exe`):
/// su un server Windows e' l'exe corrente stesso; su un server Linux e'
/// il PE materializzato/uploadato. Fallback su self_exe se l'artefatto
/// manca (dev build senza embed).
fn write_ver_file(dir: &Path, self_exe: &Path) -> Result<()> {
    let exe_artifact = dir.join("crosspilot.exe");
    let exe_to_hash = if exe_artifact.is_file() {
        &exe_artifact
    } else {
        self_exe
    };
    let exe_hash = sha256_file_hex(exe_to_hash)?;
    let sidecar = dir.join(version::LINUX_SIDECAR_NAME);
    let linux_hash = if sidecar.is_file() {
        Some(sha256_file_hex(&sidecar)?)
    } else {
        None
    };
    let content = version::render_ver_file(version::BUILD_TS, &exe_hash, linux_hash.as_deref());
    let ver_path = dir.join(version::VER_FILE_NAME);
    std::fs::write(&ver_path, content)
        .with_context(|| format!("scrittura {}", ver_path.display()))?;
    eprintln!("[update] .ver scritto: {} (ts={})", ver_path.display(), version::BUILD_TS);
    Ok(())
}

/// SHA-256 hex uppercase di un file.
fn sha256_file_hex(path: &Path) -> Result<String> {
    let mut f = std::fs::File::open(path)
        .with_context(|| format!("apertura {}", path.display()))?;
    let digest = verify::sha256_file_handle(&mut f)?;
    Ok(digest
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
        .to_uppercase())
}

// ---------------------------------------------------------------------------
// IGIENE: self-describe + sweep degli artefatti staged.
// ---------------------------------------------------------------------------

/// Rende il server "self-describing" e pulito all'avvio: ripulisce gli
/// artefatti staged/residui nella dir dell'exe, materializza i binari
/// scaricabili per i client dell'altro OS (crosspilot.linux sempre;
/// crosspilot.exe solo se non e' l'exe corrente — su Windows e' gia' il
/// running exe) e (ri)scrive crosspilot.ver. Chiamata da server_mode;
/// errori solo loggati.
pub fn self_describe() {
    let Ok(self_exe) = std::env::current_exe() else {
        return;
    };
    let Some(dir) = self_exe.parent().map(|p| p.to_path_buf()) else {
        return;
    };
    sweep_staged(&dir);
    materialize_artifact(&dir, version::LINUX_SIDECAR_NAME, deploy::LINUX_BIN);
    let self_name = self_exe
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if self_name != "crosspilot.exe" {
        materialize_artifact(&dir, "crosspilot.exe", deploy::WINDOWS_EXE);
    }
    // Fallback senza embed (es. il sidecar musl stesso, buildato con
    // assets vuoti): il self e' comunque un binario valido per l'OS
    // corrente -> copialo come artefatto scaricabile omonimo.
    materialize_self_fallback(&dir, &self_exe, &self_name);
    if let Err(e) = write_ver_file(&dir, &self_exe) {
        eprintln!("[update] WARNING self_describe: {}", e);
    }
}

/// Se l'embed dell'artefatto per QUESTO OS e' vuoto (build senza
/// build-release.sh, o il sidecar musl che non embedda se' stesso),
/// copia l'exe corrente come `crosspilot.linux` (unix) / `crosspilot.exe`
/// (windows) cosi' il remote resta "sorgente" per i client omonimi.
fn materialize_self_fallback(dir: &Path, self_exe: &Path, self_name: &str) {
    #[cfg(unix)]
    let artifact = version::LINUX_SIDECAR_NAME;
    #[cfg(windows)]
    let artifact = "crosspilot.exe";
    if self_name == artifact {
        return; // il self e' gia' l'artefatto
    }
    let needs_fallback = {
        #[cfg(unix)]
        {
            deploy::LINUX_BIN.is_empty()
        }
        #[cfg(windows)]
        {
            deploy::WINDOWS_EXE.is_empty()
        }
    };
    if !needs_fallback {
        return;
    }
    let dst = dir.join(artifact);
    if dst.exists() {
        return;
    }
    match std::fs::copy(self_exe, &dst) {
        Ok(_) => eprintln!("[update] materializzato {} da self", dst.display()),
        Err(e) => eprintln!("[update] WARNING self-copy {}: {}", dst.display(), e),
    }
}

/// Scrive `dir/name` dai byte embeddati se il file manca e i bytes non
/// sono vuoti. Serve a rendere il remote "sorgente" per client dell'altro
/// OS (es. un server Linux puo' servire crosspilot.exe ai client Windows).
fn materialize_artifact(dir: &Path, name: &str, bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    let path = dir.join(name);
    if path.exists() {
        return;
    }
    match std::fs::write(&path, bytes) {
        Ok(()) => eprintln!("[update] materializzato artefatto {}", path.display()),
        Err(e) => eprintln!("[update] WARNING materialize {}: {}", path.display(), e),
    }
}

/// Elimina gli artefatti staged/residui nella dir: `crosspilot-<ts>[.exe]`
/// (diverso dall'exe corrente), `*.b64`, `*.new`, `*.part`.
/// `.old` e `.bak` restano (rollback).
pub fn sweep_staged(dir: &Path) {
    let self_name = std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
        .unwrap_or_default();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name == self_name {
            continue;
        }
        let leftover = name.ends_with(".b64")
            || name.ends_with(".new")
            || name.ends_with(".part");
        if is_staged_name(&name) || leftover {
            match std::fs::remove_file(entry.path()) {
                Ok(()) => eprintln!("[update] sweep: rimosso {}", name),
                Err(e) => eprintln!("[update] sweep: impossibile rimuovere {}: {}", name, e),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helper path remoti (separator-aware: Windows \ e Unix / per i test locali).
// ---------------------------------------------------------------------------

/// True se `p` sembra un path Windows: lettera di unita' (`C:\...`) o UNC
/// (`\\server\share`). `/` iniziale => unix.
fn is_windows_path(p: &str) -> bool {
    let b = p.as_bytes();
    (b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':')
        || (p.starts_with("\\\\") && !p.starts_with('/'))
}

/// Directory parent di un path remoto, sep-aware (\' o '/').
fn remote_parent(p: &str) -> &str {
    match p.rfind(['\\', '/']) {
        Some(i) => &p[..i],
        None => p,
    }
}

/// Join dir+nome col separatore coerente col dir ('\\' se Windows, '/' altrove).
fn remote_join(dir: &str, name: &str) -> String {
    let sep = if dir.contains('\\') { "\\" } else { "/" };
    format!("{}{}{}", dir.trim_end_matches(['\\', '/']), sep, name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staged_name_matching() {
        assert!(is_staged_name("crosspilot-1758530400.exe"));
        assert!(is_staged_name("crosspilot-1758530400"));
        assert!(!is_staged_name("crosspilot.exe"));
        assert!(!is_staged_name("crosspilot.linux"));
        assert!(!is_staged_name("crosspilot.ver"));
        assert!(!is_staged_name("crosspilot-abc.exe"));
        assert!(!is_staged_name("other-123.exe"));
    }

    #[test]
    fn remote_parent_and_join() {
        assert_eq!(remote_parent(r"C:\ci\crosspilot.exe"), r"C:\ci");
        assert_eq!(remote_parent("/tmp/remote/crosspilot"), "/tmp/remote");
        assert_eq!(remote_join(r"C:\ci", "crosspilot-1.exe"), r"C:\ci\crosspilot-1.exe");
        assert_eq!(remote_join("/tmp/remote", "crosspilot-1"), "/tmp/remote/crosspilot-1");
        assert_eq!(remote_join(r"C:\ci\", "x"), r"C:\ci\x");
    }

    #[test]
    fn windows_path_detection() {
        assert!(is_windows_path(r"C:\ci\crosspilot.exe"));
        assert!(is_windows_path("D:\\x"));
        assert!(!is_windows_path("/tmp/remote/crosspilot"));
        assert!(!is_windows_path("relative\\path"));
    }
}
