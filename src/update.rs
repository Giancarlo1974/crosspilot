// Modulo update: auto-update bidirezionale via TCP, senza WinRM.
// Separato da bootstrap.rs/deploy.rs (WinRM) per rispettare la
// best-practice < 1000 righe.
//
// ARCHITETTURA ("il piu' vecchio si aggiorna da solo", over TCP):
// l'handshake del server e' "READY <BUILD_TS> [<os>]\n" — il tag OS
// (L|W) e' opzionale e non ancora inviato; i server legacy mandano
// "READY\n" secco -> ts=None -> trattati come i piu' vecchi di tutti.
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
//                             * server legacy: comando shell schtasks
//                               (task temporaneo nasce da svchost, fuori
//                               dal job e fuori da WmiPrvSE — i figli WMI
//                               morivano su H166) oppure `setsid` su
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
// - wait-and-see post-bind (BUG-13): il bind da solo non prova la vita —
//   su H101/H166 il server rilanciato moriva 3-7s dopo il bind.
//   confirm_server_stable osserva 30s (pid vivo + porta in ascolto, con
//   heartbeat nel log): una finestra piu' corta poteva chiudersi PRIMA
//   del kill -> updater gia' uscito -> nessun rollback -> remote scuro.
//   Se il server cade nella finestra -> stesso rollback.
// - rilancio server via Task Scheduler su Windows (BUG-13): in
//   server-mode il nuovo server nasce da un task temporaneo
//   (schtasks create/run/delete, padre svchost, sessione 0) e NON come
//   figlio dell'updater ne' di WmiPrvSE — su H166 i processi WMI
//   morivano ~3s dopo il bind, i task-spawned sopravvivono (canale
//   verificato in vivo, lo stesso del bootstrap). Fallback a
//   spawn_detached se schtasks non e' utilizzabile; su unix
//   spawn_detached (nuovo process group) e' gia' sufficiente.
// - firewall inbound su ENTRAMBI gli OS del remote (macro-blocco): netsh
//   su Windows, cascata ufw/firewalld/iptables/nft su Linux — prima
//   coperto solo Windows (un remote Linux firewallato restava invisibile).
// - --target esplicito negli spawn schtasks/setsid: default_target
//   assume il nome `crosspilot[.exe]`, un EXE_PATH con nome diverso
//   swappava il file sbagliato.
// - PUT con retry: "early eof" intermittenti su upload grossi.
//
// NOTE CHIAVE (motivazioni, non ripetere bug):
// - I figli shell-mode su Windows sono in un Job Object KILL_ON_JOB_CLOSE:
//   un updater spawnato cosi' morirebbe insieme al server. Per questo lo
//   staged va spawnato detached dal server stesso (MSG_UPDATE_REQ) o via
//   schtasks/setsid (legacy). CREATE_BREAKAWAY_FROM_JOB non basta: il
//   nostro job non ha JOB_OBJECT_LIMIT_BREAKAWAY_OK -> ERROR_ACCESS_DENIED.
// - NIENTE WMI per spawnare processi: su H166 i figli di WmiPrvSE
//   (Win32_Process.Create) morivano ~3s dopo l'avvio — verificato in
//   vivo 2 volte — mentre figli del Task Scheduler e figli detached
//   sopravvivono. Regola: spawn out-of-band = schtasks, mai WMI.
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
    /// Riconnessione dopo il fallback sul canale di bootstrap
    /// (WinRM su remote Windows, SSH su remote Linux): il vecchio server
    /// e' gia' stato fermato (`quit`) e quello nuovo e' gia' in ascolto
    /// (verificato dal polling di bootstrap_server) — l'attesa della
    /// caduta della porta (wait_remote_restart_begin) e' inutile qui,
    /// si riconnette subito.
    ReconnectNoWait,
}

/// Dedup: un update per processo. Evita retry-storm quando l'update e'
/// fallito ma il server e' comunque raggiungibile (sync apre N connessioni).
static UPDATE_TRIED: AtomicBool = AtomicBool::new(false);

/// True se in questo processo e' stato tentato un update del server.
/// Usato da final_connect_error per suggerire la lettura del log
/// updater remoto quando il server non torna su dopo il trigger.
pub fn update_attempted() -> bool {
    UPDATE_TRIED.load(Ordering::Relaxed)
}

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
/// il client. `hello` e' il saluto parsato ("READY [<ts> [<os>]]"): oltre
/// al ts puo' portare l'OS dichiarato dal server (tag L|W, non ancora
/// inviato dai server attuali) che guida la scelta del payload di update.
/// Infallibile: ogni fallimento degenera in Proceed con warning
/// (un server disallineato e' comunque utilizzabile, stesso protocollo).
pub async fn reconcile(hello: version::ServerHello) -> Reconcile {
    let remote_ts = hello.ts;
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
            match update_remote(remote_ts, hello.os).await {
                Ok(()) => Reconcile::Reconnect,
                Err(e) => {
                    eprintln!(
                        "[update] WARNING update remoto via TCP fallito: {:#}",
                        e
                    );
                    // --- FALLBACK canale bootstrap (WinRM | SSH) ---
                    // Il transfer TCP puo' essere rotto SUL REMOTE (caso
                    // reale H101: server di una build intermedia con
                    // VERSION=2 del protocollo che rifiuta i messaggi framed
                    // dei client v1 chiudendo il socket -> "early eof" su
                    // OGNI put, anche da 1KB). Shell-mode (testo raw) e
                    // handshake continuano pero' a funzionare, quindi il
                    // server e' vivo ma non aggiornabile via TCP.
                    //
                    // Il canale di bootstrap (WinRM su remote Windows, SSH
                    // su remote Linux/Unix — dispatch interno di
                    // channel_probe/bootstrap_server) e' indipendente dal
                    // framing TCP. Sequenza SICURA:
                    //   1. preflight del canale (channel_probe): se non
                    //      risponde NON si tocca il server corrente
                    //      (fermarlo senza via di ripristino = brick);
                    //   2. `quit` in shell-mode (raw: funziona anche con
                    //      framing rotto) -> il vecchio server esce pulito,
                    //      niente race col comando client;
                    //   3. bootstrap_server(): deploy staged sul canale
                    //      (functional check `--version` + swap .old)
                    //      + riavvio detached + attesa;
                    //   4. Reconnect: riconnesione e verifica del ts nuovo.
                    if let Some(_info) = bootstrap::channel_probe().await {
                        eprintln!(
                            "[update] fallback bootstrap: fermo il vecchio server via shell-mode (`quit`)..."
                        );
                        let _ = send_shell_and_drain("quit").await;
                        eprintln!("[update] fallback bootstrap: vecchio server fermato, deploy + riavvio sul canale dedicato...");
                        match bootstrap::bootstrap_server().await {
                            Ok(()) => {
                                eprintln!(
                                    "[update] fallback bootstrap completato: riconnessione al server aggiornato..."
                                );
                                // Il vecchio server e' gia' uscito (quit) e
                                // bootstrap_server ha atteso il nuovo in
                                // ascolto: niente attesa caduta porta.
                                return Reconcile::ReconnectNoWait;
                            }
                            Err(e2) => {
                                eprintln!(
                                    "[update] WARNING fallback bootstrap fallito: {:#} — proseguo col server corrente",
                                    e2
                                );
                            }
                        }
                    } else {
                        eprintln!(
                            "[update] canale bootstrap (WinRM/SSH) non raggiungibile: nessun fallback \
                             disponibile, proseguo col server corrente (TCP non aggiornabile da questo client)."
                        );
                    }
                    Reconcile::Proceed
                }
            }
        }
    }
}

/// Update del server remoto (client piu' nuovo).
///
/// === LOGICA A MACRO-BLOCCHI (4 combinazioni client x server) ===
/// CrossPilot gira su Linux e Windows e puo' connettersi a entrambi:
/// il flusso qui sotto e' IDENTICO per tutte le combinazioni — ogni
/// blocco esiste sempre; cambia solo l'implementazione interna in base
/// all'OS del REMOTE (dispatch su `remote_os`). Regola: aggiungere un
/// blocco nuovo = implementarlo per Windows E Linux.
///
///   BLOCCO 0 — guard anti retry-storm (marker crosspilot-<ts>.bad)
///   BLOCCO 1 — payload staged per-OS (PE | binario linux) + PUT retry
///   BLOCCO 2 — functional check staged '<staged> --version' (chmod su unix)
///   BLOCCO 3 — artefatti cross-serve + .env minimale
///   BLOCCO 4 — regola firewall inbound TCP/<porta> (netsh | ufw/firewalld/iptables/nft)
///   BLOCCO 5 — trigger swap: UPDATE_REQ (server nuovi) | spawn schtasks/setsid (legacy)
///
/// `remote_os_hint` e' l'OS dichiarato dal server nell'handshake (tag L|W):
/// se presente sostituisce l'euristica su EXE_PATH, che resta il fallback
/// per i server che non lo inviano ancora.
async fn update_remote(remote_ts: Option<u64>, remote_os_hint: Option<version::RemoteOs>) -> Result<()> {
    let exe_path =
        envs::var("EXE_PATH").context("CROSSPILOT_EXE_PATH necessario per l'update remoto")?;

    // Risoluzione OS del remote (blocco preliminare a tutti gli altri).
    let remote_os = resolve_remote_os(remote_os_hint, &exe_path);
    let remote_windows = remote_os == version::RemoteOs::Windows;
    eprintln!(
        "[DEBUG] update_remote: os_dichiarato={:?} exe_path='{}' -> remote_os={:?}",
        remote_os_hint, exe_path, remote_os
    );

    // Payload disponibili: servono sia allo staged (BLOCCO 1) sia agli
    // artefatti cross-serve (BLOCCO 3). PE: l'embed su build non-Windows,
    // su client Windows il binario stesso (e' gia' un PE — l'embed
    // avrebbe chicken-and-egg). Linux: embed musl preferito; su unix
    // senza embed il self (un client linux/musl e' gia' un binario linux).
    let win_exe = deploy::windows_exe_bytes().unwrap_or_default();
    let linux_bin = deploy::linux_bin_bytes().unwrap_or_default();

    // --- BLOCCO 1a: scelta payload staged per l'OS del REMOTE ---
    // Il payload staged deve matchare l'OS del REMOTE (non quello del
    // client): PE su Windows, binario linux su Linux — altrimenti lo
    // spawn dell'updater fallisce (ENOEXEC).
    let staged_name = match remote_os {
        version::RemoteOs::Windows => format!("crosspilot-{}.exe", version::BUILD_TS),
        version::RemoteOs::Linux => format!("crosspilot-{}", version::BUILD_TS),
    };
    let staged_payload = match remote_os {
        version::RemoteOs::Windows => win_exe.clone(),
        version::RemoteOs::Linux => linux_bin.clone(),
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

    // --- BLOCCO 0: marker anti retry-storm ---
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

    // --- BLOCCO 1b: PUT exe staged ---
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

    // --- BLOCCO 2: functional check dello staged PRIMA del trigger ---
    // Il path WinRM prova `'<exe>.new' --version` prima dello swap; qui
    // mancava e uno staged non eseguibile (OS troppo vecchio, AV, upload
    // troncato) brickava il remote: l'updater non partiva e il vecchio
    // server era gia' stato ucciso. Fallire qui abortisce l'update con
    // il server ancora vivo e utilizzabile.
    check_staged_runnable(&staged_remote, remote_os).await?;

    // --- BLOCCO 3a: PUT degli artefatti scaricabili (cross-serve) ---
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

    // --- BLOCCO 3b: .env remoto — MERGE, non overwrite ---
    // Come nel path WinRM (deploy_exe): il server legge
    // CROSSPILOT_SERVER_PORT dalla .env della dir dell'exe; la porta e'
    // quella a cui il client si connette (CLIENT_PORT), non la default.
    // MA il .env remoto puo' contenere altri campi (LOG_PATH, ERR_PATH,
    // ambienti): un overwrite cieco li cancellava — su H166 il nuovo
    // server perdeva i suoi log file. Quindi: GET dell'esistente ->
    // upsert della sola riga SERVER_PORT (envs::upsert_field, lo stesso
    // writer line-based del CRUD `env set`: preserva commenti e ordine)
    // -> PUT del risultato. File assente -> si crea il minimale.
    let port = envs::var("CLIENT_PORT")
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(5330);
    let env_remote = remote_join(&dir, ".env");
    let env_content = remote_env_with_port(&env_remote, port).await;
    let tmp_env = std::env::temp_dir().join(format!("crosspilot-env-{}", std::process::id()));
    std::fs::write(&tmp_env, &env_content)
        .with_context(|| format!("scrittura {}", tmp_env.display()))?;
    let tmp_env_s = tmp_env.to_string_lossy().to_string();
    let put_res = put_with_retry(&tmp_env_s, &env_remote, ".env").await;
    let _ = std::fs::remove_file(&tmp_env);
    match put_res {
        Ok(()) => eprintln!("[update] .env remoto aggiornato (SERVER_PORT={}, merge)", port),
        Err(e) => eprintln!("[update] WARNING upload .env: {}", e),
    }

    // --- BLOCCO 4: regola firewall inbound via shell-mode ---
    // Macro-blocco presente per ENTRAMBI gli OS del remote: il vecchio
    // server e' ANCORA vivo e puo' eseguire comandi shell-mode —
    // approfittiamone per assicurare la regola firewall PRIMA del trigger.
    // Senza regola inbound il nuovo server riparte ma i SYN dall'esterno
    // vengono droppati dal firewall — il client vede "connect timeout"
    // per 90s e casca nel bootstrap lento (caso H132: swap completato in
    // 1s dall'updater ma invisibile dall'esterno per l'intera finestra di
    // retry; su H166 ha portato al remote "scuro"). Implementazioni:
    // Windows -> netsh delete-then-add; Linux -> cascata ufw/firewalld/
    // iptables/nft (vedi inbound_allow_cmd).
    ensure_inbound_allow_shell(remote_os, port).await;

    // --- BLOCCO 5: trigger dello swap ---
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
            // l'updater via shell (fuori dal job: task scheduler su
            // Windows, setsid su Linux) e poi si manda `quit` per far
            // uscire il vecchio server.
            // L'updater attende la porta libera, poi swappa e rilancia.
            // --target esplicito: default_target() assumerebbe il nome
            // `crosspilot[.exe]` nella dir dello staged; se EXE_PATH ha
            // un nome diverso (es. deploy rinominato) lo swap colpirebbe
            // il file sbagliato. Meglio dire all'updater qual e' l'exe
            // reale da sostituire.
            let spawn_cmd = legacy_spawn_cmd(remote_os, &staged_remote, port, &exe_path);
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
        let updater_pid = spawn_detached(&staged, &args, false)?;
        eprintln!(
            "[update] updater spawnato (pid {}); il client esce per lo swap.",
            updater_pid
        );
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
    let (s, _hello) = crate::connect_raw(&addr).await?;
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

/// Risolve l'OS del REMOTE: preferenza al tag dichiarato nell'handshake
/// ("READY <ts> L|W"), altrimenti euristica storica su EXE_PATH
/// (drive letter/UNC -> Windows, '/' -> unix). E' il blocco preliminare
/// da cui dipende il dispatch per-OS di tutti i macro-blocchi successivi.
fn resolve_remote_os(declared: Option<version::RemoteOs>, exe_path: &str) -> version::RemoteOs {
    match declared {
        Some(os) => os,
        None => {
            if is_windows_path(exe_path) {
                version::RemoteOs::Windows
            } else {
                version::RemoteOs::Linux
            }
        }
    }
}

/// MACRO-BLOCCO firewall: assicura l'inbound TCP/<porta> usando lo
/// shell-mode del server ANCORA in esecuzione (testo raw: funziona
/// sempre, anche col framing rotto). Il blocco c'e' per entrambi gli
/// OS del remote; cambia solo il comando (inbound_allow_cmd).
///
/// Best-effort: se il server non e' elevato (Windows) o l'utente non e'
/// root (Linux) il comando fallisce — il bootstrap del canale dedicato
/// (WinRM ensure_firewall_rule / SSH ensure_inbound_allow) lo ritentera'
/// comunque con privilegi propri.
async fn ensure_inbound_allow_shell(remote_os: version::RemoteOs, port: u16) {
    let cmd = inbound_allow_cmd(remote_os, port);
    eprintln!(
        "[update] firewall ({:?}): assicuro inbound TCP/{} via shell-mode remoto...",
        remote_os, port
    );
    match send_shell_and_drain(&cmd).await {
        Ok(out) => {
            let trimmed = out.trim();
            if trimmed.is_empty() {
                eprintln!("[update] firewall: regola applicata (nessun output)");
            } else {
                eprintln!("[update] firewall: {}", trimmed);
            }
        }
        Err(e) => eprintln!(
            "[update] WARNING regola firewall non creata via shell-mode: {} \
             (il bootstrap del canale dedicato la ritentera', se serve)",
            e
        ),
    }
}

/// Comando remoto del macro-blocco firewall, per-OS:
/// - Windows: netsh delete-then-add (idempotente, keyword inglesi su
///   ogni locale);
/// - Linux: script POSIX in cascata ufw -> firewalld -> iptables -> nft
///   (condiviso col bootstrap SSH: stesso blocco, altro trasporto).
fn inbound_allow_cmd(remote_os: version::RemoteOs, port: u16) -> String {
    match remote_os {
        version::RemoteOs::Windows => windows_inbound_allow_cmd(port),
        version::RemoteOs::Linux => linux_inbound_allow_script(port),
    }
}

/// Implementazione Windows del macro-blocco firewall: regola inbound
/// `crosspilot-server-<porta>` via netsh delete-then-add. La delete rende
/// l'add privo di duplicati e le keyword netsh sono in inglese su ogni
/// locale -> indipendente dalla lingua del remote.
fn windows_inbound_allow_cmd(port: u16) -> String {
    let name = format!("crosspilot-server-{}", port);
    format!(
        "netsh advfirewall firewall delete rule name=\"{n}\" >nul 2>&1 & \
         netsh advfirewall firewall add rule name=\"{n}\" dir=in action=allow \
         protocol=TCP localport={p}",
        n = name,
        p = port
    )
}

/// Implementazione Linux del macro-blocco firewall: script POSIX in
/// cascata sui frontend comuni — ufw -> firewalld -> iptables -> nft.
/// Stampa `FW=<esito>` per il log diagnostico. Tutto best-effort:
/// - ufw: `allow` registra la regola anche a ufw inattivo (no enable);
/// - firewalld: regola runtime + permanent (richiede il daemon attivo);
/// - iptables: `-C` check poi `-I` insert (idempotente; copre anche i
///   sistemi iptables-nft dove nft gestisce il backend);
/// - nft puro: tentativo su `inet filter input` — fallisce se la chain
///   non esiste (tabelle custom): il FW=fail:nft resta come evidenza;
/// - nessun frontend: FW=none (host senza firewall locale: OK).
///
/// NOTA: il comando shell-mode e' letto dal server in UN buffer da
/// 1024 byte (handle_connection): lo script deve restare compatto.
/// pub(crate): riusato da bootstrap_ssh (stesso blocco, trasporto ssh).
pub(crate) fn linux_inbound_allow_script(port: u16) -> String {
    format!(
        "p={p}; \
         if command -v ufw >/dev/null 2>&1; then \
           ufw allow $p/tcp >/dev/null 2>&1 && echo FW=ufw || echo FW=fail:ufw; \
         elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then \
           firewall-cmd --add-port=$p/tcp >/dev/null 2>&1; \
           firewall-cmd --permanent --add-port=$p/tcp >/dev/null 2>&1 && echo FW=firewalld || echo FW=fail:firewalld; \
         elif command -v iptables >/dev/null 2>&1; then \
           iptables -C INPUT -p tcp --dport $p -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport $p -j ACCEPT 2>/dev/null; \
           [ $? -eq 0 ] && echo FW=iptables || echo FW=fail:iptables; \
         elif command -v nft >/dev/null 2>&1; then \
           nft add rule inet filter input tcp dport $p accept 2>/dev/null && echo FW=nft || echo FW=fail:nft; \
         else echo FW=none; fi",
        p = port
    )
}

/// BLOCCO 5 (server legacy): comando shell che spawna l'updater FUORI
/// dal job object del server. Windows: task temporaneo via schtasks —
/// il processo nasce dal servizio Task Scheduler (svchost), NON come
/// discendente del nostro cmd (i figli shell-mode muoiono col job
/// KILL_ON_JOB_CLOSE alla disconnessione) e NON come figlio di WmiPrvSE
/// (BUG-13/H166: i processi creati via WMI morivano ~3s dopo l'avvio —
/// un updater ucciso a meta' swap bricka il remote). `setsid` su Linux
/// (nuova sessione). --target esplicito: default_target() assumerebbe
/// `crosspilot[.exe]`.
fn legacy_spawn_cmd(remote_os: version::RemoteOs, staged: &str, port: u16, target: &str) -> String {
    match remote_os {
        version::RemoteOs::Windows => task_spawn_cmd(staged, port, target),
        version::RemoteOs::Linux => format!(
            "setsid \"{}\" update --target \"{}\" --port {} >/dev/null 2>&1 &",
            staged, target, port
        ),
    }
}

/// BLOCCO 3b: contenuto .env remoto con CROSSPILOT_SERVER_PORT
/// aggiornato, preservando i campi esistenti. Scarica il .env attuale
/// via GET (best-effort: assente/errore -> contenuto minimale), splitta
/// in righe e fa upsert della sola chiave SERVER_PORT tramite
/// envs::upsert_field — lo stesso writer del CRUD `env set`: righe
/// sconosciute, commenti e ordine restano intatti. Righe lette con
/// strip di `\r` finale: il .env remoto su Windows puo' essere CRLF.
async fn remote_env_with_port(env_remote: &str, port: u16) -> String {
    let tmp_in = std::env::temp_dir().join(format!("crosspilot-envin-{}", std::process::id()));
    let tmp_in_s = tmp_in.to_string_lossy().to_string();
    let get_res = async {
        let mut s = open_conn().await?;
        transfer::get_client(&mut s, env_remote, &tmp_in_s).await
    }
    .await;
    let mut lines: Vec<String> = Vec::new();
    match get_res {
        Ok(()) => {
            let raw = std::fs::read_to_string(&tmp_in).unwrap_or_default();
            for l in raw.lines() {
                let clean = l.trim_end_matches('\r');
                lines.push(clean.to_string());
            }
            eprintln!(
                "[update] .env remoto esistente: {} righe, upsert SERVER_PORT={}",
                lines.len(),
                port
            );
        }
        Err(e) => {
            eprintln!(
                "[update] .env remoto assente/illeggibile ({}): scrittura minimale",
                e
            );
        }
    }
    let _ = std::fs::remove_file(&tmp_in);
    envs::upsert_field(&mut lines, None, "SERVER_PORT", &port.to_string());
    let mut content = lines.join("\n");
    content.push('\n');
    content
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

/// Functional check dello staged sul remote (BLOCCO 2): esegue
/// `<staged> --version` in shell-mode e verifica che il build_ts
/// stampato sia quello atteso. Chiamata PRIMA del trigger di swap: se
/// fallisce, il vecchio server resta vivo e il remote non viene
/// brickato (a differenza del bug H166, dove l'updater non e' mai
/// partito e non c'era modo di saperlo).
async fn check_staged_runnable(staged: &str, remote_os: version::RemoteOs) -> Result<()> {
    // Su unix il file appena uploadato ha permessi 644 (PUT non setta
    // +x): chmod prima dell'esecuzione. Su Windows il bit non esiste.
    let cmd = match remote_os {
        version::RemoteOs::Windows => format!("\"{}\" --version", staged),
        version::RemoteOs::Linux => format!("chmod 755 \"{}\" && \"{}\" --version", staged, staged),
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

/// Comando cmd che spawna l'updater tramite un task schedulato
/// temporaneo (create → run → delete). Il processo nasce dal servizio
/// Task Scheduler: fuori dal job object del server (i figli shell-mode
/// muoiono col job alla disconnessione — vedi win_job in main.rs) e
/// fuori da WmiPrvSE — su H166 i processi WMI morivano ~3s dopo il bind
/// mentre quelli task-spawned sopravvivono (verificato in vivo, BUG-13).
///
/// Cascata `/RU SYSTEM /RL HIGHEST` → senza `/RU` (utente corrente):
/// `A || B & C & D` in cmd esegue B solo se A fallisce, poi C e D
/// comunque — il run tenta sempre, il delete pulisce sempre.
/// `/SC ONCE /ST 00:00`: trigger nel passato → il task non riparte da
/// solo; il `/Delete` immediato elimina comunque ogni residuo.
///
/// Il quoting `\"` e' il formato atteso da schtasks dentro una /TR
/// doppiamente quotata via cmd (stessa convenzione di bootstrap.rs).
fn task_spawn_cmd(staged: &str, port: u16, target: &str) -> String {
    let task = format!("crosspilot-upd-{}", version::BUILD_TS);
    // L'azione del task e' `cmd /c start /b` dell'updater: cmd esce
    // SUBITO (istanza completata) mentre l'updater resta orfano e vivo.
    // MOTIVO: /Delete su un task con istanza ancora in avvio/esecuzione
    // TERMINA il processo spawnato (Task Scheduler event 111, exit
    // 0x80070001 — verificato su H166: il delete immediato uccideva il
    // server rilanciato ~1s dopo). Con start /b il delete e' sicuro e
    // `timeout /t 2` gli lascia margine prima della rimozione.
    let tr = format!(
        "cmd /c start /b \\\"\\\" \\\"{}\\\" update --target \\\"{}\\\" --port {}",
        staged, target, port
    );
    format!(
        "schtasks /Create /TN {t} /TR \"{tr}\" /SC ONCE /ST 00:00 /RU SYSTEM /RL HIGHEST /F \
         || schtasks /Create /TN {t} /TR \"{tr}\" /SC ONCE /ST 00:00 /F \
         & schtasks /Run /TN {t} \
         & timeout /t 2 /nobreak >nul \
         & schtasks /Delete /TN {t} /F",
        t = task,
        tr = tr
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

    // Log updater accanto allo staged: le fasi di spawn (qui, lato
    // server) si appendono allo stesso file che l'updater usera' — se
    // l'updater non dovesse mai partire, il remote conserva la traccia
    // della richiesta invece del buco nero del brick silenzioso.
    let dir = match staged.parent() {
        Some(p) => p.to_path_buf(),
        None => PathBuf::from("."),
    };
    let log = UpdaterLog::new(&dir);
    log.line(&format!(
        "UPDATE_REQ ricevuto: spawn updater {} (deve sopravvivere alla chiusura del server pid {})",
        staged.display(),
        pid
    ));

    match spawn_updater(&staged, &args, &log).await {
        Ok(updater_pid) => {
            let res = proto::UpdateRes {
                status: 0,
                message: format!(
                    "updater avviato (pid {:?}), server pid {} in uscita",
                    updater_pid, pid
                ),
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
            log.line(&format!("FATAL spawn updater fallito: {}", e));
            Err(e)
        }
    }
}

/// Spawna l'updater staged in modo che SOPRAVVIVA alla chiusura del
/// server chiamante — il vincolo centrale della ricetta BUG-13 ("se il
/// vecchio crosspilot si chiude, l'updater resta comunque aperto").
///
/// Windows: PRIMA il task schedulato `crosspilot-updater`. Motivo: lo
/// spawn_detached eredita il Job Object del parent — se il server fosse
/// dentro un job KILL_ON_JOB_CLOSE (supervisor esterno, avvio via
/// shell-mode di un altro crosspilot) l'updater morirebbe insieme a lui
/// e lo swap non partirebbe MAI: brick silenzioso senza log. Il processo
/// nato dal servizio Task Scheduler (svchost) e' immune a qualunque job
/// del chiamante — stessa regola del rilancio server ("spawn out-of-band
/// = schtasks, mai WMI": i figli di WmiPrvSE morivano ~3s su H166).
/// Il task NON viene cancellato: /Delete su un'istanza running termina
/// il processo (evento 111). Il redirect `>> crosspilot-update.log`
/// dell'azione cattura anche output pre-logger e panic dell'updater.
/// Fallback: spawn_detached (canale gia' verificato su H166).
/// Unix: spawn_detached (process_group(0)) basta — niente job object.
///
/// Ritorna Some(pid) solo per lo spawn diretto, None via task scheduler
/// (schtasks non restituisce il pid — non serve: chi attua l'attesa e'
/// l'updater sul wait_pid del server, non chi lo spawnza).
async fn spawn_updater(staged: &Path, args: &[String], log: &UpdaterLog) -> Result<Option<u32>> {
    #[cfg(target_os = "windows")]
    {
        match schtasks_spawn_local(staged, args, "crosspilot-updater", UPDATER_LOG_NAME, log).await {
            Ok(()) => return Ok(None),
            Err(e) => {
                log.line(&format!(
                    "WARNING spawn updater via task scheduler fallito ({}): fallback spawn_detached",
                    e
                ));
            }
        }
    }
    // Su unix `log` resta inutilizzato (nessun blocco task scheduler).
    let _ = log;
    let pid = spawn_detached(staged, args, false)?;
    Ok(Some(pid))
}

// ---------------------------------------------------------------------------
// UPDATER: `crosspilot-<ts> update` — attende la morte del server, swappa,
// rilancia. Esegue detached o nato dal task scheduler, fuori dal job
// object del server.
// ---------------------------------------------------------------------------

/// Finestra di attesa per il bind del server rilanciato, prima di
/// dichiarare fallito l'update e fare rollback a `.old`. 90s: su H166
/// la socket zombie del server morto restava bound ~40s (BUG-13) — il
/// server rilanciato ora attende paziente (ADDRINUSE_RETRY_SECS) ma
/// l'updater deve dargli il tempo di vincere l'attesa.
const SERVER_UP_WAIT_SECS: u64 = 90;

/// Attesa della liberazione della porta dopo la morte del vecchio
/// server (BUG-13): la morte del pid non coincide col rilascio della
/// socket listening su Windows. Bound corto: se lo zombie e' piu'
/// longevo si procede comunque — il bind paziente del server e' la
/// rete finale.
const PORT_RELEASE_WAIT_SECS: u64 = 15;

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
    /// true dopo il primo fallimento di scrittura: il WARNING su stderr
    /// viene emesso solo alle transizioni (fail->ok, ok->fail), non ad
    /// ogni riga. Necessario perche' sul path schtasks l'azione
    /// `cmd /c ... >> crosspilot-update.log` tiene il file aperto senza
    /// share-write per TUTTA la vita dell'updater: ogni append fallisce
    /// con ERROR_SHARING_VIOLATION (32) e senza dedup il log era una
    /// riga utile + un WARNING ripetuto (~30 volte per update su H166).
    /// Le righe non si perdono: il mirror su stderr finisce comunque
    /// nel file tramite il redirect di cmd.
    write_failed: std::sync::atomic::AtomicBool,
}

impl UpdaterLog {
    fn new(dir: &Path) -> Self {
        Self {
            path: dir.join(UPDATER_LOG_NAME),
            write_failed: std::sync::atomic::AtomicBool::new(false),
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
        use std::sync::atomic::Ordering;
        if let Err(e) = res {
            // Nemmeno il log file e' scrivibile: resta solo stderr
            // (visibile se l'updater e' lanciato a mano con console, o
            // catturato dal redirect `>>` dell'azione schtasks). Warning
            // una sola volta per transizione ok->fail.
            if !self.write_failed.swap(true, Ordering::Relaxed) {
                eprintln!(
                    "[updater] WARNING log {} non scrivibile: {} (warning ripetuti soppressi)",
                    self.path.display(),
                    e
                );
            }
        } else if self.write_failed.swap(false, Ordering::Relaxed) {
            eprintln!("[updater] log {} tornato scrivibile", self.path.display());
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
/// l'updater VERIFICA che la porta torni in ascolto E resti tale per una
/// finestra di stabilizzazione (wait-and-see, BUG-13: su H101 il server
/// bindava e moriva subito dopo). Se il server non binda o cade nella
/// finestra, fa rollback a `.old` e rilancia il vecchio binario (meglio
/// un server vecchio che un remote morto), lasciando il marker
/// `crosspilot-<ts>.bad` che impedisce al client di ritentare lo stesso
/// build all'infinito.
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
    // BUG-13 (ricetta del report): l'updater dichiara subito di essere
    // vivo e di NON essere il listener — se il killer osservato su H166
    // colpisce "chi possiede la porta", questo processo e' immune e il
    // log file deve dimostrare la sopravvivenza riga per riga
    // ("sono vivo" / "sono ancora vivo"). La pausa di 1s separa lo spawn
    // dal lavoro vero e produce la prima prova di vita nel log.
    log.line("sono vivo: mode update — nessun bind, non sono il listener della porta (un killer del listener non puo' colpirmi)");
    tokio::time::sleep(Duration::from_secs(1)).await;
    log.line("sono ancora vivo dopo 1s — procedo con l'attesa della morte del vecchio server");

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
                    // BUG-13: attende il rilascio reale della porta
                    // (socket zombie del server appena morto) prima del
                    // rilancio — il vecchio build esce subito su AddrInUse.
                    wait_port_free(port, PORT_RELEASE_WAIT_SECS, &log).await;
                    match relaunch_server(&target_path, &["--server".to_string()], false, &log).await {
                        Ok(old_pid) => {
                            // Wait-and-see anche qui (BUG-13): un bind
                            // seguito da morte immediata non e' "operativo".
                            let up = wait_port_up(port, 30, &log).await;
                            let stable = up
                                && confirm_server_stable(old_pid, port, &log).await;
                            if stable {
                                log.line("vecchio server ripartito: update fallito ma remote operativo");
                            } else {
                                log.line("WARNING: vecchio server non in ascolto/stabile dopo il rilancio di emergenza");
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
    // Windows passa gli argv originali via --arg. Il pid va nel log:
    // e' la prova necessaria per il wait-and-see di step 5 (BUG-13).
    let relaunch = if server_mode {
        vec!["--server".to_string()]
    } else {
        relaunch_args
    };
    // Server-mode: rilancio tramite il macro-blocco per-OS (task
    // scheduler su Windows — BUG-13 — spawn_detached su unix).
    // Client-mode: spawn diretto con gli argv originali (console
    // visibile su Windows).
    if server_mode {
        // Ricetta BUG-13: "eseguo crosspilot --server in modo che resti
        // vivo anche se l'updater si chiude" — il rilancio NON e' un
        // figlio dipendente: nasce dal servizio Task Scheduler
        // (svchost, sessione 0) su Windows o in un nuovo process group
        // su unix. L'uscita dell'updater non lo trascina.
        log.line("adesso rilancio il target come server indipendente (task scheduler / detached): restera' vivo anche quando l'updater si chiude");
    }
    let spawn_res: Result<Option<u32>> = if server_mode {
        relaunch_server(&target_path, &relaunch, console, &log).await
    } else {
        match spawn_detached(&target_path, &relaunch, console) {
            Ok(pid) => Ok(Some(pid)),
            Err(e) => Err(e),
        }
    };
    let spawned_pid = match spawn_res {
        Ok(pid) => {
            log.line(&format!(
                "rilanciato {} {:?} (pid {:?})",
                target_path.display(),
                relaunch,
                pid
            ));
            pid
        }
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
    };

    // --- Step 5: conferma che il server rilanciato binda la porta ---
    // Solo in server-mode: il rilancio di un client Windows (--arg con
    // gli argv originali) non apre listener, non c'e' nulla da verificare.
    if !server_mode {
        log.line("relaunch custom (--arg): skip check porta. Updater terminato OK.");
        return Ok(());
    }
    if wait_port_up(port, SERVER_UP_WAIT_SECS, &log).await {
        // BUG-13 (wait-and-see): su H101/H166 il server rilanciato
        // BINDAVA e poi moriva 3-7s dopo — l'updater loggava "in ascolto
        // (tentativo 1) -> COMPLETATO" e usciva mentre il killer non era
        // ancora entrato in azione. Il bind da solo non basta come prova
        // di vita: l'updater resta vivo per l'intera finestra di
        // osservazione (30s, la "pausa diagnosi" della ricetta) a
        // ricontrollare pid vivo + porta in ascolto. Se il server cade
        // nella finestra -> stesso rollback del caso "mai bindato":
        // meglio il server vecchio che un remote scuro.
        log.line(&format!(
            "finestra di diagnosi: resto vivo {}s a osservare il server rilanciato (se cade, rollback a .old)",
            POST_BIND_OBSERVE_SECS
        ));
        if confirm_server_stable(spawned_pid, port, &log).await {
            log.line(&format!(
                "nuovo server in ascolto su porta {} e stabile (pid {:?}): update COMPLETATO — l'updater si chiude",
                port, spawned_pid
            ));
            return Ok(());
        }
        log.line(&format!(
            "nuovo server (pid {:?}) caduto entro la finestra di stabilizzazione: ROLLBACK",
            spawned_pid
        ));
    } else {
        // --- Step 6: rollback automatico ---
        // Il nuovo exe e' partito (spawn ok) ma la porta non si e' mai
        // aperta: crash post-avvio, bind fallito, AV che lo ammazza
        // dopo lo spawn. Si ripristina .old e si rilancia: il remote
        // torna alla versione precedente invece di restare morto.
        log.line(&format!(
            "nuovo server NON in ascolto dopo {}s: ROLLBACK a {}",
            SERVER_UP_WAIT_SECS,
            old_path.display()
        ));
    }
    rollback_to_old(&dir, &target_path, &old_path, Some(port), &["--server".to_string()], false, &log).await;
    Ok(())
}

/// Rilancio del SERVER post-swap — macro-blocco per-OS (BUG-13).
///
/// Windows (server-mode, console=false): task schedulato temporaneo
/// (create/run/delete) — il server nasce dal servizio Task Scheduler
/// (svchost, sessione 0), NON figlio dell'updater ne' di WmiPrvSE.
/// Questo canale e' scelto perche' VERIFICATO in vivo su H166: i figli
/// WMI (Win32_Process.Create) morivano ~3s dopo il bind, il figlio del
/// Task Scheduler sopravvive — stesso canale che il bootstrap usa da
/// sempre per i server stabili della flotta. Ritorna Ok(None): schtasks
/// non restituisce il pid, il wait-and-see verifica solo la porta (un
/// server morto chiude il listener — la prova resta valida).
/// Fallback: spawn_detached se schtasks non e' utilizzabile.
/// Client-mode (console=true): spawn_detached — l'utente vuole la
/// console visibile, un task in sessione 0 non la darebbe.
/// Linux/Unix: spawn_detached (nuovo process group) e' sufficiente.
///
/// Ritorna Some(pid) se lo spawn ne fornisce uno (spawn_detached),
/// None per il path task scheduler.
async fn relaunch_server(
    target: &Path,
    relaunch: &[String],
    console: bool,
    log: &UpdaterLog,
) -> Result<Option<u32>> {
    #[cfg(target_os = "windows")]
    {
        if !console {
            // Task FISSO `crosspilot-server` (stesso nome del bootstrap):
            // e' il launcher canonico del server; /F lo sovrascrive ad
            // ogni rilancio senza accumuli. Log dedicato
            // `crosspilot-server.log`: stdout/stderr del server su file.
            match schtasks_spawn_local(
                target,
                relaunch,
                "crosspilot-server",
                "crosspilot-server.log",
                log,
            )
            .await
            {
                Ok(()) => return Ok(None),
                Err(e) => {
                    // schtasks non utilizzabile (servizio fermo, permessi):
                    // il fallback e' lo spawn diretto (pre-fix BUG-13).
                    log.line(&format!(
                        "WARNING rilancio via task scheduler fallito ({}): fallback spawn_detached",
                        e
                    ));
                }
            }
        }
    }
    let _ = log;
    let pid = spawn_detached(target, relaunch, console)?;
    Ok(Some(pid))
}

/// Spawna `program args` tramite il task schedulato `task` — nomi
/// condivisi col resto del sistema: `crosspilot-server` per il rilancio
/// del server (lo STESSO del bootstrap, convergenza: /F sovrascrive ad
/// ogni rilancio) e `crosspilot-updater` per lo spawn dell'updater da
/// server_apply_update. Il processo nasce dal servizio Task Scheduler
/// (svchost, sessione 0): fuori dal job object del chiamante e fuori da
/// WmiPrvSE — il canale che sopravvive su H166 (BUG-13).
///
/// Azione = `cmd /c ""<exe>" "<arg>" ... >> "<dir>\<log_name>" 2>&1"`:
/// stdout/stderr del processo finiscono su file — un processo detached
/// e' altrimenti un buco nero diagnostico (e' per questo che BUG-13 e'
/// rimasto cieco per giorni). Ogni arg e' quotato: gli argv dell'updater
/// contengono path con possibili spazi (`--target "C:\...\exe"`). Il cmd
/// resta parente del processo, quindi l'istanza del task resta "running".
///
/// NESSUN /Delete: cancellare un task con istanza in esecuzione TERMINA
/// il processo spawnato (Task Scheduler event 111 + exit 0x80070001 —
/// osservato in vivo su H166: il delete immediato uccideva il server
/// rilanciato ~1s dopo il bind). Il task resta registrato come launcher
/// — trigger ONCE/00:00 nel passato, non riparte da solo.
/// Cascata identica a bootstrap::start_server: `/RU SYSTEM /RL HIGHEST`,
/// poi `/RU <USERNAME> /NP /RL HIGHEST` (S4U, niente logon interattivo),
/// poi task semplice dell'utente corrente. Ogni tentativo e' loggato.
#[cfg(target_os = "windows")]
async fn schtasks_spawn_local(
    program: &Path,
    args: &[String],
    task: &str,
    log_name: &str,
    log: &UpdaterLog,
) -> Result<()> {
    let dir = program
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| ".".to_string());
    let srv_log = format!("{}\\{}", dir.trim_end_matches(['\\', '/']), log_name);
    // CommandLine del task: cmd /c + intero comando doppiamente quotato
    // (pattern `cmd /c ""inner" ..."`): il redirect dentro le virgolette
    // manda stdout/stderr del processo sul file di log.
    let mut cmdline = format!("cmd /c \"\"{}\"", program.display());
    for a in args {
        cmdline.push_str(&format!(" \"{}\"", a));
    }
    cmdline.push_str(&format!(" >> \"{}\" 2>&1\"", srv_log));
    let user = std::env::var("USERNAME").unwrap_or_default();
    // Tentativi /RU in cascata: SYSTEM -> utente corrente S4U -> plain.
    let run_as_variants: Vec<Vec<String>> = vec![
        vec![
            "/RU".to_string(),
            "SYSTEM".to_string(),
            "/RL".to_string(),
            "HIGHEST".to_string(),
        ],
        vec![
            "/RU".to_string(),
            user,
            "/NP".to_string(),
            "/RL".to_string(),
            "HIGHEST".to_string(),
        ],
        Vec::new(),
    ];
    let mut created = false;
    for extra in &run_as_variants {
        let mut cargs: Vec<String> = vec![
            "/Create".to_string(),
            "/TN".to_string(),
            task.to_string(),
            "/TR".to_string(),
            cmdline.clone(),
            "/SC".to_string(),
            "ONCE".to_string(),
            "/ST".to_string(),
            "00:00".to_string(),
        ];
        for e in extra {
            cargs.push(e.clone());
        }
        cargs.push("/F".to_string());
        let out = tokio::process::Command::new("schtasks")
            .args(&cargs)
            .stdin(Stdio::null())
            .output()
            .await
            .context("spawn schtasks /Create")?;
        let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        log.line(&format!(
            "schtasks /Create {:?}: ok={} out={} err={}",
            extra,
            out.status.success(),
            stdout,
            stderr
        ));
        if out.status.success() {
            created = true;
            break;
        }
    }
    if !created {
        bail!("schtasks /Create fallito in tutte le modalita' (SYSTEM/S4U/plain)");
    }
    let out = tokio::process::Command::new("schtasks")
        .args(["/Run", "/TN", &task])
        .stdin(Stdio::null())
        .output()
        .await
        .context("spawn schtasks /Run")?;
    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    log.line(&format!(
        "schtasks /Run {}: ok={} out={}",
        task,
        out.status.success(),
        stdout
    ));
    // NESSUN /Delete: su un task con istanza "running" il delete TERMINA
    // il processo (Task Scheduler event 111 + exit 0x80070001 — il bug
    // osservato su H166 con i task temporanei). Il task `crosspilot-server`
    // resta registrato come launcher persistente — stessa convenzione del
    // bootstrap, che non lo cancella mai.
    if !out.status.success() {
        bail!("schtasks /Run fallito per {}", task);
    }
    Ok(())
}

/// Probe positiva di vita: true solo se su 127.0.0.1:port risponde un
/// server crosspilot VIVO (riga di handshake READY entro il timeout).
///
/// PERCHE' non basta il bare connect (BUG-13, provato su H166): la
/// socket listening del server appena morto resta bound per decine di
/// secondi e il kernel completa comunque l'handshake TCP dal backlog —
/// il connect "riesce" ma nessuno risponde READY. L'updater loggava
/// "porta in ascolto (tentativo 1)" su un socket morto mentre il server
/// rilanciato usciva per AddrInUse. Solo la riga READY distingue un
/// server vero da uno zombie.
async fn probe_server_ready(port: u16) -> bool {
    let addr = format!("127.0.0.1:{}", port);
    let conn = tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(&addr)).await;
    let mut stream = match conn {
        Ok(Ok(s)) => s,
        _ => return false,
    };
    let hello = tokio::time::timeout(Duration::from_secs(2), crate::read_ready_line(&mut stream)).await;
    matches!(hello, Ok(Ok(_)))
}

/// Attende che la porta sia davvero LIBERA (connect rifiutato) per
/// `secs`. Serve dopo la morte del vecchio server e prima del rilancio
/// di rollback: su Windows il socket del processo morto puo' restare
/// bound per decine di secondi (BUG-13 — socket zombie osservato su
/// H166: netstat lo mostrava LISTENING col pid morto ~40s dopo).
/// Ritorna false allo scadere (porta ancora occupata): il chiamante
/// procede comunque — il bind paziente del server e' la rete finale.
/// Solo ConnectionRefused conta come "libera": un timeout (backlog dello
/// zombie pieno) significa che la porta e' ancora bound.
async fn wait_port_free(port: u16, secs: u64, log: &UpdaterLog) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        let probe = TcpStream::connect(format!("127.0.0.1:{}", port)).await;
        match probe {
            Err(e) => {
                let kind = e.kind();
                drop(e);
                if kind == std::io::ErrorKind::ConnectionRefused {
                    log.line(&format!("porta {} libera.", port));
                    return true;
                }
            }
            Ok(s) => drop(s),
        }
        if Instant::now() >= deadline {
            log.line(&format!(
                "WARNING: porta {} ancora occupata dopo {}s (socket zombie del server morto?): procedo comunque — il bind paziente del server copre il caso",
                port, secs
            ));
            return false;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Poll su 127.0.0.1:port per `secs`: true appena un server crosspilot
/// risponde READY (probe_server_ready — immune al falso positivo dello
/// zombie socket). Ogni probe riuscita viene subito chiusa: il server
/// vedra' un handshake abortito (peek timeout) — rumore innocuo.
async fn wait_port_up(port: u16, secs: u64, log: &UpdaterLog) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut attempt = 0u32;
    while Instant::now() < deadline {
        attempt += 1;
        if probe_server_ready(port).await {
            log.line(&format!(
                "porta {} risponde READY (tentativo {})",
                port, attempt
            ));
            return true;
        }
        if attempt % 10 == 1 {
            log.line(&format!(
                "attesa READY su porta {} (tentativo {})",
                port, attempt
            ));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    log.line(&format!("porta {} MAI in ascolto (READY) entro {}s", port, secs));
    false
}

/// Finestra di OSSERVAZIONE post-bind (BUG-13): per questo lasso
/// l'updater resta vivo e ricontrolla che il server rilanciato sia vivo
/// E in ascolto prima di dichiarare l'update completato.
///
/// PERCHE' 30s e non di meno: su H166 il server moriva 3-7s dopo il
/// bind. Con una finestra di 5s il kill a t+6s cadeva DOPO l'uscita
/// dell'updater: "COMPLETATO" nel log, server morto un attimo dopo e
/// nessuno vivo a fare rollback -> remote scuro (il sintomo esatto di
/// BUG-13). Restando vivo 30s l'updater e' ancora presente quando il
/// killer colpisce: registra il timestamp esatto della morte e puo'
/// ancora ripristinare `.old`. E' anche la "pausa diagnosi" della
/// ricetta del report: gli heartbeat periodici nel log file mostrano
/// che l'updater non viene mai ucciso (non e' il listener) e fissano
/// l'istante in cui il server cade.
const POST_BIND_OBSERVE_SECS: u64 = 30;

/// Cadence dei heartbeat "ancora vivo" dentro la finestra di osservazione.
const OBSERVE_HEARTBEAT_SECS: u64 = 5;

/// Wait-and-see post-bind (BUG-13): per `POST_BIND_OBSERVE_SECS`
/// ricontrolla ogni 500ms che il processo `child_pid` sia vivo E la
/// porta accetti ancora connessioni TCP, loggando un heartbeat ogni
/// `OBSERVE_HEARTBEAT_SECS`. Ritorna true solo se entrambe le condizioni
/// reggono per tutta la finestra.
///
/// PERCHE': il caso reale H101 — l'updater loggava "porta in ascolto
/// (tentativo 1)" e subito "update COMPLETATO", ma il processo era gia'
/// morto (o moriva un attimo dopo): bind riuscito NON equivale a server
/// stabile. `child_pid` e' il pid ritornato da spawn_detached (Some nel
/// path normale); con None (spawn via task scheduler) si verifica solo
/// la porta — un server morto chiude il listener, la prova resta valida.
async fn confirm_server_stable(child_pid: Option<u32>, port: u16, log: &UpdaterLog) -> bool {
    let started = Instant::now();
    let deadline = started + Duration::from_secs(POST_BIND_OBSERVE_SECS);
    let mut next_heartbeat = OBSERVE_HEARTBEAT_SECS;
    loop {
        if let Some(pid) = child_pid {
            let alive = process_alive(pid);
            if !alive {
                // Prova diretta della tesi BUG-13: il processo rilanciato
                // e' morto nonostante il bind riuscito — il log file
                // (sul remote) registra pid e timestamp della morte.
                let elapsed_dur = started.elapsed();
                let elapsed = elapsed_dur.as_secs();
                log.line(&format!(
                    "wait-and-see: processo {} MORTO a t+{}s dal bind \
                     (server caduto: AV/sessione/job/killer esterno?)",
                    pid, elapsed
                ));
                return false;
            }
        }
        // Probe READY (non bare connect): la socket zombie del predecessore
        // accetta SYN dal backlog senza rispondere — solo la riga READY
        // prova che un server crosspilot vero sta servendo la porta.
        let probe_ok = probe_server_ready(port).await;
        if !probe_ok {
            let elapsed_dur = started.elapsed();
            let elapsed = elapsed_dur.as_secs();
            log.line(&format!(
                "wait-and-see: porta {} non risponde READY a t+{}s dal bind (pid {:?}) — server morto dopo il bind",
                port, elapsed, child_pid
            ));
            return false;
        }
        let elapsed_dur = started.elapsed();
        let elapsed = elapsed_dur.as_secs();
        if elapsed >= next_heartbeat {
            // Heartbeat richiesto dalla ricetta BUG-13: dimostra nel log
            // che l'updater e' VIVO per tutta la finestra (non e' il
            // listener -> un killer del listener non puo' colpirlo) e
            // fissa la timeline esatta di un'eventuale morte del server.
            log.line(&format!(
                "heartbeat t+{}s: updater vivo (mode update, nessun listener), \
                 server pid {:?} vivo, porta {} in ascolto",
                elapsed, child_pid, port
            ));
            next_heartbeat = elapsed + OBSERVE_HEARTBEAT_SECS;
        }
        if Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    log.line(&format!(
        "wait-and-see OK: pid {:?} vivo e porta {} in ascolto dopo {}s di osservazione",
        child_pid, port, POST_BIND_OBSERVE_SECS
    ));
    true
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
    // Server-mode (port = Some): macro-blocco per-OS — task scheduler su
    // Windows (BUG-13: figli WMI uccisi ~3s dopo il bind su H166),
    // spawn_detached su unix. `spawn_detached` ritorna Some(pid); il
    // path task scheduler ritorna None (pid sconosciuto, check porta).
    //
    // Prima del rilancio si attende la liberazione REALE della porta
    // (BUG-13): il binario .old puo' essere un build senza bind paziente
    // — se la socket zombie del server appena morto e' ancora bound,
    // il rollback troverebbe AddrInUse e uscirebbe subito (osservato su
    // H166: "neanche il vecchio server binda"). Bounded 30s: se lo zombie
    // sopravvive si procede comunque (i build nuovi retryano da soli).
    if let Some(p) = port {
        wait_port_free(p, 30, log).await;
    }
    let spawn_res: Result<Option<u32>> = if port.is_some() {
        relaunch_server(target, relaunch, console, log).await
    } else {
        match spawn_detached(target, relaunch, console) {
            Ok(pid) => Ok(Some(pid)),
            Err(e) => Err(e),
        }
    };
    let restored_pid = match spawn_res {
        Ok(pid) => {
            log.line(&format!(
                "rollback: binario ripristinato rilanciato {:?} (pid {:?})",
                relaunch, pid
            ));
            pid
        }
        Err(e) => {
            log.line(&format!("FATAL rollback: spawn fallito: {}", e));
            return;
        }
    };
    // 5) Conferma bind + wait-and-see: solo in server-mode (client:
    // niente listener). Il settle check serve anche qui: il vecchio
    // binario puo' subire lo STESSO kill post-bind del nuovo (es. AV
    // che flagga entrambi gli exe unsigned — in quel caso il rollback
    // non ha salvato il remote e il log deve dirlo).
    let Some(port) = port else {
        log.line("rollback COMPLETATO (client-mode: nessuna porta da verificare)");
        return;
    };
    let up = wait_port_up(port, 30, log).await;
    if up && confirm_server_stable(restored_pid, port, log).await {
        log.line("rollback COMPLETATO: vecchio server di nuovo in ascolto e stabile");
    } else if up {
        log.line("FATAL rollback: vecchio server bindato poi morto — intervento manuale");
    } else {
        log.line("FATAL rollback: neanche il vecchio server binda — intervento manuale");
    }
}

/// Attende che il vecchio server muoia: per PID (preciso, path nuovo) o
/// per liberazione della porta TCP (fallback legacy / senza pid).
///
/// BUG-13 (H166): morte del pid != rilascio della porta. La socket
/// listening del processo morto puo' restare bound per decine di
/// secondi (socket zombie — netstat la mostrava LISTENING col pid morto
/// ~40s dopo): rilanciare subito il nuovo server gli faceva trovare
/// AddrInUse e uscire ~6s dopo — la "morte misteriosa" investigata.
/// Dopo la morte del pid si attende anche la liberazione reale della
/// porta (bounded PORT_RELEASE_WAIT_SECS: se lo zombie e' piu' longevo
/// si procede comunque — il bind paziente del server e' la rete finale).
async fn wait_server_down(wait_pid: Option<u32>, port: u16, wait_secs: u64, log: &UpdaterLog) {
    let deadline = Instant::now() + Duration::from_secs(wait_secs);
    if let Some(pid) = wait_pid {
        while Instant::now() < deadline {
            if !process_alive(pid) {
                log.line(&format!("pid {} terminato.", pid));
                // Morte del processo != porta libera: breve attesa del
                // rilascio della socket prima di swap + rilancio.
                wait_port_free(port, PORT_RELEASE_WAIT_SECS, log).await;
                return;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        log.line(&format!("WARNING: pid {} ancora vivo dopo {}s", pid, wait_secs));
    }
    // Porta: attesa che il listener muoia (complementare al pid, o unico
    // segnale quando il pid non e' noto — es. spawn via task scheduler).
    let free = wait_port_free(port, wait_secs, log).await;
    if !free {
        // Ultima spiaggia su Windows: kill diretto dei PID in ascolto
        // (riusa la logica AddrInUse del server). Sullo zombie il pid e' gia'
        // morto e il taskkill fallisce in modo innocuo.
        #[cfg(target_os = "windows")]
        {
            log.line(&format!("forzo kill listener su porta {}", port));
            let _ = crate::kill_listener_on_port_windows(port).await;
        }
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
/// Ritorna il PID del figlio: il chiamante lo passa a
/// confirm_server_stable per il wait-and-see post-bind (BUG-13).
fn spawn_detached(program: &Path, args: &[String], console: bool) -> Result<u32> {
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
    let pid = child.id();
    eprintln!(
        "[update] spawn detached pid={} {} {:?}",
        pid,
        program.display(),
        args
    );
    Ok(pid)
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

/// Igiene all'avvio su OGNI invocazione (non solo `--server`): se l'exe
/// corrente ha il nome canonico (`crosspilot` / `crosspilot.exe`,
/// case-insensitive) spazza gli artefatti residui dell'auto-update
/// nella sua stessa directory.
///
/// Il check sul nome canonico e' obbligatorio: uno staged
/// `crosspilot-<ts>[.exe]` in esecuzione (functional check `--version`
/// del deploy, oppure updater a meta' swap) NON deve mai cancellare se'
/// stesso ne' i file del proprio update — uno sweep fatto dal binario
/// giusto (`crosspilot.exe` post-swap) invece e' il momento ideale per
/// ripulire i residui del round precedente. Per la stessa ragione si
/// salta quando argv[1] e' `update`: un updater (ri)lanciato col nome
/// canonico non deve spazzare lo staged che sta per installare.
/// Best-effort: ogni errore e' solo loggato da sweep_staged, mai fatale.
/// Chiamata da main() dopo l'early return di --version (il functional
/// check dello staged non deve produrre side-effect).
pub fn startup_sweep() {
    let first_arg = std::env::args().nth(1).unwrap_or_default();
    if first_arg == "update" {
        return;
    }
    let self_exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return,
    };
    let self_name = match self_exe.file_name() {
        Some(n) => n.to_string_lossy(),
        None => return,
    };
    if !is_canonical_exe_name(&self_name) {
        return;
    }
    let Some(dir) = self_exe.parent() else {
        return;
    };
    sweep_staged(dir);
}

/// Nome canonico del binario installato: `crosspilot` (unix) o
/// `crosspilot.exe` (windows). Qualunque altra cosa — staged
/// `crosspilot-<ts>`, sidecar `crosspilot.linux`, exe rinominato —
/// non fa sweep all'avvio.
fn is_canonical_exe_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower == "crosspilot" || lower == "crosspilot.exe"
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
/// pub(crate): riusata da bootstrap_ssh per l'euristica OS del remote.
pub(crate) fn is_windows_path(p: &str) -> bool {
    let b = p.as_bytes();
    (b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':')
        || (p.starts_with("\\\\") && !p.starts_with('/'))
}

/// Directory parent di un path remoto, sep-aware (\' o '/').
/// pub(crate): riusata da bootstrap_ssh per i path degli artefatti.
pub(crate) fn remote_parent(p: &str) -> &str {
    match p.rfind(['\\', '/']) {
        Some(i) => &p[..i],
        None => p,
    }
}

/// Join dir+nome col separatore coerente col dir ('\\' se Windows, '/' altrove).
/// pub(crate): riusata da bootstrap_ssh per i path degli artefatti.
pub(crate) fn remote_join(dir: &str, name: &str) -> String {
    let sep = if dir.contains('\\') { "\\" } else { "/" };
    format!("{}{}{}", dir.trim_end_matches(['\\', '/']), sep, name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_exe_name_matching() {
        assert!(is_canonical_exe_name("crosspilot"));
        assert!(is_canonical_exe_name("crosspilot.exe"));
        assert!(is_canonical_exe_name("CrossPilot.EXE"));
        assert!(!is_canonical_exe_name("crosspilot-1758530400.exe"));
        assert!(!is_canonical_exe_name("crosspilot-1758530400"));
        assert!(!is_canonical_exe_name("crosspilot.linux"));
        assert!(!is_canonical_exe_name("crosspilot.exe.old"));
        assert!(!is_canonical_exe_name("other.exe"));
    }

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

    #[test]
    fn resolve_remote_os_dichiarato_vince_su_euristica() {
        // Tag handshake presente: vince sempre sull'euristica EXE_PATH
        // (caso reale: path atipici, mount point, exe rinominati).
        let os = resolve_remote_os(Some(version::RemoteOs::Linux), r"C:\ci\crosspilot.exe");
        assert_eq!(os, version::RemoteOs::Linux);
        let os = resolve_remote_os(Some(version::RemoteOs::Windows), "/srv/crosspilot");
        assert_eq!(os, version::RemoteOs::Windows);
    }

    #[test]
    fn resolve_remote_os_euristica_fallback() {
        // Senza tag: drive letter/UNC -> Windows, '/' -> Linux.
        let os = resolve_remote_os(None, r"C:\ci\crosspilot.exe");
        assert_eq!(os, version::RemoteOs::Windows);
        let os = resolve_remote_os(None, "/opt/crosspilot/crosspilot");
        assert_eq!(os, version::RemoteOs::Linux);
    }

    #[test]
    fn inbound_allow_cmd_dispatch_per_os() {
        // Macro-blocco firewall: lo stesso blocco produce il comando
        // giusto per l'OS del remote (netsh su Windows, POSIX su Linux).
        let win = inbound_allow_cmd(version::RemoteOs::Windows, 5330);
        assert!(win.contains("netsh advfirewall firewall add rule"));
        assert!(win.contains("localport=5330"));
        let lin = inbound_allow_cmd(version::RemoteOs::Linux, 5330);
        assert!(lin.contains("ufw allow $p/tcp"));
        assert!(lin.contains("--dport $p"));
        assert!(lin.contains("p=5330"));
    }

    #[test]
    fn firewall_scripts_entro_buffer_shell_mode() {
        // VINCOLO: handle_connection legge il comando shell-mode in UN
        // buffer da 1024 byte — entrambi i comandi devono starci.
        let win = windows_inbound_allow_cmd(65535);
        let lin = linux_inbound_allow_script(65535);
        assert!(win.len() <= 1024, "netsh cmd troppo lungo: {}", win.len());
        assert!(lin.len() <= 1024, "posix script troppo lungo: {}", lin.len());
    }

    #[test]
    fn legacy_spawn_cmd_dispatch_per_os() {
        // BLOCCO 5 legacy: task scheduler su Windows (i figli WMI
        // muoiono ~3s dopo il bind su alcune macchine — H166), setsid
        // su Linux; entrambi con --target esplicito (mai default_target()).
        let win = legacy_spawn_cmd(version::RemoteOs::Windows, r"C:\ci\crosspilot-1.exe", 5330, r"C:\ci\crosspilot.exe");
        assert!(win.contains("schtasks /Create /TN crosspilot-upd-"));
        assert!(win.contains("/RU SYSTEM /RL HIGHEST"));
        assert!(win.contains("schtasks /Run"));
        assert!(win.contains("schtasks /Delete"));
        assert!(win.contains("--port 5330"));
        assert!(win.contains("crosspilot-1.exe"));
        let lin = legacy_spawn_cmd(version::RemoteOs::Linux, "/opt/crosspilot-1", 5330, "/opt/crosspilot");
        assert!(lin.contains("setsid \"/opt/crosspilot-1\" update --target \"/opt/crosspilot\" --port 5330"));
    }

    #[test]
    fn env_merge_preserva_campi_remoti() {
        // Il .env remoto puo' avere campi propri (LOG_PATH, ambienti):
        // l'upsert deve cambiare SOLO SERVER_PORT (fix: l'overwrite cieco
        // cancellava LOG_PATH/ERR_PATH su H166).
        let mut lines: Vec<String> = vec![
            "# config remote".to_string(),
            "CROSSPILOT_LOG_PATH=C:\\crosspilot.log".to_string(),
            "CROSSPILOT_SERVER_PORT=9999".to_string(),
            "CROSSPILOT_ERR_PATH=C:\\crosspilot.err".to_string(),
        ];
        crate::envs::upsert_field(&mut lines, None, "SERVER_PORT", "5330");
        assert_eq!(lines.len(), 4);
        assert_eq!(lines[0], "# config remote");
        assert_eq!(lines[1], "CROSSPILOT_LOG_PATH=C:\\crosspilot.log");
        assert_eq!(lines[2], "CROSSPILOT_SERVER_PORT=5330");
        assert_eq!(lines[3], "CROSSPILOT_ERR_PATH=C:\\crosspilot.err");
    }

    #[test]
    fn env_merge_append_quando_assente() {
        let mut lines: Vec<String> = Vec::new();
        crate::envs::upsert_field(&mut lines, None, "SERVER_PORT", "15330");
        assert_eq!(lines, vec!["CROSSPILOT_SERVER_PORT=15330".to_string()]);
    }
}
