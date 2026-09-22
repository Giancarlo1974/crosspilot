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

use crate::{deploy, envs, path, proto, transfer, verify, version};
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
}

/// Dedup: un update per processo. Evita retry-storm quando l'update e'
/// fallito ma il server e' comunque raggiungibile (sync apre N connessioni).
static UPDATE_TRIED: AtomicBool = AtomicBool::new(false);

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
                        "[update] WARNING update remoto fallito: {:#} — proseguo col server corrente",
                        e
                    );
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
    let put_res = async {
        let mut s = open_conn().await?;
        transfer::put_client(&mut s, &tmp_exe_s, &staged_remote).await
    }
    .await;
    let _ = std::fs::remove_file(&tmp_exe);
    put_res.context("upload exe staged")?;
    eprintln!("[update] exe staged uploadato: {}", staged_remote);

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
        let put_res = async {
            let mut s = open_conn().await?;
            transfer::put_client(&mut s, &tmp_art_s, &artifact_remote).await
        }
        .await;
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
    let put_res = async {
        let mut s = open_conn().await?;
        transfer::put_client(&mut s, &tmp_env_s, &env_remote).await
    }
    .await;
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
            let spawn_cmd = if remote_windows {
                wmi_spawn_cmd(&staged_remote, port)
            } else {
                format!(
                    "setsid \"{}\" update --port {} >/dev/null 2>&1 &",
                    staged_remote, port
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

/// Comando PowerShell (EncodedCommand, UTF-16LE base64: zero problemi di
/// quoting via cmd /C) che crea il processo updater via WMI.
/// Win32_Process.Create spawna il processo dal servizio WMI: nasce FUORI
/// dal job object del server e sopravvive alla sua terminazione.
fn wmi_spawn_cmd(staged: &str, port: u16) -> String {
    let cmdline = format!("\"{}\" update --port {}", staged, port);
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

/// Entry point del sottocomando `update` (usato dallo staged binary).
/// `target`: exe da sostituire (default: `crosspilot[.exe]` nella dir dello
/// staged). `wait_pid`/`port`: condizioni di attesa morte server.
/// `relaunch_args`: argv per il rilancio post-swap (default `["--server"]`;
/// il self-update di un client Windows rilancia gli argv originali).
/// `console`: su Windows rilancia con una console nuova (output visibile —
/// usato per i comandi client; i server restano hidden).
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

    eprintln!(
        "[update] updater: self={} target={} wait_pid={:?} port={} wait={}s",
        self_exe.display(),
        target_path.display(),
        wait_pid,
        port,
        wait_secs
    );

    // --- Step 1: attende la morte del vecchio server ---
    wait_server_down(wait_pid, port, wait_secs).await;
    // Grace: rilascio handle file post-mortem (e coda AV).
    tokio::time::sleep(Duration::from_millis(500)).await;

    // --- Step 2: swap rename-first ---
    // target -> target.old (rollback point), poi self -> target.
    // Su Windows il rename di un exe running e' consentito: lo swap
    // funziona anche se il vecchio processo e' ancora in chiusura.
    let dir = target_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let mut old_os = target_path.as_os_str().to_owned();
    old_os.push(".old");
    let old_path = PathBuf::from(old_os);
    if target_path.exists() {
        let _ = std::fs::remove_file(&old_path);
        retry_rename(&target_path, &old_path, 60)
            .await
            .context("rename target -> .old")?;
        eprintln!("[update] backup: {}", old_path.display());
    }
    match retry_rename(&self_exe, &target_path, 60).await {
        Ok(()) => eprintln!("[update] staged -> {} (rename)", target_path.display()),
        Err(e) => {
            // Fallback copy (es. rename cross-volume impossibile — non
            // dovrebbe accadere: staged e target sono nella stessa dir).
            eprintln!("[update] rename fallito ({}), fallback copy...", e);
            std::fs::copy(&self_exe, &target_path).with_context(|| {
                format!("copy {} -> {}", self_exe.display(), target_path.display())
            })?;
            eprintln!(
                "[update] staged -> {} (copy; lo staged resta su disco, lo sweep pulisce)",
                target_path.display()
            );
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
    if let Err(e) = write_ver_file(&dir, &target_path) {
        eprintln!("[update] WARNING scrittura .ver: {}", e);
    }
    sweep_staged(&dir);

    // --- Step 4: rilancio dell'exe aggiornato ---
    // Default: --server (update del server). Il self-update di un client
    // Windows passa gli argv originali via --arg.
    let relaunch = if relaunch_args.is_empty() {
        vec!["--server".to_string()]
    } else {
        relaunch_args
    };
    spawn_detached(&target_path, &relaunch, console)?;
    eprintln!(
        "[update] rilanciato {} {:?}. Update completato.",
        target_path.display(),
        relaunch
    );
    Ok(())
}

/// Attende che il vecchio server muoia: per PID (preciso, path nuovo) o
/// per liberazione della porta TCP (fallback legacy / senza pid).
async fn wait_server_down(wait_pid: Option<u32>, port: u16, wait_secs: u64) {
    let deadline = Instant::now() + Duration::from_secs(wait_secs);
    if let Some(pid) = wait_pid {
        while Instant::now() < deadline {
            if !process_alive(pid) {
                eprintln!("[update] pid {} terminato.", pid);
                return;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        eprintln!("[update] WARNING: pid {} ancora vivo dopo {}s", pid, wait_secs);
    }
    // Porta: attesa che il listener muoia (complementare al pid, o unico
    // segnale quando il pid non e' noto — es. spawn WMI legacy).
    while Instant::now() < deadline {
        if TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .is_err()
        {
            eprintln!("[update] porta {} libera.", port);
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    eprintln!(
        "[update] WARNING: porta {} ancora occupata dopo {}s",
        port, wait_secs
    );
    // Ultima spiaggia su Windows: kill diretto dei PID in ascolto
    // (riusa la logica AddrInUse del server).
    #[cfg(target_os = "windows")]
    {
        eprintln!("[update] forzo kill listener su porta {}", port);
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
