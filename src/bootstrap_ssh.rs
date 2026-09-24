// Modulo bootstrap_ssh: cold bootstrap del server via canale SSH
// unificato (russh — spec docs/ssh-unified-prescan-bootstrap-spec.md §1).
// Speculare a bootstrap.rs (WinRM) e bootstrap_smb.rs: stesso contratto —
// pre-check stato build, deploy staged, avvio detached, polling TCP — ma
// il trasporto e' ssh_transport (connect+auth a catena+TOFU, exec, SFTP).
//
// DUE DIALETTI (§1.4, generatori in bootstrap_ssh_cmds.rs): la sessione
// SSH e' una sola, cambiano i comandi remoti in base all'OS del REMOTE:
//   - Posix (remote unix): test -f / sha256sum / chmod / mv / setsid;
//   - PowerShell (remote Windows via OpenSSH-for-Windows): Test-Path /
//     Get-FileHash / Move-Item / netsh / schtasks — SEMPRE via
//     `powershell -NoProfile -EncodedCommand` (immune al DefaultShell).
//   Le file ops (upload/download/stat) NON dipendono dalla shell remota:
//   passano per il sottosistema SFTP (decisivo per SSH->Windows).
//
// Selezione dialetto: bootstrap::remote_is_unix() — deterministico e
// testabile (v1: niente auto-detect via `uname`, spec §1.4).
//
// AUTH: a catena in ssh_transport (agent -> key files -> SSH_PASS/PASS).
// L'host key e' verificata TOFU su crosspilot_known_hosts accanto al
// .env; mismatch -> HostKeyMismatch FATALE (non si prosegue: MITM?).
//
// Campi ambiente: SSH_HOST (fallback HOST), SSH_PORT (default 22),
// SSH_USER (fallback USER), SSH_KEY, SSH_PASS (fallback PASS),
// SSH_INSECURE_NO_HOSTKEY (dev), EXE_PATH, CLIENT_PORT/SERVER_PORT,
// LOG_PATH/ERR_PATH (opzionali).
//
// Deploy staged (mai sovrascrivere l'exe in uso prima delle verifiche):
//   SFTP write staged -> hash remoto -> chmod/--version -> swap con .old
//   -> artefatti + .ver + .env. Identico contratto degli altri canali.

use anyhow::{bail, Context, Result};

use crate::bootstrap;
use crate::bootstrap_ssh_cmds::{
    copy_cmd, dialect, file_hash_cmd, mkdir_cmd, remote_build_info_cmd, rm_cmd, sftp_path,
    staged_name, swap_cmd,
};
pub use crate::bootstrap_ssh_cmds::Dialect;
use crate::bootstrap_ssh_cmds::{
    diag_cmd, firewall_cmd, functional_check_cmd, start_server_cmd, sudo_wrap_posix,
};
use crate::deploy;
use crate::envs;
use crate::self_update;
use crate::ssh_transport::{ExecOut, SshCtx, SshSession};
use crate::update;
use crate::version::{self, RemoteBuildInfo};

/// Risolve endpoint+credenziali SSH dall'ambiente attivo (spec §1.5):
/// SSH_HOST (fallback HOST), SSH_PORT (default 22), SSH_USER (fallback
/// USER, poi utente di processo), SSH_KEY, SSH_PASS (fallback PASS —
/// su remote Windows sono tipicamente le stesse credenziali WinRM).
fn ssh_context() -> SshCtx {
    let host = match envs::var("SSH_HOST") {
        Some(h) => h,
        None => envs::var("HOST").unwrap_or_else(|| "127.0.0.1".to_string()),
    };
    let port = match envs::var("SSH_PORT") {
        Some(p) => p.parse::<u16>().unwrap_or(22),
        None => 22,
    };
    let user = match envs::var("SSH_USER") {
        Some(u) => u,
        None => match envs::var("USER") {
            Some(u) => u,
            // Nessun campo: utente di processo (USER unix / USERNAME win).
            None => match std::env::var("USER") {
                Ok(u) => u,
                Err(_) => std::env::var("USERNAME").unwrap_or_else(|_| "root".to_string()),
            },
        },
    };
    let key_path = envs::var("SSH_KEY");
    // SSH_PASS dedicato; fallback PASS = credenziali WinRM (caso tipico
    // di SSH->Windows, dove USER/PASS sono gia' configurati).
    let password = ssh_password();
    // Mai loggare la password (spec §3: stessa disciplina di ssh_context
    // storico — solo target/porta/utente).
    eprintln!(
        "[DEBUG] ssh_context: {}@{}:{} key={} pass={}",
        user,
        host,
        port,
        key_path.as_deref().unwrap_or("<default>"),
        if password.is_some() { "set" } else { "none" }
    );
    SshCtx {
        host,
        port,
        user,
        key_path,
        password,
    }
}

/// Password SSH configurata: SSH_PASS, fallback PASS. Condivisa da
/// ssh_context (auth) e dal macro-blocco firewall (sudo -S via stdin).
fn ssh_password() -> Option<String> {
    envs::var("SSH_PASS").or_else(|| envs::var("PASS"))
}

// ---------------------------------------------------------------------------
// Primitive sul trasporto (sessione gia' autenticata)
// ---------------------------------------------------------------------------

/// Esegue un comando remoto e ritorna stdout/stderr/exit-status.
/// `what` compare nei log di contesto.
async fn ssh_run(sess: &SshSession, cmd: &str, what: &str) -> Result<ExecOut> {
    let out = sess
        .exec(cmd)
        .await
        .with_context(|| format!("ssh exec ({})", what))?;
    Ok(out)
}

/// Scrive `data` su `remote_path` via SFTP (shell-independent: funziona
/// identico su posix e Windows). La directory parent viene creata prima
/// via exec nel dialetto giusto (SFTP non crea i livelli intermedi).
async fn ssh_write(
    sess: &SshSession,
    d: Dialect,
    remote_path: &str,
    data: &[u8],
) -> Result<()> {
    let dir = update::remote_parent(remote_path).to_string();
    let mk = ssh_run(sess, &mkdir_cmd(d, &dir), "mkdir remoto").await;
    if let Err(e) = mk {
        eprintln!("[deploy-ssh] WARNING mkdir {}: {}", dir, e);
    }
    let sp = sftp_path(d, remote_path);
    sess.write_file(&sp, data)
        .await
        .with_context(|| format!("upload SFTP {}", remote_path))?;
    // Cross-check dimensione post-upload: il controllo forte e' l'hash
    // SHA-256 piu' avanti, ma un size mismatch qui e' un segnale precoce
    // (e copre i path dove l'hash non viene ricontrollato, es. .ver/.env).
    let attrs = sess.stat(&sp).await;
    match attrs {
        Some(a) => {
            if a.size != Some(data.len() as u64) {
                eprintln!(
                    "[deploy-ssh] WARNING size mismatch su {}: attesi {} remoti {:?}",
                    remote_path,
                    data.len(),
                    a.size
                );
            }
        }
        None => eprintln!(
            "[DEBUG] deploy-ssh: stat post-upload {} non disponibile",
            remote_path
        ),
    }
    Ok(())
}

/// SHA-256 (hex) del file remoto, o None se assente/illeggibile.
/// Complemento di remote_build_info per i check sugli artefatti extra.
async fn ssh_file_hash(sess: &SshSession, d: Dialect, remote_path: &str) -> Option<String> {
    let cmd = file_hash_cmd(d, remote_path);
    let out = ssh_run(sess, &cmd, "hash remoto").await.ok()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let hash = stdout.trim().to_string();
    if hash.is_empty() {
        None
    } else {
        Some(hash)
    }
}

/// Equivalente SSH di deploy::remote_build_info: UNA sola chiamata exec
/// (nel dialetto giusto) che riporta presenza exe + hash + sidecar +
/// contenuto .ver, parsata col medesimo version::parse_remote_info.
/// Un remote senza .ver = deploy legacy -> ts effettivo 0 -> upgrade.
async fn remote_build_info(
    sess: &SshSession,
    d: Dialect,
    exe_path: &str,
) -> Result<RemoteBuildInfo> {
    let dir = update::remote_parent(exe_path);
    let cmd = remote_build_info_cmd(d, exe_path, dir);
    let out = ssh_run(sess, &cmd, "remote_build_info").await?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let info = version::parse_remote_info(&stdout);
    eprintln!(
        "[DEBUG] remote_build_info (ssh/{:?}): exe_present={} ts={:?} linux_present={}",
        d, info.exe_present, info.build_ts, info.linux_present
    );
    if let Some(h) = &info.exe_sha256 {
        eprintln!(
            "[DEBUG] remote_build_info (ssh): exe_sha256={}",
            &h[..16.min(h.len())]
        );
    }
    Ok(info)
}

/// Preflight SSH (analogo di bootstrap::channel_probe) per il fallback
/// di update::reconcile: verifica che il canale SSH sia VIVO prima di
/// fermare un server funzionante — fermarlo senza via di ripristino
/// sarebbe un brick volontario.
pub async fn probe(exe_path: &str) -> Option<RemoteBuildInfo> {
    let ctx = ssh_context();
    let d = dialect();
    let sess = match SshSession::connect(&ctx).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[update-fallback] preflight SSH fallito (connect): {}", e);
            return None;
        }
    };
    match remote_build_info(&sess, d, exe_path).await {
        Ok(info) => {
            eprintln!(
                "[update-fallback] preflight SSH OK: ts remoto={:?} locale={} exe_present={}",
                info.build_ts,
                version::BUILD_TS,
                info.exe_present
            );
            Some(info)
        }
        Err(e) => {
            eprintln!("[update-fallback] preflight SSH fallito: {}", e);
            None
        }
    }
}

/// Deploy completo e idempotente via SSH, speculare a deploy::deploy_exe:
/// staged upload -> hash -> chmod -> functional check --version -> swap
/// (exe->exe.old, staged->exe), poi artefatti collaterali, .ver e .env.
/// `info` e' lo stato remoto gia' letto (evita un secondo round-trip).
///
/// Payload per-OS del REMOTE: binario linux (embed musl / self-read) su
/// remote unix, PE (embed / self-read su client Windows) su remote win.
async fn deploy_exe(
    sess: &SshSession,
    d: Dialect,
    exe_path: &str,
    info: &RemoteBuildInfo,
) -> Result<()> {
    let payload = match d {
        Dialect::Posix => deploy::linux_bin_bytes().unwrap_or_default(),
        Dialect::PowerShell => deploy::windows_exe_bytes().unwrap_or_default(),
    };
    if payload.is_empty() {
        bail!(
            "artefatto {} non disponibile (embed vuoto: build senza \
             build-release.sh) — deploy SSH non possibile",
            match d {
                Dialect::Posix => "linux",
                Dialect::PowerShell => "windows",
            }
        );
    }
    let local_hash = deploy::sha256_bytes(&payload);
    eprintln!(
        "[deploy-ssh] build locale: ts={} payload {:?} = {} byte sha256={}",
        version::BUILD_TS,
        d,
        payload.len(),
        &local_hash[..16.min(local_hash.len())]
    );

    // --- Step 1: exe (staged + functional check + swap) ---
    let mut aligned = false;
    if info.exe_present {
        if let Some(h) = &info.exe_sha256 {
            aligned = h.eq_ignore_ascii_case(&local_hash);
        }
    }
    if aligned {
        eprintln!("[deploy-ssh] exe remoto gia' allineato (hash match). Skip upload exe.");
    } else {
        let staged = staged_name(d, exe_path);
        eprintln!(
            "[deploy-ssh] exe remoto {}: upload staged di {} byte -> {} ...",
            if info.exe_present { "obsoleto" } else { "mancante" },
            payload.len(),
            staged
        );
        ssh_write(sess, d, &staged, &payload).await?;

        // Hash dello staged PRIMA di toccare l'exe corrente.
        let staged_hash = ssh_file_hash(sess, d, &staged)
            .await
            .unwrap_or_default();
        if !staged_hash.eq_ignore_ascii_case(&local_hash) {
            let _ = ssh_run(sess, &rm_cmd(d, &staged), "cleanup staged").await;
            bail!(
                "SHA-256 MISMATCH staged '{}': atteso {} remoto {}",
                staged,
                &local_hash[..16.min(local_hash.len())],
                &staged_hash[..16.min(staged_hash.len())]
            );
        }

        // Functional check (come nel path WinRM): '<staged>' --version
        // deve uscire 0 e stampare il build_ts locale — prova che il
        // binario e' integro ED eseguibile su QUEL sistema.
        let check_cmd = functional_check_cmd(d, &staged);
        let out = ssh_run(sess, &check_cmd, "functional check staged").await?;
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let mut staged_ts: Option<u64> = None;
        for line in stdout.lines() {
            if let Some(ts) = version::parse_version_ts(line) {
                staged_ts = Some(ts);
            }
        }
        eprintln!(
            "[DEBUG] deploy-ssh functional check: exit={:?} ts={:?} atteso={}",
            out.code,
            staged_ts,
            version::BUILD_TS
        );
        if out.code != Some(0) || staged_ts != Some(version::BUILD_TS) {
            let _ = ssh_run(sess, &rm_cmd(d, &staged), "cleanup staged").await;
            bail!(
                "functional check fallito su '{}': exit={:?} ts={:?} (atteso {}). \
                 Exe originale NON toccato.",
                staged,
                out.code,
                staged_ts,
                version::BUILD_TS
            );
        }

        // Swap: exe -> exe.old, staged -> exe, poi hash finale.
        let out = ssh_run(sess, &swap_cmd(d, exe_path, &staged), "swap exe").await?;
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        if out.code != Some(0) {
            let stderr = String::from_utf8_lossy(&out.stderr);
            bail!(
                "swap staged -> {} fallito (exit {:?}): {}",
                exe_path,
                out.code,
                stderr.trim()
            );
        }
        let final_hash = stdout.trim().to_string();
        if !final_hash.eq_ignore_ascii_case(&local_hash) {
            bail!(
                "SHA-256 MISMATCH post-swap '{}': atteso {} remoto {}",
                exe_path,
                &local_hash[..16.min(local_hash.len())],
                &final_hash[..16.min(final_hash.len())]
            );
        }
        eprintln!(
            "[deploy-ssh] '{}' aggiornato e verificato (backup in .old).",
            exe_path
        );
    }

    let dir = update::remote_parent(exe_path).to_string();

    // --- Step 2: sidecar crosspilot.linux ---
    // Posix: il sidecar E' lo stesso payload dell'exe deployato -> copia
    // locale sul remote (idempotente, zero upload).
    // PowerShell: l'exe e' un PE — il sidecar va UPLOADATO dagli embed.
    let linux_path = update::remote_join(&dir, version::LINUX_SIDECAR_NAME);
    match d {
        Dialect::Posix => {
            let out = ssh_run(sess, &copy_cmd(d, exe_path, &linux_path), "sidecar linux").await;
            match out {
                Ok(o) if o.code == Some(0) => {
                    eprintln!("[deploy-ssh] sidecar {} allineato all'exe.", linux_path)
                }
                Ok(o) => eprintln!(
                    "[deploy-ssh] WARNING copia sidecar: {}",
                    String::from_utf8_lossy(&o.stderr).trim()
                ),
                Err(e) => return Err(e),
            }
        }
        Dialect::PowerShell => {
            let linux_data = deploy::linux_bin_bytes().unwrap_or_default();
            if linux_data.is_empty() {
                eprintln!(
                    "[deploy-ssh] WARNING: asset linux non embeddato: il remote \
                     non potra' servire self-update a client Linux"
                );
            } else {
                let local_linux_hash = deploy::sha256_bytes(&linux_data);
                let remote_hash = ssh_file_hash(sess, d, &linux_path).await;
                let mut linux_aligned = false;
                if let Some(h) = &remote_hash {
                    linux_aligned = h.eq_ignore_ascii_case(&local_linux_hash);
                }
                if linux_aligned {
                    eprintln!("[deploy-ssh] sidecar linux remoto gia' allineato. Skip.");
                } else {
                    let res = ssh_write(sess, d, &linux_path, &linux_data).await;
                    match res {
                        Ok(()) => eprintln!("[deploy-ssh] sidecar {} uploadato.", linux_path),
                        Err(e) => eprintln!("[deploy-ssh] WARNING upload sidecar: {}", e),
                    }
                }
            }
        }
    }

    // --- Step 3: artefatto crosspilot.exe (per futuri client Windows) ---
    // Posix: l'exe deployato e' linux -> il PE embeddato va materializzato
    //        come artefatto scaricabile.
    // PowerShell: l'exe deployato E' il PE -> copia locale verso
    //        <dir>\crosspilot.exe (skip se EXE_PATH e' gia' quel nome).
    let mut win_hash: Option<String> = None;
    match d {
        Dialect::Posix => {
            let win = deploy::windows_exe_bytes().unwrap_or_default();
            if win.is_empty() {
                eprintln!(
                    "[deploy-ssh] WARNING: asset windows non embeddato: il remote \
                     non potra' servire self-update a client Windows"
                );
            } else {
                let local_win_hash = deploy::sha256_bytes(&win);
                let win_path = update::remote_join(&dir, "crosspilot.exe");
                let remote_win_hash = ssh_file_hash(sess, d, &win_path).await;
                let mut win_aligned = false;
                if let Some(h) = &remote_win_hash {
                    win_aligned = h.eq_ignore_ascii_case(&local_win_hash);
                }
                if win_aligned {
                    eprintln!("[deploy-ssh] crosspilot.exe remoto gia' allineato. Skip.");
                } else {
                    match ssh_write(sess, d, &win_path, &win).await {
                        Ok(()) => eprintln!("[deploy-ssh] artefatto {} uploadato.", win_path),
                        Err(e) => eprintln!("[deploy-ssh] WARNING upload crosspilot.exe: {}", e),
                    }
                }
                win_hash = Some(local_win_hash);
            }
        }
        Dialect::PowerShell => {
            let win_path = update::remote_join(&dir, "crosspilot.exe");
            if exe_path == win_path {
                // EXE_PATH e' gia' crosspilot.exe: l'exe deployato E'
                // l'artefatto scaricabile, niente copia.
                eprintln!("[deploy-ssh] exe e' gia' l'artefatto crosspilot.exe. Skip copia.");
            } else {
                let out =
                    ssh_run(sess, &copy_cmd(d, exe_path, &win_path), "artefatto exe").await;
                match out {
                    Ok(o) if o.code == Some(0) => {
                        eprintln!("[deploy-ssh] artefatto {} allineato all'exe.", win_path)
                    }
                    Ok(o) => eprintln!(
                        "[deploy-ssh] WARNING copia artefatto exe: {}",
                        String::from_utf8_lossy(&o.stderr).trim()
                    ),
                    Err(e) => eprintln!("[deploy-ssh] WARNING copia artefatto exe: {}", e),
                }
            }
            win_hash = Some(local_hash.clone());
        }
    }

    // --- Step 4: .ver (metadati per bootstrap/self-update futuri) ---
    // EXE_SHA256 descrive l'artefatto WINDOWS scaricabile; LINUX_SHA256
    // l'hash del sidecar (posix: stesso payload dell'exe; windows: embed).
    let exe_ver_hash = match &win_hash {
        Some(h) => h.clone(),
        None => local_hash.clone(),
    };
    let linux_ver_hash: Option<String> = match d {
        Dialect::Posix => Some(local_hash.clone()),
        Dialect::PowerShell => {
            let linux_data = deploy::linux_bin_bytes().unwrap_or_default();
            if linux_data.is_empty() {
                None
            } else {
                Some(deploy::sha256_bytes(&linux_data).to_uppercase())
            }
        }
    };
    let ver_content = version::render_ver_file(
        version::BUILD_TS,
        &exe_ver_hash.to_uppercase(),
        linux_ver_hash.as_deref(),
    );
    let ver_path = update::remote_join(&dir, version::VER_FILE_NAME);
    match ssh_write(sess, d, &ver_path, ver_content.as_bytes()).await {
        Ok(()) => eprintln!("[deploy-ssh] .ver scritto: {} (ts={})", ver_path, version::BUILD_TS),
        Err(e) => eprintln!("[deploy-ssh] WARNING scrittura .ver: {}", e),
    }

    // --- Step 5: .env minimale per il server (CROSSPILOT_SERVER_PORT) ---
    // Posix: porta vista dal client (CLIENT_PORT — comportamento storico
    // del canale SSH unix, identico alla porta pollata). PowerShell:
    // SERVER_PORT come nel path WinRM, con fallback CLIENT_PORT (la porta
    // effettivamente pollata) per coprire le configurazioni che settano
    // solo quest'ultima.
    let port_field = match d {
        Dialect::Posix => "CLIENT_PORT",
        Dialect::PowerShell => "SERVER_PORT",
    };
    let port_raw = match envs::var(port_field) {
        Some(p) => Some(p),
        None => match d {
            Dialect::Posix => None,
            Dialect::PowerShell => envs::var("CLIENT_PORT"),
        },
    };
    let port = match port_raw {
        Some(p) => p.parse::<u16>().unwrap_or(5330),
        None => 5330,
    };
    let env_content = format!("CROSSPILOT_SERVER_PORT={}\n", port);
    let env_remote = update::remote_join(&dir, ".env");
    match ssh_write(sess, d, &env_remote, env_content.as_bytes()).await {
        Ok(()) => eprintln!("[deploy-ssh] .env remoto scritto (porta {})", port),
        Err(e) => eprintln!("[deploy-ssh] WARNING scrittura .env: {}", e),
    }

    eprintln!(
        "[deploy-ssh] artefatti remoti allineati al build locale (ts={})",
        version::BUILD_TS
    );
    Ok(())
}

/// Self-update via SSH (remote piu' nuovo del client): download del
/// sidecar crosspilot.linux via SFTP read (binario raw, shell-
/// independent — sostituisce il vecchio `cat` su stdout), poi
/// install_staged_file condiviso (hash + chmod + --version + rename
/// atomico + re-exec). MAI downgrade: chiamata solo se remote_ts >
/// locale. Su successo NON ritorna (re-exec sostituisce il processo).
async fn self_update_ssh(
    sess: &SshSession,
    d: Dialect,
    exe_path: &str,
    remote_ts: u64,
    expected_sha256: Option<&str>,
) -> Result<()> {
    // Il sidecar e' un binario linux: inutile (e il rename fallirebbe)
    // su client Windows — stesso vincolo del path WinRM.
    if cfg!(target_os = "windows") {
        bail!("self-update SSH non supportato su client Windows");
    }
    let dir = update::remote_parent(exe_path);
    let sidecar = update::remote_join(dir, version::LINUX_SIDECAR_NAME);
    eprintln!(
        "[self-update] remote piu' nuovo (ts={} > locale {}): download '{}' via SFTP...",
        remote_ts,
        version::BUILD_TS,
        sidecar
    );
    let sp = sftp_path(d, &sidecar);
    let data = sess
        .read_file(&sp)
        .await
        .with_context(|| format!("sidecar '{}' non leggibile sul remote", sidecar))?;
    if data.is_empty() {
        bail!("sidecar '{}' vuoto sul remote", sidecar);
    }
    eprintln!("[self-update] scaricati {} byte", data.len());

    let self_path = std::env::current_exe().context("current_exe")?;
    let staged = self_update::staged_path(&self_path);
    std::fs::write(&staged, &data)
        .with_context(|| format!("scrittura {}", staged.display()))?;
    // install_staged_file: verifica hash + functional check locale +
    // rename atomico + re-exec (non ritorna su successo).
    let result = self_update::install_staged_file(&staged, remote_ts, expected_sha256).await;
    if result.is_err() {
        let _ = std::fs::remove_file(&staged);
    }
    result
}

/// Avvio detached del server nel dialetto giusto (setsid | schtasks).
/// Il controllo di successo legge il marker emesso dallo script:
/// STARTED su posix, RUNAS=<mode> su Windows (la catena schtasks la
/// stampa; FAILED = tutte le modalita' fallite).
async fn start_server(sess: &SshSession, d: Dialect, exe_path: &str, user: &str) -> Result<()> {
    let cmd = start_server_cmd(d, exe_path, user);
    let out = ssh_run(sess, &cmd, "avvio server").await?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    match d {
        Dialect::Posix => {
            if out.code != Some(0) || !stdout.contains("STARTED") {
                let stderr = String::from_utf8_lossy(&out.stderr);
                bail!("avvio server via SSH fallito: {}", stderr.trim());
            }
            eprintln!("[bootstrap-ssh] server avviato detached (setsid).");
        }
        Dialect::PowerShell => {
            // Interpretazione RUNAS= condivisa col path WinRM.
            bootstrap::report_runas_mode(&stdout, user);
            let failed = stdout.contains("RUNAS=FAILED");
            if out.code != Some(0) || failed {
                let stderr = String::from_utf8_lossy(&out.stderr);
                bail!(
                    "avvio server via SSH/schtasks fallito (exit {:?}): {}",
                    out.code,
                    stderr.trim()
                );
            }
        }
    }
    Ok(())
}

/// MACRO-BLOCCO firewall (speculare a bootstrap::ensure_firewall_rule
/// WinRM e bootstrap_smb): assicura l'inbound TCP/<porta> sul remote
/// PRIMA dell'avvio del server. Senza regola un server vivo e in
/// ascolto e' indistinguibile da uno spento visto dal client (SYN
/// droppato -> "connect timeout"). Best-effort: errori solo loggati.
async fn ensure_inbound_allow(sess: &SshSession, d: Dialect) {
    let port = bootstrap::server_tcp_port();
    let cmd = firewall_cmd(d, port);
    // Remote Posix + password nota: i frontend firewall (ufw, iptables,
    // nft) richiedono root — un utente sudoer fallirebbe comunque
    // (FW=fail:*). Primo tentativo via `sudo -S` con la password su
    // stdin del canale (exec_stdin): mai in argv ne' nei log remoti.
    // Se l'output non contiene il marker FW= (sudo assente, password
    // errata o diversa da SSH_PASS) si cade sul run non privilegiato,
    // che produce l'evidenza diagnostica come prima.
    if d == Dialect::Posix {
        if let Some(pw) = ssh_password() {
            let wrapped = sudo_wrap_posix(&cmd);
            match sess
                .exec_stdin(&wrapped, format!("{}\n", pw).as_bytes())
                .await
            {
                Ok(out) if String::from_utf8_lossy(&out.stdout).contains("FW=") => {
                    eprintln!(
                        "[bootstrap-ssh] firewall: {}",
                        String::from_utf8_lossy(&out.stdout).trim()
                    );
                    return;
                }
                Ok(_) => eprintln!(
                    "[bootstrap-ssh] firewall: escalation sudo senza esito, retry non privilegiato"
                ),
                Err(e) => eprintln!("[bootstrap-ssh] WARNING firewall sudo: {}", e),
            }
        }
    }
    match ssh_run(sess, &cmd, "regola firewall").await {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if stdout.is_empty() {
                eprintln!("[bootstrap-ssh] firewall: comando eseguito (nessun output)");
            } else {
                eprintln!("[bootstrap-ssh] firewall: {}", stdout);
            }
        }
        Err(e) => eprintln!("[bootstrap-ssh] WARNING regola firewall: {}", e),
    }
}

/// Diagnostica post-bootstrap-fallito via SSH (analogo di
/// remote_startup_diag WinRM): riporta processo vivo, porta in ascolto
/// locale e frontend firewall. Posix usa righe PROC:/LISTEN:/FWTOOL:;
/// Windows lo script+parser condivisi col path WinRM
/// (righe PROC=/LISTEN=/FW=).
async fn remote_startup_diag(sess: &SshSession, d: Dialect) {
    let port = bootstrap::server_tcp_port();
    eprintln!("[bootstrap-ssh] server non in ascolto dopo 30s: diagnostica remota via SSH...");
    let cmd = diag_cmd(d, port);
    match ssh_run(sess, &cmd, "diagnostica").await {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            eprintln!("[bootstrap-ssh] diagnostica remota:\n{}", stdout.trim());
            match d {
                Dialect::Posix => {
                    let has_proc = stdout.contains("PROC:");
                    let has_listen = stdout.contains("LISTEN:");
                    // READY_PROBE (diag_cmd Posix): banner letto via
                    // bash /dev/tcp su 127.0.0.1. Il server binda SUBITO
                    // ma risponde READY solo dopo ensure_inbound_allow_local
                    // + self_describe — che ricalcola gli SHA-256 degli
                    // artefatti ad ogni avvio e puo' durare decine di
                    // secondi (caso H41: 659MB appena uploadati -> ~50s
                    // di "not ready" pur essendo in LISTEN; la vecchia
                    // euristica PROC+LISTEN concludeva "e' il firewall",
                    // verdetto errato). Loopback non attraversa le regole
                    // inbound: READY ok = filtro esterno reale; READY
                    // fail = server ancora in init o bloccato.
                    let ready_probe_done = stdout.contains("READY_PROBE:");
                    let ready_probe_ok = stdout.contains("READY_PROBE: ok");
                    // Debug log di supporto: l'esito del probe e' la prova
                    // diretta della tesi (init lenta vs filtro esterno).
                    eprintln!(
                        "[DEBUG] diag: proc={} listen={} ready_probe={}",
                        has_proc,
                        has_listen,
                        if !ready_probe_done {
                            "n/a"
                        } else if ready_probe_ok {
                            "ok"
                        } else {
                            "fail"
                        }
                    );
                    if has_proc && has_listen {
                        if ready_probe_ok {
                            eprintln!(
                                "[bootstrap-ssh] READY su loopback OK ma porta {} irraggiungibile \
                                 dal client: e' la rete/firewall tra client e server a bloccare \
                                 (vedi righe FWTOOL per il frontend eventualmente da configurare).",
                                port
                            );
                        } else if ready_probe_done {
                            eprintln!(
                                "[bootstrap-ssh] processo ATTIVO e porta {} in ascolto ma NESSUN \
                                 READY su loopback: server ancora in inizializzazione (self_describe \
                                 ricalcola gli hash degli artefatti ad ogni avvio) o bloccato — \
                                 NON e' detto che sia il firewall. Controlla server.err sul remote.",
                                port
                            );
                        } else {
                            eprintln!(
                                "[bootstrap-ssh] processo ATTIVO e porta {} in ascolto LOCALE: \
                                 il server e' vivo (probe READY non disponibile: bash assente) — \
                                 possibile filtro rete/firewall (vedi FWTOOL) oppure init lenta \
                                 (self_describe su artefatti grandi).",
                                port
                            );
                        }
                    } else if has_proc {
                        eprintln!(
                            "[bootstrap-ssh] processo ATTIVO ma porta {} NON in ascolto: \
                             bind fallito (porta occupata? .env stale?).",
                            port
                        );
                    } else {
                        eprintln!(
                            "[bootstrap-ssh] NESSUN processo crosspilot attivo: crash all'avvio \
                             (controllare i file server.log/server.err accanto all'exe)."
                        );
                    }
                }
                Dialect::PowerShell => {
                    // Parser+report condivisi col path WinRM.
                    bootstrap::interpret_windows_diag(port, &stdout);
                }
            }
        }
        Err(e) => eprintln!("[bootstrap-ssh] diagnostica non disponibile: {}", e),
    }
}

/// Bootstrap SSH completo — stesso contratto di bootstrap::bootstrap_server
/// e bootstrap_smb::bootstrap_server:
///   1. connect+auth+TOFU (ssh_transport)
///   2. remote_build_info (1 round-trip): stato build remoto
///   3. exe mancante/piu' vecchio -> deploy_exe staged; piu' nuovo ->
///      self-update del client (mai downgrade); uguale -> deploy idempotente
///   4. macro-blocco firewall inbound
///   5. avvio detached (setsid | schtasks) + polling TCP
///      (riusa poll_server_startup)
///
/// Errori di trasporto -> ChannelUnreachable("SSH"): fail-fast nel
/// retry loop del chiamante (bug B1). HostKeyMismatch -> fatale.
pub async fn bootstrap_server(exe_path: &str) -> Result<()> {
    let ctx = ssh_context();
    let d = dialect();
    eprintln!(
        "[bootstrap-ssh] bootstrap via SSH ({:?}) verso {}@{}:{} (exe={})",
        d, ctx.user, ctx.host, ctx.port, exe_path
    );

    // Connect: errori di trasporto -> ChannelUnreachable("SSH");
    // host key mismatch -> HostKeyMismatch (fatale, propagato).
    let sess = SshSession::connect(&ctx).await?;

    match remote_build_info(&sess, d, exe_path).await {
        Ok(info) => {
            if !info.exe_present {
                eprintln!("[bootstrap-ssh] exe remoto mancante. Avvio deploy via SSH...");
                match deploy_exe(&sess, d, exe_path, &info).await {
                    Ok(()) => {}
                    Err(e) => {
                        // Trasporto morto -> fail-fast; altri errori ->
                        // warning: il server potrebbe essere gia' attivo
                        // (il polling decide).
                        if e.downcast_ref::<bootstrap::ChannelUnreachable>().is_some() {
                            return Err(e);
                        }
                        eprintln!("[ERROR] bootstrap-ssh: deploy fallito: {}", e);
                    }
                }
            } else if info.is_newer_than_local() {
                // Remote PIU' NUOVO: il "piu' vecchio" e' il client ->
                // self-update (mai downgrade). Stessa escape hatch del
                // path WinRM: CROSSPILOT_NO_SELF_UPDATE=1.
                let self_update_disabled = match envs::var("NO_SELF_UPDATE") {
                    Some(v) => v == "1" || v.eq_ignore_ascii_case("true"),
                    None => false,
                };
                if self_update_disabled {
                    eprintln!(
                        "[self-update] remote piu' nuovo (ts={} > {}) ma \
                         CROSSPILOT_NO_SELF_UPDATE attivo: proseguo senza aggiornare.",
                        info.effective_ts(),
                        version::BUILD_TS
                    );
                } else {
                    let update_result = self_update_ssh(
                        &sess,
                        d,
                        exe_path,
                        info.effective_ts(),
                        info.linux_sha256.as_deref(),
                    )
                    .await;
                    match update_result {
                        Ok(()) => {
                            // Irraggiungibile su unix (exec sostituisce il processo).
                            eprintln!("[self-update] re-exec completato senza sostituzione processo?");
                        }
                        Err(e) => {
                            // Trasporto morto -> fail-fast (il remote non
                            // e' stato toccato: mai downgrade).
                            if e.downcast_ref::<bootstrap::ChannelUnreachable>().is_some() {
                                return Err(e);
                            }
                            eprintln!(
                                "[WARNING] Remote piu' nuovo (ts={}) ma self-update SSH fallito: {}",
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
                // Remote piu' vecchio o uguale: deploy idempotente (skip
                // upload se hash gia' allineato; .ver/.env sempre riscritti).
                match deploy_exe(&sess, d, exe_path, &info).await {
                    Ok(()) => {}
                    Err(e) => {
                        if e.downcast_ref::<bootstrap::ChannelUnreachable>().is_some() {
                            return Err(e);
                        }
                        eprintln!("[ERROR] bootstrap-ssh: deploy fallito: {}", e);
                    }
                }
            }
        }
        Err(e) => {
            // remote_build_info fallito: trasporto morto
            // (ChannelUnreachable) o errore deterministico -> propagato.
            return Err(e);
        }
    }

    // --- MACRO-BLOCCO firewall inbound (speculare agli altri canali) ---
    ensure_inbound_allow(&sess, d).await;

    // --- Avvio detached + polling (contratto condiviso) ---
    match start_server(&sess, d, exe_path, &ctx.user).await {
        Ok(()) => {}
        Err(e) => {
            if e.downcast_ref::<bootstrap::ChannelUnreachable>().is_some() {
                return Err(e);
            }
            // Avvio fallito ma trasporto vivo: il server potrebbe essere
            // gia' in esecuzione — il polling decide.
            eprintln!("[ERROR] bootstrap-ssh: avvio server fallito: {}", e);
        }
    }

    let up = bootstrap::poll_server_startup().await;
    if !up {
        remote_startup_diag(&sess, d).await;
    }
    Ok(())
}
