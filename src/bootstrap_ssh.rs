// Modulo bootstrap_ssh: cold bootstrap del server su host Linux/Unix
// via SSH (bug B3). Speculare a bootstrap.rs (WinRM + schtasks per i
// remote Windows): stesso contratto — pre-check stato build, deploy
// staged, avvio detached, polling TCP — ma il trasporto e' il binario
// `ssh` di sistema (OpenSSH client).
//
// SELEZIONE: bootstrap::remote_is_unix() — EXE_PATH unix-style ("/...")
// oppure campo OS=linux/unix dell'ambiente attivo.
//
// AUTH: SOLO chiavi/agent — `BatchMode=yes` impedisce qualunque prompt
// interattivo (niente password nel .env, niente attese infinite su un
// prompt mai visibile). Conseguenza: la PRIMA connessione verso un host
// sconosciuto fallisce con "Host key verification failed" (exit 255):
// l'host key va accettata una volta a mano (ssh manuale / ssh-copy-id).
//
// Campi ambiente: HOST (o SSH_HOST se diverso), SSH_PORT (default 22),
// SSH_USER (omesso = utente di default di ssh), EXE_PATH, CLIENT_PORT,
// LOG_PATH/ERR_PATH (opzionali).
//
// Deploy staged (mai sovrascrivere l'exe in uso prima delle verifiche):
//   cat > <exe>.new -> sha256sum -> chmod 755 -> '<exe>.new' --version
//   -> swap mv exe->exe.old / exe.new->exe -> hash finale. Identico al
//   path WinRM (deploy.rs) ma con primitive POSIX.

use anyhow::{bail, Context, Result};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::bootstrap;
use crate::deploy;
use crate::envs;
use crate::self_update;
use crate::update;
use crate::version::{self, RemoteBuildInfo};

/// Dedup del messaggio di remediation SSH (stesso pattern di
/// HINT_PRINTED per WinRM: il retry loop richiama bootstrap piu' volte).
static SSH_HINT_PRINTED: AtomicBool = AtomicBool::new(false);

/// Contesto SSH risolto dai campi ambiente (target + porta + host per log).
struct SshCtx {
    /// "[user@]host" passato come destinazione a ssh.
    target: String,
    /// Porta SSH (campo SSH_PORT, default 22).
    port: u16,
}

/// Risolve endpoint SSH dall'ambiente attivo: SSH_HOST con fallback a
/// HOST (la macchina e' la stessa, cambia solo il servizio), SSH_PORT
/// default 22, SSH_USER opzionale (ssh usa l'utente locale se omesso).
fn ssh_context() -> SshCtx {
    let host = envs::var("SSH_HOST")
        .or_else(|| envs::var("HOST"))
        .unwrap_or_else(|| "127.0.0.1".to_string());
    let port = envs::var("SSH_PORT")
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(22);
    let target = match envs::var("SSH_USER") {
        Some(u) => format!("{}@{}", u, host),
        None => host.clone(),
    };
    eprintln!(
        "[DEBUG] ssh_context: target={} port={}",
        target, port
    );
    SshCtx { target, port }
}

/// Costruisce il comando ssh con le opzioni comuni:
/// - BatchMode=yes: nessun prompt (password/host key) — l'auth e' solo a
///   chiavi/agent; un prompt invisibile bloccherebbe il processo.
/// - ConnectTimeout=5: fallimento veloce e deterministico su host down.
fn ssh_cmd(ctx: &SshCtx) -> Command {
    let mut cmd = Command::new("ssh");
    cmd.arg("-p").arg(ctx.port.to_string());
    cmd.arg("-o").arg("BatchMode=yes");
    cmd.arg("-o").arg("ConnectTimeout=5");
    cmd.arg(&ctx.target);
    cmd
}

/// Remediation una-tantum per SSH non funzionante (exit 255).
fn print_ssh_hint(ctx: &SshCtx) {
    if SSH_HINT_PRINTED.swap(true, Ordering::Relaxed) {
        return;
    }
    eprintln!();
    eprintln!(
        "[HINT] SSH verso {}:{} fallito (exit 255: host down, auth o host key rifiutata).",
        ctx.target, ctx.port
    );
    eprintln!("       Verificare a mano:  ssh -p {} {}", ctx.port, ctx.target);
    eprintln!("       - la prima connessione DEVE essere interattiva (accettare l'host key);");
    eprintln!("       - auth solo a chiavi/agent: ssh-copy-id -p {} {}", ctx.port, ctx.target);
    eprintln!("       Campi ambiente: SSH_HOST (fallback HOST), SSH_PORT, SSH_USER.");
    eprintln!();
}

/// Classifica l'exit status ssh: 255 = errore di TRASPORTO (host down,
/// rete irraggiungibile, auth/host key rifiutata) — deterministico, ogni
/// chiamata successiva fallirebbe identica -> errore dedicato fail-fast.
fn check_transport(out: &std::process::Output, ctx: &SshCtx, what: &str) -> Result<()> {
    if out.status.code() == Some(255) {
        let stderr = String::from_utf8_lossy(&out.stderr);
        eprintln!(
            "[ERROR] bootstrap SSH: {} fallito verso {}: {}",
            what,
            ctx.target,
            stderr.trim()
        );
        print_ssh_hint(ctx);
        return Err(bootstrap::ChannelUnreachable("SSH").into());
    }
    Ok(())
}

/// Esegue `remote_cmd` sulla shell remota (sh -c) e ritorna l'Output.
/// stdin null: i comandi di questo path non leggono input (l'upload usa
/// ssh_write). Exit 255 -> ChannelUnreachable (vedi check_transport).
async fn ssh_run(ctx: &SshCtx, remote_cmd: &str, what: &str) -> Result<std::process::Output> {
    let mut cmd = ssh_cmd(ctx);
    cmd.arg(remote_cmd);
    cmd.stdin(Stdio::null());
    let out = cmd
        .output()
        .await
        .with_context(|| format!("esecuzione ssh ({}) verso {}", what, ctx.target))?;
    check_transport(&out, ctx, what)?;
    Ok(out)
}

/// Scrive `data` su `remote_path` via `ssh ... 'mkdir -p <dir> && cat > path'`
/// con stdin piped: i byte passano raw (niente base64: ssh trasporta
/// binario arbitrario). mkdir -p rende l'upload autonomo anche al primo
/// deploy (dir inesistente).
async fn ssh_write(ctx: &SshCtx, remote_path: &str, data: &[u8]) -> Result<()> {
    let dir = update::remote_parent(remote_path).to_string();
    let script = format!("mkdir -p '{}' && cat > '{}'", dir, remote_path);
    let mut cmd = ssh_cmd(ctx);
    cmd.arg(&script);
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::piped());
    let mut child = cmd.spawn().context("spawn ssh upload")?;
    let mut stdin = child.stdin.take().context("stdin ssh non disponibile")?;
    eprintln!(
        "[deploy-ssh] upload {} byte -> {}",
        data.len(),
        remote_path
    );
    if let Err(e) = stdin.write_all(data).await {
        // EPIPE tipico: il comando remoto e' morto subito (permessi, disco).
        return Err(e).context("scrittura stdin ssh (remote morto?)");
    }
    // Chiusura stdin -> EOF per il cat remoto -> ssh puo' terminare.
    drop(stdin);
    let out = child
        .wait_with_output()
        .await
        .context("attesa completamento ssh upload")?;
    check_transport(&out, ctx, "upload")?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        bail!(
            "upload {} fallito (exit {:?}): {}",
            remote_path,
            out.status.code(),
            stderr.trim()
        );
    }
    Ok(())
}

/// SHA-256 (lowercase hex) del file remoto, o None se assente.
/// Complemento di remote_build_info per i check sugli artefatti extra.
async fn ssh_file_hash(ctx: &SshCtx, remote_path: &str) -> Option<String> {
    let script = format!(
        "if [ -f '{p}' ]; then sha256sum '{p}' | awk '{{print $1}}'; fi",
        p = remote_path
    );
    let out = ssh_run(ctx, &script, "hash remoto").await.ok()?;
    let hash = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if hash.is_empty() {
        None
    } else {
        Some(hash)
    }
}

/// Equivalente SSH di deploy::remote_build_info: UNA sola chiamata che
/// riporta presenza exe + hash + sidecar + contenuto .ver, parsata col
/// medesimo version::parse_remote_info (righe CHIAVE=valore). Un remote
/// senza .ver = deploy legacy -> ts effettivo 0 -> upgrade.
async fn remote_build_info(ctx: &SshCtx, exe_path: &str) -> Result<RemoteBuildInfo> {
    let dir = update::remote_parent(exe_path);
    let linux_path = update::remote_join(dir, version::LINUX_SIDECAR_NAME);
    let ver_path = update::remote_join(dir, version::VER_FILE_NAME);
    // Righe emesse (parse_remote_info): EXE=True|False, EXE_HASH=<sha>,
    // LINUX_PRESENT=True|False, piu' le righe grezze del .ver.
    let script = format!(
        "if [ -f '{e}' ]; then echo EXE=True; \
         sha256sum '{e}' | awk '{{print \"EXE_HASH=\" $1}}'; \
         else echo EXE=False; fi; \
         if [ -f '{l}' ]; then echo LINUX_PRESENT=True; \
         else echo LINUX_PRESENT=False; fi; \
         if [ -f '{v}' ]; then cat '{v}'; fi",
        e = exe_path,
        l = linux_path,
        v = ver_path
    );
    let out = ssh_run(ctx, &script, "remote_build_info").await?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let info = version::parse_remote_info(&stdout);
    eprintln!(
        "[DEBUG] remote_build_info (ssh): exe_present={} ts={:?} linux_present={}",
        info.exe_present, info.build_ts, info.linux_present
    );
    if let Some(h) = &info.exe_sha256 {
        eprintln!("[DEBUG] remote_build_info (ssh): exe_sha256={}", &h[..16.min(h.len())]);
    }
    Ok(info)
}

/// Preflight SSH (analogo di bootstrap::channel_probe) per il fallback
/// di update::reconcile: verifica che il canale SSH sia VIVO prima di
/// fermare un server funzionante — fermarlo senza via di ripristino
/// sarebbe un brick volontario.
pub async fn probe(exe_path: &str) -> Option<RemoteBuildInfo> {
    let ctx = ssh_context();
    match remote_build_info(&ctx, exe_path).await {
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
/// (exe->exe.old, exe.new->exe), poi artefatti collaterali
/// (crosspilot.linux = copia locale dell'exe, crosspilot.exe embeddato),
/// .ver e .env. `info` e' lo stato remoto gia' letto (evita un secondo
/// round-trip).
async fn deploy_exe(ctx: &SshCtx, exe_path: &str, info: &RemoteBuildInfo) -> Result<()> {
    // Payload: su remote unix l'exe E' un binario linux (embed musl,
    // fallback self-read su client unix — vedi deploy::linux_bin_bytes).
    let linux = deploy::linux_bin_bytes().unwrap_or_default();
    if linux.is_empty() {
        bail!(
            "asset linux non embeddato e self-read non disponibile: \
             deploy SSH non possibile (build senza build-release.sh?)"
        );
    }
    let local_hash = deploy::sha256_bytes(&linux);
    eprintln!(
        "[deploy-ssh] build locale: ts={} linux={} byte sha256={}",
        version::BUILD_TS,
        linux.len(),
        &local_hash[..16.min(local_hash.len())]
    );

    // --- Step 1: exe (staged + functional check + swap) ---
    let aligned = info.exe_present
        && info
            .exe_sha256
            .as_deref()
            .map(|h| h.eq_ignore_ascii_case(&local_hash))
            .unwrap_or(false);
    if aligned {
        eprintln!("[deploy-ssh] exe remoto gia' allineato (hash match). Skip upload exe.");
    } else {
        let staged = format!("{}.new", exe_path);
        eprintln!(
            "[deploy-ssh] exe remoto {}: upload staged di {} byte...",
            if info.exe_present { "obsoleto" } else { "mancante" },
            linux.len()
        );
        ssh_write(ctx, &staged, &linux).await?;

        // Hash dello staged PRIMA di toccare l'exe corrente.
        let staged_hash = ssh_file_hash(ctx, &staged).await.unwrap_or_default();
        if !staged_hash.eq_ignore_ascii_case(&local_hash) {
            let _ = ssh_run(ctx, &format!("rm -f '{}'", staged), "cleanup staged").await;
            bail!(
                "SHA-256 MISMATCH staged '{}': atteso {} remoto {}",
                staged,
                &local_hash[..16.min(local_hash.len())],
                &staged_hash[..16.min(staged_hash.len())]
            );
        }

        // Functional check (come nel path WinRM): '<staged>' --version
        // deve uscire 0 e stampare il build_ts locale — prova che il
        // binario e' integro ED eseguibile su QUEL sistema (libc/kernel).
        let check_cmd = format!("chmod 755 '{s}' && '{s}' --version", s = staged);
        let out = ssh_run(ctx, &check_cmd, "functional check staged").await?;
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let mut staged_ts: Option<u64> = None;
        for line in stdout.lines() {
            if let Some(ts) = version::parse_version_ts(line) {
                staged_ts = Some(ts);
            }
        }
        eprintln!(
            "[DEBUG] deploy-ssh functional check: exit={:?} ts={:?} atteso={}",
            out.status.code(),
            staged_ts,
            version::BUILD_TS
        );
        if !out.status.success() || staged_ts != Some(version::BUILD_TS) {
            let _ = ssh_run(ctx, &format!("rm -f '{}'", staged), "cleanup staged").await;
            bail!(
                "functional check fallito su '{}': ts={:?} (atteso {}). \
                 Exe originale NON toccato.",
                staged,
                staged_ts,
                version::BUILD_TS
            );
        }

        // Swap atomico-ish: exe -> exe.old (rename consentito anche col
        // processo in esecuzione), staged -> exe, poi hash finale.
        let swap_cmd = format!(
            "if [ -f '{e}' ]; then mv -f '{e}' '{e}.old'; fi; \
             mv -f '{s}' '{e}' && chmod 755 '{e}' && \
             sha256sum '{e}' | awk '{{print $1}}'",
            e = exe_path,
            s = staged
        );
        let out = ssh_run(ctx, &swap_cmd, "swap exe").await?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            bail!("swap staged -> {} fallito: {}", exe_path, stderr.trim());
        }
        let final_hash = String::from_utf8_lossy(&out.stdout).trim().to_string();
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
    // Su remote unix il sidecar E' lo stesso payload dell'exe deployato:
    // copia locale sul remote (idempotente, zero upload).
    let linux_path = update::remote_join(&dir, version::LINUX_SIDECAR_NAME);
    let cp_cmd = format!("cp -f '{}' '{}'", exe_path, linux_path);
    match ssh_run(ctx, &cp_cmd, "sidecar linux").await {
        Ok(out) if out.status.success() => {
            eprintln!("[deploy-ssh] sidecar {} allineato all'exe.", linux_path)
        }
        Ok(out) => eprintln!(
            "[deploy-ssh] WARNING copia sidecar: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ),
        Err(e) => return Err(e),
    }

    // --- Step 3: artefatto crosspilot.exe (per futuri client Windows) ---
    // L'exe deployato e' linux: per servire self-update a client Windows
    // va materializzato anche il PE embeddato (se presente).
    let win = deploy::windows_exe_bytes().unwrap_or_default();
    let mut win_hash: Option<String> = None;
    if win.is_empty() {
        eprintln!(
            "[deploy-ssh] WARNING: asset windows non embeddato: il remote \
             non potra' servire self-update a client Windows"
        );
    } else {
        let local_win_hash = deploy::sha256_bytes(&win);
        let win_path = update::remote_join(&dir, "crosspilot.exe");
        let remote_win_hash = ssh_file_hash(ctx, &win_path).await;
        let win_aligned = remote_win_hash
            .as_deref()
            .map(|h| h.eq_ignore_ascii_case(&local_win_hash))
            .unwrap_or(false);
        if win_aligned {
            eprintln!("[deploy-ssh] crosspilot.exe remoto gia' allineato. Skip.");
        } else {
            match ssh_write(ctx, &win_path, &win).await {
                Ok(()) => eprintln!("[deploy-ssh] artefatto {} uploadato.", win_path),
                Err(e) => eprintln!("[deploy-ssh] WARNING upload crosspilot.exe: {}", e),
            }
        }
        win_hash = Some(local_win_hash);
    }

    // --- Step 4: .ver (metadati per bootstrap/self-update futuri) ---
    // EXE_SHA256 descrive l'artefatto WINDOWS scaricabile (fallback: hash
    // del payload linux se il PE non e' embeddato — come write_ver_file).
    let exe_ver_hash = win_hash.unwrap_or_else(|| local_hash.clone());
    let ver_content = version::render_ver_file(
        version::BUILD_TS,
        &exe_ver_hash.to_uppercase(),
        Some(&local_hash.to_uppercase()),
    );
    let ver_path = update::remote_join(&dir, version::VER_FILE_NAME);
    match ssh_write(ctx, &ver_path, ver_content.as_bytes()).await {
        Ok(()) => eprintln!("[deploy-ssh] .ver scritto: {} (ts={})", ver_path, version::BUILD_TS),
        Err(e) => eprintln!("[deploy-ssh] WARNING scrittura .ver: {}", e),
    }

    // --- Step 5: .env minimale per il server (stessa logica di update.rs) ---
    // Il server legge CROSSPILOT_SERVER_PORT dalla .env della dir dell'exe;
    // la porta e' quella a cui il client si connette (CLIENT_PORT).
    let port = envs::var("CLIENT_PORT")
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(5330);
    let env_content = format!("CROSSPILOT_SERVER_PORT={}\n", port);
    let env_remote = update::remote_join(&dir, ".env");
    match ssh_write(ctx, &env_remote, env_content.as_bytes()).await {
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
/// sidecar crosspilot.linux via `cat` su stdout (binario raw), poi
/// install_staged_file condiviso (hash + chmod + --version + rename
/// atomico + re-exec). MAI downgrade: chiamata solo se remote_ts > locale.
/// Su successo NON ritorna (re-exec sostituisce il processo).
async fn self_update_ssh(
    ctx: &SshCtx,
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
        "[self-update] remote piu' nuovo (ts={} > locale {}): download '{}' via SSH...",
        remote_ts,
        version::BUILD_TS,
        sidecar
    );
    let mut cmd = ssh_cmd(ctx);
    cmd.arg(format!("cat '{}'", sidecar));
    cmd.stdin(Stdio::null());
    let out = cmd
        .output()
        .await
        .context("download sidecar via ssh")?;
    check_transport(&out, ctx, "download sidecar")?;
    if !out.status.success() || out.stdout.is_empty() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        bail!(
            "sidecar '{}' non leggibile sul remote: {}",
            sidecar,
            stderr.trim()
        );
    }
    eprintln!("[self-update] scaricati {} byte", out.stdout.len());

    let self_path = std::env::current_exe().context("current_exe")?;
    let staged = self_update::staged_path(&self_path);
    std::fs::write(&staged, &out.stdout)
        .with_context(|| format!("scrittura {}", staged.display()))?;
    // install_staged_file: verifica hash + functional check locale +
    // rename atomico + re-exec (non ritorna su successo).
    let result = self_update::install_staged_file(&staged, remote_ts, expected_sha256).await;
    if result.is_err() {
        let _ = std::fs::remove_file(&staged);
    }
    result
}

/// Avvio detached del server via setsid: il processo nasce in una nuova
/// sessione e sopravvive alla chiusura della connessione SSH — lo stesso
/// trigger usato da update.rs per i server Linux legacy. stdin/stdout/
/// stderr ridiretti: senza redirect ssh resterebbe appeso sugli handle
/// ereditati dal figlio.
async fn start_server(ctx: &SshCtx, exe_path: &str) -> Result<()> {
    let dir = update::remote_parent(exe_path).to_string();
    let log = envs::var("LOG_PATH")
        .unwrap_or_else(|| update::remote_join(&dir, "server.log"));
    let err = envs::var("ERR_PATH")
        .unwrap_or_else(|| update::remote_join(&dir, "server.err"));
    let script = format!(
        "setsid '{}' --server >>'{}' 2>>'{}' < /dev/null & echo STARTED",
        exe_path, log, err
    );
    let out = ssh_run(ctx, &script, "avvio server").await?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    if !out.status.success() || !stdout.contains("STARTED") {
        let stderr = String::from_utf8_lossy(&out.stderr);
        bail!("avvio server via SSH fallito: {}", stderr.trim());
    }
    eprintln!(
        "[bootstrap-ssh] server avviato detached (log: {} err: {})",
        log, err
    );
    Ok(())
}

/// MACRO-BLOCCO firewall (lato bootstrap SSH, speculare a
/// bootstrap::ensure_firewall_rule WinRM): assicura l'inbound TCP/<porta>
/// sul remote Linux PRIMA dell'avvio del server. Senza regola un server
/// vivo e in ascolto e' indistinguibile da uno spento visto dal client
/// (SYN droppato -> "connect timeout"). Lo script POSIX e' condiviso col
/// path TCP (update::linux_inbound_allow_script): stesso blocco, altro
/// trasporto. Best-effort: errori solo loggati.
async fn ensure_inbound_allow(ctx: &SshCtx) {
    let port = bootstrap::server_tcp_port();
    let script = update::linux_inbound_allow_script(port);
    match ssh_run(ctx, &script, "regola firewall").await {
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
/// locale e frontend firewall disponibili (FWTOOL).
/// PROC vuoto = task mai avviato/crash; PROC pieno + LISTEN vuoto =
/// bind fallito; entrambi = server OK e la rete/firewall a bloccare
/// (le righe FWTOOL indicano quale frontend eventualmente governare).
async fn remote_startup_diag(ctx: &SshCtx) {
    let port = bootstrap::server_tcp_port();
    eprintln!("[bootstrap-ssh] server non in ascolto dopo 30s: diagnostica remota via SSH...");
    let script = format!(
        "pgrep -fa crosspilot 2>/dev/null | head -5 | sed 's/^/PROC: /'; \
         if command -v ss >/dev/null 2>&1; then \
         ss -tln 2>/dev/null | grep ':{p} ' | sed 's/^/LISTEN: /'; \
         elif command -v netstat >/dev/null 2>&1; then \
         netstat -tln 2>/dev/null | grep ':{p} ' | sed 's/^/LISTEN: /'; fi; \
         for f in ufw firewall-cmd iptables nft; do \
         command -v $f >/dev/null 2>&1 && echo \"FWTOOL: $f\"; done",
        p = port
    );
    match ssh_run(ctx, &script, "diagnostica").await {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            eprintln!("[bootstrap-ssh] diagnostica remota:\n{}", stdout.trim());
            let has_proc = stdout.contains("PROC:");
            let has_listen = stdout.contains("LISTEN:");
            if has_proc && has_listen {
                eprintln!(
                    "[bootstrap-ssh] processo ATTIVO e porta {} in ascolto LOCALE: \
                     il server e' vivo — e' la rete/firewall tra client e server a bloccare \
                     (vedi righe FWTOOL per il frontend eventualmente da configurare).",
                    port
                );
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
        Err(e) => eprintln!("[bootstrap-ssh] diagnostica non disponibile: {}", e),
    }
}

/// Bootstrap SSH completo — stesso contratto di bootstrap::bootstrap_server:
///   1. remote_build_info (1 round-trip): stato build remoto
///   2. exe mancante/piu' vecchio -> deploy_exe staged; piu' nuovo ->
///      self-update del client (mai downgrade); uguale -> deploy idempotente
///   3. avvio detached via setsid + polling TCP (riusa poll_server_startup)
///
/// Errori di trasporto (exit 255) -> ChannelUnreachable: fail-fast nel
/// retry loop del chiamante (bug B1, stessa disciplina di WinRM).
pub async fn bootstrap_server(exe_path: &str) -> Result<()> {
    let ctx = ssh_context();
    eprintln!(
        "[bootstrap-ssh] remote unix: bootstrap via SSH verso {} (exe={})",
        ctx.target, exe_path
    );

    match remote_build_info(&ctx, exe_path).await {
        Ok(info) => {
            if !info.exe_present {
                eprintln!("[bootstrap-ssh] exe remoto mancante. Avvio deploy via SSH...");
                match deploy_exe(&ctx, exe_path, &info).await {
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
                    let update_result = self_update_ssh(
                        &ctx,
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
                match deploy_exe(&ctx, exe_path, &info).await {
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
            // remote_build_info fallito: se e' il trasporto (exit 255)
            // l'errore e' gia' ChannelUnreachable -> fail-fast; altri
            // errori (spawn ssh mancante) sono comunque deterministici.
            return Err(e);
        }
    }

    // --- MACRO-BLOCCO firewall inbound (speculare al path WinRM) ---
    // Prima dell'avvio del server: senza regola inbound il server parte
    // ma i SYN dall'esterno vengono droppati — "connect timeout"
    // indistinguibile da server spento (stesso bug del caso H102 su
    // Windows). Implementazione Linux condivisa col path TCP.
    ensure_inbound_allow(&ctx).await;

    // --- Avvio detached + polling (contratto condiviso col path WinRM) ---
    match start_server(&ctx, exe_path).await {
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
        remote_startup_diag(&ctx).await;
    }
    Ok(())
}
