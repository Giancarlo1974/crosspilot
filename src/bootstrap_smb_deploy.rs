// Modulo bootstrap_smb_deploy: la meta' "deploy" del canale SMB/SCM —
// separata da bootstrap_smb.rs (best-practice < 1000 righe/unita').
// Contiene: deploy_exe staged, self_update_smb, macro-blocco firewall,
// avvio detached del server, diagnostica post-bootstrap.
// Il contratto e' identico a bootstrap_ssh.rs / deploy.rs (WinRM):
// mai overwrite diretto dell'exe in uso, hash + functional check prima
// dello swap, backup .old, artefatti collaterali (.ver/.env/sidecar).

use anyhow::{bail, Context, Result};

use crate::bootstrap;
use crate::deploy;
use crate::bootstrap_smb::{
    self, admin_share_path, certutil_bat, parse_certutil_hash, scm_exec, scm_run_bat,
    share_dir, share_join, smb_connect, smb_err, temp_tag, tree_connect,
    version_check_bat, win_abs, SmbCtx, SCM_EXEC_TIMEOUT_SECS,
};
use crate::envs;
use crate::self_update;
use crate::update;
use crate::version::{self, RemoteBuildInfo};

/// Crea la directory del deploy sul remote se manca (mkdir annidato su
/// cmd.exe). `dir_win` e' il path assoluto Windows ("C:\ci").
async fn ensure_remote_dir(ctx: &SmbCtx, dir_win: &str) -> Result<()> {
    let bat = format!("if not exist \"{}\" mkdir \"{}\"", dir_win, dir_win);
    let out = scm_exec(ctx, &bat, 30).await?;
    let trimmed = out.trim();
    if trimmed.is_empty() {
        eprintln!("[deploy-smb] dir remota '{}' verificata", dir_win);
    } else {
        eprintln!("[deploy-smb] dir remota '{}' (out: {})", dir_win, trimmed);
    }
    Ok(())
}

/// Deploy completo e idempotente via SMB/SCM, speculare a
/// deploy::deploy_exe / bootstrap_ssh::deploy_exe:
/// upload staged via write_file su admin share -> hash certutil ->
/// functional check '<staged>' --version -> swap move (exe -> exe.old,
/// staged -> exe) + hash finale, poi sidecar crosspilot.linux, .ver e
/// merge del .env remoto. MAI overwrite diretto dell'exe in uso.
pub(crate) async fn deploy_exe(
    ctx: &SmbCtx,
    exe_path: &str,
    info: &RemoteBuildInfo,
) -> Result<()> {
    // Payload: su remote Windows l'exe E' il PE embeddato (o self-read su
    // client Windows — vedi deploy::windows_exe_bytes).
    let exe_data = deploy::windows_exe_bytes().unwrap_or_default();
    if exe_data.is_empty() {
        bail!(
            "asset windows non embeddato e self-read non disponibile: \
             deploy SMB non possibile (build senza build-release.sh?)"
        );
    }
    let linux_data = deploy::linux_bin_bytes().unwrap_or_default();
    let local_exe_hash = deploy::sha256_bytes(&exe_data).to_uppercase();
    let local_linux_hash = if linux_data.is_empty() {
        None
    } else {
        Some(deploy::sha256_bytes(&linux_data).to_uppercase())
    };
    eprintln!(
        "[deploy-smb] build locale: ts={} exe={} byte sha256={}",
        version::BUILD_TS,
        exe_data.len(),
        &local_exe_hash[..16.min(local_exe_hash.len())]
    );

    let (share, exe_rel) = admin_share_path(exe_path)?;
    // share_dir gestisce la root dello share (exe in C:\ -> "") —
    // remote_parent senza separatori restituirebbe il file stesso.
    let dir_rel = share_dir(&exe_rel).to_string();
    let dir_win = win_abs(&share, &dir_rel);

    // La dir del deploy deve esistere prima di qualunque write_file.
    ensure_remote_dir(ctx, &dir_win).await?;

    let mut client = smb_connect(ctx).await?;
    tree_connect(&mut client, ctx, &share).await?;

    // --- Step 1: exe Windows (staged + functional check + swap) ---
    let aligned = info.exe_present
        && info
            .exe_sha256
            .as_deref()
            .map(|h| h.eq_ignore_ascii_case(&local_exe_hash))
            .unwrap_or(false);
    if aligned {
        eprintln!("[deploy-smb] exe remoto gia' allineato (hash match). Skip upload exe.");
    } else {
        // Staged eseguibile: <stem>.new.exe — il functional check
        // richiede l'estensione .exe (stessa convenzione di deploy.rs).
        let stem = exe_rel
            .strip_suffix(".exe")
            .or_else(|| exe_rel.strip_suffix(".EXE"))
            .unwrap_or(&exe_rel);
        let staged_rel = format!("{}.new.exe", stem);
        let staged_win = win_abs(&share, &staged_rel);
        eprintln!(
            "[deploy-smb] exe remoto {}: upload staged di {} byte -> {}",
            if info.exe_present { "obsoleto" } else { "mancante" },
            exe_data.len(),
            staged_win
        );
        client
            .write_file(&staged_rel, &exe_data)
            .await
            .map_err(|e| smb_err(ctx, e, "write_file staged exe"))?;
        eprintln!("[deploy-smb] upload staged completato.");

        // Hash dello staged PRIMA di toccare l'exe corrente.
        let tmp_rel = format!("Windows\\Temp\\cp{}.tmp", temp_tag());
        let bat = certutil_bat(&staged_win, &tmp_rel);
        let out = scm_exec(ctx, &bat, SCM_EXEC_TIMEOUT_SECS).await?;
        let staged_hash = parse_certutil_hash(&out).unwrap_or_default();
        eprintln!(
            "[deploy-smb] hash staged: {}",
            if staged_hash.is_empty() {
                "(vuoto)".to_string()
            } else {
                staged_hash[..16.min(staged_hash.len())].to_string()
            }
        );
        if staged_hash != local_exe_hash {
            let _ = client.delete_file(&staged_rel).await;
            bail!(
                "SHA-256 MISMATCH staged '{}': atteso {} remoto {}",
                staged_win,
                &local_exe_hash[..16.min(local_exe_hash.len())],
                &staged_hash[..16.min(staged_hash.len())]
            );
        }

        // Functional check (come nel path WinRM/SSH): '<staged>'
        // --version deve stampare il build_ts locale — prova che il
        // binario e' integro ED eseguibile su QUEL sistema.
        let tmp_rel = format!("Windows\\Temp\\cp{}.tmp", temp_tag());
        let bat = version_check_bat(&staged_win, &tmp_rel);
        let out = scm_exec(ctx, &bat, SCM_EXEC_TIMEOUT_SECS).await?;
        let mut staged_ts: Option<u64> = None;
        for line in out.lines() {
            if let Some(ts) = version::parse_version_ts(line) {
                staged_ts = Some(ts);
            }
        }
        eprintln!(
            "[DEBUG] deploy-smb functional check: ts={:?} atteso={} out={:?}",
            staged_ts,
            version::BUILD_TS,
            out.trim()
        );
        if staged_ts != Some(version::BUILD_TS) {
            let _ = client.delete_file(&staged_rel).await;
            bail!(
                "functional check fallito su '{}': ts={:?} (atteso {}). \
                 Exe originale NON toccato.",
                staged_win,
                staged_ts,
                version::BUILD_TS
            );
        }

        // Swap: exe -> exe.old, staged -> exe, hash finale nel batch.
        let tmp_rel = format!("Windows\\Temp\\cp{}.tmp", temp_tag());
        let bat = bootstrap_smb::swap_bat(exe_path, &staged_win, &tmp_rel);
        let out = scm_exec(ctx, &bat, SCM_EXEC_TIMEOUT_SECS).await?;
        let final_hash = parse_certutil_hash(&out).unwrap_or_default();
        if final_hash != local_exe_hash {
            bail!(
                "SHA-256 MISMATCH post-swap '{}': atteso {} remoto {} \
                 (backup in .old)",
                exe_path,
                &local_exe_hash[..16.min(local_exe_hash.len())],
                &final_hash[..16.min(final_hash.len())]
            );
        }
        eprintln!(
            "[deploy-smb] '{}' aggiornato e verificato (backup in .old).",
            exe_path
        );
    }

    // --- Step 2: sidecar crosspilot.linux (self-update client linux) ---
    // Upload se embeddato; il .ver riporta il suo hash per i check dei
    // client unix. Nessun functional check: non gira su Windows.
    let linux_rel = share_join(&dir_rel, version::LINUX_SIDECAR_NAME);
    match &local_linux_hash {
        Some(hash) => {
            let remote_aligned = info.linux_present
                && info
                    .linux_sha256
                    .as_deref()
                    .map(|h| h.eq_ignore_ascii_case(hash))
                    .unwrap_or(false);
            if remote_aligned {
                eprintln!("[deploy-smb] sidecar {} gia' allineato. Skip.", linux_rel);
            } else {
                match client.write_file(&linux_rel, &linux_data).await {
                    Ok(()) => eprintln!("[deploy-smb] sidecar {} uploadato.", linux_rel),
                    Err(e) => eprintln!("[deploy-smb] WARNING upload sidecar: {}", e),
                }
            }
        }
        None => {
            eprintln!(
                "[deploy-smb] WARNING: sidecar linux non embeddato: il remote \
                 non potra' servire self-update a client linux"
            );
        }
    }

    // --- Step 3: .ver (metadati per bootstrap/self-update futuri) ---
    // EXE_SHA256 = hash dell'exe deployato (artefatto scaricabile dai
    // client Windows = l'exe running stesso).
    let ver_content = version::render_ver_file(
        version::BUILD_TS,
        &local_exe_hash,
        local_linux_hash.as_deref(),
    );
    let ver_rel = share_join(&dir_rel, version::VER_FILE_NAME);
    match client.write_file(&ver_rel, ver_content.as_bytes()).await {
        Ok(()) => eprintln!("[deploy-smb] .ver scritto: {} (ts={})", ver_rel, version::BUILD_TS),
        Err(e) => eprintln!("[deploy-smb] WARNING scrittura .ver: {}", e),
    }

    // --- Step 4: .env remoto — MERGE, non overwrite (stessa logica di
    // update.rs remote_env_with_port): upsert della sola riga
    // CROSSPILOT_SERVER_PORT, gli altri campi remoti restano.
    let port = bootstrap::server_tcp_port();
    let env_rel = share_join(&dir_rel, ".env");
    let mut lines: Vec<String> = Vec::new();
    match client.read_file(&env_rel).await {
        Ok(bytes) => {
            let text = String::from_utf8_lossy(&bytes);
            for line in text.lines() {
                // Strip di \r finale: il .env remoto su Windows e' CRLF.
                lines.push(line.trim_end_matches('\r').to_string());
            }
        }
        Err(_) => {
            eprintln!("[deploy-smb] .env remoto assente/illeggibile: scrittura minimale");
        }
    }
    envs::upsert_field(&mut lines, None, "SERVER_PORT", &port.to_string());
    let env_content = lines.join("\n") + "\n";
    match client.write_file(&env_rel, env_content.as_bytes()).await {
        Ok(()) => eprintln!("[deploy-smb] .env remoto aggiornato (SERVER_PORT={}, merge)", port),
        Err(e) => eprintln!("[deploy-smb] WARNING scrittura .env: {}", e),
    }

    eprintln!(
        "[deploy-smb] artefatti remoti allineati al build locale (ts={})",
        version::BUILD_TS
    );
    Ok(())
}

/// Self-update via SMB (remote piu' nuovo del client): download del
/// sidecar crosspilot.linux via read_file sull'admin share, poi
/// install_staged_file condiviso (hash + functional check + rename
/// atomico + re-exec). MAI downgrade: chiamata solo se remote_ts >
/// locale. Su successo NON ritorna (re-exec sostituisce il processo).
pub(crate) async fn self_update_smb(
    ctx: &SmbCtx,
    exe_path: &str,
    remote_ts: u64,
    expected_sha256: Option<&str>,
) -> Result<()> {
    // Il sidecar e' un binario linux: inutile (e il rename fallirebbe)
    // su client Windows — stesso vincolo degli altri canali.
    if cfg!(target_os = "windows") {
        bail!("self-update SMB non supportato su client Windows");
    }
    let (share, exe_rel) = admin_share_path(exe_path)?;
    let dir_rel = share_dir(&exe_rel);
    let sidecar_rel = share_join(dir_rel, version::LINUX_SIDECAR_NAME);
    eprintln!(
        "[self-update] remote piu' nuovo (ts={} > locale {}): download '{}' via SMB/C$...",
        remote_ts,
        version::BUILD_TS,
        sidecar_rel
    );
    let mut client = smb_connect(ctx).await?;
    tree_connect(&mut client, ctx, &share).await?;
    let data = client
        .read_file(&sidecar_rel)
        .await
        .map_err(|e| smb_err(ctx, e, "download sidecar"))?;
    if data.is_empty() {
        bail!("sidecar '{}' vuoto sul remote", sidecar_rel);
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

// ---------------------------------------------------------------------------
// Firewall + avvio server + diagnostica post-bootstrap
// ---------------------------------------------------------------------------

/// MACRO-BLOCCO firewall (lato bootstrap SMB, speculare a
/// bootstrap::ensure_firewall_rule WinRM e ensure_inbound_allow SSH):
/// netsh delete-then-add della regola `crosspilot-server-<porta>` via
/// servizio SCM (gira come LocalSystem -> privilegi sufficienti).
/// PRIMA dell'avvio del server: senza regola inbound un server vivo e'
/// indistinguibile da uno spento (SYN droppato). Best-effort.
pub(crate) async fn ensure_inbound_allow(ctx: &SmbCtx) {
    let port = bootstrap::server_tcp_port();
    let cmd = update::windows_inbound_allow_cmd(port);
    let bat = format!("{}\r\necho FW=done", cmd);
    match scm_exec(ctx, &bat, 30).await {
        Ok(out) => {
            let trimmed = out.trim();
            if trimmed.is_empty() {
                eprintln!("[bootstrap-smb] firewall: regola applicata (nessun output)");
            } else {
                eprintln!("[bootstrap-smb] firewall: {}", trimmed);
            }
        }
        Err(e) => eprintln!("[bootstrap-smb] WARNING regola firewall: {}", e),
    }
}

/// Avvio detached del server via SCM — il pattern provato su H166
/// (bug.md §2): batch remoto con redirect dell'exe sul log
/// (`start "" /b` + `cmd /c` interno). Il processo nasce dal servizio
/// transitorio e sopravvive alla sua cancellazione (LocalSystem,
/// sessione 0): niente task scheduler, niente WmiPrvSE, niente handle
/// ereditati da WinRM.
pub(crate) async fn start_server(ctx: &SmbCtx, exe_path: &str) -> Result<()> {
    let (share, exe_rel) = admin_share_path(exe_path)?;
    let dir_rel = share_dir(&exe_rel).to_string();
    let dir_win = win_abs(&share, &dir_rel);
    let log = envs::var("LOG_PATH")
        .unwrap_or_else(|| format!("{}\\crosspilot-server.log", dir_win));
    eprintln!("Bootstrapping server via SMB/SCM (servizio transitorio + start /b)...");
    let bat = format!(
        "start \"\" /b cmd /c \"\"{}\" --server >> \"{}\" 2>&1\"",
        exe_path, log
    );
    scm_run_bat(ctx, &bat).await?;
    eprintln!(
        "[bootstrap-smb] comando di avvio inviato (log remoto: {})",
        log
    );
    Ok(())
}

/// Diagnostica post-bootstrap-fallito via SMB/SCM (analogo di
/// remote_startup_diag WinRM/SSH): riporta processo vivo, porta in
/// ascolto locale e regola firewall presente. PROC vuoto = servizio mai
/// partito/exe crash; PROC + LISTEN vuoto = bind fallito; entrambi =
/// server OK e la rete/firewall a bloccare.
pub(crate) async fn remote_startup_diag(ctx: &SmbCtx) {
    let port = bootstrap::server_tcp_port();
    eprintln!("[bootstrap-smb] server non in ascolto dopo 30s: diagnostica remota via SMB/SCM...");
    let t1 = format!("Windows\\Temp\\cp{}.tmp", temp_tag());
    let t2 = format!("Windows\\Temp\\cp{}.tmp", temp_tag());
    let t3 = format!("Windows\\Temp\\cp{}.tmp", temp_tag());
    let mut bat = String::new();
    // Ogni exe dentro cmd /c con redirect interno + type (fix stdio).
    bat.push_str("echo PROC:\r\n");
    bat.push_str(&bootstrap_smb::exe_capture_lines(
        "tasklist | findstr /i crosspilot",
        &t1,
    ));
    bat.push_str("echo LISTEN:\r\n");
    bat.push_str(&bootstrap_smb::exe_capture_lines(
        &format!("netstat -an | findstr :{}", port),
        &t2,
    ));
    bat.push_str("echo FWRULE:\r\n");
    bat.push_str(&bootstrap_smb::exe_capture_lines(
        &format!(
            "netsh advfirewall firewall show rule name=crosspilot-server-{}",
            port
        ),
        &t3,
    ));
    match scm_exec(ctx, &bat, 60).await {
        Ok(out) => {
            eprintln!("[bootstrap-smb] diagnostica remota:\n{}", out.trim());
            let mut has_proc = false;
            for line in out.lines() {
                let lowered = line.trim().to_lowercase();
                if lowered.starts_with("crosspilot") && lowered.contains(".exe") {
                    has_proc = true;
                }
            }
            let has_listen = out.contains("LISTENING");
            if has_proc && has_listen {
                eprintln!(
                    "[bootstrap-smb] processo ATTIVO e porta {} in ascolto LOCALE: \
                     il server e' vivo — e' la rete/firewall tra client e server a bloccare.",
                    port
                );
            } else if has_proc {
                eprintln!(
                    "[bootstrap-smb] processo ATTIVO ma porta {} NON in ascolto: \
                     bind fallito (porta occupata? .env stale? — vedi crosspilot-server.log).",
                    port
                );
            } else {
                eprintln!(
                    "[bootstrap-smb] NESSUN processo crosspilot attivo: crash all'avvio \
                     (controllare crosspilot-server.log accanto all'exe)."
                );
            }
        }
        Err(e) => eprintln!("[bootstrap-smb] diagnostica non disponibile: {}", e),
    }
}
