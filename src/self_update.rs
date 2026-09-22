// Modulo self_update: aggiornamento del binario Linux locale quando il
// remote e' PIU' NUOVO (remote BUILD_TS > locale BUILD_TS).
//
// Direzione opposta rispetto a deploy: qui il "piu' vecchio" e' il client
// locale, che scarica il sidecar crosspilot.linux (musl statico,
// gira su qualsiasi distro) pubblicato dal remote e sostituisce se
// stesso. Mai eseguire downgrade: questo modulo si attiva SOLO se il
// remote dichiara un ts strettamente maggiore.
//
// Pipeline (verifica PRIMA del replace, mai toccare l'exe corrente su
// artefatto non validato):
//   1. download <dir>\crosspilot.linux via WinRM (base64 su stdout)
//   2. verifica SHA-256 vs hash dichiarato nel .ver remoto
//   3. scrittura su <self>.new nella dir dell'exe corrente
//   4. chmod +x e check funzionale LOCALE: '<self>.new' --version deve
//      uscire 0 e riportare il ts remoto atteso — prova che il binario
//      e' integro ED eseguibile su QUESTA piattaforma (e' il punto in
//      cui la compatibilita' libc/distro viene verificata)
//   5. backup <self> -> <self>.bak (copy), poi rename(<self>.new -> self)
//      — rename e' atomico su Linux anche col binario in esecuzione
//   6. re-exec dello stesso comando (exec unix: sostituisce il processo)
//
// Se uno step fallisce, l'exe corrente resta intatto e il chiamante
// (bootstrap) prosegue col binario vecchio: mai downgrade del remote.

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use winrm_rs::WinrmClient;

use crate::deploy;
use crate::version;

/// Esegue il self-update del binario locale dal remote.
///
/// `remote_dir`: directory Windows che contiene il sidecar
/// `remote_ts`: BUILD_TS dichiarato dal remote (dal .ver)
/// `expected_sha256`: LINUX_SHA256 dichiarato dal .ver (None = verifica
///   solo funzionale, meno forte ma comunque sicura)
///
/// In caso di successo NON ritorna: re-exec sostituisce il processo.
/// Ritorna Err se il self-update non e' possibile/sicuro (il chiamante
/// deve loggare il warning e proseguire col binario corrente).
pub async fn run(
    client: &WinrmClient,
    host: &str,
    remote_dir: &str,
    remote_ts: u64,
    expected_sha256: Option<&str>,
) -> Result<()> {
    eprintln!(
        "[self-update] remote piu' nuovo (ts={} > locale ts={}): avvio self-update da {}",
        remote_ts,
        version::BUILD_TS,
        host
    );

    // Il self-update e' pensato per client Linux/Unix: su Windows il
    // rename del proprio exe in esecuzione fallirebbe. Il sidecar e'
    // comunque un binario linux, inutile per un client Windows.
    if cfg!(target_os = "windows") {
        anyhow::bail!("self-update non supportato su client Windows");
    }

    let sidecar_remote = format!("{}\\{}", remote_dir, version::LINUX_SIDECAR_NAME);

    // --- Step 1: download via WinRM ---
    // run_powershell accumula stdout fino a max_output_bytes (default
    // 64MiB): un binario musl e' pochi MB, ampiamente sotto il cap.
    // ToBase64String emette una riga unica; whitespace extra (CRLF) viene
    // ignorato dal decoder.
    eprintln!("[self-update] download '{}' via WinRM...", sidecar_remote);
    let dl_script = format!(
        "if (Test-Path '{0}') {{ [Convert]::ToBase64String([IO.File]::ReadAllBytes('{0}')) }} else {{ Write-Output 'MISSING' }}",
        sidecar_remote
    );
    let out = client
        .run_powershell(host, &dl_script)
        .await
        .context("download sidecar linux")?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let payload = stdout.trim();
    if payload == "MISSING" || payload.is_empty() {
        anyhow::bail!(
            "sidecar '{}' assente sul remote (deployato da versione senza auto-update?)",
            sidecar_remote
        );
    }
    let new_bin = deploy::base64_decode(payload).context("decode base64 sidecar")?;
    eprintln!("[self-update] scaricati {} byte", new_bin.len());

    // --- Step 2: verifica SHA-256 vs .ver remoto ---
    let local_hash = sha256_bytes(&new_bin).to_uppercase();
    eprintln!("[self-update] sha256 scaricato: {}", &local_hash[..16]);
    if let Some(expected) = expected_sha256 {
        if !local_hash.eq_ignore_ascii_case(expected) {
            anyhow::bail!(
                "SHA-256 MISMATCH sidecar: atteso {} scaricato {}",
                &expected[..16.min(expected.len())],
                &local_hash[..16]
            );
        }
        eprintln!("[self-update] SHA-256 match con .ver remoto.");
    } else {
        eprintln!(
            "[self-update] WARNING: .ver remoto senza LINUX_SHA256, \
             verifica solo funzionale (--version)"
        );
    }

    // --- Step 3: scrittura su <self>.new ---
    let self_path = std::env::current_exe().context("current_exe")?;
    let new_path = staged_path(&self_path);
    eprintln!(
        "[self-update] exe corrente: {} -> staged: {}",
        self_path.display(),
        new_path.display()
    );
    std::fs::write(&new_path, &new_bin)
        .with_context(|| format!("scrittura {}", new_path.display()))?;

    // Risultato del self-update: da qui in poi in caso di errore
    // rimuoviamo il .new per non lasciare artefatti.
    let result = finish_update(&self_path, &new_path, remote_ts).await;
    if result.is_err() {
        let _ = std::fs::remove_file(&new_path);
    }
    result
}

/// Path del file staged: `<self>.new` nella stessa directory dell'exe
/// (stesso filesystem = rename atomico garantito).
fn staged_path(self_path: &std::path::Path) -> PathBuf {
    let mut p = self_path.as_os_str().to_owned();
    p.push(".new");
    PathBuf::from(p)
}

/// Step finali del self-update: exec-check, backup, swap, re-exec.
/// Separato da run() per gestire la pulizia dello staged su errore.
async fn finish_update(
    self_path: &std::path::Path,
    new_path: &std::path::Path,
    remote_ts: u64,
) -> Result<()> {
    // --- Step 4: check funzionale LOCALE ---
    // Rende eseguibile e lancia '<self>.new' --version: se il binario
    // non e' compatibile con questa piattaforma (libc mancante, arch
    // sbagliata, binario troncato) il comando fallisce e abortiamo PRIMA
    // del replace. Il ts nell'output deve coincidere col remote.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(new_path)
            .with_context(|| format!("metadata {}", new_path.display()))?
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(new_path, perms)
            .with_context(|| format!("chmod {}", new_path.display()))?;
    }

    eprintln!("[self-update] functional check: '{}' --version", new_path.display());
    let check = tokio::process::Command::new(new_path)
        .arg("--version")
        .output()
        .await
        .with_context(|| format!("esecuzione staged {}", new_path.display()))?;
    let ver_out = String::from_utf8_lossy(&check.stdout);
    let staged_ts = version::parse_version_ts(&ver_out);
    eprintln!(
        "[DEBUG] self-update functional check: exit={} output={} ts={:?} atteso={}",
        check.status,
        ver_out.trim(),
        staged_ts,
        remote_ts
    );
    if !check.status.success() || staged_ts != Some(remote_ts) {
        anyhow::bail!(
            "functional check locale fallito: exit={} ts={:?} (atteso {}). \
             Binario corrente NON toccato.",
            check.status,
            staged_ts,
            remote_ts
        );
    }
    eprintln!("[self-update] functional check OK: staged esegue su questa piattaforma.");

    // --- Step 5: backup + replace atomico ---
    // Backup via copy (non rename): il processo corrente tiene comunque
    // l'inode vecchio aperto, la copia serve solo per rollback manuale.
    let mut bak_os = self_path.as_os_str().to_owned();
    bak_os.push(".bak");
    let bak_path = PathBuf::from(bak_os);
    if let Err(e) = std::fs::copy(self_path, &bak_path) {
        // Backup non critico: log e prosegui (il .new e' verificato).
        eprintln!("[self-update] WARNING: backup {} fallito: {}", bak_path.display(), e);
    } else {
        eprintln!("[self-update] backup: {}", bak_path.display());
    }

    // rename() e' atomico su Linux anche se il destinazione e' il
    // binario in esecuzione (il processo mantiene l'inode vecchio).
    std::fs::rename(new_path, self_path).with_context(|| {
        format!(
            "replace atomico {} -> {}",
            new_path.display(),
            self_path.display()
        )
    })?;
    eprintln!(
        "[self-update] binario sostituito: {} (ts {} -> {})",
        self_path.display(),
        version::BUILD_TS,
        remote_ts
    );

    // --- Step 6: re-exec ---
    // exec() sostituisce il processo corrente col nuovo binario e gli
    // stessi argomenti: l'utente non deve rilanciare nulla. Il nuovo
    // processo rientra nel flow connect->bootstrap con ts aggiornato
    // (== remote) -> deploy skippato -> schtasks avvia il server.
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    eprintln!(
        "[self-update] re-exec: {} {:?}",
        self_path.display(),
        args
    );
    println!(
        "Self-update completato (build {} -> {}). Riavvio il comando...",
        version::BUILD_TS, remote_ts
    );

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = std::process::Command::new(self_path).args(&args).exec();
        // exec() ritorna SOLO in caso di errore (altrimenti non ritorna mai).
        anyhow::bail!("re-exec fallito: {}", err);
    }

    #[cfg(not(unix))]
    {
        let _ = args;
        anyhow::bail!("re-exec non supportato su questa piattaforma");
    }
}

/// Calcola SHA-256 di byte in memoria (duplicato minimo di deploy.rs:
/// tenere le due copie indipendenti evita accoppiamento nel replace path).
fn sha256_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}
