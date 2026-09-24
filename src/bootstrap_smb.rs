// Modulo bootstrap_smb: terzo canale di bootstrap per remote Windows
// senza WinRM (spec docs/smb-scm-bootstrap-spec.md §1; motivazione
// bug.md §2 — su H166 WinRM era filtrato ma SMB(:445)+SCM operativi).
// Speculare a bootstrap_ssh.rs: stesso contratto — pre-check stato build,
// deploy staged, functional check, macro-blocco firewall, avvio detached
// che sopravvive al teardown del trasporto.
//
// STACK (puro Rust, niente FFI: compatibile col build musl statico e
// windows-gnu):
// - smb2-client VENDORED (vendor/smb2-client — [patch] in Cargo.toml):
//   SMB2 NEGOTIATE + SESSION_SETUP NTLMv2 + tree connect sulle admin
//   share (IPC$ per la pipe svcctl, C$/D$... per il file I/O). Il vendor
//   aggiunge write_file/delete_file su file disco (upstream 0.2.5 ha
//   solo read: l'upload degli artefatti ne ha bisogno).
// - ms-scmr: MS-SCMR over \PIPE\svcctl — servizio transitorio con
//   binpath arbitrario + start + delete (pattern "psexec" validato in
//   vivo su H166: stesso risultato di `net rpc service create`).
//
// SELEZIONE (bootstrap_prescan::candidates — spec ssh-unified §2.3):
// - campo ambiente BOOTSTRAP=smb -> questo canale come unico;
// - altrimenti posizione nella lista ordinata dal prescan (SMB Open ->
//   primo se WinRM/SSH sono morti — il caso H166 senza timeout).
//
// ESECUZIONE REMOTA (bug.md §2 — il pattern provato): ms_scmr::run crea
// un servizio transitorio il cui binpath e' `start "" /b cmd /c "<cmd>"`:
// il payload sopravvive alla cancellazione del servizio (LocalSystem,
// sessione 0). Quirk provato su H166: lo stdio ereditato dal contesto
// servizio e' NULO — l'output degli EXE figli si cattura solo con un
// redirect esplicito nel cmd interno. Per questo scm_exec() carica un
// .bat su C$ in cui ogni exe gira dentro `cmd /c "... > <tmp> 2>&1"`
// seguito da `type <tmp>`; il file .out chiude col marker __CP_DONE__
// emesso come ultima riga del batch — poll sul marker, non sul timeout
// interno di ms_scmr::exec (~3s: troppo corto per certutil/netsh lenti).
//
// SICUREZZA (spec §1.6): richiede admin locale sul remote (admin share
// + create service); ACCESS_DENIED -> errore auth/permessi, non "canale
// morto". Stessi artefatti forensi di psexec: 4624 type 3, 4697, 7045.
// NTLMv2 only (niente NTLMv1/LM). PASS mai in argv remoto ne' in log.
//
// SPLIT: il deploy staged + firewall + avvio server + diagnostica sono
// in bootstrap_smb_deploy.rs (best-practice < 1000 righe/unita').

use anyhow::{bail, Context, Result};
use smb2_client::{SmbClient, SmbError};
use std::io::ErrorKind;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, Instant};

use crate::bootstrap;
use crate::bootstrap_smb_deploy;
use crate::envs;
use crate::update;
use crate::version::{self, RemoteBuildInfo};

/// Codici NTSTATUS rilevanti per l'error mapping (spec §1.7).
pub(crate) const STATUS_LOGON_FAILURE: u32 = 0xC000_006D;
pub(crate) const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
pub(crate) const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
pub(crate) const STATUS_OBJECT_PATH_NOT_FOUND: u32 = 0xC000_003A;

/// Marker emesso come ultima riga di ogni batch remoto: il poll del file
/// .out sa che il batch e' FINITO quando il marker appare.
pub(crate) const DONE_MARKER: &str = "__CP_DONE__";

/// Timeout per la singola operazione SMB (connect/login/tree/op):
/// smb2-client non ha timeout interni — un SYN droppato su 445
/// altrimenti resterebbe appeso al timeout TCP del kernel (~2min).
const SMB_OP_TIMEOUT: Duration = Duration::from_secs(15);

/// Timeout di default del poll sull'output di un batch remoto.
pub(crate) const SCM_EXEC_TIMEOUT_SECS: u64 = 60;

/// Settato quando il canale SMB/SCM risulta deterministicamente
/// irraggiungibile (TCP 445 refused/timeout): letto da
/// main::final_connect_error per il messaggio finale (spec §3).
static SMB_UNREACHABLE: AtomicBool = AtomicBool::new(false);

/// True se il canale SMB/SCM e' risultato irraggiungibile in questa run.
pub fn smb_unreachable() -> bool {
    SMB_UNREACHABLE.load(Ordering::Relaxed)
}

/// Dedup del remediation SMB (stesso pattern di HINT_PRINTED WinRM /
/// del dedup hint SSH: bootstrap_server puo' essere richiamata dal retry
/// loop — il hint va stampato una sola volta per processo).
static SMB_HINT_PRINTED: AtomicBool = AtomicBool::new(false);

/// Contatore per nomi temporanei remoti univoci (bat/out/tmp su C$).
static TEMP_SEQ: AtomicU32 = AtomicU32::new(0);

// NOTA: l'override BOOTSTRAP=smb|ssh|winrm e' ora parsato da
// bootstrap_prescan::candidates (spec ssh-unified §2.3 — lista
// candidati ordinata, un solo punto di selezione del canale).

/// Contesto SMB risolto dai campi ambiente (host + credenziali NTLM).
/// pub(crate): riusato da bootstrap_smb_deploy.
pub(crate) struct SmbCtx {
    /// Hostname/IP del remote Windows (campo HOST).
    pub(crate) host: String,
    /// Dominio NetBIOS da "DOMAIN\user" (vuoto se UPN/nessuno — il
    /// dominio e' comunque auto-rilevato dal challenge NTLM Type 2).
    pub(crate) domain: String,
    /// Username senza dominio.
    pub(crate) user: String,
    /// Password NTLMv2 (mai loggata).
    pub(crate) pass: String,
}

/// Risolve endpoint/credenziali dall'ambiente attivo: HOST, USER, PASS —
/// gli stessi campi del path WinRM (split DOMAIN\user / user@domain via
/// bootstrap::split_domain_user condiviso).
pub(crate) fn smb_context() -> SmbCtx {
    let host = envs::var("HOST").unwrap_or_else(|| "127.0.0.1".to_string());
    let user_raw = envs::var("USER").unwrap_or_else(|| "gianca".to_string());
    let pass = envs::var("PASS").unwrap_or_else(|| "gianca".to_string());
    let (user, domain) = bootstrap::split_domain_user(&user_raw);
    eprintln!(
        "[DEBUG] smb_context: host={} user={} domain={}",
        host, user, domain
    );
    SmbCtx {
        host,
        domain,
        user,
        pass,
    }
}

/// Tag univoco per i file temporanei remoti (cp<tag>.bat/.out/.tmp in
/// C:\Windows\Temp): nanos + contatore, come fa ms-scmr per i nomi
/// servizio.
pub(crate) fn temp_tag() -> String {
    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("{:08x}{:02x}", nanos, seq & 0xff)
}

/// Codici Win32 restituiti da StartService trattati come "avviato": il
/// servizio transitorio non fa handshake SCM (e' un cmd) — il servizio
/// muore subito con uno di questi errori mentre il payload detached
/// sopravvive (bug.md §2; stessa whitelist di ms-scmr::exec).
pub(crate) fn scm_start_ok(code: u32) -> bool {
    matches!(
        code,
        0 // ERROR_SUCCESS
        | 1053 // ERROR_SERVICE_REQUEST_TIMEOUT (mai arrivato l'handshake)
        | 1054 // ERROR_SERVICE_NO_THREAD
        | 1064 // ERROR_EXCEPTION_IN_SERVICE
        | 1067 // ERROR_PROCESS_ABORTED
    )
}

/// Remediation una-tantum per il canale SMB/SCM non funzionante.
fn print_smb_hint(ctx: &SmbCtx, reason: &str) {
    if SMB_HINT_PRINTED.swap(true, Ordering::Relaxed) {
        return;
    }
    eprintln!();
    eprintln!(
        "[HINT] Canale SMB/SCM verso {} non utilizzabile: {}.",
        ctx.host, reason
    );
    eprintln!("       Requisiti sul remote Windows (spec §1.6):");
    eprintln!("       - TCP 445 raggiungibile (File and Printer Sharing attivo);");
    eprintln!("       - account admin locale (admin share C$ + create service SCM);");
    eprintln!("       - credenziali USER/PASS valide (crosspilot env show <nome>).");
    eprintln!();
}

/// Mappa un errore SMB/RPC nella diagnostica del canale (spec §1.7):
/// - TCP refused/timeout -> ChannelUnreachable("SMB/SCM") (fail-fast,
///   come il WINRM_UNREACHABLE del path WinRM);
/// - STATUS_LOGON_FAILURE -> errore credenziali (hint dedicato);
/// - STATUS_ACCESS_DENIED -> account non admin / admin share non
///   accessibile (hint dedicato);
/// - altro -> errore generico col contesto.
pub(crate) fn smb_err(ctx: &SmbCtx, e: SmbError, what: &str) -> anyhow::Error {
    match e {
        SmbError::Io(io) => {
            let dead = matches!(
                io.kind(),
                ErrorKind::ConnectionRefused
                    | ErrorKind::TimedOut
                    | ErrorKind::HostUnreachable
                    | ErrorKind::NetworkUnreachable
            );
            if dead {
                SMB_UNREACHABLE.store(true, Ordering::Relaxed);
                print_smb_hint(ctx, &format!("TCP 445 non risponde ({})", io.kind()));
                return bootstrap::ChannelUnreachable("SMB/SCM").into();
            }
            anyhow::anyhow!("SMB {} fallito (io): {}", what, io)
        }
        SmbError::Status(STATUS_LOGON_FAILURE, _) => {
            print_smb_hint(ctx, "autenticazione NTLM rifiutata");
            anyhow::anyhow!(
                "SMB {} fallito: STATUS_LOGON_FAILURE — credenziali USER/PASS errate",
                what
            )
        }
        SmbError::Status(STATUS_ACCESS_DENIED, _) => {
            print_smb_hint(ctx, "ACCESS_DENIED su admin share/SCM");
            anyhow::anyhow!(
                "SMB {} fallito: ACCESS_DENIED — l'account non e' admin locale sul remote \
                 (admin share C$ e create service richiedono admin; su account locali \
                 non-Administrator serve LocalAccountTokenFilterPolicy=1)",
                what
            )
        }
        other => anyhow::anyhow!("SMB {} fallito: {}", what, other),
    }
}

/// Connessione SMB autenticata: TCP 445 + NEGOTIATE + SESSION_SETUP
/// NTLMv2 (smb2-client). Timeout esplicito su connect e login: il crate
/// non ne ha di interni e un 445 filtrato darebbe un hang lunghissimo.
pub(crate) async fn smb_connect(ctx: &SmbCtx) -> Result<SmbClient> {
    let connect = SmbClient::connect(&ctx.host);
    let mut client = tokio::time::timeout(SMB_OP_TIMEOUT, connect)
        .await
        .map_err(|_| {
            SMB_UNREACHABLE.store(true, Ordering::Relaxed);
            print_smb_hint(ctx, "TCP 445 filtrato (timeout)");
            anyhow::Error::from(bootstrap::ChannelUnreachable("SMB/SCM"))
        })?
        .map_err(|e| smb_err(ctx, e, "TCP connect 445"))?;
    let login = client.login(&ctx.host, &ctx.domain, &ctx.user, &ctx.pass);
    tokio::time::timeout(SMB_OP_TIMEOUT, login)
        .await
        .map_err(|_| {
            // TCP 445 aperta ma NEGOTIATE/SESSION_SETUP mai completati:
            // canale morto di fatto — stesso hint del connect timeout,
            // senza di esso il fallimento era completamente silenzioso.
            SMB_UNREACHABLE.store(true, Ordering::Relaxed);
            print_smb_hint(ctx, "TCP 445 accetta ma il login NTLMv2 non risponde (timeout)");
            anyhow::Error::from(bootstrap::ChannelUnreachable("SMB/SCM"))
        })?
        .map_err(|e| smb_err(ctx, e, "login NTLMv2"))?;
    Ok(client)
}

/// Tree connect su una share del remote (es. "C$", "IPC$").
/// SmbClient tiene UN solo tree_id: ogni cambio share richiede una
/// tree_connect esplicita (ms_scmr::exec fa lo stesso internamente).
pub(crate) async fn tree_connect(
    client: &mut SmbClient,
    ctx: &SmbCtx,
    share: &str,
) -> Result<()> {
    let unc = format!("\\\\{}\\{}", ctx.host, share);
    let fut = client.tree_connect(&unc);
    tokio::time::timeout(SMB_OP_TIMEOUT, fut)
        .await
        .context("timeout tree_connect")?
        .map_err(|e| smb_err(ctx, e, &format!("tree_connect {}", unc)))?;
    Ok(())
}

/// Converte un path assoluto Windows "X:\dir\file" nella coppia
/// (admin share "X$", path relativo allo share "dir\file").
/// I path UNC (\\srv\share\...) non sono admin-share path -> errore
/// esplicito (spec §1.4: il deploy avviene sulle admin share per-drive).
pub(crate) fn admin_share_path(win_path: &str) -> Result<(String, String)> {
    let bytes = win_path.as_bytes();
    let valid = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/');
    if !valid {
        bail!(
            "EXE_PATH '{}' non e' un path con drive letter: il canale SMB usa le \
             admin share per-drive (C$, D$, ...) — i path UNC non sono supportati",
            win_path
        );
    }
    let drive = (bytes[0] as char).to_ascii_uppercase();
    let share = format!("{}$", drive);
    let rel = win_path[3..].replace('/', "\\");
    Ok((share, rel))
}

/// Ricostruisce il path Windows assoluto "X:\<rel>" da share name + path
/// relativo allo share ("C$" + "ci\x.exe" -> "C:\ci\x.exe").
pub(crate) fn win_abs(share: &str, rel: &str) -> String {
    let drive = share.trim_end_matches('$');
    if rel.is_empty() {
        format!("{}:\\", drive)
    } else {
        format!("{}:\\{}", drive, rel)
    }
}

/// Directory parent di un path RELATIVO allo share, con caso-limite
/// "file in root": remote_parent("crosspilot.exe") non trova separatori
/// e restituirebbe il file stesso — qui diventa "" (root dello share).
pub(crate) fn share_dir(rel: &str) -> &str {
    let parent = update::remote_parent(rel);
    if parent == rel {
        ""
    } else {
        parent
    }
}

/// Join dir+nome su un path RELATIVO allo share: separatore sempre '\'
/// (i path SMB/share-relative sono Windows) e root dello share gestita
/// (dir "" -> solo il nome; remote_join("") produrrebbe "/nome" col
/// separatore unix).
pub(crate) fn share_join(dir_rel: &str, name: &str) -> String {
    if dir_rel.is_empty() {
        name.to_string()
    } else {
        format!("{}\\{}", dir_rel.trim_end_matches('\\'), name)
    }
}

/// True se `path` esiste sul tree corrente come file (probe CREATE
/// read-attrs + close vendored — nessun trasferimento dati, robusta
/// anche sulla root dello share dove QUERY_DIRECTORY sul nome vuoto
/// restituisce NOT_A_DIRECTORY su alcuni server).
async fn file_exists(client: &mut SmbClient, ctx: &SmbCtx, path: &str) -> Result<bool> {
    client
        .file_exists(path)
        .await
        .map_err(|e| smb_err(ctx, e, "file_exists"))
}

// ---------------------------------------------------------------------------
// Batch builder + exec remota via SCM con output catturato su C$
// ---------------------------------------------------------------------------

/// Batch builder: esegue `<inner>` dentro un cmd /c con redirect su un
/// file tmp, poi lo `type`a nel canale out del batch e lo rimuove.
/// Il redirect nel cmd INTERNO e' il fix provato su H166 per la stdio
/// nulla del contesto servizio (vedi header del modulo).
/// `tmp_rel` deve essere un path SENZA spazi (usiamo Windows\Temp\cp*).
pub(crate) fn exe_capture_lines(inner_cmd: &str, tmp_rel: &str) -> String {
    let tmp_win = format!("C:\\{}", tmp_rel);
    format!(
        "cmd /c \"{inner} > \"{tmp}\" 2>&1\"\r\ntype \"{tmp}\"\r\ndel /f /q \"{tmp}\" >nul 2>&1\r\n",
        inner = inner_cmd,
        tmp = tmp_win
    )
}

/// Batch per l'hash SHA-256 remoto via certutil (exe -> inner redirect).
pub(crate) fn certutil_bat(target_win: &str, tmp_rel: &str) -> String {
    let inner = format!("certutil -hashfile \"{}\" SHA256", target_win);
    exe_capture_lines(&inner, tmp_rel)
}

/// Batch per il functional check `"<exe>" --version` (cattura + type).
pub(crate) fn version_check_bat(exe_win: &str, tmp_rel: &str) -> String {
    let inner = format!("\"{}\" --version", exe_win);
    exe_capture_lines(&inner, tmp_rel)
}

/// Batch di swap: exe -> exe.old (rename consentito col processo in
/// esecuzione), staged -> exe, poi hash finale via certutil (post-swap
/// verification, come il path WinRM/SSH).
pub(crate) fn swap_bat(exe_win: &str, staged_win: &str, tmp_rel: &str) -> String {
    let mut body = String::new();
    body.push_str(&format!(
        "if exist \"{old}\" del /f /q \"{old}\"\r\n",
        old = format!("{}.old", exe_win)
    ));
    body.push_str(&format!(
        "if exist \"{e}\" move /y \"{e}\" \"{e}.old\"\r\n",
        e = exe_win
    ));
    body.push_str(&format!(
        "move /y \"{s}\" \"{e}\"\r\n",
        s = staged_win,
        e = exe_win
    ));
    body.push_str(&certutil_bat(exe_win, tmp_rel));
    body
}

/// Estrae l'hash SHA-256 (64 hex) dall'output di certutil -hashfile:
/// la riga dell'hash puo' essere contigua o separata da spazi a seconda
/// della versione di Windows — si strip-pa tutto il whitespace prima del
/// match. Ritorna uppercase, coerente con deploy::sha256_bytes().
pub(crate) fn parse_certutil_hash(output: &str) -> Option<String> {
    for line in output.lines() {
        let stripped: String = line.chars().filter(|c| !c.is_whitespace()).collect();
        let is_hex64 = stripped.len() == 64
            && stripped.chars().all(|c| c.is_ascii_hexdigit());
        if is_hex64 {
            return Some(stripped.to_uppercase());
        }
    }
    None
}

/// Exec remota via servizio SCM transitorio con output catturato su C$.
/// Protocollo:
///   1. upload di un .bat (body + `echo __CP_DONE__`) su C$ via
///      write_file (patch vendored);
///   2. ms_scmr::run su IPC$: `cmd /c <bat> > <out> 2>&1` dentro il
///      servizio transitorio detached (start "" /b interno al crate);
///   3. poll di read_file(<out>) su C$ finche' compare il marker
///      __CP_DONE__ (o timeout);
///   4. cleanup: delete-on-close dell'out + delete_file del .bat
///      (spec §1.4.7: niente file temporanei residui).
///
/// Ogni exec usa una connessione dedicata: ms_scmr::run lascia il client
/// sul tree IPC$, gli step su C$ fanno tree_connect esplicita — nessuno
/// stato condiviso da ripristinare.
pub(crate) async fn scm_exec(ctx: &SmbCtx, bat_body: &str, timeout_secs: u64) -> Result<String> {
    let tag = temp_tag();
    // Windows\Temp: sempre presente/scrivibile da SYSTEM su ogni Windows.
    let bat_rel = format!("Windows\\Temp\\cp{}.bat", tag);
    let out_rel = format!("Windows\\Temp\\cp{}.out", tag);
    let bat_win = win_abs("C$", &bat_rel);
    let out_win = win_abs("C$", &out_rel);

    let mut client = smb_connect(ctx).await?;

    // Step 1: upload .bat su C$.
    tree_connect(&mut client, ctx, "C$").await?;
    let bat_content = format!("@echo off\r\n{}\r\necho {}\r\n", bat_body, DONE_MARKER);
    client
        .write_file(&bat_rel, bat_content.as_bytes())
        .await
        .map_err(|e| smb_err(ctx, e, "upload .bat"))?;

    // Step 2: esecuzione detached via SCM (tree IPC$ obbligatorio per
    // \PIPE\svcctl). Il redirect > out vive DENTRO il comando del
    // servizio — e' il canale di cattura del batch.
    tree_connect(&mut client, ctx, "IPC$").await?;
    let run_cmd = format!("cmd.exe /c {} > {} 2>&1", bat_win, out_win);
    let start_ret = match ms_scmr::run(&mut client, &run_cmd).await {
        Ok(code) => code,
        Err(e) => {
            // Cleanup del .bat prima di propagare l'errore.
            let _ = tree_connect(&mut client, ctx, "C$").await;
            let _ = client.delete_file(&bat_rel).await;
            return Err(anyhow::anyhow!("svcctl start fallito: {}", e));
        }
    };
    if !scm_start_ok(start_ret) {
        let _ = tree_connect(&mut client, ctx, "C$").await;
        let _ = client.delete_file(&bat_rel).await;
        bail!(
            "servizio SCM transitorio non avviato (win32 {}): controllare i privilegi",
            start_ret
        );
    }

    // Step 3: poll dell'out su C$ finche' appare il marker.
    tree_connect(&mut client, ctx, "C$").await?;
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let mut output: Option<String> = None;
    while Instant::now() < deadline {
        match client.read_file(&out_rel).await {
            Ok(bytes) => {
                let text = String::from_utf8_lossy(&bytes).replace('\r', "");
                if let Some(pos) = text.find(DONE_MARKER) {
                    output = Some(text[..pos].trim_end().to_string());
                    break;
                }
                // File presente ma marker assente: batch ancora in corso.
            }
            Err(SmbError::Status(status, _)) => {
                // File non ancora creato (spawn in corso) o lock di
                // scrittura: entrambi transienti fino al deadline.
                let transient = matches!(
                    status,
                    STATUS_OBJECT_NAME_NOT_FOUND
                        | STATUS_OBJECT_PATH_NOT_FOUND
                        | smb2_client::status::SHARING_VIOLATION
                );
                if !transient {
                    eprintln!(
                        "[bootstrap-smb] WARNING poll out {}: status {:#010x}",
                        out_rel, status
                    );
                }
            }
            Err(e) => {
                eprintln!("[bootstrap-smb] WARNING poll out {}: {}", out_rel, e);
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // Step 4: cleanup temporanei — sempre, anche su timeout (spec §1.4.7).
    let _ = client.read_file_delete(&out_rel).await;
    let _ = client.delete_file(&bat_rel).await;

    output.ok_or_else(|| {
        anyhow::anyhow!(
            "scm_exec: timeout {}s senza marker {} (batch mai completato?)",
            timeout_secs,
            DONE_MARKER
        )
    })
}

/// Variante fire-and-forget di scm_exec per comandi il cui esito non va
/// atteso (avvio server detached): il .bat parte via SCM e si auto-
/// rimuove (il `del` del proprio path come ultima riga e' legale in cmd).
pub(crate) async fn scm_run_bat(ctx: &SmbCtx, bat_body: &str) -> Result<()> {
    let tag = temp_tag();
    let bat_rel = format!("Windows\\Temp\\cp{}.bat", tag);
    let bat_win = win_abs("C$", &bat_rel);

    let mut client = smb_connect(ctx).await?;
    tree_connect(&mut client, ctx, "C$").await?;
    let bat_content = format!(
        "@echo off\r\n{}\r\ndel /f /q \"{}\" >nul 2>&1\r\n",
        bat_body, bat_win
    );
    client
        .write_file(&bat_rel, bat_content.as_bytes())
        .await
        .map_err(|e| smb_err(ctx, e, "upload .bat"))?;

    tree_connect(&mut client, ctx, "IPC$").await?;
    let start_ret = ms_scmr::run(&mut client, &bat_win)
        .await
        .map_err(|e| anyhow::anyhow!("svcctl start fallito: {}", e))?;
    if !scm_start_ok(start_ret) {
        bail!(
            "servizio SCM transitorio non avviato (win32 {})",
            start_ret
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Build info via admin share (C$, D$, ...)
// ---------------------------------------------------------------------------

/// Equivalente SMB di deploy::remote_build_info / bootstrap_ssh:
/// list_directory + read del .ver via admin share, hash dell'exe via
/// certutil su SCM. Produce lo stesso report CHIAVE=valore e lo passa a
/// version::parse_remote_info — un remote senza .ver = deploy legacy
/// (ts effettivo 0 -> upgrade).
async fn remote_build_info(
    client: &mut SmbClient,
    ctx: &SmbCtx,
    exe_path: &str,
) -> Result<RemoteBuildInfo> {
    let (share, exe_rel) = admin_share_path(exe_path)?;
    tree_connect(client, ctx, &share).await?;

    // dir_rel: remote_parent sul path RELATIVO allo share, col caso
    // limite "exe in root del drive" (C:\crosspilot.exe -> "") —
    // remote_parent senza separatori restituirebbe il file stesso come
    // dir (bug reale H166: list_directory("crosspilot.exe") -> CREATE
    // su file -> STATUS_NOT_A_DIRECTORY).
    let dir_rel = share_dir(&exe_rel).to_string();
    let ver_rel = share_join(&dir_rel, version::VER_FILE_NAME);
    let linux_rel = share_join(&dir_rel, version::LINUX_SIDECAR_NAME);

    // Probe di esistenza per-file (CREATE read-attrs + close): nessun
    // trasferimento dati e nessuna QUERY_DIRECTORY — la listing della
    // root dello share (dir_rel == "") non e' portable.
    let exe_present = file_exists(client, ctx, &exe_rel).await?;
    let linux_present = file_exists(client, ctx, &linux_rel).await?;

    // Report CHIAVE=valore — stesso formato dei canali WinRM/SSH.
    let mut report = String::new();
    report.push_str(if exe_present { "EXE=True\n" } else { "EXE=False\n" });
    report.push_str(if linux_present {
        "LINUX_PRESENT=True\n"
    } else {
        "LINUX_PRESENT=False\n"
    });

    // Righe grezze del .ver (BUILD_TS / EXE_SHA256 / LINUX_SHA256).
    match client.read_file(&ver_rel).await {
        Ok(bytes) => {
            let text = String::from_utf8_lossy(&bytes).replace('\r', "");
            report.push_str(&text);
            if !text.ends_with('\n') {
                report.push('\n');
            }
        }
        Err(SmbError::Status(status, _))
            if status == STATUS_OBJECT_NAME_NOT_FOUND
                || status == STATUS_OBJECT_PATH_NOT_FOUND =>
        {
            // Deploy legacy senza .ver: ts effettivo 0.
        }
        Err(e) => return Err(smb_err(ctx, e, "read .ver")),
    }

    // Hash dell'exe remoto via certutil su SCM (prova end-to-end del
    // canale exec; None se exe assente o exec fallita -> deploy fara'
    // comunque upload+verifica).
    if exe_present {
        let tmp_rel = format!("Windows\\Temp\\cp{}.tmp", temp_tag());
        let bat = certutil_bat(exe_path, &tmp_rel);
        match scm_exec(ctx, &bat, SCM_EXEC_TIMEOUT_SECS).await {
            Ok(out) => {
                if let Some(hash) = parse_certutil_hash(&out) {
                    report.push_str(&format!("EXE_HASH={}\n", hash));
                } else {
                    eprintln!(
                        "[bootstrap-smb] WARNING: hash exe remoto non parsato: {}",
                        out.trim()
                    );
                }
            }
            Err(e) => {
                eprintln!("[bootstrap-smb] WARNING hash exe remoto via SCM: {}", e);
            }
        }
    }

    let info = version::parse_remote_info(&report);
    eprintln!(
        "[DEBUG] remote_build_info (smb): exe_present={} ts={:?} linux_present={}",
        info.exe_present, info.build_ts, info.linux_present
    );
    if let Some(h) = &info.exe_sha256 {
        eprintln!(
            "[DEBUG] remote_build_info (smb): exe_sha256={}",
            &h[..16.min(h.len())]
        );
    }
    Ok(info)
}

// ---------------------------------------------------------------------------
// Entry point del canale
// ---------------------------------------------------------------------------

/// Preflight SMB/SCM (analogo di bootstrap::channel_probe /
/// bootstrap_ssh::probe) per il fallback di update::reconcile: verifica
/// che il canale sia VIVO prima di fermare un server funzionante —
/// fermarlo senza via di ripristino sarebbe un brick volontario.
pub async fn probe(exe_path: &str) -> Option<RemoteBuildInfo> {
    let ctx = smb_context();
    let mut client = match smb_connect(&ctx).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[update-fallback] preflight SMB fallito: {}", e);
            return None;
        }
    };
    match remote_build_info(&mut client, &ctx, exe_path).await {
        Ok(info) => {
            eprintln!(
                "[update-fallback] preflight SMB OK: ts remoto={:?} locale={} exe_present={}",
                info.build_ts,
                version::BUILD_TS,
                info.exe_present
            );
            Some(info)
        }
        Err(e) => {
            eprintln!("[update-fallback] preflight SMB fallito: {}", e);
            None
        }
    }
}

/// Bootstrap SMB/SCM completo — stesso contratto di
/// bootstrap::bootstrap_server / bootstrap_ssh::bootstrap_server:
///   1. remote_build_info: stato build remoto (C$ + certutil via SCM)
///   2. exe mancante/piu' vecchio -> deploy staged; piu' nuovo ->
///      self-update del client (mai downgrade); uguale -> deploy
///      idempotente
///   3. macro-blocco firewall (netsh via SCM)
///   4. avvio detached + polling TCP (riusa poll_server_startup)
///
/// Errori di trasporto -> ChannelUnreachable("SMB/SCM"): stesso
/// fail-fast del retry loop per WinRM/SSH (bug B1).
pub async fn bootstrap_server(exe_path: &str) -> Result<()> {
    let ctx = smb_context();
    eprintln!(
        "[bootstrap-smb] remote windows: bootstrap via SMB/SCM verso {} (exe={})",
        ctx.host, exe_path
    );

    let mut client = smb_connect(&ctx).await?;

    match remote_build_info(&mut client, &ctx, exe_path).await {
        Ok(info) => {
            if !info.exe_present {
                eprintln!("[bootstrap-smb] exe remoto mancante. Avvio deploy via SMB/SCM...");
                match bootstrap_smb_deploy::deploy_exe(&ctx, exe_path, &info).await {
                    Ok(()) => {}
                    Err(e) => {
                        // Trasporto morto -> fail-fast; altri errori ->
                        // warning: il server potrebbe essere gia' attivo
                        // (il polling decide).
                        if e.downcast_ref::<bootstrap::ChannelUnreachable>().is_some() {
                            return Err(e);
                        }
                        eprintln!("[ERROR] bootstrap-smb: deploy fallito: {}", e);
                    }
                }
            } else if info.is_newer_than_local() {
                // Remote PIU' NUOVO: il "piu' vecchio" e' il client ->
                // self-update (mai downgrade). Stessa escape hatch degli
                // altri canali: CROSSPILOT_NO_SELF_UPDATE=1.
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
                    let update_result = bootstrap_smb_deploy::self_update_smb(
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
                            if e.downcast_ref::<bootstrap::ChannelUnreachable>().is_some() {
                                return Err(e);
                            }
                            eprintln!(
                                "[WARNING] Remote piu' nuovo (ts={}) ma self-update SMB fallito: {}",
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
                match bootstrap_smb_deploy::deploy_exe(&ctx, exe_path, &info).await {
                    Ok(()) => {}
                    Err(e) => {
                        if e.downcast_ref::<bootstrap::ChannelUnreachable>().is_some() {
                            return Err(e);
                        }
                        eprintln!("[ERROR] bootstrap-smb: deploy fallito: {}", e);
                    }
                }
            }
        }
        Err(e) => {
            // remote_build_info fallito: trasporto morto (ChannelUnreachable)
            // o errore deterministico (auth/access) -> fail-fast.
            return Err(e);
        }
    }

    // --- MACRO-BLOCCO firewall inbound (speculare agli altri canali) ---
    bootstrap_smb_deploy::ensure_inbound_allow(&ctx).await;

    // --- Avvio detached + polling (contratto condiviso) ---
    match bootstrap_smb_deploy::start_server(&ctx, exe_path).await {
        Ok(()) => {}
        Err(e) => {
            if e.downcast_ref::<bootstrap::ChannelUnreachable>().is_some() {
                return Err(e);
            }
            // Avvio fallito ma trasporto vivo: il server potrebbe essere
            // gia' in esecuzione — il polling decide.
            eprintln!("[ERROR] bootstrap-smb: avvio server fallito: {}", e);
        }
    }

    let up = bootstrap::poll_server_startup().await;
    if !up {
        bootstrap_smb_deploy::remote_startup_diag(&ctx).await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_share_path_drive_letter() {
        let (share, rel) = admin_share_path("C:\\ci\\crosspilot.exe").unwrap();
        assert_eq!(share, "C$");
        assert_eq!(rel, "ci\\crosspilot.exe");
        // Separatore '/' tollerato e normalizzato.
        let (share, rel) = admin_share_path("d:/tools/x.exe").unwrap();
        assert_eq!(share, "D$");
        assert_eq!(rel, "tools\\x.exe");
        // Root del drive.
        let (share, rel) = admin_share_path("E:\\x.exe").unwrap();
        assert_eq!(share, "E$");
        assert_eq!(rel, "x.exe");
    }

    #[test]
    fn admin_share_path_rejects_non_drive() {
        assert!(admin_share_path("/unix/path").is_err());
        assert!(admin_share_path("\\\\srv\\share\\x.exe").is_err());
        assert!(admin_share_path("C:").is_err());
        assert!(admin_share_path("").is_err());
    }

    #[test]
    fn win_abs_roundtrip() {
        assert_eq!(win_abs("C$", "ci\\x.exe"), "C:\\ci\\x.exe");
        assert_eq!(win_abs("C$", ""), "C:\\");
    }

    #[test]
    fn certutil_hash_parsing() {
        // Formato contiguo (Win10+).
        let out = "SHA256 hash of file C:\\ci\\x.exe:\r\n\
                   0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n\
                   CertUtil: -hashfile command completed successfully.\r\n";
        assert_eq!(
            parse_certutil_hash(out).as_deref(),
            Some("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")
        );
        // Formato con spazi tra i byte (versioni vecchie).
        let spaced = "aa bb cc dd ee ff 00 11 aa bb cc dd ee ff 00 11 \
                      aa bb cc dd ee ff 00 11 aa bb cc dd ee ff 00 11";
        let out2 = format!("SHA256 hash of file:\r\n{}\r\nCertUtil: ok\r\n", spaced);
        assert!(parse_certutil_hash(&out2).is_some());
        // Nessun hash -> None.
        assert_eq!(parse_certutil_hash("CertUtil: -hashfile FAILED"), None);
    }

    #[test]
    fn bat_builders_shape() {
        // Ogni exe va nel cmd /c interno con redirect + type (fix stdio
        // nulla del contesto servizio — bug.md §2).
        let bat = certutil_bat("C:\\ci\\x.new.exe", "Windows\\Temp\\t.tmp");
        assert!(bat.contains("cmd /c \"certutil -hashfile \"C:\\ci\\x.new.exe\" SHA256"));
        assert!(bat.contains("type \"C:\\Windows\\Temp\\t.tmp\""));
        assert!(bat.contains("del /f /q \"C:\\Windows\\Temp\\t.tmp\""));

        let v = version_check_bat("C:\\ci\\x.new.exe", "Windows\\Temp\\t.tmp");
        assert!(v.contains("\"C:\\ci\\x.new.exe\" --version"));

        let s = swap_bat("C:\\ci\\x.exe", "C:\\ci\\x.new.exe", "Windows\\Temp\\t.tmp");
        assert!(s.contains("move /y \"C:\\ci\\x.exe\" \"C:\\ci\\x.exe.old\""));
        assert!(s.contains("move /y \"C:\\ci\\x.new.exe\" \"C:\\ci\\x.exe\""));
        // Hash post-swap nello stesso batch.
        assert!(s.contains("certutil -hashfile \"C:\\ci\\x.exe\""));
    }

    #[test]
    fn scm_start_codes() {
        assert!(scm_start_ok(0));
        assert!(scm_start_ok(1053));
        assert!(scm_start_ok(1067));
        assert!(!scm_start_ok(5)); // ACCESS_DENIED
        assert!(!scm_start_ok(1058)); // SERVICE_DISABLED
    }
}
