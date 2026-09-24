// Modulo ssh_transport: canale SSH unificato su russh + russh-sftp
// (spec docs/ssh-unified-prescan-bootstrap-spec.md §1.3).
//
// Nasconde completamente i tipi russh dietro 4 primitive usate da
// bootstrap_ssh: connect (auth a catena + host key TOFU), exec (stdout/
// stderr/exit-status), write_file/read_file/stat via SFTP. Una sola
// implementazione client (niente binario `ssh` di sistema): il dialetto
// dei comandi remoti (POSIX vs PowerShell) e' responsabilita' del
// chiamante — qui passa solo la stringa gia' pronta.
//
// AUTH (catena, primo successo vince — spec §1.5):
//   1. agent (SSH_AUTH_SOCK su unix; named pipe OpenSSH + Pageant su Windows)
//   2. key file: SSH_KEY, poi ~/.ssh/id_ed25519, id_rsa, id_ecdsa
//   3. password: SSH_PASS, poi fallback PASS (credenziali WinRM)
//
// HOST KEY TOFU: file crosspilot_known_hosts accanto al .env, formato
// standard known_hosts (host[:port] key-type base64). Prima vista ->
// accetta + append + warning; mismatch -> errore FATALE HostKeyMismatch
// (mai accettare in silenzio: possibile MITM). Escape hatch dev:
// SSH_INSECURE_NO_HOSTKEY=1 accetta tutto con WARNING esplicito.
//
// Errori di trasporto (connect refused/timeout, handshake fallito, auth
// esaurita) -> bootstrap::ChannelUnreachable("SSH"): stesso contratto
// del vecchio check_transport exit-255 del binario ssh.

use anyhow::{bail, Context, Result};
use russh::client::{self, Handle, Handler};
use russh::keys::agent::client::AgentClient;
use russh::keys::agent::AgentIdentity;
use russh::keys::known_hosts::{check_known_hosts_path, learn_known_hosts_path};
use russh::keys::{load_secret_key, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::ChannelMsg;
use russh_sftp::client::SftpSession;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex as AsyncMutex;

use crate::bootstrap;
use crate::envs;

/// Timeout del connect TCP+handshake SSH (come il vecchio ConnectTimeout=5
/// del binario ssh): refused/timeout -> ChannelUnreachable.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Timeout di un singolo exec remoto: i comandi del bootstrap (hash,
/// --version, mv, setsid, schtasks) sono rapidi; 120s copre sha256sum di
/// file grossi su dischi lenti senza lasciare il client appeso per sempre.
const EXEC_TIMEOUT: Duration = Duration::from_secs(120);

/// Dimensione chunk per gli upload SFTP (spec §1.3: mai un write unico
/// da ~MB — progress loggabile e finestra di flow-control rispettata).
const SFTP_CHUNK: usize = 64 * 1024;

/// Timeout per-request del sottosistema SFTP.
const SFTP_REQ_TIMEOUT_SECS: u64 = 60;

/// Errore FATALE: la host key del server non corrisponde a quella
/// registrata nel known_hosts TOFU (possibile MITM o host reinstallato).
/// NON e' un ChannelUnreachable: il bootstrap NON deve tentare altri
//  canali sulla stessa macchina — il chiamante deve propagare subito.
#[derive(Debug)]
pub struct HostKeyMismatch(pub String);

impl std::fmt::Display for HostKeyMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for HostKeyMismatch {}

/// Contesto SSH risolto dai campi ambiente (generalizzazione del vecchio
/// SshCtx di bootstrap_ssh: host/port/user espliciti + credenziali
/// opzionali per la catena di auth).
pub struct SshCtx {
    /// Hostname/IP del remote (SSH_HOST con fallback HOST).
    pub host: String,
    /// Porta SSH (SSH_PORT, default 22).
    pub port: u16,
    /// Username SSH (SSH_USER con fallback USER / utente di processo).
    pub user: String,
    /// Path esplicito della chiave privata (campo SSH_KEY, opzionale).
    pub key_path: Option<String>,
    /// Password SSH (campo SSH_PASS con fallback PASS, opzionale).
    pub password: Option<String>,
}

/// Output di un exec remoto: stdout+stderr accumulati e exit-status
/// (None se il server non l'ha inviato — connessione caduta a meta').
#[derive(Debug, Default)]
pub struct ExecOut {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub code: Option<u32>,
}

/// Attributi file riportati da stat() — wrapper dei metadata SFTP per
/// non esporre tipi russh-sftp al resto del codice.
#[derive(Debug, Clone, Copy)]
pub struct SftpAttrs {
    /// Dimensione in byte (None se il server non la riporta).
    pub size: Option<u64>,
}

/// Decisione TOFU su una host key: Ok(()) = accetta (nota o appena
/// imparata), Err(msg) = rifiuta — mismatch FATALE o keystore
/// illeggibile (mai accettare cieco). Funzione sincrona e separata
/// dall'handler per essere unit-testabile (spec §4: file noto ->
/// accept/reject/mismatch).
fn check_tofu(
    kh_path: &Path,
    host: &str,
    port: u16,
    pubkey: &russh::keys::ssh_key::PublicKey,
    insecure: bool,
) -> std::result::Result<(), String> {
    let fingerprint = pubkey.fingerprint(russh::keys::HashAlg::Sha256);

    // Escape hatch diagnostico (dev only): accetta tutto con WARNING
    // in chiaro ad ogni connect — documentato come insicuro.
    if insecure {
        eprintln!(
            "[ssh] WARNING: SSH_INSECURE_NO_HOSTKEY attivo — host key di {}:{} accettata senza verifica ({})",
            host, port, fingerprint
        );
        return Ok(());
    }

    if kh_path.exists() {
        let check = check_known_hosts_path(host, port, pubkey, kh_path);
        match check {
            Ok(true) => return Ok(()),
            Ok(false) => {
                // Host nel file ma questa chiave non registrata (o altro
                // algoritmo): il caso "chiave CAMBIATA sulla stessa tupla"
                // e' segnalato da Err(KeyChanged); qui e' first-seen ->
                // si cade sotto: registra e accetta.
            }
            Err(e) => {
                // KeyChanged = mismatch sulla stessa tupla host/port/
                // algoritmo: FATALE. Anche gli errori io/parse del file
                // sono fatali (mai accettare cieco su keystore illeggibile).
                let msg = format!(
                    "host key mismatch per {}:{} — la chiave presentata ({}) \
                     NON corrisponde a quella registrata in {}: possibile MITM \
                     o host reinstallato. Verificare a mano ed eventualmente \
                     rimuovere la riga stale. Dettaglio: {}",
                    host,
                    port,
                    fingerprint,
                    kh_path.display(),
                    e
                );
                eprintln!("[ssh] FATAL: {}", msg);
                return Err(msg);
            }
        }
    }

    // First-seen (file assente o host non registrato): append + warning.
    let learn = learn_known_hosts_path(host, port, pubkey, kh_path);
    match learn {
        Ok(()) => {
            eprintln!(
                "[ssh] TOFU: host key di {}:{} registrata in {} ({})",
                host,
                port,
                kh_path.display(),
                fingerprint
            );
            Ok(())
        }
        Err(e) => {
            eprintln!(
                "[ssh] WARNING: impossibile registrare la host key in {}: {} — accetto comunque questa sessione",
                kh_path.display(),
                e
            );
            Ok(())
        }
    }
}

/// Handler russh lato client: implementa il TOFU della host key.
/// `mismatch` e' condiviso col chiamante: check_server_key ritorna solo
/// bool, quindi il motivo del rifiuto va comunicato out-of-band per
/// distinguere il mismatch FATALE da un generico fallimento di connect.
struct SshHandler {
    host: String,
    port: u16,
    kh_path: PathBuf,
    insecure: bool,
    mismatch: Arc<Mutex<Option<String>>>,
}

impl Handler for SshHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let pubkey = server_public_key.public_key();
        let decision = check_tofu(
            &self.kh_path,
            &self.host,
            self.port,
            &pubkey,
            self.insecure,
        );
        match decision {
            Ok(()) => Ok(true),
            Err(msg) => {
                if let Ok(mut guard) = self.mismatch.lock() {
                    *guard = Some(msg);
                }
                Ok(false)
            }
        }
    }
}

/// Sessione SSH autenticata: handle russh + sottosistema SFTP aperto
/// lazy (alcuni sshd non lo espongono: niente SFTP = niente file ops ma
/// exec resta utilizzabile; il primo accesso fallisce li', non qui).
pub struct SshSession {
    handle: Handle<SshHandler>,
    sftp: AsyncMutex<Option<SftpSession>>,
}

/// Path del known_hosts dedicato: accanto al .env risolto da envs
/// (stessa directory -> viaggia con la configurazione degli ambienti).
fn known_hosts_path() -> PathBuf {
    let env_path = envs::env_file_path();
    let dir = match env_path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    dir.join("crosspilot_known_hosts")
}

/// Home directory del processo senza dipendenze extra: HOME su unix,
/// USERPROFILE su Windows.
fn home_dir() -> Option<PathBuf> {
    if let Some(h) = std::env::var_os("HOME") {
        return Some(PathBuf::from(h));
    }
    if let Some(h) = std::env::var_os("USERPROFILE") {
        return Some(PathBuf::from(h));
    }
    None
}

/// Tipo unico per gli AgentClient delle varie piattaforme (boxed via
/// `dynamic()`: stream eterogenei — UnixStream, named pipe, Pageant —
/// dietro lo stesso trait AgentStream).
type DynAgent = AgentClient<Box<dyn russh::keys::agent::client::AgentStream + Send + Unpin>>;

/// Connette al solo agent SSH disponibile su questa piattaforma:
/// - unix: SSH_AUTH_SOCK (connect_env);
/// - Windows: named pipe dell'agent OpenSSH, poi Pageant.
///
/// Ritorna l'AgentClient boxed oppure None se nessun agent e'
/// raggiungibile.
async fn connect_agent() -> Option<DynAgent> {
    agent_impl().await
}

#[cfg(unix)]
async fn agent_impl() -> Option<DynAgent> {
    let agent = AgentClient::connect_env().await;
    match agent {
        Ok(a) => Some(a.dynamic()),
        Err(e) => {
            eprintln!("[DEBUG] ssh auth: agent SSH_AUTH_SOCK non raggiungibile: {}", e);
            None
        }
    }
}

#[cfg(windows)]
async fn agent_impl() -> Option<DynAgent> {
    // OpenSSH for Windows usa una named pipe; Pageant e' il formato
    // storico (chiavi PuTTY). Provati in questo ordine.
    let pipe = AgentClient::connect_named_pipe(r"\\.\pipe\openssh-ssh-agent").await;
    match pipe {
        Ok(a) => return Some(a.dynamic()),
        Err(e) => {
            eprintln!("[DEBUG] ssh auth: named pipe openssh-agent non raggiungibile: {}", e);
        }
    }
    let pageant = AgentClient::connect_pageant().await;
    match pageant {
        Ok(a) => Some(a.dynamic()),
        Err(e) => {
            eprintln!("[DEBUG] ssh auth: Pageant non raggiungibile: {}", e);
            None
        }
    }
}

#[cfg(not(any(unix, windows)))]
async fn agent_impl() -> Option<DynAgent> {
    None
}

/// Hash preferito per le chiavi RSA (rsa-sha2-256/512: ssh-rsa/SHA1 e'
/// deprecato); None per gli altri algoritmi (ed25519/ecdsa non ne
/// hanno bisogno).
async fn rsa_hash_for<H: Handler>(
    handle: &Handle<H>,
    key: &russh::keys::ssh_key::PublicKey,
) -> Option<russh::keys::HashAlg> {
    let is_rsa = key.algorithm().is_rsa();
    if !is_rsa {
        return None;
    }
    let best = handle.best_supported_rsa_hash().await;
    match best {
        Ok(h) => h.flatten(),
        Err(_) => None,
    }
}

impl SshSession {
    /// connect TCP + handshake SSH + auth a catena + TOFU host key.
    /// Errori di trasporto -> ChannelUnreachable("SSH"); mismatch host
    /// key -> HostKeyMismatch (fatale, non ritentare su altri canali).
    pub async fn connect(ctx: &SshCtx) -> Result<Self> {
        let insecure = match envs::var("SSH_INSECURE_NO_HOSTKEY") {
            Some(v) => v == "1" || v.eq_ignore_ascii_case("true"),
            None => false,
        };
        let mismatch: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let handler = SshHandler {
            host: ctx.host.clone(),
            port: ctx.port,
            kh_path: known_hosts_path(),
            insecure,
            mismatch: mismatch.clone(),
        };

        let config = client::Config {
            nodelay: true,
            ..Default::default()
        };
        let config = Arc::new(config);
        let target = (ctx.host.as_str(), ctx.port);
        eprintln!(
            "[DEBUG] ssh connect: {}@{}:{} (timeout {}s)",
            ctx.user,
            ctx.host,
            ctx.port,
            CONNECT_TIMEOUT.as_secs()
        );
        let connect_fut = client::connect(config, target, handler);
        let connect_res = tokio::time::timeout(CONNECT_TIMEOUT, connect_fut).await;
        let mut handle = match connect_res {
            Ok(Ok(h)) => h,
            Ok(Err(e)) => {
                // Handshake SSH fallito: se la causa e' il mismatch della
                // host key e' un errore FATALE (flag settato dall'handler);
                // altrimenti e' trasporto -> ChannelUnreachable.
                if let Ok(guard) = mismatch.lock() {
                    if let Some(msg) = guard.as_ref() {
                        return Err(HostKeyMismatch(msg.clone()).into());
                    }
                }
                eprintln!("[DEBUG] ssh handshake fallito: {}", e);
                let err = anyhow::Error::from(bootstrap::ChannelUnreachable("SSH"));
                return Err(err.context(format!(
                    "handshake SSH verso {}:{}",
                    ctx.host, ctx.port
                )));
            }
            Err(_) => {
                eprintln!(
                    "[DEBUG] ssh connect timeout {}s verso {}:{}",
                    CONNECT_TIMEOUT.as_secs(),
                    ctx.host,
                    ctx.port
                );
                let err = anyhow::Error::from(bootstrap::ChannelUnreachable("SSH"));
                return Err(err.context(format!(
                    "connect SSH timeout verso {}:{}",
                    ctx.host, ctx.port
                )));
            }
        };

        authenticate(&mut handle, ctx).await?;
        eprintln!("[ssh] autenticato su {}:{}", ctx.host, ctx.port);

        Ok(SshSession {
            handle,
            sftp: AsyncMutex::new(None),
        })
    }

    /// Esegue `cmd` sulla shell di default del remote (testo raw — il
    /// dialetto giusto e' scelto dal chiamante). Niente PTY: exec batch
    /// non interattivo.
    pub async fn exec(&self, cmd: &str) -> Result<ExecOut> {
        let mut channel = self
            .handle
            .channel_open_session()
            .await
            .context("ssh channel_open_session")?;
        channel.exec(true, cmd).await.context("ssh exec request")?;

        let mut out = ExecOut::default();
        let read_loop = async {
            while let Some(msg) = channel.wait().await {
                match msg {
                    ChannelMsg::Data { data } => {
                        out.stdout.extend_from_slice(&data);
                    }
                    ChannelMsg::ExtendedData { data, .. } => {
                        // ext=1 (SSH_EXTENDED_DATA_STDERR): stderr remoto.
                        out.stderr.extend_from_slice(&data);
                    }
                    ChannelMsg::ExitStatus { exit_status } => {
                        out.code = Some(exit_status);
                    }
                    _ => {}
                }
            }
        };
        let done = tokio::time::timeout(EXEC_TIMEOUT, read_loop).await;
        if done.is_err() {
            bail!(
                "exec SSH timeout ({}s): comando remoto appeso: {:?}",
                EXEC_TIMEOUT.as_secs(),
                &cmd[..cmd.len().min(80)]
            );
        }
        Ok(out)
    }

    /// Sottosistema SFTP lazy: aperto al primo accesso e riusato.
    /// Errore qui (sshd senza sftp) riguarda solo le file ops.
    async fn sftp(&self) -> Result<tokio::sync::MutexGuard<'_, Option<SftpSession>>> {
        let mut guard = self.sftp.lock().await;
        if guard.is_none() {
            let channel = self
                .handle
                .channel_open_session()
                .await
                .context("sftp channel_open_session")?;
            channel
                .request_subsystem(true, "sftp")
                .await
                .context("sftp request_subsystem")?;
            let stream = channel.into_stream();
            let session = SftpSession::new(stream)
                .await
                .context("sftp session init")?;
            session.set_timeout(SFTP_REQ_TIMEOUT_SECS);
            *guard = Some(session);
        }
        Ok(guard)
    }

    /// Upload di `data` su `path` remoto via SFTP chunked (64KB).
    /// QUIRK russh-sftp (verificato nello spike): `write()` usa
    /// OpenFlags::WRITE senza CREATE -> "No such file" su file nuovi;
    /// l'upload corretto e' `create()` (CREATE|TRUNCATE|WRITE) +
    /// write_all sul File.
    pub async fn write_file(&self, path: &str, data: &[u8]) -> Result<()> {
        let guard = self.sftp().await?;
        let sftp = match guard.as_ref() {
            Some(s) => s,
            None => bail!("sftp non inizializzato"),
        };
        eprintln!(
            "[deploy-ssh] upload SFTP {} byte -> {}",
            data.len(),
            path
        );
        let mut file = sftp
            .create(path)
            .await
            .with_context(|| format!("sftp create {}", path))?;
        let mut off = 0usize;
        while off < data.len() {
            let end = (off + SFTP_CHUNK).min(data.len());
            file.write_all(&data[off..end])
                .await
                .with_context(|| format!("sftp write {} (off {})", path, off))?;
            off = end;
        }
        file.shutdown()
            .await
            .with_context(|| format!("sftp close {}", path))?;
        Ok(())
    }

    /// Download di `path` remoto via SFTP (binario raw — sostituisce il
    /// vecchio `cat` via exec, shell-independent).
    pub async fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        let guard = self.sftp().await?;
        let sftp = match guard.as_ref() {
            Some(s) => s,
            None => bail!("sftp non inizializzato"),
        };
        let data = sftp
            .read(path)
            .await
            .with_context(|| format!("sftp read {}", path))?;
        Ok(data)
    }

    /// Metadata del file remoto, o None se assente/illegibile.
    pub async fn stat(&self, path: &str) -> Option<SftpAttrs> {
        let guard = self.sftp().await.ok()?;
        let sftp = match guard.as_ref() {
            Some(s) => s,
            None => return None,
        };
        let meta = sftp.metadata(path).await.ok()?;
        Some(SftpAttrs { size: meta.size })
    }
}

/// Catena di autenticazione (spec §1.5): agent -> key files -> password.
/// Ogni fallimento e' loggato a livello debug; se TUTTI i metodi
/// falliscono -> ChannelUnreachable("SSH") (stesso contratto del vecchio
/// exit 255 di BatchMode).
async fn authenticate(handle: &mut Handle<SshHandler>, ctx: &SshCtx) -> Result<()> {
    // --- Metodo 1: agent ---
    let agent = connect_agent().await;
    if let Some(mut agent) = agent {
        let identities = agent.request_identities().await;
        match identities {
            Ok(list) => {
                eprintln!("[DEBUG] ssh auth: agent espone {} identita'", list.len());
                for identity in &list {
                    // Solo chiavi plain: i certificati OpenSSH richiedono
                    // authenticate_openssh_cert (fuori scope v1).
                    let key = match identity {
                        AgentIdentity::PublicKey { key, .. } => key.clone(),
                        _ => continue,
                    };
                    let hash_alg = rsa_hash_for(handle, &key).await;
                    let res = handle
                        .authenticate_publickey_with(ctx.user.clone(), key, hash_alg, &mut agent)
                        .await;
                    match res {
                        Ok(r) if r.success() => return Ok(()),
                        Ok(_) => eprintln!("[DEBUG] ssh auth: identita' agent rifiutata"),
                        Err(e) => eprintln!("[DEBUG] ssh auth: errore agent: {}", e),
                    }
                }
            }
            Err(e) => eprintln!("[DEBUG] ssh auth: request_identities fallita: {}", e),
        }
    }

    // --- Metodo 2: key files ---
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(k) = &ctx.key_path {
        candidates.push(PathBuf::from(k));
    }
    if let Some(home) = home_dir() {
        let ssh_dir = home.join(".ssh");
        candidates.push(ssh_dir.join("id_ed25519"));
        candidates.push(ssh_dir.join("id_rsa"));
        candidates.push(ssh_dir.join("id_ecdsa"));
    }
    for path in candidates {
        if !path.exists() {
            continue;
        }
        let key = load_secret_key(&path, None);
        let key = match key {
            Ok(k) => k,
            Err(e) => {
                eprintln!(
                    "[DEBUG] ssh auth: chiave {} non caricabile: {}",
                    path.display(),
                    e
                );
                continue;
            }
        };
        let pubkey = key.public_key().clone();
        let hash_alg = rsa_hash_for(handle, &pubkey).await;
        let wrapped = PrivateKeyWithHashAlg::new(Arc::new(key), hash_alg);
        let res = handle
            .authenticate_publickey(ctx.user.clone(), wrapped)
            .await;
        match res {
            Ok(r) if r.success() => {
                eprintln!("[DEBUG] ssh auth: OK con chiave {}", path.display());
                return Ok(());
            }
            Ok(_) => eprintln!("[DEBUG] ssh auth: chiave {} rifiutata", path.display()),
            Err(e) => eprintln!(
                "[DEBUG] ssh auth: errore con chiave {}: {}",
                path.display(),
                e
            ),
        }
    }

    // --- Metodo 3: password ---
    if let Some(pass) = &ctx.password {
        let res = handle
            .authenticate_password(ctx.user.clone(), pass.clone())
            .await;
        match res {
            Ok(r) if r.success() => {
                eprintln!("[DEBUG] ssh auth: OK con password (SSH_PASS/PASS)");
                return Ok(());
            }
            Ok(_) => eprintln!("[DEBUG] ssh auth: password rifiutata"),
            Err(e) => eprintln!("[DEBUG] ssh auth: errore password: {}", e),
        }
    }

    let err = anyhow::Error::from(bootstrap::ChannelUnreachable("SSH"));
    Err(err.context(format!(
        "autenticazione SSH verso {}@{}:{} fallita con tutti i metodi \
         (agent, key files, password)",
        ctx.user, ctx.host, ctx.port
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Due chiavi pubbliche ed25519 di fixture (generate una tantum con
    /// ssh-keygen; dati di test pubblici, non segreti).
    const KEY_A: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIPVpFaCV29ktwTMPG7x415sY3XA8C7r89rz/njlr5s3+";
    const KEY_B: &str = "AAAAC3NzaC1lZDI1NTE5AAAAILgKSH+JQhZ4p3OIt0XMoFL0TLfH+itbdIyZq59brSEK";

    fn pubkey(b64: &str) -> russh::keys::ssh_key::PublicKey {
        let parsed = russh::keys::parse_public_key_base64(b64);
        parsed.expect("fixture key parse")
    }

    fn temp_kh(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir();
        let name = format!("crosspilot-kh-test-{}-{}", std::process::id(), tag);
        let path = dir.join(name);
        let _ = std::fs::remove_file(&path);
        path
    }

    #[test]
    fn tofu_first_seen_learn_then_accept() {
        let kh = temp_kh("learn");
        let key = pubkey(KEY_A);
        // Prima vista: file assente -> accetta e registra.
        let d = check_tofu(&kh, "host-a", 22, &key, false);
        assert!(d.is_ok());
        assert!(kh.exists());
        // Seconda vista: stessa chiave -> accetta senza errori.
        let d = check_tofu(&kh, "host-a", 22, &key, false);
        assert!(d.is_ok());
        let _ = std::fs::remove_file(&kh);
    }

    #[test]
    fn tofu_mismatch_is_fatal() {
        let kh = temp_kh("mismatch");
        // Registra KEY_A, poi presenta KEY_B per lo stesso host:port:
        // deve risultare un rifiuto (mismatch = possibile MITM).
        let d = check_tofu(&kh, "host-b", 22, &pubkey(KEY_A), false);
        assert!(d.is_ok());
        let d = check_tofu(&kh, "host-b", 22, &pubkey(KEY_B), false);
        assert!(d.is_err());
        let msg = d.err().unwrap_or_default();
        assert!(msg.contains("host key mismatch"));
        let _ = std::fs::remove_file(&kh);
    }

    #[test]
    fn tofu_porta_diversa_e_host_diverso() {
        let kh = temp_kh("scope");
        let d = check_tofu(&kh, "host-c", 22, &pubkey(KEY_A), false);
        assert!(d.is_ok());
        // Stessa chiave su porta diversa: known_hosts usa [host]:port —
        // tupla diversa -> first-seen, non mismatch.
        let d = check_tofu(&kh, "host-c", 2222, &pubkey(KEY_A), false);
        assert!(d.is_ok());
        // Stessa chiave su host diverso: first-seen.
        let d = check_tofu(&kh, "altro", 22, &pubkey(KEY_A), false);
        assert!(d.is_ok());
        let _ = std::fs::remove_file(&kh);
    }

    #[test]
    fn tofu_insecure_accetta_tutto() {
        // SSH_INSECURE_NO_HOSTKEY=1: anche il mismatch e' accettato
        // (con WARNING nel log). Solo dev.
        let kh = temp_kh("insecure");
        let d = check_tofu(&kh, "h", 22, &pubkey(KEY_A), false);
        assert!(d.is_ok());
        let d = check_tofu(&kh, "h", 22, &pubkey(KEY_B), true);
        assert!(d.is_ok());
        let _ = std::fs::remove_file(&kh);
    }
}
