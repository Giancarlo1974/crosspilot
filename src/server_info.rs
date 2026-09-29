// Modulo server_info: self-describe del server (INFO_REQ/INFO_RES) e
// risoluzione dell'identita' remota (spec selfdescribe-guardrail §2-§4).
//
// PRINCIPIO: il server sa chi e' — il client non deve mai dedurre l'OS
// o il path dell'exe remoto dall'env senza una verifica. Ordine di
// verita' (§3): INFO_RES (server vivo che si descrive) > discovery
// RUNNING_EXE del canale bootstrap > env (gate coerenza §5).
//
// Lato server: handle_file_mode risponde a MSG_INFO_REQ con le righe
// CHIAVE=valore costruite da info_res_payload().
// Lato client: fetch() apre UNA connessione dedicata, chiede INFO_RES e
// cachea il risultato per processo (OnceCell: il remote non cambia OS
// a meta' sessione).

use anyhow::{Context, Result};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::OnceCell;

use crate::{bootstrap, envs, path, proto, update, version};

// ---------------------------------------------------------------------------
// Lato server: costruzione del payload INFO_RES.
// ---------------------------------------------------------------------------

/// Cache dell'INFO_RES: l'exe in esecuzione non cambia per la vita del
/// processo -> l'hash e' calcolato UNA sola volta.
///
/// Bug trovato in e2e (debug build ~250 MB): l'hash a OGNI INFO_REQ
/// impiegava ~12s > INFO_TIMEOUT (5s) del client -> il client dropava
/// e il server loggava "Broken pipe"; peggio, fetch() cacheava il None
/// per tutto il processo e `remote_is_unix_resolved` restava sempre
/// sul fallback env (remote unix visto come windows -> quoting cmd).
/// Con la cache (piu' warm-up all'avvio) ogni INFO_REQ risponde subito.
static INFO_RES: std::sync::OnceLock<proto::InfoRes> = std::sync::OnceLock::new();

/// Payload di self-describe (lato server): OS compile-time, path
/// canonico dell'exe in esecuzione, BUILD_TS e SHA-256 (hex minuscolo)
/// dell'exe — i dati che un .ver scritto "a posteriori" non puo'
/// garantire perche' l'exe potrebbe essere stato sostituito a mano.
/// Risultato cacheato: sicuro e veloce da riusare a ogni INFO_REQ.
pub(crate) fn info_res_payload() -> Result<&'static proto::InfoRes> {
    if let Some(res) = INFO_RES.get() {
        return Ok(res);
    }
    let built = build_info_res()?;
    Ok(INFO_RES.get_or_init(|| built))
}

/// Warm-up della cache INFO_RES all'avvio del server: la prima
/// interrogazione client trova la risposta gia' pronta (il costo dell'
/// hash si paga in init, non dentro il budget INFO_TIMEOUT del client).
pub(crate) fn warm_up() {
    if let Err(e) = info_res_payload() {
        crate::qprintln!("[DEBUG] server_info warm-up fallito: {}", e);
    }
}

/// Costruisce il payload INFO_RES (eseguito una volta, poi cacheato).
fn build_info_res() -> Result<proto::InfoRes> {
    let exe = std::env::current_exe().context("current_exe")?;
    // canonicalize risolve symlink e '.' — il path e' la verita' del
    // filesystem, non quella dichiarata in EXE_PATH.
    let canon = exe.canonicalize().unwrap_or(exe);
    let hash = update::sha256_file_hex(&canon)
        .context("hash exe in esecuzione")?
        .to_lowercase();
    Ok(proto::InfoRes {
        os_tag: if cfg!(target_os = "windows") {
            "W"
        } else {
            "L"
        }
        .to_string(),
        exe_path: canon.to_string_lossy().to_string(),
        build_ts: version::BUILD_TS,
        exe_sha256: hash,
    })
}

// ---------------------------------------------------------------------------
// Lato client: fetch + cache.
// ---------------------------------------------------------------------------

/// Cache del self-describe: una sola interrogazione per processo
/// (reconcile puo' essere richiamato piu' volte nel retry loop).
static SERVER_INFO: OnceCell<Option<version::ServerInfo>> = OnceCell::const_new();

/// Chiede al server remoto la propria identita' (INFO_REQ) e la
/// restituisce tipizzata. None su: server pre-selfdescribe (ERR),
/// connessione fallita, payload incompleto/tag OS ignoto.
/// Il risultato e' cacheato: le chiamate successive sono gratis.
pub async fn fetch() -> Option<version::ServerInfo> {
    let cached = SERVER_INFO.get_or_init(fetch_once).await;
    cached.clone()
}

/// Timeout della risposta INFO_RES: un server vecchio risponde ERR
/// subito; il timeout copre solo server silenziosi/anomali.
const INFO_TIMEOUT: Duration = Duration::from_secs(5);

/// Una interrogazione INFO_RES su connessione dedicata (regola del
/// peek server: i messaggi framed vanno su connessioni che inviano
/// subito — mai riusare il socket dell'handshake).
async fn fetch_once() -> Option<version::ServerInfo> {
    let host = envs::var("HOST").unwrap_or_else(|| "127.0.0.1".to_string());
    let port = envs::var("CLIENT_PORT").unwrap_or_else(|| "47330".to_string());
    let addr = format!("{}:{}", host, port);
    let (mut s, _hello) = match crate::connect_raw(&addr).await {
        Ok(v) => v,
        Err(e) => {
            crate::qprintln!("[DEBUG] INFO_RES fetch: connect {} fallita: {}", addr, e);
            return None;
        }
    };
    if let Err(e) = proto::send_info_req(&mut s).await {
        crate::qprintln!("[DEBUG] INFO_RES fetch: send fallita: {}", e);
        return None;
    }
    let read = tokio::time::timeout(INFO_TIMEOUT, proto::read_msg(&mut s)).await;
    match read {
        Ok(Ok((proto::MSG_INFO_RES, payload))) => match proto::decode_info_res(&payload) {
            Ok(raw) => match version::ServerInfo::from_info_res(&raw) {
                Some(info) => {
                    crate::qprintln!(
                        "[DEBUG] INFO_RES: os={:?} exe={} ts={} sha256={}",
                        info.os,
                        info.exe_path,
                        info.build_ts,
                        &info.exe_sha256[..8.min(info.exe_sha256.len())]
                    );
                    Some(info)
                }
                None => {
                    crate::qprintln!("[DEBUG] INFO_RES: payload senza OS/EXE_PATH validi");
                    None
                }
            },
            Err(e) => {
                crate::qprintln!("[DEBUG] INFO_RES: payload malformato: {}", e);
                None
            }
        },
        // Server pre-selfdescribe: tipo sconosciuto -> ERR o close.
        Ok(Ok((proto::MSG_ERR, _))) => {
            crate::qprintln!("[DEBUG] INFO_RES non supportato dal server (pre-selfdescribe)");
            None
        }
        Ok(Ok((t, _))) => {
            crate::qprintln!("[DEBUG] INFO_RES fetch: tipo inatteso {}", t);
            None
        }
        Ok(Err(e)) => {
            crate::qprintln!("[DEBUG] INFO_RES fetch: read fallita: {}", e);
            None
        }
        Err(_) => {
            crate::qprintln!(
                "[DEBUG] INFO_RES fetch: timeout {}s",
                INFO_TIMEOUT.as_secs()
            );
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Identita' remota risolta (spec §3).
// ---------------------------------------------------------------------------

/// Fonte della verita' sull'identita' remota (ordine di precedenza).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentitySource {
    /// INFO_RES del server vivo (self-describe §2).
    InfoRes,
    /// RUNNING_EXE dal preflight del canale bootstrap (§6).
    Discovery,
    /// Configurazione .env (gate coerenza §5 applicato).
    Env,
}

/// Identita' risolta del remote: OS reale + path reale dell'exe +
/// fonte (per i log e per reconcile_config §4).
#[derive(Debug, Clone)]
pub struct RemoteIdentity {
    /// OS reale del server.
    pub os: version::RemoteOs,
    /// Path dell'exe remoto (canonico se da INFO_RES, reale se da
    /// discovery, configurato se da env).
    pub exe_path: String,
    /// Fonte della verita' usata.
    pub source: IdentitySource,
}

/// Risolve l'identita' remota secondo l'ordine di verita' §3:
///   1. INFO_RES del server vivo (vince sempre — e' il processo stesso
///      che parla);
///   2. RUNNING_EXE della discovery canale (preflight §6 gia' fatto);
///   3. env, SOLO dopo il gate di coerenza §5 (la config e' la sola
///      fonte e non puo' essere contraddittoria).
pub async fn remote_identity(
    discovery: Option<&version::RemoteBuildInfo>,
) -> Result<RemoteIdentity> {
    // 1. INFO_RES.
    if let Some(info) = fetch().await {
        return Ok(RemoteIdentity {
            os: info.os,
            exe_path: info.exe_path,
            source: IdentitySource::InfoRes,
        });
    }
    // 2. Discovery: path del processo VIVO, mai quello configurato.
    if let Some(info) = discovery {
        if let Some(rxe) = &info.running_exe {
            if !rxe.trim().is_empty() {
                let os = if path::is_windows_path(rxe) {
                    version::RemoteOs::Windows
                } else {
                    version::RemoteOs::Linux
                };
                return Ok(RemoteIdentity {
                    os,
                    exe_path: rxe.clone(),
                    source: IdentitySource::Discovery,
                });
            }
        }
    }
    // 3. Env: unica fonte -> il gate §5 blocca le configurazioni
    //    incoerenti (OS=linux + EXE_PATH Windows ereditato = il caso
    //    del brick reale).
    envs::check_os_exe_coherence()?;
    let exe_path = envs::var("EXE_PATH").context(
        "EXE_PATH non configurato e nessuna identita' remota disponibile \
         (server pre-selfdescribe e discovery assente)",
    )?;
    let os = if bootstrap::remote_is_unix() {
        version::RemoteOs::Linux
    } else {
        version::RemoteOs::Windows
    };
    Ok(RemoteIdentity {
        os,
        exe_path,
        source: IdentitySource::Env,
    })
}

// ---------------------------------------------------------------------------
// reconcile_config (spec §4): drift env <-> identita' remota.
// ---------------------------------------------------------------------------

/// Dedup del warning di drift (una volta per processo).
static DRIFT_WARNED: AtomicBool = AtomicBool::new(false);

/// Una divergenza tra env e identita' remota: campo, valore env (None =
/// assente), valore remoto.
#[derive(Debug, PartialEq)]
pub struct ConfigDrift {
    /// Campo .env divergente (es. "EXE_PATH", "OS").
    pub field: &'static str,
    /// Valore env attuale (None = campo assente).
    pub env_value: Option<String>,
    /// Valore reale del remote.
    pub remote_value: String,
}

/// Confronto puro env<->identita' (testabile, nessun I/O):
/// - EXE_PATH: confronto normalizzato (case-insensitive + '/'->'\'
///   su remote Windows; esatto su unix);
/// - OS: l'env conta solo se dichiara un OS riconosciuto che
///   contraddice l'identita' (OS assente = nessuna pretesa).
pub(crate) fn config_drifts(
    id: &RemoteIdentity,
    env_os: Option<&str>,
    env_exe: Option<&str>,
) -> Vec<ConfigDrift> {
    let mut out = Vec::new();
    // EXE_PATH.
    let exe_drift = match env_exe {
        Some(v) => !same_remote_path_as(id.os, v, &id.exe_path),
        // EXE_PATH assente mentre il remote ne ha uno reale: drift solo
        // se la fonte remota e' autorevole (segnaliamo il campo mancante).
        None => true,
    };
    if exe_drift {
        out.push(ConfigDrift {
            field: "EXE_PATH",
            env_value: env_exe.map(|s| s.to_string()),
            remote_value: id.exe_path.clone(),
        });
    }
    // OS: solo se l'env dichiara un OS riconosciuto e contraddittorio.
    if let Some(v) = env_os {
        let declared = match v.trim().to_lowercase().as_str() {
            "linux" | "unix" => Some(version::RemoteOs::Linux),
            "windows" | "win" | "win32" | "nt" => Some(version::RemoteOs::Windows),
            _ => None,
        };
        if let Some(decl) = declared {
            if decl != id.os {
                let remote_tag = match id.os {
                    version::RemoteOs::Linux => "linux",
                    version::RemoteOs::Windows => "windows",
                };
                out.push(ConfigDrift {
                    field: "OS",
                    env_value: Some(v.to_string()),
                    remote_value: remote_tag.to_string(),
                });
            }
        }
    }
    out
}

/// Confronto di path remoti tenendo conto dell'OS: su Windows il
/// confronto e' case-insensitive e '/' e' normalizzato a '\'; su unix
/// e' esatto. Riallineato a update::same_remote_path.
fn same_remote_path_as(os: version::RemoteOs, a: &str, b: &str) -> bool {
    match os {
        version::RemoteOs::Windows => {
            let na = a.replace('/', "\\").to_lowercase();
            let nb = b.replace('/', "\\").to_lowercase();
            na == nb
        }
        version::RemoteOs::Linux => a == b,
    }
}

/// Chiave .env per il campo dell'ambiente attivo (CROSSPILOT_<ENV>_<F>
/// o CROSSPILOT_<F> sul default).
fn field_key(field: &str) -> String {
    match envs::active_name() {
        Some(n) => format!("CROSSPILOT_{}_{}", n, field),
        None => format!("CROSSPILOT_{}", field),
    }
}

/// Spec §4: se l'identita' risolta (fonte remota) diverge dalla config,
/// avvisa UNA volta per processo con la chiave corretta suggerita.
/// Write-back delle sole chiavi divergenti: con --fix-env /
/// CROSSPILOT_FIX_ENV=1, oppure — per richiesta utente (deviazione da
/// spec §9) — auto-abilitato: se la chiave FIX_ENV e' del tutto assente
/// viene scritta `CROSSPILOT_FIX_ENV=1` nel .env e il fix parte subito.
pub fn reconcile_config(id: &RemoteIdentity) {
    if id.source == IdentitySource::Env {
        return; // la config E' la fonte: niente drift da rilevare
    }
    let env_os = envs::var("OS");
    let env_exe = envs::var("EXE_PATH");
    let drifts = config_drifts(id, env_os.as_deref(), env_exe.as_deref());
    if drifts.is_empty() {
        return;
    }
    if !DRIFT_WARNED.swap(true, Ordering::Relaxed) {
        for d in &drifts {
            let env_val = d
                .env_value
                .clone()
                .unwrap_or_else(|| "<assente>".to_string());
            eprintln!(
                "[config] {} env='{}' remoto='{}' (fonte: {:?})",
                d.field, env_val, d.remote_value, id.source
            );
            eprintln!("         — uso il valore remoto per questa sessione.");
            eprintln!(
                "         Per renderlo permanente: {}={}",
                field_key(d.field),
                d.remote_value
            );
        }
    }
    // Write-back: --fix-env/CROSSPILOT_FIX_ENV=1, oppure auto-abilitato
    // scrivendo la chiave nel .env quando assente (richiesta utente —
    // deviazione documentata dall'opt-in di spec §9).
    if envs::fix_env_enabled() || envs::ensure_fix_env() {
        let name = envs::active_name();
        for d in &drifts {
            match envs::fix_field(name.as_deref(), d.field, &d.remote_value) {
                Ok(()) => eprintln!(
                    "[fix-env] {} scritto: {}",
                    field_key(d.field),
                    d.remote_value
                ),
                Err(e) => eprintln!("[fix-env] WARNING scrittura {}: {}", field_key(d.field), e),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Test.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn id(source: IdentitySource, os: version::RemoteOs, exe: &str) -> RemoteIdentity {
        RemoteIdentity {
            os,
            exe_path: exe.to_string(),
            source,
        }
    }

    #[test]
    fn drifts_exe_divergente() {
        // Il caso reale: env eredita un path Windows su remote Linux.
        let rid = id(
            IdentitySource::InfoRes,
            version::RemoteOs::Linux,
            "/home/rocky/crosspilot",
        );
        let d = config_drifts(
            &rid,
            Some("linux"),
            Some("C:\\Users\\gianca\\crosspilot.exe"),
        );
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].field, "EXE_PATH");
        assert_eq!(d[0].remote_value, "/home/rocky/crosspilot");
    }

    #[test]
    fn drifts_os_contraddittorio_e_assente() {
        let rid = id(
            IdentitySource::Discovery,
            version::RemoteOs::Linux,
            "/opt/cp",
        );
        // OS=windows esplicito contro remote linux -> drift.
        let d = config_drifts(&rid, Some("windows"), Some("/opt/cp"));
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].field, "OS");
        assert_eq!(d[0].remote_value, "linux");
        // OS assente: nessuna pretesa -> nessun drift OS.
        let d = config_drifts(&rid, None, Some("/opt/cp"));
        assert!(d.is_empty());
        // OS sconosciuto: tollerato.
        let d = config_drifts(&rid, Some("haiku"), Some("/opt/cp"));
        assert!(d.is_empty());
    }

    #[test]
    fn drifts_exe_normalizzato_windows() {
        // Su remote Windows il confronto ignora case e separatori.
        let rid = id(
            IdentitySource::InfoRes,
            version::RemoteOs::Windows,
            "C:\\Ci\\CrossPilot.exe",
        );
        let d = config_drifts(&rid, Some("windows"), Some("c:/ci/crosspilot.exe"));
        assert!(d.is_empty(), "drift spurio su path equivalente: {:?}", d);
        // Diverso davvero.
        let d = config_drifts(&rid, Some("windows"), Some("D:\\other\\cp.exe"));
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].field, "EXE_PATH");
    }

    #[test]
    fn drifts_exe_assente_env() {
        // EXE_PATH mancante del tutto: segnalato (il remote sa dove gira).
        let rid = id(
            IdentitySource::Discovery,
            version::RemoteOs::Linux,
            "/opt/cp",
        );
        let d = config_drifts(&rid, None, None);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].field, "EXE_PATH");
        assert_eq!(d[0].env_value, None);
    }

    #[test]
    fn info_res_payload_forma_attesa() {
        // Il payload del server ha sempre tutte e 4 le chiavi.
        let res = info_res_payload().unwrap();
        assert!(res.os_tag == "L" || res.os_tag == "W");
        assert!(!res.exe_path.is_empty());
        assert_eq!(res.build_ts, version::BUILD_TS);
        assert_eq!(res.exe_sha256.len(), 64);
        // Roundtrip completo: encode -> decode -> ServerInfo.
        let payload = proto::encode_info_res(res).unwrap();
        let raw = proto::decode_info_res(&payload).unwrap();
        let info = version::ServerInfo::from_info_res(&raw).unwrap();
        assert_eq!(info.exe_path, res.exe_path);
    }
}
