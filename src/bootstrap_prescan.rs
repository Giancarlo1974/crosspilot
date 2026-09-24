// Modulo bootstrap_prescan: prescan TCP delle porte di management PRIMA
// della scelta del canale + lista candidati ordinata
// (spec docs/ssh-unified-prescan-bootstrap-spec.md §2).
//
// Motivazione: prima la "selezione" del canale era scoprire il canale
// morto pagando il timeout del protocollo (WinRM filtrato = ~30s prima
// del fallback SMB). Spostando la probe TCP (3s, sequenziale — MAI
// parallela verso il remote, best-practice traffico) PRIMA della scelta
// si arriva al canale giusto in ~3s e l'evidenza raccolta riempie
// MGMT_EVIDENCE gratis (niente ri-probe in print_psremoting_hint).
//
// Una sola scansione per processo (PRESCAN OnceCell, dedup tipo
// HINT_PRINTED): bootstrap_server rientra nel retry loop e la seconda
// scansione non deve costare altri 9-12s.

use anyhow::Result;
use std::fmt::Write;
use std::sync::Mutex;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::OnceCell;

use crate::bootstrap;
use crate::bootstrap_smb;
use crate::bootstrap_ssh;
use crate::envs;
use crate::version::RemoteBuildInfo;

/// Timeout della singola probe TCP (vincolo esistente, invariato).
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Stato di una porta TCP remota dopo una probe di connect.
/// La distinzione refused/timeout e' diagnostica: refused (RST) = host
/// vivo senza listener; timeout/drop = firewall o host giu'.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PortState {
    /// Connect riuscita: listener attivo.
    Open,
    /// RST immediato: host vivo, nessun listener sulla porta.
    Refused,
    /// Timeout o errore di rete: SYN filtrato oppure host irraggiungibile.
    Filtered,
}

impl PortState {
    fn label(self) -> &'static str {
        match self {
            PortState::Open => "aperta",
            PortState::Refused => "chiusa (refused: host vivo, nessun listener)",
            PortState::Filtered => "filtrata/irraggiungibile (timeout)",
        }
    }
}

/// Risultato del prescan: stato delle porte di management del remote.
/// Le porte non pertinenti all'OS del remote restano None (su unix non
/// si probano 445/5985; su Windows si probano anche 22 — spec §2.2).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Prescan {
    /// Porta del server crosspilot (CLIENT_PORT).
    pub(crate) server_port: u16,
    pub(crate) server: PortState,
    /// Porta SSH (SSH_PORT, default 22). Sempre probata: su remote unix
    /// e' il canale primario, su remote Windows e' il canale SSH-win.
    pub(crate) ssh_port: u16,
    pub(crate) ssh: Option<PortState>,
    /// Porta WinRM (PORT, default 5985) — solo remote Windows.
    pub(crate) winrm_port: u16,
    pub(crate) winrm: Option<PortState>,
    /// SMB/SCM (445 fisso) — solo remote Windows.
    pub(crate) smb: Option<PortState>,
}

impl Prescan {
    /// Blocco "TCP porta: stato" per i messaggi utente (stessa matrice
    /// del vecchio MgmtProbe, estesa con la riga SSH). Solo le porte
    /// effettivamente probatae compaiono.
    pub(crate) fn render(&self) -> String {
        let mut ev = String::new();
        let _ = writeln!(
            ev,
            "       TCP {} (server):  {}",
            self.server_port,
            self.server.label()
        );
        if let Some(w) = self.winrm {
            let _ = writeln!(
                ev,
                "       TCP {} (WinRM):    {}",
                self.winrm_port,
                w.label()
            );
        }
        if let Some(s) = self.smb {
            let _ = writeln!(ev, "       TCP 445 (SMB/SCM): {}", s.label());
        }
        if let Some(s) = self.ssh {
            let _ = write!(
                ev,
                "       TCP {} (SSH):      {}",
                self.ssh_port,
                s.label()
            );
        }
        ev
    }

    /// True se almeno un canale di management e' Open (usato dalla
    /// diagnosi anticipata "porta server filtrata" di spec §2.5).
    fn any_mgmt_open(&self) -> bool {
        let ssh_open = self.ssh == Some(PortState::Open);
        let winrm_open = self.winrm == Some(PortState::Open);
        let smb_open = self.smb == Some(PortState::Open);
        ssh_open || winrm_open || smb_open
    }

    /// Diagnosi sintetica dagli stati delle porte (matrice spec §3.2
    /// estesa con la riga SSH): evidence-based, mai "Enable-PSRemoting"
    /// come unica risposta.
    pub(crate) fn diagnosis(&self) -> &'static str {
        // Remote unix: l'unico canale e' SSH — diagnosi centrata su sshd.
        if self.winrm.is_none() && self.smb.is_none() {
            if self.ssh == Some(PortState::Refused) {
                return "host VIVO ma servizio SSH fermo (RST): avviare \
                        sshd sul remote ('systemctl start ssh').";
            }
            if self.ssh == Some(PortState::Open) {
                return "SSH raggiungibile: il fallimento e' lato protocollo \
                        (auth/host key) — vedi i log [ssh] sopra.";
            }
            if self.server == PortState::Open {
                return "host parzialmente raggiungibile ma SSH filtrato — \
                        verificare firewall/security group sulla porta SSH.";
            }
            return "host non raggiungibile (nessuna porta risponde): verificare \
                    che sia acceso/connesso e che sshd sia in ascolto.";
        }

        // Remote Windows: matrice WinRM/SMB/SSH.
        if self.smb == Some(PortState::Open) {
            // Host vivo, canale SMB disponibile: il bootstrap lo ordina
            // per primo automaticamente (o BOOTSTRAP=smb per forzarlo).
            return "host VIVO e SMB/SCM raggiungibile: il bootstrap provera' \
                    il canale SMB/SCM automaticamente (campo BOOTSTRAP=smb \
                    per forzarlo). WinRM resta spento/filtrato.";
        }
        if self.ssh == Some(PortState::Open) {
            // OpenSSH-for-Windows installato: canale SSH-win utilizzabile.
            return "host VIVO e SSH raggiungibile: il bootstrap provera' \
                    il canale SSH (dialetto PowerShell; campo BOOTSTRAP=ssh \
                    per forzarlo). WinRM/SMB spenti o filtrati.";
        }
        if self.winrm == Some(PortState::Refused) {
            return "servizio WinRM fermo (RST: host vivo, nessun listener): \
                    'Start-Service WinRM' + 'Set-Service WinRM -StartupType \
                    Automatic' (le regole firewall esistono gia').";
        }
        if self.server == PortState::Open
            || self.smb == Some(PortState::Refused)
            || self.winrm == Some(PortState::Refused)
            || self.ssh == Some(PortState::Refused)
        {
            // Qualcosa risponde con RST: host vivo ma management filtrato.
            return "host parzialmente raggiungibile ma i canali di management \
                    (WinRM / SMB 445 / SSH) sono filtrati — verificare firewall/GPO.";
        }
        "host non raggiungibile (nessuna porta management risponde): verificare \
         che sia acceso/connesso — 'Enable-PSRemoting' non basta."
    }
}

/// Canale di bootstrap candidato, ordinato dal prescan (spec §2.3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum BootstrapChannel {
    /// SSH verso remote unix (dialetto POSIX).
    SshPosix,
    /// SSH verso remote Windows (dialetto PowerShell).
    SshWin,
    /// WinRM nativo (remote Windows).
    WinRm,
    /// SMB admin share + Service Control Manager (remote Windows).
    SmbScm,
}

impl BootstrapChannel {
    /// Stato probe del canale in questo prescan (None = non scansionato).
    fn probe_state(self, p: &Prescan) -> Option<PortState> {
        match self {
            BootstrapChannel::SshPosix | BootstrapChannel::SshWin => p.ssh,
            BootstrapChannel::WinRm => p.winrm,
            BootstrapChannel::SmbScm => p.smb,
        }
    }

    /// Preflight del canale: remote_build_info via quel trasporto.
    /// None = canale non utilizzabile (contratto di channel_probe).
    pub(crate) async fn probe(&self, exe_path: &str) -> Option<RemoteBuildInfo> {
        match self {
            BootstrapChannel::SshPosix | BootstrapChannel::SshWin => {
                bootstrap_ssh::probe(exe_path).await
            }
            BootstrapChannel::WinRm => bootstrap::winrm_probe(exe_path).await,
            BootstrapChannel::SmbScm => bootstrap_smb::probe(exe_path).await,
        }
    }

    /// Deploy + avvio server via quel canale (dispatch ai moduli
    /// esistenti; il dialetto SSH e' scelto internamente da
    /// bootstrap_ssh via remote_is_unix()).
    pub(crate) async fn bootstrap(&self, exe_path: &str) -> Result<()> {
        match self {
            BootstrapChannel::SshPosix | BootstrapChannel::SshWin => {
                bootstrap_ssh::bootstrap_server(exe_path).await
            }
            BootstrapChannel::WinRm => bootstrap::bootstrap_winrm(exe_path).await,
            BootstrapChannel::SmbScm => bootstrap_smb::bootstrap_server(exe_path).await,
        }
    }
}

/// Il prescan del processo: calcolato una sola volta, poi condiviso
/// (bootstrap_server rientra nel retry loop — niente doppie scansioni).
static PRESCAN: OnceCell<Prescan> = OnceCell::const_new();

/// Evidenza della probe, conservata per final_connect_error (main.rs):
/// l'evidenza raccolta, non il remediation generico (spec §3.3).
static MGMT_EVIDENCE: Mutex<Option<String>> = Mutex::new(None);

/// Il blocco "TCP porta: stato" + diagnosi raccolti dal prescan.
pub fn mgmt_evidence() -> Option<String> {
    let guard = match MGMT_EVIDENCE.lock() {
        Ok(g) => g,
        Err(_) => return None,
    };
    guard.clone()
}

/// Canale che ha risposto positivamente al preflight di channel_probe:
/// bootstrap_server lo tenta per primo (spec §2.6 — evita di ri-bussare
/// a canali morti nel path a server vivo).
static PROBED_CHANNEL: Mutex<Option<BootstrapChannel>> = Mutex::new(None);

/// Registra il canale vincente del preflight.
pub(crate) fn set_probed_channel(ch: BootstrapChannel) {
    if let Ok(mut guard) = PROBED_CHANNEL.lock() {
        *guard = Some(ch);
    }
}

/// Il canale che ha risposto al preflight, se c'e'.
pub(crate) fn probed_channel() -> Option<BootstrapChannel> {
    let guard = PROBED_CHANNEL.lock().ok()?;
    *guard
}

/// Ultimo errore reale del loop candidati: final_connect_error lo
/// concatena all'evidenza (mai ingoiare l'errore non-trasporto —
/// spec §2.4).
static LAST_BOOTSTRAP_ERROR: Mutex<Option<String>> = Mutex::new(None);

/// Registra l'ultimo errore del loop candidati (testo gia' formattato).
pub(crate) fn set_last_bootstrap_error(msg: String) {
    if let Ok(mut guard) = LAST_BOOTSTRAP_ERROR.lock() {
        *guard = Some(msg);
    }
}

/// L'ultimo errore reale del bootstrap, se presente.
pub fn last_bootstrap_error() -> Option<String> {
    let guard = LAST_BOOTSTRAP_ERROR.lock().ok()?;
    guard.clone()
}

/// Probe TCP singola con timeout 3s. Connect riuscita = Open, RST =
/// Refused, qualunque altro esito (timeout incluso) = Filtered.
async fn tcp_probe(host: &str, port: u16) -> PortState {
    let target = format!("{}:{}", host, port);
    let connect = TcpStream::connect(target);
    let timed = tokio::time::timeout(PROBE_TIMEOUT, connect).await;
    match timed {
        Ok(Ok(_stream)) => PortState::Open,
        Ok(Err(e)) => {
            if e.kind() == std::io::ErrorKind::ConnectionRefused {
                PortState::Refused
            } else {
                PortState::Filtered
            }
        }
        Err(_) => PortState::Filtered,
    }
}

/// Il prescan del processo (lazy, una sola esecuzione).
/// unix: server + ssh (2 probe, ~6s max); win: server + winrm + smb +
/// ssh (4 probe, ~12s max). Sequenziali, 3s ciascuna.
pub(crate) async fn prescan() -> &'static Prescan {
    let init = PRESCAN.get_or_init(prescan_run);
    init.await
}

/// Esecuzione effettiva del prescan (chiamata una sola volta da
/// OnceCell::get_or_init).
async fn prescan_run() -> Prescan {
    let unix = bootstrap::remote_is_unix();
    let host = envs::var("HOST").unwrap_or_else(|| "127.0.0.1".to_string());
    // SSH puo' puntare a un host diverso da HOST (stesso fallback dei
    // vecchi ssh_context/winrm_context).
    let ssh_host = match envs::var("SSH_HOST") {
        Some(h) => h,
        None => host.clone(),
    };
    let ssh_port = match envs::var("SSH_PORT") {
        Some(p) => p.parse::<u16>().unwrap_or(22),
        None => 22,
    };
    let winrm_port = match envs::var("PORT") {
        Some(p) => p.parse::<u16>().unwrap_or(5985),
        None => 5985,
    };
    let server_port = bootstrap::server_tcp_port();

    eprintln!(
        "[bootstrap] prescan TCP verso {} (sequenziale, {}s max per porta)...",
        host,
        PROBE_TIMEOUT.as_secs()
    );

    let server = tcp_probe(&host, server_port).await;
    let ssh = Some(tcp_probe(&ssh_host, ssh_port).await);
    let mut winrm = None;
    let mut smb = None;
    if !unix {
        winrm = Some(tcp_probe(&host, winrm_port).await);
        smb = Some(tcp_probe(&host, 445).await);
    }

    let p = Prescan {
        server_port,
        server,
        ssh_port,
        ssh,
        winrm_port,
        winrm,
        smb,
    };

    // --- §2.5: la porta server e' predittiva anche se giu' ---
    // server Filtered + almeno un canale management Open = il server
    // deployato restera' irraggiungibile: diagnosi anticipata del caso
    // "deploy ok ma connect timeout".
    if p.server == PortState::Filtered && p.any_mgmt_open() {
        eprintln!(
            "[bootstrap] WARNING: porta server TCP/{} filtrata mentre un canale \
             management risponde: il macro-blocco firewall sara' OBBLIGATORIO \
             perche' il server deployato sia raggiungibile.",
            p.server_port
        );
    }

    // Evidenza per il messaggio finale: riempita qui, una volta sola —
    // print_psremoting_hint renderizza dal prescan senza ri-probare.
    let evidence = p.render();
    let diagnosis = p.diagnosis();
    if let Ok(mut guard) = MGMT_EVIDENCE.lock() {
        *guard = Some(format!("{}\n       Diagnosi: {}", evidence, diagnosis));
    }
    eprintln!("[bootstrap] prescan:\n{}", evidence.trim_end());

    p
}

/// Tier di ordinamento dei candidati (spec §2.3): Open prima (ordine
/// base stabile tra loro), Refused dopo (RST deterministico: il connect
/// reale fallirebbe identico, ma si tenta lo stesso in coda — costo ~ms,
/// copre la race "servizio avviato tra probe e tentativo"), Filtered
/// ultimi (falso negativo possibile su rete lenta: mai escludere un
/// canale, solo deprioritizzare). Canale non scansionato (None): resta
/// nel tier subito dopo gli Open — "sconosciuto" non va penalizzato
/// come un morto noto.
fn channel_tier(state: Option<PortState>) -> u8 {
    match state {
        Some(PortState::Open) => 0,
        None => 1,
        Some(PortState::Refused) => 2,
        Some(PortState::Filtered) => 3,
    }
}

/// Lista candidati ordinata (spec §2.3): wrapper che legge l'OS del
/// remote e l'override BOOTSTRAP dall'ambiente, poi delega alla logica
/// pura candidates_for (unit-testabile senza env).
pub(crate) fn candidates(p: &Prescan) -> Vec<BootstrapChannel> {
    let unix = bootstrap::remote_is_unix();
    let bootstrap_override = envs::var("BOOTSTRAP");
    let order = candidates_for(unix, p, bootstrap_override.as_deref());
    eprintln!("[bootstrap] candidati ordinati: {:?}", order);
    order
}

/// Logica pura della lista candidati (spec §2.3):
/// 1. remote unix -> [SshPosix], sempre (unico canale);
/// 2. remote win, BOOTSTRAP=smb|ssh|winrm -> override a canale singolo;
/// 3. remote win, nessun override -> ordine base [WinRm, SshWin, SmbScm]
///    riordinato per stato probe (Open -> Refused -> Filtered, stabile).
fn candidates_for(
    unix: bool,
    p: &Prescan,
    bootstrap_override: Option<&str>,
) -> Vec<BootstrapChannel> {
    if unix {
        // Unico canale su unix: l'override BOOTSTRAP e' ignorato (warning
        // per non far credere all'utente che abbia effetto).
        if let Some(v) = bootstrap_override {
            eprintln!(
                "[bootstrap] WARNING: BOOTSTRAP={} ignorato su remote unix \
                 (unico canale: SSH).",
                v
            );
        }
        return vec![BootstrapChannel::SshPosix];
    }

    if let Some(raw) = bootstrap_override {
        let trimmed = raw.trim();
        let lowered = trimmed.to_ascii_lowercase();
        match lowered.as_str() {
            "smb" => return vec![BootstrapChannel::SmbScm],
            "ssh" => return vec![BootstrapChannel::SshWin],
            "winrm" => return vec![BootstrapChannel::WinRm],
            _ => {
                // Valori sconosciuti: fail-open sulla lista default
                // (warning, non fatale — spec §2.7).
                eprintln!(
                    "[bootstrap] WARNING: BOOTSTRAP={} sconosciuto (attesi: smb|ssh|winrm): \
                     uso la lista default.",
                    raw
                );
            }
        }
    }

    let mut order = vec![
        BootstrapChannel::WinRm,
        BootstrapChannel::SshWin,
        BootstrapChannel::SmbScm,
    ];
    // Ordinamento STABILE per tier: a parita' di tier vince l'ordine
    // base (es. due canali Open -> WinRM prima di SSH prima di SMB).
    order.sort_by_key(|ch| channel_tier(ch.probe_state(p)));
    order
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Prescan di comodo per i test della matrice (remote Windows).
    fn prescan_win(server: PortState, winrm: PortState, smb: PortState, ssh: PortState) -> Prescan {
        Prescan {
            server_port: 5330,
            server,
            ssh_port: 22,
            ssh: Some(ssh),
            winrm_port: 5985,
            winrm: Some(winrm),
            smb: Some(smb),
        }
    }

    #[test]
    fn prescan_render_shape() {
        let p = prescan_win(
            PortState::Filtered,
            PortState::Refused,
            PortState::Open,
            PortState::Filtered,
        );
        let ev = p.render();
        assert!(ev.contains("TCP 5330 (server):"));
        assert!(ev.contains("TCP 5985 (WinRM):"));
        assert!(ev.contains("TCP 445 (SMB/SCM):"));
        assert!(ev.contains("TCP 22 (SSH):"));
        assert!(ev.contains("aperta"));
        assert!(ev.contains("chiusa (refused"));
        assert!(ev.contains("filtrata"));
    }

    #[test]
    fn prescan_diagnosis_matrix() {
        // SMB aperta -> canale alternativo (mai "Enable-PSRemoting" secco).
        let p = prescan_win(
            PortState::Filtered,
            PortState::Filtered,
            PortState::Open,
            PortState::Filtered,
        );
        assert!(p.diagnosis().contains("SMB/SCM raggiungibile"));
        assert!(p.diagnosis().contains("BOOTSTRAP=smb"));

        // SSH aperta (SMB/WinRM morti) -> canale SSH-win.
        let p = prescan_win(
            PortState::Filtered,
            PortState::Filtered,
            PortState::Filtered,
            PortState::Open,
        );
        assert!(p.diagnosis().contains("SSH raggiungibile"));
        assert!(p.diagnosis().contains("BOOTSTRAP=ssh"));

        // WinRM refused + canali morti -> servizio WinRM fermo.
        let p = prescan_win(
            PortState::Filtered,
            PortState::Refused,
            PortState::Filtered,
            PortState::Filtered,
        );
        assert!(p.diagnosis().contains("WinRM fermo"));

        // Qualcosa refused ma niente management utile -> host parziale.
        let p = prescan_win(
            PortState::Open,
            PortState::Filtered,
            PortState::Refused,
            PortState::Filtered,
        );
        assert!(p.diagnosis().contains("filtrati"));

        // Tutto filtrato -> host irraggiungibile.
        let p = prescan_win(
            PortState::Filtered,
            PortState::Filtered,
            PortState::Filtered,
            PortState::Filtered,
        );
        assert!(p.diagnosis().contains("non raggiungibile"));
    }

    #[test]
    fn prescan_diagnosis_unix() {
        // Remote unix: solo server + ssh probati.
        let p = Prescan {
            server_port: 5330,
            server: PortState::Refused,
            ssh_port: 22,
            ssh: Some(PortState::Refused),
            winrm_port: 5985,
            winrm: None,
            smb: None,
        };
        assert!(p.diagnosis().contains("SSH fermo"));

        let p = Prescan {
            server_port: 5330,
            server: PortState::Filtered,
            ssh_port: 2222,
            ssh: Some(PortState::Filtered),
            winrm_port: 5985,
            winrm: None,
            smb: None,
        };
        assert!(p.diagnosis().contains("non raggiungibile"));
    }

    // --- candidates_for: matrice di ordinamento (spec §4) ---

    #[test]
    fn candidates_unix_sempre_solo_ssh() {
        // Remote unix: UNICO canale SshPosix, qualunque prescan/override.
        let p = prescan_win(
            PortState::Filtered,
            PortState::Filtered,
            PortState::Filtered,
            PortState::Filtered,
        );
        assert_eq!(
            candidates_for(true, &p, None),
            vec![BootstrapChannel::SshPosix]
        );
        // L'override e' ignorato (con warning) — mai WinRM/SMB su unix.
        assert_eq!(
            candidates_for(true, &p, Some("smb")),
            vec![BootstrapChannel::SshPosix]
        );
    }

    #[test]
    fn candidates_all_open_ordine_base() {
        // Tutto aperto -> ordine base stabile: WinRM, SSH-win, SMB/SCM.
        let p = prescan_win(
            PortState::Open,
            PortState::Open,
            PortState::Open,
            PortState::Open,
        );
        assert_eq!(
            candidates_for(false, &p, None),
            vec![
                BootstrapChannel::WinRm,
                BootstrapChannel::SshWin,
                BootstrapChannel::SmbScm
            ]
        );
    }

    #[test]
    fn candidates_h166_smb_primo() {
        // Caso H166: WinRM filtrato, SMB operativo -> SmbScm primo,
        // senza pagare il timeout WinRM (spec: lo scenario motivante).
        let p = prescan_win(
            PortState::Filtered,
            PortState::Filtered,
            PortState::Open,
            PortState::Refused,
        );
        assert_eq!(
            candidates_for(false, &p, None),
            vec![
                BootstrapChannel::SmbScm,
                BootstrapChannel::SshWin,
                BootstrapChannel::WinRm
            ]
        );
    }

    #[test]
    fn candidates_host_morto_ordine_base() {
        // Tutto filtrato -> a parita' di tier vince l'ordine base (i
        // canali si tentano comunque: il falso negativo e' possibile).
        let p = prescan_win(
            PortState::Filtered,
            PortState::Filtered,
            PortState::Filtered,
            PortState::Filtered,
        );
        assert_eq!(
            candidates_for(false, &p, None),
            vec![
                BootstrapChannel::WinRm,
                BootstrapChannel::SshWin,
                BootstrapChannel::SmbScm
            ]
        );
    }

    #[test]
    fn candidates_solo_ssh_aperto() {
        // Solo OpenSSH-for-Windows -> SshWin primo (tier Open).
        let p = prescan_win(
            PortState::Filtered,
            PortState::Refused,
            PortState::Filtered,
            PortState::Open,
        );
        assert_eq!(
            candidates_for(false, &p, None),
            vec![
                BootstrapChannel::SshWin,
                BootstrapChannel::WinRm,
                BootstrapChannel::SmbScm
            ]
        );
    }

    #[test]
    fn candidates_override_canale_singolo() {
        let p = prescan_win(
            PortState::Open,
            PortState::Open,
            PortState::Open,
            PortState::Open,
        );
        assert_eq!(
            candidates_for(false, &p, Some("smb")),
            vec![BootstrapChannel::SmbScm]
        );
        assert_eq!(
            candidates_for(false, &p, Some("ssh")),
            vec![BootstrapChannel::SshWin]
        );
        assert_eq!(
            candidates_for(false, &p, Some("winrm")),
            vec![BootstrapChannel::WinRm]
        );
        // Case/spazi tollerati.
        assert_eq!(
            candidates_for(false, &p, Some(" SMB ")),
            vec![BootstrapChannel::SmbScm]
        );
        // Valore sconosciuto -> fail-open sulla lista ordinata.
        let got = candidates_for(false, &p, Some("telnet"));
        assert_eq!(got.len(), 3);
    }
}
