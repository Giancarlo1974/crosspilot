// Modulo version: costanti di build e parsing dei metadati di versione.
//
// Il sistema di auto-update bidirezionale ("il piu' vecchio si aggiorna
// da solo") si basa su un build timestamp unix (CROSSPILOT_BUILD_TS) uguale
// per tutti gli artefatti di una release, perche' il solo hash SHA-256
// puo' dire "diverso" ma non "piu' nuovo/piu' vecchio".
//
// Layout dei file sul remote (nella stessa directory dell'exe):
//   crosspilot.exe    — server Windows
//   crosspilot.linux  — binario Linux musl statico (sidecar per il
//                           self-update dei client piu' vecchi)
//   crosspilot.ver    — metadati testuali (BUILD_TS, EXE_SHA256,
//                           LINUX_SHA256) scritti dal deploy
//
// Il .ver viene letto via WinRM senza eseguire l'exe remoto: funziona
// anche se l'exe e' locked o sotto scansione AV.

/// Timestamp unix del build (condiviso tra artefatti via build-release.sh).
/// Parsato a compile-time con un parser const (str::parse non e' const):
/// accetta solo cifre decimali; input malformato -> 0 (build "ignota",
/// trattata come piu' vecchia di qualsiasi ts reale).
pub const BUILD_TS: u64 = parse_ts_const(env!("CROSSPILOT_BUILD_TS"));

/// Parser u64 const-compatibile: solo cifre, niente segno/overflow check
/// (il ts unix attuale sta ampiamente in u64; overflow -> wrap, accettato).
const fn parse_ts_const(s: &str) -> u64 {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return 0;
    }
    let mut i = 0;
    let mut v: u64 = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if !c.is_ascii_digit() {
            return 0;
        }
        v = v.wrapping_mul(10).wrapping_add((c - b'0') as u64);
        i += 1;
    }
    v
}

// Nota: build.rs emette anche CROSSPILOT_TARGET (target triple), usata dentro
// VERSION_STR via env! (concat! non puo' riferirsi ad altre const).

/// Nome del sidecar Linux (musl statico) deployato accanto all'exe remoto.
pub const LINUX_SIDECAR_NAME: &str = "crosspilot.linux";

/// Nome del file metadati di versione deployato accanto all'exe remoto.
pub const VER_FILE_NAME: &str = "crosspilot.ver";

/// Stringa versione stampata da --version (clap) e usata nel functional
/// check post-deploy: formato "0.1.0+<ts> (<target>)".
/// &'static str perche' Command::version() richiede IntoResettable<Str>
/// (String non implementato). Esempio: "0.1.0+1758530400 (x86_64-pc-windows-gnu)".
pub const VERSION_STR: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    "+",
    env!("CROSSPILOT_BUILD_TS"),
    " (",
    env!("CROSSPILOT_TARGET"),
    ")"
);

/// OS del server remoto come dichiarato nell'handshake
/// "READY <ts> <L|W>" (terzo token opzionale).
/// I server attuali non lo inviano ancora: in quel caso il client
/// ricade sull'euristica EXE_PATH per decidere il payload di update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteOs {
    /// Server su host Linux/Unix (payload update: binario linux staged).
    Linux,
    /// Server su host Windows (payload update: PE staged).
    Windows,
}

impl RemoteOs {
    /// Parsa il tag OS del terzo token dell'handshake:
    /// "L" -> Linux, "W" -> Windows. Token assenti o sconosciuti -> None
    /// (server che non dichiara il proprio OS).
    pub fn from_tag(tag: &str) -> Option<RemoteOs> {
        match tag {
            "L" => Some(RemoteOs::Linux),
            "W" => Some(RemoteOs::Windows),
            _ => None,
        }
    }
}

/// Saluto del server nell'handshake TCP: "READY [<ts> [<os>]]".
/// - ts=None: server legacy pre auto-update ("READY" secco);
/// - os=None: server che non dichiara ancora il proprio OS — il client
///   usa l'euristica EXE_PATH per la scelta del payload di update.
#[derive(Debug, Clone, Copy, Default)]
pub struct ServerHello {
    /// BUILD_TS dichiarato dal server (None = server legacy).
    pub ts: Option<u64>,
    /// OS del server (None = non dichiarato, handshake "READY <ts>").
    pub os: Option<RemoteOs>,
}

/// Stato della build deployata sul remote, ricostruito da remote_build_info()
/// in deploy.rs (una sola chiamata WinRM).
///
/// build_ts: Option perche' i deploy legacy (pre auto-update) non hanno
/// il file .ver: in quel caso exe_present=true ma build_ts=None, e il
/// remote va trattato come "piu' vecchio di qualsiasi build versionato"
/// (ts effettivo = 0).
#[derive(Debug, Clone, Default)]
pub struct RemoteBuildInfo {
    /// L'exe remoto esiste in EXE_PATH.
    pub exe_present: bool,
    /// BUILD_TS dal .ver remoto (None = deploy legacy senza versione).
    pub build_ts: Option<u64>,
    /// SHA-256 uppercase dell'exe remoto (None se exe assente).
    pub exe_sha256: Option<String>,
    /// Il sidecar crosspilot.linux esiste sul remote.
    pub linux_present: bool,
    /// SHA-256 del sidecar linux dichiarato nel .ver remoto.
    pub linux_sha256: Option<String>,
}

impl RemoteBuildInfo {
    /// Timestamp remoto effettivo per il confronto: un remote senza .ver
    /// e' un deploy legacy, per definizione precedente a questa feature.
    pub fn effective_ts(&self) -> u64 {
        self.build_ts.unwrap_or(0)
    }

    /// True se il remote dichiara un build piu' recente del binario locale.
    /// In quel caso il client deve fare self-update (mai downgrade).
    pub fn is_newer_than_local(&self) -> bool {
        self.exe_present && self.effective_ts() > BUILD_TS
    }
}

/// Parsa l'output di `remote_build_info`: righe `CHIAVE=valore`.
///
/// Lo script PowerShell emette:
///   EXE=True|False
///   EXE_HASH=<sha256 uppercase>          (solo se exe presente)
///   LINUX_PRESENT=True|False
///   BUILD_TS=<unix ts>                   (righe grezze del .ver, se esiste)
///   EXE_SHA256=<sha256>
///   LINUX_SHA256=<sha256>
///
/// Le righe del .ver passano inalterate nell'output, quindi il parser
/// accetta sia le chiavi dello script che quelle del file.
pub fn parse_remote_info(stdout: &str) -> RemoteBuildInfo {
    let mut info = RemoteBuildInfo::default();
    for line in stdout.lines() {
        let line = line.trim();
        // Split solo sul primo '=': i valori non contengono '=' ma il
        // parser resta robusto a valori futuri che lo contenessero.
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        match key {
            "EXE" => {
                info.exe_present = value.eq_ignore_ascii_case("true");
            }
            "EXE_HASH" => {
                // Hash REALE dell'exe su disco (calcolato dallo script).
                // NOTA: il .ver contiene EXE_SHA256 (hash al momento del
                // deploy) — NON mappato qui perche' potrebbe essere stale
                // se l'exe e' stato sostituito a mano dopo il deploy:
                // deploy_exe deve confrontare l'hash reale, non il
                // metadato dichiarato.
                if !value.is_empty() {
                    info.exe_sha256 = Some(value.to_uppercase());
                }
            }
            "EXE_SHA256" => {} // dal .ver: dichiarato, possibilmente stale
            "LINUX_PRESENT" => {
                info.linux_present = value.eq_ignore_ascii_case("true");
            }
            "LINUX_SHA256" => {
                if !value.is_empty() {
                    info.linux_sha256 = Some(value.to_uppercase());
                }
            }
            "BUILD_TS" => {
                info.build_ts = value.parse::<u64>().ok();
            }
            _ => {}
        }
    }
    info
}

/// Estrae il build timestamp dall'output di `crosspilot --version`.
///
/// Formato atteso: "crosspilot 0.1.0+<ts> (<target>)".
/// Il functional check post-deploy cerca "+<ts>" nella prima riga:
/// un exe corrotto o non eseguibile produce exit_code != 0 o output
/// senza il marker, e il deploy abortisce PRIMA dello swap.
pub fn parse_version_ts(version_output: &str) -> Option<u64> {
    let line = version_output.lines().next()?.trim();
    // Cerca il primo '+' seguito da cifre: "0.1.0+1758530400 (...)".
    let plus = line.find('+')?;
    let digits: String = line[plus + 1..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse::<u64>().ok()
}

/// Genera il contenuto del file .ver remoto (chiavi CHIAVE=valore).
/// Scrivere ts + hash rende il remote "sorgente" verificabile per i
/// self-update dei client piu' vecchi.
pub fn render_ver_file(build_ts: u64, exe_sha256: &str, linux_sha256: Option<&str>) -> String {
    let mut out = format!("BUILD_TS={}\nEXE_SHA256={}\n", build_ts, exe_sha256);
    if let Some(h) = linux_sha256 {
        out.push_str(&format!("LINUX_SHA256={}\n", h));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_remote_info_completo() {
        let out = "EXE=True\nEXE_HASH=AB12CD\nLINUX_PRESENT=True\nBUILD_TS=1758530400\nEXE_SHA256=AB12CD\nLINUX_SHA256=FF00EE\n";
        let info = parse_remote_info(out);
        assert!(info.exe_present);
        assert_eq!(info.build_ts, Some(1758530400));
        assert_eq!(info.exe_sha256.as_deref(), Some("AB12CD"));
        assert!(info.linux_present);
        assert_eq!(info.linux_sha256.as_deref(), Some("FF00EE"));
    }

    #[test]
    fn parse_remote_info_exe_mancante() {
        let out = "EXE=False\nLINUX_PRESENT=False\n";
        let info = parse_remote_info(out);
        assert!(!info.exe_present);
        assert_eq!(info.build_ts, None);
        assert!(!info.linux_present);
    }

    #[test]
    fn parse_remote_info_legacy_senza_ver() {
        // Deploy pre-feature: exe presente ma nessuna riga BUILD_TS.
        let out = "EXE=True\nEXE_HASH=99AA\nLINUX_PRESENT=False\n";
        let info = parse_remote_info(out);
        assert!(info.exe_present);
        assert_eq!(info.effective_ts(), 0);
    }

    #[test]
    fn parse_remote_info_righe_rumorose_ignorate() {
        // WinRM puo' intercalare righe di stato: il parser le salta.
        let out = "DEBUG noise\nEXE=True\n\n  \nBUILD_TS=42\n";
        let info = parse_remote_info(out);
        assert_eq!(info.build_ts, Some(42));
    }

    #[test]
    fn parse_version_ts_ok() {
        assert_eq!(
            parse_version_ts("crosspilot 0.1.0+1758530400 (x86_64-pc-windows-gnu)"),
            Some(1758530400)
        );
        assert_eq!(parse_version_ts("0.1.0+7"), Some(7));
    }

    #[test]
    fn parse_version_ts_formati_invalidi() {
        assert_eq!(parse_version_ts("crosspilot 0.1.0"), None);
        assert_eq!(parse_version_ts(""), None);
        assert_eq!(parse_version_ts("abc+xyz"), None);
        assert_eq!(parse_version_ts("0.1.0+"), None);
    }

    #[test]
    fn remote_os_from_tag() {
        assert_eq!(RemoteOs::from_tag("L"), Some(RemoteOs::Linux));
        assert_eq!(RemoteOs::from_tag("W"), Some(RemoteOs::Windows));
        // Token sconosciuti o malformati: tollerati come "non dichiarato".
        assert_eq!(RemoteOs::from_tag("X"), None);
        assert_eq!(RemoteOs::from_tag("linux"), None);
        assert_eq!(RemoteOs::from_tag(""), None);
    }

    #[test]
    fn render_ver_file_con_e_senza_linux() {
        let v = render_ver_file(123, "AA", Some("BB"));
        assert!(v.contains("BUILD_TS=123"));
        assert!(v.contains("EXE_SHA256=AA"));
        assert!(v.contains("LINUX_SHA256=BB"));

        let v_no_linux = render_ver_file(123, "AA", None);
        assert!(!v_no_linux.contains("LINUX_SHA256"));
    }
}
