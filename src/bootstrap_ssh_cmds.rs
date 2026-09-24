// Modulo bootstrap_ssh_cmds: generatori di comando per dialetto del
// canale SSH unificato (spec ssh-unified §1.4). Separato da
// bootstrap_ssh.rs per dimensione (best-practice < 1000 righe).
//
// Sono funzioni PURE (stringhe, niente I/O): il dialetto e' scelto una
// volta da remote_is_unix() e ogni comando remoto e' un `*_cmd(d, ...)`.
// Regola d'oro PowerShell: sempre via `powershell -NoProfile
// -EncodedCommand <base64 UTF-16LE>` — immune al DefaultShell del remote
// (cmd.exe o PowerShell indifferente: powershell.exe e' in PATH).

use crate::bootstrap;
use crate::deploy;
use crate::envs;
use crate::update;
use crate::version;

/// Dialetto dei comandi remoti (spec §1.4): scelto dall'OS del REMOTE.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Dialect {
    /// Shell POSIX (remote Linux/Unix).
    Posix,
    /// PowerShell via `powershell -NoProfile -EncodedCommand`
    /// (remote Windows con OpenSSH-for-Windows).
    PowerShell,
}

/// Dialetto del remote: SOLO da remote_is_unix() (deterministico,
/// testabile — niente auto-detect via `uname` in v1, spec §1.4).
pub(crate) fn dialect() -> Dialect {
    if bootstrap::remote_is_unix() {
        Dialect::Posix
    } else {
        Dialect::PowerShell
    }
}

/// Quoting POSIX single-quote (escape '\'' embedded).
fn sh_sq(s: &str) -> String {
    let escaped = s.replace('\'', "'\\''");
    format!("'{}'", escaped)
}

/// Quoting PowerShell single-quote ('' = quote letterale in PS).
fn ps_sq(s: &str) -> String {
    let escaped = s.replace('\'', "''");
    format!("'{}'", escaped)
}

/// Wrapper obbligatorio dei comandi PowerShell (spec §1.4): lo script
/// viene codificato UTF-16LE -> base64 -> `powershell -NoProfile
/// -EncodedCommand`, identico al trick di winrm_rs::run_powershell.
/// Immune al DefaultShell del remote (cmd.exe o PowerShell indifferente:
/// powershell.exe e' in PATH in entrambi i casi).
pub(crate) fn ps_encoded(script: &str) -> String {
    let mut utf16: Vec<u8> = Vec::with_capacity(script.len() * 2);
    for unit in script.encode_utf16() {
        let bytes = unit.to_le_bytes();
        utf16.push(bytes[0]);
        utf16.push(bytes[1]);
    }
    let b64 = deploy::base64_encode(&utf16);
    format!("powershell -NoProfile -EncodedCommand {}", b64)
}

/// Path passato a SFTP: su remote Windows OpenSSH normalizza i
/// separatori '/' (C:/ci/x.exe); su unix il path e' gia' pronto.
pub(crate) fn sftp_path(d: Dialect, path: &str) -> String {
    match d {
        Dialect::Posix => path.to_string(),
        Dialect::PowerShell => path.replace('\\', "/"),
    }
}

/// Nome dello staged per l'OS remoto: su Windows DEVE finire in `.exe`
/// (PowerShell rifiuta di invocare nomi non eseguibili — la stessa nota
/// di deploy::upload_artifact): `crosspilot.new.exe`, non
/// `crosspilot.exe.new`. Su unix `<exe>.new` come da tradizione.
pub(crate) fn staged_name(d: Dialect, exe_path: &str) -> String {
    match d {
        Dialect::Posix => format!("{}.new", exe_path),
        Dialect::PowerShell => {
            let stem = exe_path.strip_suffix(".exe").unwrap_or(exe_path);
            format!("{}.new.exe", stem)
        }
    }
}

/// `remote_build_info`: UNA chiamata che riporta presenza exe + hash +
/// sidecar + contenuto .ver, sempre nel formato righe CHIAVE=valore
/// parsato da version::parse_remote_info (invariato tra i dialetti).
pub(crate) fn remote_build_info_cmd(d: Dialect, exe_path: &str, dir: &str) -> String {
    let linux_path = update::remote_join(dir, version::LINUX_SIDECAR_NAME);
    let ver_path = update::remote_join(dir, version::VER_FILE_NAME);
    match d {
        Dialect::Posix => format!(
            "if [ -f {e} ]; then echo EXE=True; \
             sha256sum {e} | awk '{{print \"EXE_HASH=\" $1}}'; \
             else echo EXE=False; fi; \
             if [ -f {l} ]; then echo LINUX_PRESENT=True; \
             else echo LINUX_PRESENT=False; fi; \
             if [ -f {v} ]; then cat {v}; fi",
            e = sh_sq(exe_path),
            l = sh_sq(&linux_path),
            v = sh_sq(&ver_path)
        ),
        Dialect::PowerShell => {
            let script = format!(
                "if (Test-Path {e}) {{ Write-Output 'EXE=True'; \
                 Write-Output \"EXE_HASH=$((Get-FileHash {e} -Algorithm SHA256).Hash)\" }} \
                 else {{ Write-Output 'EXE=False' }}; \
                 if (Test-Path {l}) {{ Write-Output 'LINUX_PRESENT=True' }} \
                 else {{ Write-Output 'LINUX_PRESENT=False' }}; \
                 if (Test-Path {v}) {{ Get-Content {v} }}",
                e = ps_sq(exe_path),
                l = ps_sq(&linux_path),
                v = ps_sq(&ver_path)
            );
            ps_encoded(&script)
        }
    }
}

/// SHA-256 (lowercase/uppercase hex — il confronto e' case-insensitive)
/// del file remoto, o stringa vuota se assente.
pub(crate) fn file_hash_cmd(d: Dialect, path: &str) -> String {
    match d {
        Dialect::Posix => format!(
            "if [ -f {p} ]; then sha256sum {p} | awk '{{print $1}}'; fi",
            p = sh_sq(path)
        ),
        Dialect::PowerShell => {
            let script = format!(
                "if (Test-Path {p}) {{ Write-Output (Get-FileHash {p} -Algorithm SHA256).Hash }}",
                p = ps_sq(path)
            );
            ps_encoded(&script)
        }
    }
}

/// Crea la directory remota che contiene l'exe (idempotente).
pub(crate) fn mkdir_cmd(d: Dialect, dir: &str) -> String {
    match d {
        Dialect::Posix => format!("mkdir -p {}", sh_sq(dir)),
        Dialect::PowerShell => {
            let script = format!(
                "New-Item -ItemType Directory -Force -Path {} | Out-Null; \
                 Write-Output (Test-Path {})",
                ps_sq(dir),
                ps_sq(dir)
            );
            ps_encoded(&script)
        }
    }
}

/// Rimuove un file remoto (best-effort, cleanup staged falliti).
pub(crate) fn rm_cmd(d: Dialect, path: &str) -> String {
    match d {
        Dialect::Posix => format!("rm -f {}", sh_sq(path)),
        Dialect::PowerShell => {
            let script =
                format!("Remove-Item -Force {} -ErrorAction SilentlyContinue", ps_sq(path));
            ps_encoded(&script)
        }
    }
}

/// Functional check dello staged: '<staged>' --version deve uscire 0 e
/// stampare il ts atteso. Su unix preceduto da chmod 755 (l'upload SFTP
/// lascia i permessi di default, non eseguibile); su Windows no-op
/// (l'eseguibilita' non dipende dai permessi) e invoke via `&`.
pub(crate) fn functional_check_cmd(d: Dialect, staged: &str) -> String {
    match d {
        Dialect::Posix => format!("chmod 755 {s} && {s} --version", s = sh_sq(staged)),
        Dialect::PowerShell => {
            let script = format!("& {} --version", ps_sq(staged));
            ps_encoded(&script)
        }
    }
}

/// Swap staged -> exe con backup .old (rename consentito anche sull'exe
/// in esecuzione — stessa regola dell'updater), poi emette l'hash
/// finale del file per la verifica del chiamante.
pub(crate) fn swap_cmd(d: Dialect, exe_path: &str, staged: &str) -> String {
    match d {
        Dialect::Posix => format!(
            "if [ -f {e} ]; then mv -f {e} {e}.old; fi; \
             mv -f {s} {e} && chmod 755 {e} && \
             sha256sum {e} | awk '{{print $1}}'",
            e = sh_sq(exe_path),
            s = sh_sq(staged)
        ),
        Dialect::PowerShell => {
            let old = format!("{}.old", exe_path);
            let script = format!(
                "if (Test-Path {e}) {{ Move-Item -Force {e} {o} }}; \
                 Move-Item -Force {s} {e}; \
                 Write-Output (Get-FileHash {e} -Algorithm SHA256).Hash",
                e = ps_sq(exe_path),
                o = ps_sq(&old),
                s = ps_sq(staged)
            );
            ps_encoded(&script)
        }
    }
}

/// Copia file remoto (sidecar su unix; artefatto crosspilot.exe su win).
pub(crate) fn copy_cmd(d: Dialect, src: &str, dst: &str) -> String {
    match d {
        Dialect::Posix => format!("cp -f {} {}", sh_sq(src), sh_sq(dst)),
        Dialect::PowerShell => {
            let script = format!("Copy-Item -Force {} {}", ps_sq(src), ps_sq(dst));
            ps_encoded(&script)
        }
    }
}

/// MACRO-BLOCCO firewall inbound per la porta del server: su unix lo
/// script POSIX in cascata ufw->firewalld->iptables->nft (condiviso col
/// path TCP, update::linux_inbound_allow_script); su Windows netsh
/// delete-then-add — stessa regola `crosspilot-server-<porta>` del
/// macro-blocco update::windows_inbound_allow_cmd, ma in sintassi
/// PowerShell (l'operatore `&` di cmd.exe non gira in PS).
pub(crate) fn firewall_cmd(d: Dialect, port: u16) -> String {
    match d {
        Dialect::Posix => update::linux_inbound_allow_script(port),
        Dialect::PowerShell => {
            let script = format!(
                "$n='crosspilot-server-{p}'; \
                 netsh advfirewall firewall delete rule name=\"$n\" | Out-Null; \
                 netsh advfirewall firewall add rule name=\"$n\" dir=in action=allow \
                 protocol=TCP localport={p} | Out-Null; \
                 if ($LASTEXITCODE -eq 0) {{ Write-Output 'FW=netsh' }} else {{ Write-Output 'FW=fail:netsh' }}",
                p = port
            );
            ps_encoded(&script)
        }
    }
}

/// Avvio detached del server (spec §1.4):
/// - Posix: setsid in nuova sessione con redirect su log/err — il
///   processo sopravvive alla chiusura del canale SSH.
/// - PowerShell: la STESSA catena schtasks SYSTEM->S4U->interattivo del
///   path WinRM (bootstrap::schtasks_start_script condiviso): il server
///   nasce dal servizio Task Scheduler in sessione 0, fuori dalla
///   sessione SSH e da qualunque job object.
pub(crate) fn start_server_cmd(d: Dialect, exe_path: &str, user: &str) -> String {
    match d {
        Dialect::Posix => {
            let dir = update::remote_parent(exe_path).to_string();
            let log = match envs::var("LOG_PATH") {
                Some(l) => l,
                None => update::remote_join(&dir, "server.log"),
            };
            let err = match envs::var("ERR_PATH") {
                Some(e) => e,
                None => update::remote_join(&dir, "server.err"),
            };
            format!(
                "setsid {} --server >>{} 2>>{} < /dev/null & echo STARTED",
                sh_sq(exe_path),
                sh_sq(&log),
                sh_sq(&err)
            )
        }
        Dialect::PowerShell => {
            let script = bootstrap::schtasks_start_script(exe_path, user);
            ps_encoded(&script)
        }
    }
}

/// Comando di diagnostica post-bootstrap-fallito, per dialetto:
/// - Posix: processo vivo + porta in ascolto + frontend firewall
///   (righe PROC:/LISTEN:/FWTOOL:);
/// - PowerShell: lo script condiviso col path WinRM
///   (bootstrap::windows_diag_script — righe PROC=/LISTEN=/FW=).
pub(crate) fn diag_cmd(d: Dialect, port: u16) -> String {
    match d {
        Dialect::Posix => format!(
            "pgrep -ax crosspilot 2>/dev/null | head -5 | sed 's/^/PROC: /'; \
             if command -v ss >/dev/null 2>&1; then \
             ss -tln 2>/dev/null | grep ':{p} ' | sed 's/^/LISTEN: /'; \
             elif command -v netstat >/dev/null 2>&1; then \
             netstat -tln 2>/dev/null | grep ':{p} ' | sed 's/^/LISTEN: /'; fi; \
             for f in ufw firewall-cmd iptables nft; do \
             command -v $f >/dev/null 2>&1 && echo \"FWTOOL: $f\"; done",
            p = port
        ),
        Dialect::PowerShell => {
            let script = bootstrap::windows_diag_script(port);
            ps_encoded(&script)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decodifica il payload EncodedCommand (base64 UTF-16LE) per
    /// verificare lo script PowerShell interno.
    fn decode_ps(cmd: &str) -> String {
        let b64 = cmd
            .strip_prefix("powershell -NoProfile -EncodedCommand ")
            .expect("prefisso EncodedCommand");
        let bytes = deploy::base64_decode(b64).expect("base64");
        let mut units: Vec<u16> = Vec::new();
        let mut i = 0;
        while i + 1 < bytes.len() {
            let u = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
            units.push(u);
            i += 2;
        }
        String::from_utf16_lossy(&units)
    }

    #[test]
    fn ps_encoded_fixture() {
        // Fixture spec §4: UTF-16LE di "AB" = [0x41,0x00,0x42,0x00]
        // -> base64 "QQBCAA==".
        let enc = ps_encoded("AB");
        assert_eq!(enc, "powershell -NoProfile -EncodedCommand QQBCAA==");
    }

    #[test]
    fn staged_name_per_dialetto() {
        assert_eq!(
            staged_name(Dialect::Posix, "/opt/crosspilot"),
            "/opt/crosspilot.new"
        );
        // Su Windows lo staged DEVE finire in .exe (deploy.rs: PowerShell
        // rifiuta di invocare nomi non eseguibili).
        assert_eq!(
            staged_name(Dialect::PowerShell, "C:\\ci\\crosspilot.exe"),
            "C:\\ci\\crosspilot.new.exe"
        );
    }

    #[test]
    fn comandi_posix_invariati() {
        // remote_build_info: stesso formato righe CHIAVE=valore di prima.
        let cmd = remote_build_info_cmd(Dialect::Posix, "/opt/cp/crosspilot", "/opt/cp");
        assert!(cmd.contains("EXE=True"));
        assert!(cmd.contains("EXE_HASH="));
        assert!(cmd.contains("LINUX_PRESENT="));
        assert!(cmd.contains("crosspilot.linux"));
        assert!(cmd.contains("crosspilot.ver"));

        let cmd = swap_cmd(Dialect::Posix, "/opt/cp/crosspilot", "/opt/cp/crosspilot.new");
        assert!(cmd.contains("mv -f"));
        assert!(cmd.contains(".old"));
        assert!(cmd.contains("chmod 755"));
        assert!(cmd.contains("sha256sum"));

        let cmd = start_server_cmd(Dialect::Posix, "/opt/cp/crosspilot", "user");
        assert!(cmd.contains("setsid"));
        assert!(cmd.contains("--server"));
        assert!(cmd.contains("STARTED"));

        let cmd = firewall_cmd(Dialect::Posix, 5330);
        assert!(cmd.contains("ufw"));
        assert!(cmd.contains("5330"));
    }

    #[test]
    fn comandi_powershell_encoded() {
        let cmd =
            remote_build_info_cmd(Dialect::PowerShell, "C:\\ci\\crosspilot.exe", "C:\\ci");
        let ps = decode_ps(&cmd);
        assert!(ps.contains("Test-Path 'C:\\ci\\crosspilot.exe'"));
        assert!(ps.contains("EXE_HASH="));
        assert!(ps.contains("Get-FileHash"));
        assert!(ps.contains("LINUX_PRESENT="));
        assert!(ps.contains("Get-Content"));

        let cmd = functional_check_cmd(Dialect::PowerShell, "C:\\ci\\crosspilot.new.exe");
        let ps = decode_ps(&cmd);
        assert!(ps.contains("& 'C:\\ci\\crosspilot.new.exe' --version"));

        let cmd = swap_cmd(
            Dialect::PowerShell,
            "C:\\ci\\crosspilot.exe",
            "C:\\ci\\crosspilot.new.exe",
        );
        let ps = decode_ps(&cmd);
        assert!(ps.contains("Move-Item -Force"));
        assert!(ps.contains(".old"));
        assert!(ps.contains("Get-FileHash"));

        let cmd = start_server_cmd(Dialect::PowerShell, "C:\\ci\\crosspilot.exe", "user");
        let ps = decode_ps(&cmd);
        assert!(ps.contains("schtasks"));
        assert!(ps.contains("crosspilot-server"));
        assert!(ps.contains("--server"));

        let cmd = firewall_cmd(Dialect::PowerShell, 5330);
        let ps = decode_ps(&cmd);
        assert!(ps.contains("netsh advfirewall firewall delete rule"));
        assert!(ps.contains("netsh advfirewall firewall add rule"));
        assert!(ps.contains("crosspilot-server-5330"));
        assert!(ps.contains("localport=5330"));
    }

    #[test]
    fn sftp_path_normalizza_windows() {
        assert_eq!(sftp_path(Dialect::Posix, "/a/b"), "/a/b");
        assert_eq!(
            sftp_path(Dialect::PowerShell, "C:\\ci\\x.exe"),
            "C:/ci/x.exe"
        );
    }
}
