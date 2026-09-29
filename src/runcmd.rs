//! Costruzione della command-line remota (`--` forma raw, `run`, `put --exec`).
//!
//! Due problemi distinti risolti qui:
//!
//! 1. **Quoting fragile (bug report)**: il client univa i token dopo `--`
//!    con spazi nudi, perdendo il raggruppamento fatto dalla shell locale:
//!    `crosspilot -- sh -c "sleep 8; docker ps"` arrivava come
//!    `sh -c sleep 8; docker ps` -> "sleep: missing operand". Il modello
//!    era quello di cmd.exe e andava bene "per caso" su comandi semplici.
//!    Su remote UNIX i token sono ora ri-quotati stile POSIX (single-quote
//!    solo dove serve: spazi, quote, e metacaratteri di raggruppamento
//!    `;&|<>()`), cosi' `sh -c` remoto riceve il raggruppamento originale.
//!    `$`, `*`, `~`, `{}`, `[]`, backtick restano NON quotati per
//!    preservare l'espansione remota (es. `crosspilot -- echo $HOME`).
//!    Su remote Windows il join con spazi resta (semantica cmd.exe
//!    storicamente documentata: "i token sono uniti con spazi").
//!
//!    Eccezioni al quoting (bug report "niente comandi composti"):
//!    - **token singolo**: `crosspilot -- "cmd1 && cmd2"` era quotato come
//!      `'cmd1 && cmd2'` -> sh remoto lo leggeva come UN nome di comando ->
//!      "No such file or directory". Un token unico dopo `--` E' una
//!      command-line completa: passa raw (l'unica interpretazione utile).
//!    - **operatori shell puri** (`&&`, `||`, `;`, `|`, `&`, `>`, `>>`,
//!      `2>`, `2>&1`, `&>` ...): un token fatto solo di metacaratteri
//!      shell non puo' essere un argomento — se quotato non funzionera'
//!      MAI come operatore. Passa raw: `crosspilot -- a '&&' b` funziona.
//!      Un token come `a&&b` (testo + metacaratteri) resta quotato:
//!      e' un argomento letterale, non un operatore.
//!
//! 4. **Quoting cmd.exe (bug report)**: su remote Windows i token erano
//!    solo uniti con spazi — i single quote NON raggruppano per cmd
//!    (`dir 'D:\a b'` -> cmd vedeva due argomenti) e i metacaratteri cmd
//!    (`|`, `&`) dentro un argomento venivano interpretati da cmd invece
//!    di arrivare al processo figlio (powershell). Ora i token con
//!    whitespace sono ri-quotati con i DOPPI apici (`cmd_requote`), la
//!    sola forma di raggruppamento che cmd riconosce; un `"` gia'
//!    presente nel token disattiva il re-quote (l'utente ha fatto il
//!    quoting lui stesso — cmd non ha escape affidabile per `"` innestati).
//!
//! 2. **Subcommand `run`**: upload script in tmp remoto + esecuzione +
//!    cleanup. Path tmp e interprete dipendono dall'OS remoto.
//!
//! 3. **Exit code**: il server non restituiva l'exit status dei comandi
//!    shell-mode. Col prefisso-sentinel `EXIT_CODE_PREFIX` (compreso solo
//!    da server dello stesso BUILD_TS) il server accoda al flusso la riga
//!    `CROSSPILOT_EXIT_CODE=<n>` che il client estrae e usa come exit code.

use anyhow::{bail, Result};

use crate::envs;

/// Prefisso-sentinel shell-mode: il server lo riconosce, esegue il comando
/// e accoda `\nCROSSPILOT_EXIT_CODE=<n>\n` al flusso prima di chiudere.
/// Inviato SOLO a server dello stesso BUILD_TS (altri lo passerebbero a
/// cmd.exe/sh come testo ignoto) — stesso caveat di QUIT_AFTER_PREFIX.
pub const EXIT_CODE_PREFIX: &str = "crosspilot:exit-code ";

/// Marca emessa dal server a fine comando (riga autonoma nel flusso).
pub const EXIT_MARKER: &str = "CROSSPILOT_EXIT_CODE=";

/// Coda massima tenuta in buffer lato client per estrarre il marker
/// (la riga e' <= ~40 byte; 128 da margine su prefix + newline).
pub const EXIT_MARKER_TAIL: usize = 128;

// ---------------------------------------------------------------------------
// Quoting POSIX (remote unix) vs join nudo (remote Windows).
// ---------------------------------------------------------------------------

/// True se il carattere e' "sicuro" in una command-line POSIX senza quoting:
/// insieme stile shlex + caratteri di espansione remota che vogliamo
/// preservare (`$`, `~`, `*`, `?`, `{}`, `[]`, backtick, `!`, `%`, `=`, `:`,
/// `,`, `.`, `/`, `-`, `_`, `+`, `@`, `^`, `#`).
/// I caratteri che rompono il raggruppamento (spazio, quote, `;&|<>()`)
/// NON sono nella safe list e forzano il quoting.
fn is_posix_safe(c: char) -> bool {
    matches!(
        c,
        'a'..='z' | 'A'..='Z' | '0'..='9'
            | '_' | '@' | '%' | '+' | '=' | ':' | ',' | '.' | '/' | '-' | '^' | '#'
            | '$' | '~' | '*' | '?' | '{' | '}' | '[' | ']' | '`' | '!'
    )
}

/// Quota un singolo token per la shell POSIX: single-quote + escape
/// `'` -> `'\''`. I token sicuri passano invariati.
pub fn posix_quote(token: &str) -> String {
    let safe = !token.is_empty() && token.chars().all(is_posix_safe);
    if safe {
        return token.to_string();
    }
    let mut out = String::with_capacity(token.len() + 2);
    out.push('\'');
    for c in token.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

/// True se il token e' un OPERATORE di shell puro: composto solo da
/// metacaratteri (`&`, `|`, `;`, `<`, `>`, `(`, `)`) e cifre di fd
/// (redirect `2>`, `2>&1`, `>&2`...), con almeno un metacarattere.
/// Esempi: `&&`, `||`, `;`, `|`, `&`, `>`, `>>`, `<`, `2>`, `2>&1`,
/// `&>`, `&>>`, `;;`, `|&`, `(`, `)`. Un token cosi' non puo' essere un
/// argomento di un comando: se quotato (`'&&'`) viene passato a sh come
/// TESTO e il composto non funziona mai (bug report: "No such file or
/// directory" su `crosspilot -- a '&&' b`).
/// `123` (solo cifre, nessun metacarattere) NON e' un operatore.
fn is_shell_operator_token(token: &str) -> bool {
    let mut has_operator_char = false;
    for c in token.chars() {
        let is_op_char = matches!(c, '&' | '|' | ';' | '<' | '>' | '(' | ')');
        let is_fd_digit = c.is_ascii_digit();
        if !is_op_char && !is_fd_digit {
            return false;
        }
        if is_op_char {
            has_operator_char = true;
        }
    }
    has_operator_char
}

/// Ricostruisce la command-line remota dai token catturati da clap dopo `--`.
/// - `unix = true`  -> ogni token e' posix_quote()-ato e unito con spazi:
///   il raggruppamento della shell locale sopravvive al transito (fix del
///   bug "sleep: missing operand" / "docker ps accepts no arguments").
/// - `unix = false` -> cmd_requote(): doppi apici sui token con whitespace
///   (fix "dir 'D:\a b'" splittato da cmd — i single quote NON raggruppano
///   per cmd.exe, ci vogliono i doppi apici).
///   Eccezioni COMUNI ai due OS (fix "niente comandi composti"):
///   - UN token solo -> raw: e' una command-line completa
///     (`crosspilot -- "a && b"`), quotarla la rende un nome di comando;
///   - operatori shell puri (`&&`, `;`, `|`...) -> raw: sono operatori,
///     non argomenti.
pub fn rejoin_command(tokens: &[String], unix: bool) -> String {
    // Token singolo (unix E windows): nessun raggruppamento da preservare —
    // quotarlo forzerebbe la shell remota a cercare un comando letterale
    // (con spazi e metacaratteri inclusi) che non esiste. Raw = l'unica
    // lettura sensata.
    if tokens.len() == 1 {
        let only = &tokens[0];
        return only.clone();
    }
    let mut parts: Vec<String> = Vec::with_capacity(tokens.len());
    for t in tokens {
        // Operatori puri -> nudi (sono operatori, mai argomenti).
        // Testo con metacaratteri misti (es. `a&&b`) -> quotato com'e'.
        let is_operator = is_shell_operator_token(t);
        if is_operator {
            let raw = t.clone();
            parts.push(raw);
        } else if unix {
            let q = posix_quote(t);
            parts.push(q);
        } else {
            let q = cmd_requote(t);
            parts.push(q);
        }
    }
    parts.join(" ")
}

/// True se il carattere forza il quoting cmd.exe: whitespace (spezza gli
/// argomenti) o metacaratteri cmd (`& | < > ^` e i blocchi `()`). I `"` sono
/// gestiti dal chiamante (token con `"` interno passano raw). `%` NON forza
/// quoting: cmd espande %VAR% anche dentro i doppi apici, quindi il quoting
/// non proteggerebbe comunque — e `*`/`?` devono restare glob remoti.
fn cmd_needs_quote(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\r' | '"' | '&' | '|' | '<' | '>' | '^' | '(' | ')')
}

/// Quota un token per cmd.exe remoto (fix bug report su quoting Windows):
/// i doppi apici sono l'UNICO raggruppamento che cmd riconosce — i single
/// quote sono caratteri normali (`dir 'D:\a b'` era splittato sullo
/// spazio, dando "D:\a" + "b'" come due path).
///
/// Regole (deliberatamente conservative):
/// - nessun carattere da `cmd_needs_quote` -> invariato;
/// - token con `"` interno -> invariato: l'utente ha fatto quoting a mano
///   (es. `dir "\"D:\a b\""`) e cmd non ha un escape affidabile per
///   apici innestati — raddoppiare romperebbe i builtin cmd, `\"` non e'
///   un escape per cmd (solo per CommandLineToArgvW dei figli);
/// - altrimenti `"token"`: dentro gli apici spazi e `& | < > ^` restano
///   letterali per cmd (fix "powershell -Command X | Y" dove la pipe era
///   intercettata da cmd) e il figlio li rivede dopo CommandLineToArgvW.
///
/// Il backslash FINALE prima della chiusura e' raddoppiato:
/// `"C:\dir\"` -> CommandLineToArgvW legge `\"` come apice escaped e
/// mangia il quoting (l'exe figlio riceverebbe `C:\dir"` troncato).
/// `"C:\dir\\"` e' corretta per entrambi: il figlio vede `C:\dir\` e i
/// builtin cmd / fs Windows collassano `\\` a `\` comunque.
pub fn cmd_requote(token: &str) -> String {
    if token.is_empty() {
        return "\"\"".to_string();
    }
    let needs = token.chars().any(cmd_needs_quote);
    if !needs || token.contains('"') {
        return token.to_string();
    }
    let mut out = String::with_capacity(token.len() + 3);
    out.push('"');
    out.push_str(token);
    if token.ends_with('\\') {
        out.push('\\');
    }
    out.push('"');
    out
}

/// Quota un argomento per cmd.exe remoto (doppie virgolette + escape di ").
/// Usato dagli argomenti di `run` su remote Windows (approssimazione —
/// il quoting cmd resta intrinsecamente fragile, vedi --help).
pub fn cmd_quote(arg: &str) -> String {
    let safe = !arg.is_empty()
        && arg.chars().all(|c| {
            matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9'
                | '_' | '-' | '.' | '/' | '\\' | ':' | '=' | '+' | ',')
        });
    if safe {
        return arg.to_string();
    }
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    for c in arg.chars() {
        if c == '"' {
            out.push('"');
        }
        out.push(c);
    }
    out.push('"');
    out
}

// ---------------------------------------------------------------------------
// `run` subcommand: path tmp remoto + comando di esecuzione/cleanup.
// ---------------------------------------------------------------------------

/// Estensione del file locale (lowercase, senza punto), per scegliere
/// l'interprete remoto. Vuota se assente.
fn script_ext(local_script: &str) -> String {
    let p = std::path::Path::new(local_script);
    let ext = p
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    ext
}

/// True se lo script locale inizia con shebang `#!` (letti i primi 2 byte:
/// con shebang su remote unix si esegue DIRETTAMENTE dopo chmod +x, cosi'
/// l'interprete dichiarato dallo script — bash/python/... — e' rispettato).
fn local_has_shebang(local_script: &str) -> bool {
    let read = std::fs::read(local_script);
    match read {
        Ok(bytes) => bytes.starts_with(b"#!"),
        Err(_) => false,
    }
}

/// Path remoto dello script staged di `run`.
/// - unix:    `/tmp/crosspilot-run-<pid>-<nanos>[.<ext>]`
/// - windows: `<dir di EXE_PATH>\crosspilot-run-<pid>-<nanos>[.<ext>]`;
///   se EXE_PATH non e' configurato ripiega su `C:\Windows\Temp`.
///
/// Conserva l'estensione dello script (serve a .bat/.ps1 su Windows).
pub fn remote_tmp_script_path(local_script: &str, unix: bool) -> Result<String> {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let ext = script_ext(local_script);
    let name = if ext.is_empty() {
        format!("crosspilot-run-{}-{}", pid, nanos)
    } else {
        format!("crosspilot-run-{}-{}.{}", pid, nanos, ext)
    };
    if unix {
        return Ok(format!("/tmp/{}", name));
    }
    // Windows: preferisci la dir dell'exe remoto (deployata = scrivibile).
    let exe_path = envs::var("EXE_PATH").unwrap_or_default();
    let dir = if exe_path.is_empty() {
        "C:\\Windows\\Temp".to_string()
    } else {
        let trimmed = exe_path.trim_end_matches(['\\', '/']);
        match trimmed.rfind(['\\', '/']) {
            Some(pos) => trimmed[..pos].to_string(),
            None => "C:\\Windows\\Temp".to_string(),
        }
    };
    Ok(format!("{}\\{}", dir, name))
}

/// Prefisso "attendi che il file staged esista" per comandi eseguiti
/// subito dopo un PUT sulla stessa destinazione.
///
/// Race osservata in e2e: put_client ritorna dopo la conferma di hash, ma
/// il rename atomico `.part` -> dest sul server avviene DOPO, mentre la
/// connessione shell-mode successiva (chmod/exec) viaggia in parallelo e
/// puo' arrivare prima del rename — `chmod`/`sh` sul path mancante
/// fallirebbero silenziosamente. Il wait-loop lato shell assorbe il lag
/// (il rename e' istantaneo; il ciclo copre casi patologici ~10s).
pub fn wait_for_file_prefix(remote_path: &str, unix: bool) -> String {
    if unix {
        let quoted = posix_quote(remote_path);
        // sleep frazionario non e' POSIX: fallback a sleep 1 dove manca
        // (busybox/sh vecchi). ~100 iterazioni = margine largo.
        format!(
            "i=0; while [ ! -f {q} ] && [ \"$i\" -lt 100 ]; do i=$((i+1)); sleep 0.1 2>/dev/null || sleep 1; done; ",
            q = quoted
        )
    } else {
        // cmd.exe: delay fisso ~1s (ping loopback) — il rename e' istantaneo,
        // questo copre il lag del canale senza for/goto fragili in one-liner.
        "ping -n 2 127.0.0.1 >nul & ".to_string()
    }
}

/// Comando shell-mode che esegue lo script remoto `remote_path` con `args`.
/// - unix: con shebang -> `chmod 755 'p' && 'p' args...` (interprete dallo
///   script); senza shebang -> `sh 'p' args...`.
/// - windows: `.ps1` -> `powershell -NoProfile -ExecutionPolicy Bypass -File "p"`;
///   altro -> `cmd /c call "p"` (batch/cmd o qualunque eseguibile).
///
/// Il comando e' preceduto dall'attesa del file staged (race PUT->rename,
/// vedi wait_for_file_prefix).
pub fn build_exec_command(
    local_script: &str,
    remote_path: &str,
    args: &[String],
    unix: bool,
) -> Result<String> {
    if unix {
        let quoted_path = posix_quote(remote_path);
        let mut cmd = wait_for_file_prefix(remote_path, true);
        if local_has_shebang(local_script) {
            // chmod per l'esecuzione diretta: il PUT lascia 644.
            cmd.push_str("chmod 755 ");
            cmd.push_str(&quoted_path);
            cmd.push_str(" && ");
            cmd.push_str(&quoted_path);
        } else {
            cmd.push_str("sh ");
            cmd.push_str(&quoted_path);
        }
        for a in args {
            cmd.push(' ');
            cmd.push_str(&posix_quote(a));
        }
        return Ok(cmd);
    }
    let ext = script_ext(local_script);
    let mut cmd = wait_for_file_prefix(remote_path, false);
    if ext == "ps1" {
        cmd.push_str("powershell -NoProfile -ExecutionPolicy Bypass -File ");
        cmd.push_str(&cmd_quote(remote_path));
    } else {
        // Batch/cmd/qualunque: call preserva il return di ERRORLEVEL.
        cmd.push_str("cmd /c call ");
        cmd.push_str(&cmd_quote(remote_path));
    }
    for a in args {
        cmd.push(' ');
        cmd.push_str(&cmd_quote(a));
    }
    Ok(cmd)
}

/// Comando shell-mode di cleanup dello script staged (best-effort).
pub fn build_cleanup_command(remote_path: &str, unix: bool) -> String {
    if unix {
        let mut cmd = String::from("rm -f ");
        cmd.push_str(&posix_quote(remote_path));
        cmd
    } else {
        let mut cmd = String::from("del /f /q ");
        cmd.push_str(&cmd_quote(remote_path));
        cmd
    }
}

/// Estrae il marker `CROSSPILOT_EXIT_CODE=<n>` dalla coda dell'output.
/// Ritorna (byte-di-coda-da-stampare, exit code opzionale). La coda senza
/// marker (server vecchio o comando ucciso) viene restituita integrale.
pub fn extract_exit_marker(tail: &[u8]) -> (&[u8], Option<i32>) {
    let text = String::from_utf8_lossy(tail);
    // Cerca l'ULTIMA occorrenza del marker (robusto se l'output ne contiene).
    let pos = text.rfind(EXIT_MARKER);
    let pos = match pos {
        Some(p) => p,
        None => return (tail, None),
    };
    let after = &text[pos + EXIT_MARKER.len()..];
    let digits: String = after
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '-')
        .collect();
    let code = digits.parse::<i32>().ok();
    if code.is_none() {
        return (tail, None);
    }
    // Taglia alla newline che precede il marker (il marker e' su riga propria).
    let byte_pos = tail.len() - (text.len() - pos);
    let mut end = byte_pos;
    if end > 0 && tail[end - 1] == b'\r' {
        end -= 1;
    }
    if end > 0 && tail[end - 1] == b'\n' {
        end -= 1;
    }
    (&tail[..end], code)
}

/// Verifica che il remote path tmp non contenga null (validazione difensiva).
pub fn check_remote_path(remote_path: &str) -> Result<()> {
    if remote_path.is_empty() || remote_path.contains('\0') {
        bail!("run: remote path tmp invalido: {:?}", remote_path);
    }
    if remote_path.len() > 4096 {
        bail!("run: remote path tmp troppo lungo");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn posix_quote_safe_untouched() {
        // Token senza caratteri di raggruppamento: passano invariati
        // (inclusi $, *, ~ che DEVONO espandersi sul remote).
        assert_eq!(posix_quote("docker"), "docker");
        assert_eq!(posix_quote("$HOME"), "$HOME");
        assert_eq!(posix_quote("/tmp/*.log"), "/tmp/*.log");
        assert_eq!(posix_quote("--format={{.Names}}"), "--format={{.Names}}");
    }

    #[test]
    fn posix_quote_groups_preserved() {
        // Il bug riportato: token con spazi/quote devono restare un gruppo.
        assert_eq!(posix_quote("sleep 8; docker ps"), "'sleep 8; docker ps'");
        assert_eq!(
            posix_quote("{{.Names}} {{.Status}}"),
            "'{{.Names}} {{.Status}}'"
        );
        assert_eq!(posix_quote("it's"), "'it'\\''s'");
        assert_eq!(posix_quote(""), "''");
        assert_eq!(posix_quote("a|b"), "'a|b'");
        assert_eq!(posix_quote("a&&b"), "'a&&b'");
        assert_eq!(posix_quote("x>y"), "'x>y'");
    }

    #[test]
    fn rejoin_unix_quotes_only_when_needed() {
        // Ricostruzione del caso del bug report: i token locali gia'
        // raggruppati devono arrivare intatti a sh -c remoto.
        let tokens = vec![
            "sh".to_string(),
            "-c".to_string(),
            "sleep 8; docker ps".to_string(),
        ];
        assert_eq!(rejoin_command(&tokens, true), "sh -c 'sleep 8; docker ps'");

        let tokens2 = vec!["docker".to_string(), "ps".to_string()];
        assert_eq!(rejoin_command(&tokens2, true), "docker ps");
        // Windows: i token con spazi sono ri-quotati coi doppi apici
        // (fix "dir 'D:\a b'" splittato da cmd — i single quote non
        // raggruppano per cmd.exe). Token sicuri restano nudi.
        assert_eq!(
            rejoin_command(&tokens, false),
            "sh -c \"sleep 8; docker ps\""
        );
    }

    #[test]
    fn rejoin_windows_quotes_only_when_needed() {
        // Bug report: `crosspilot -- dir 'D:\Progetti\[DELPHI SORGENTI]'`
        // -> bash toglie i single quote -> token "D:\Progetti\[DELPHI
        // SORGENTI]" -> il join nudo lo riconsegnava a cmd come DUE
        // argomenti ("File non trovato"). Ora i doppi apici raggruppano.
        let tokens = vec![
            "dir".to_string(),
            "D:\\Progetti\\[DELPHI SORGENTI]".to_string(),
        ];
        assert_eq!(
            rejoin_command(&tokens, false),
            "dir \"D:\\Progetti\\[DELPHI SORGENTI]\""
        );
        // Token senza spazi: nessun quoting aggiunto (invariato).
        let tokens2 = vec!["dir".to_string(), "c:\\".to_string()];
        assert_eq!(rejoin_command(&tokens2, false), "dir c:\\");
        // Token singolo: raw su entrambi gli OS (command-line completa).
        let single = vec!["dir c:\\ && echo ok".to_string()];
        assert_eq!(rejoin_command(&single, false), "dir c:\\ && echo ok");
    }

    #[test]
    fn rejoin_windows_powershell_command() {
        // Bug report: `powershell -Command "Get-Item 'p' | Select"` — la
        // pipe nel token veniva interpretata da cmd. Col re-quote i
        // metacaratteri restano letterali dentro i doppi apici e arrivano
        // intatti a powershell.exe come unico argomento di -Command.
        let tokens = vec![
            "powershell".to_string(),
            "-Command".to_string(),
            "Get-Item 'D:\\a b' | Select-Object FullName".to_string(),
        ];
        assert_eq!(
            rejoin_command(&tokens, false),
            "powershell -Command \"Get-Item 'D:\\a b' | Select-Object FullName\""
        );
    }

    #[test]
    fn cmd_requote_rules() {
        // Nessun metacarattere: invariato.
        assert_eq!(cmd_requote("c:\\dir"), "c:\\dir");
        assert_eq!(cmd_requote("%PATH%"), "%PATH%");
        assert_eq!(cmd_requote("*.txt"), "*.txt");
        // Spazi/metacaratteri cmd -> doppi apici.
        assert_eq!(cmd_requote("a b"), "\"a b\"");
        assert_eq!(cmd_requote("a|b"), "\"a|b\"");
        assert_eq!(cmd_requote("a&&b"), "\"a&&b\"");
        assert_eq!(cmd_requote("x>y"), "\"x>y\"");
        // Backslash finale: raddoppiato prima della quote di chiusura
        // (CommandLineToArgvW leggerebbe \" come apice escaped).
        assert_eq!(cmd_requote("C:\\a b\\"), "\"C:\\a b\\\\\"");
        // Apice interno: l'utente ha gia' quotato -> raw (niente escape
        // affidabile per " innestati via cmd).
        assert_eq!(cmd_requote("\"D:\\a b\""), "\"D:\\a b\"");
        // Token vuoto -> quoting vuoto esplicito.
        assert_eq!(cmd_requote(""), "\"\"");
    }

    #[test]
    fn rejoin_windows_pure_operators_unquoted() {
        // Gli operatori puri restano raw anche su remote Windows:
        // `crosspilot -- a '&&' b` deve restare un composto cmd.
        let tokens = vec!["dir".to_string(), "&&".to_string(), "echo".to_string(), "ok".to_string()];
        assert_eq!(rejoin_command(&tokens, false), "dir && echo ok");
    }

    #[test]
    fn rejoin_unix_single_token_is_raw() {
        // Bug report: `crosspilot -- "cmd1 && cmd2"` arriva come UN token —
        // quotarlo produceva 'cmd1 && cmd2' -> sh lo cercava come comando
        // letterale ("No such file or directory"). Ora passa raw.
        let tokens = vec!["systemctl restart nginx && systemctl status nginx".to_string()];
        assert_eq!(
            rejoin_command(&tokens, true),
            "systemctl restart nginx && systemctl status nginx"
        );
        // Anche con ; e pipe.
        let tokens2 = vec!["a; b | c > /tmp/out".to_string()];
        assert_eq!(rejoin_command(&tokens2, true), "a; b | c > /tmp/out");
        // Token singolo semplice: invariato (raw == non-quotato).
        let tokens3 = vec!["hostname".to_string()];
        assert_eq!(rejoin_command(&tokens3, true), "hostname");
    }

    #[test]
    fn rejoin_unix_pure_operators_unquoted() {
        // Bug report: `crosspilot -- a '&&' b` produceva a '&&' b -> a
        // riceveva "&&" e "b" come argomenti. L'operatore puro passa raw.
        let tokens = vec!["ls".to_string(), "&&".to_string(), "pwd".to_string()];
        assert_eq!(rejoin_command(&tokens, true), "ls && pwd");
        // Redirect e pipe puri.
        let tokens2 = vec![
            "echo".to_string(),
            "hi".to_string(),
            ">>".to_string(),
            "/tmp/f".to_string(),
        ];
        assert_eq!(rejoin_command(&tokens2, true), "echo hi >> /tmp/f");
        // fd redirect composto: 2>&1 e' tutto metacaratteri+cifre -> operatore.
        let tokens3 = vec![
            "cmd".to_string(),
            "2>&1".to_string(),
            "|".to_string(),
            "less".to_string(),
        ];
        assert_eq!(rejoin_command(&tokens3, true), "cmd 2>&1 | less");
        // NON operatori: testo misto con metacaratteri resta argomento quotato.
        let tokens4 = vec!["echo".to_string(), "a&&b".to_string()];
        assert_eq!(rejoin_command(&tokens4, true), "echo 'a&&b'");
        // Solo cifre: non e' operatore (ma e' posix-safe: resta nudo).
        let tokens5 = vec!["sleep".to_string(), "5".to_string()];
        assert_eq!(rejoin_command(&tokens5, true), "sleep 5");
    }

    #[test]
    fn exec_command_unix_shebang_vs_sh() {
        // Nota: local_has_shebang legge il file — qui testiamo solo la
        // parte non-shebang (il ramo shebang e' coperto dal path con #!).
        let cmd = build_exec_command("x.sh", "/tmp/x.sh", &[], true).unwrap();
        // File "x.sh" non esiste -> niente shebang -> wait-loop + sh /tmp/x.sh
        // (il path non ha caratteri di raggruppamento -> niente quoting).
        assert!(cmd.ends_with("; sh /tmp/x.sh"), "cmd={}", cmd);
        assert!(
            cmd.starts_with("i=0; while [ ! -f /tmp/x.sh ]"),
            "cmd={}",
            cmd
        );
        let cmd_args = build_exec_command(
            "x.sh",
            "/tmp/x.sh",
            &["--name".to_string(), "a b".to_string()],
            true,
        )
        .unwrap();
        assert!(
            cmd_args.ends_with("; sh /tmp/x.sh --name 'a b'"),
            "cmd={}",
            cmd_args
        );
    }

    #[test]
    fn exec_command_windows() {
        let cmd = build_exec_command("x.bat", "C:\\ci\\x.bat", &[], false).unwrap();
        assert_eq!(cmd, "ping -n 2 127.0.0.1 >nul & cmd /c call C:\\ci\\x.bat");
        let ps = build_exec_command("x.ps1", "C:\\ci dir\\x.ps1", &[], false).unwrap();
        assert_eq!(
            ps,
            "ping -n 2 127.0.0.1 >nul & powershell -NoProfile -ExecutionPolicy Bypass -File \"C:\\ci dir\\x.ps1\""
        );
    }

    #[test]
    fn exit_marker_roundtrip() {
        let tail = b"output\nCROSSPILOT_EXIT_CODE=3\n";
        let (rest, code) = extract_exit_marker(tail);
        assert_eq!(rest, b"output");
        assert_eq!(code, Some(3));
        // Senza marker: coda integrale.
        let (rest2, code2) = extract_exit_marker(b"output only");
        assert_eq!(rest2, b"output only");
        assert_eq!(code2, None);
    }
}
