// Modulo envs: gestione degli ambienti (configurazioni host) nel file .env.
//
// Il .env può contenere N ambienti identificati da un nome prefisso:
//
//   # ambiente default (chiavi non prefissate, retrocompatibile)
//   CROSSPILOT_HOST=127.0.0.1
//   CROSSPILOT_USER=gianca
//
//   # ambiente "prod"
//   CROSSPILOT_PROD_HOST=10.0.0.5
//   CROSSPILOT_PROD_USER=administrator
//
//   # selettore ambiente attivo
//   CROSSPILOT_ENV=PROD
//
// Risoluzione di un campo (es. HOST) a runtime:
//   1. CROSSPILOT_<ENV>_<CAMPO>   (se CROSSPILOT_ENV è impostato)
//   2. CROSSPILOT_<CAMPO>         (fallback: chiavi non prefissate)
//   3. default hardcoded       (a carico del chiamante)
//
// I comandi CRUD (`crosspilot env ...`) operano sul file .env risolto
// con la stessa ricerca usata dal loader (cwd -> exe dir -> project root),
// preservando commenti e righe non correlate (edit line-based).

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Campi e regole di naming
// ---------------------------------------------------------------------------

/// Campi configurabili di un ambiente host.
///
/// ORDINE IMPORTANTE: longest-first. Il parsing delle chiavi usa il match per
/// suffisso, quindi i campi composti devono essere provati prima di quelli
/// brevi: `CROSSPILOT_EU_CLIENT_PORT` -> env `EU` + campo `CLIENT_PORT`
/// (non env `EU_CLIENT` + campo `PORT`).
const FIELDS: &[&str] = &[
    "SEGMENT_SIZE",
    "CLIENT_PORT",
    "SERVER_PORT",
    "EXE_PATH",
    "LOG_PATH",
    "ERR_PATH",
    "HOST",
    "PORT",
    "USER",
    "PASS",
];

/// Ordine di presentazione/scrittura dei campi (show + add).
const FIELD_ORDER: &[&str] = &[
    "HOST",
    "PORT",
    "USER",
    "PASS",
    "EXE_PATH",
    "CLIENT_PORT",
    "SERVER_PORT",
    "LOG_PATH",
    "ERR_PATH",
    "SEGMENT_SIZE",
];

/// Nomi riservati: un ambiente con questi nomi colliderebbe con chiavi non
/// prefissate o con il selettore:
/// - ENV:     CROSSPILOT_ENV è il selettore dell'ambiente attivo;
/// - SERVER:  CROSSPILOT_SERVER_PORT (campo PORT dell'env SERVER) colliderebbe
///   con la chiave non prefissata CROSSPILOT_SERVER_PORT;
/// - CLIENT:  idem per CROSSPILOT_CLIENT_PORT;
/// - DEFAULT: nome logico dell'ambiente non prefissato.
const RESERVED: &[&str] = &["ENV", "SERVER", "CLIENT", "DEFAULT"];

/// Chiave del selettore dell'ambiente attivo.
const SELECTOR_KEY: &str = "CROSSPILOT_ENV";

// ---------------------------------------------------------------------------
// Path del file .env (stessa ricerca del loader in main)
// ---------------------------------------------------------------------------

/// Path candidati del .env, in ordine di priorità:
/// 1. cwd/.env
/// 2. <exe dir>/.env
/// 3. <project root>/.env (parent di target/release o target/debug)
fn candidate_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Ok(cwd) = env::current_dir() {
        paths.push(cwd.join(".env"));
    }

    if let Ok(exe_path) = env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            paths.push(exe_dir.join(".env"));
            if exe_dir.ends_with("release") || exe_dir.ends_with("debug") {
                if let Some(project_root) = exe_dir.parent().and_then(|t| t.parent()) {
                    paths.push(project_root.join(".env"));
                }
            }
        }
    }

    paths
}

/// Path del .env da usare per il CRUD: il primo esistente tra i candidati,
/// altrimenti ./.env (viene creato alla prima scrittura).
pub fn env_file_path() -> PathBuf {
    let found = candidate_paths().into_iter().find(|p| p.exists());
    found.unwrap_or_else(|| PathBuf::from(".env"))
}

/// Carica il primo .env trovato nei path candidati (dotenvy).
/// Le variabili già presenti nel processo NON vengono sovrascritte:
/// `CROSSPILOT_ENV=staging crosspilot ...` funziona come override ad-hoc.
pub fn load_dotenv() -> bool {
    let tried: Vec<PathBuf> = candidate_paths();
    for path in &tried {
        if !path.exists() {
            continue;
        }
        match dotenvy::from_path(path) {
            Ok(_) => {
                eprintln!("[DEBUG] Loaded .env from: {}", path.display());
                return true;
            }
            Err(e) => {
                eprintln!("[DEBUG] Failed to load .env from {}: {}", path.display(), e);
            }
        }
    }

    eprintln!("[WARNING] No .env file found in any of these locations:");
    for path in &tried {
        eprintln!("  - {}", path.display());
    }
    eprintln!("Using defaults or system environment variables.");
    false
}

// ---------------------------------------------------------------------------
// Risoluzione runtime (usata da main/bootstrap/deploy)
// ---------------------------------------------------------------------------

/// Nome dell'ambiente attivo (CROSSPILOT_ENV), normalizzato uppercase.
/// None -> ambiente "default" (chiavi non prefissate).
pub fn active_name() -> Option<String> {
    let raw = env::var(SELECTOR_KEY).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_uppercase())
    }
}

/// Chiave completa di un campo per un dato ambiente.
/// name=None -> chiave non prefissata (ambiente default).
fn key_for(name: Option<&str>, field: &str) -> String {
    match name {
        Some(n) => format!("CROSSPILOT_{}_{}", n, field),
        None => format!("CROSSPILOT_{}", field),
    }
}

/// Risolve un campo di configurazione host leggendo il process environment
/// (dove load_dotenv ha già caricato il .env).
///
/// Cerca prima CROSSPILOT_<ENV>_<CAMPO> (ambiente attivo), poi la chiave non
/// prefissata CROSSPILOT_<CAMPO>. I valori vuoti sono ignorati.
pub fn var(field: &str) -> Option<String> {
    let active = active_name();
    var_for(active.as_deref(), field)
}

/// Come var(), ma per un ambiente esplicito (usata da `env show`).
pub fn var_for(name: Option<&str>, field: &str) -> Option<String> {
    if let Some(n) = name {
        let key = key_for(Some(n), field);
        if let Ok(v) = env::var(&key) {
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    let key = key_for(None, field);
    let value = env::var(&key).ok()?;
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

// ---------------------------------------------------------------------------
// Parsing delle righe .env
// ---------------------------------------------------------------------------

/// Esito del parsing di una chiave CROSSPILOT_*.
#[derive(Debug, PartialEq)]
enum ParsedKey {
    /// CROSSPILOT_ENV (selettore ambiente attivo).
    Selector,
    /// Campo di un ambiente: nome (None = default non prefissato) + campo.
    Field(Option<String>, &'static str),
    /// Chiave non riconducibile ad un ambiente (es. CROSSPILOT_DEBUG).
    Other,
}

/// Analizza una chiave .env e la classifica.
fn parse_key(key: &str) -> ParsedKey {
    let rest = match key.strip_prefix("CROSSPILOT_") {
        Some(r) => r,
        None => return ParsedKey::Other,
    };
    if rest == "ENV" {
        return ParsedKey::Selector;
    }
    for field in FIELDS {
        if rest == *field {
            return ParsedKey::Field(None, field);
        }
        let suffix = format!("_{}", field);
        if let Some(name) = rest.strip_suffix(&suffix) {
            if !name.is_empty() {
                return ParsedKey::Field(Some(name.to_string()), field);
            }
        }
    }
    ParsedKey::Other
}

/// Estrae (chiave, valore) da una riga .env.
/// Salta righe vuote/commenti, gestisce il prefisso opzionale `export `,
/// rimuove le virgolette attorno al valore.
fn parse_line(line: &str) -> Option<(String, String)> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let body = trimmed.strip_prefix("export ").unwrap_or(trimmed);
    let (key, value) = body.split_once('=')?;
    let key = key.trim().to_string();
    if key.is_empty() {
        return None;
    }
    let value = unquote(strip_inline_comment(value.trim()));
    Some((key, value))
}

/// Rimuove il commento inline (` # ...`) dai valori non quotati, replicando
/// la semantica di dotenvy a runtime: un `#` preceduto da whitespace apre un
/// commento, un `#` attaccato al valore (es. `PASS=abc#def`) resta parte del
/// valore. I valori quotati non vengono toccati (`#` e' letterale).
fn strip_inline_comment(value: &str) -> &str {
    let bytes = value.as_bytes();
    if bytes.first() == Some(&b'"') || bytes.first() == Some(&b'\'') {
        return value;
    }
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'#' && i > 0 && bytes[i - 1].is_ascii_whitespace() {
            return value[..i].trim_end();
        }
    }
    value
}

/// Rimuove una coppia di virgolette attorno al valore, se presente.
/// Per i double-quoted elabora gli escape stile dotenvy (\\ -> \, \n, \r, \t, ...);
/// i single-quoted sono letterali.
fn unquote(value: &str) -> String {
    let bytes = value.as_bytes();
    if bytes.len() < 2 {
        return value.to_string();
    }
    let first = bytes[0];
    let last = bytes[bytes.len() - 1];
    if first == b'"' && last == b'"' {
        let inner = &value[1..value.len() - 1];
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                match chars.next() {
                    Some('n') => out.push('\n'),
                    Some('r') => out.push('\r'),
                    Some('t') => out.push('\t'),
                    Some(other) => out.push(other),
                    None => out.push('\\'),
                }
            } else {
                out.push(c);
            }
        }
        return out;
    }
    if first == b'\'' && last == b'\'' {
        return value[1..value.len() - 1].to_string();
    }
    value.to_string()
}

/// Quota il valore se contiene caratteri che richiedono quoting in un .env
/// (spazi, #, virgolette, backtick, $, backslash). Altrimenti lo restituisce
/// com'è. I backslash (path Windows) vengono quotati+escaped per coerenza
/// con il formato gia' usato nel .env (C:\\Users\\...).
fn quote_value(value: &str) -> String {
    let needs_quote = value
        .chars()
        .any(|c| c.is_whitespace() || c == '#' || c == '"' || c == '\'' || c == '$' || c == '`' || c == '\\');
    if needs_quote {
        let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
        format!("\"{}\"", escaped)
    } else {
        value.to_string()
    }
}

// ---------------------------------------------------------------------------
// Validazione nomi ambiente
// ---------------------------------------------------------------------------

/// Normalizza e valida un nome ambiente. Ritorna il nome uppercase.
/// "default" (case-insensitive) -> Ok(None) via try_default().
fn validate_name(name: &str) -> Result<String> {
    let upper = name.trim().to_uppercase();
    if upper.is_empty() {
        bail!("nome ambiente vuoto");
    }
    if !upper.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        bail!(
            "nome ambiente '{}' non valido: sono ammessi solo lettere, cifre e underscore",
            name
        );
    }
    if RESERVED.contains(&upper.as_str()) {
        bail!(
            "nome ambiente '{}' riservato (colliderebbe con chiavi CROSSPILOT_* esistenti)",
            upper
        );
    }
    Ok(upper)
}

/// Come validate_name, ma accetta anche "default" -> None (ambiente non prefissato).
fn parse_name_arg(name: &str) -> Result<Option<String>> {
    if name.trim().eq_ignore_ascii_case("default") {
        return Ok(None);
    }
    Ok(Some(validate_name(name)?))
}

// ---------------------------------------------------------------------------
// Operazioni pure su righe (unit-testabili)
// ---------------------------------------------------------------------------

/// Mappa chiave -> valore di tutte le righe KEY=VALUE del file.
fn values_map(lines: &[String]) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for line in lines {
        if let Some((key, value)) = parse_line(line) {
            map.insert(key, value);
        }
    }
    map
}

/// Nomi degli ambienti definiti nel file (quelli con almeno una chiave campo).
fn collect_names(lines: &[String]) -> Vec<String> {
    let mut names = Vec::new();
    for line in lines {
        if let Some((key, _)) = parse_line(line) {
            if let ParsedKey::Field(Some(name), _) = parse_key(&key) {
                if !names.contains(&name) {
                    names.push(name);
                }
            }
        }
    }
    names.sort();
    names
}

/// True se il file contiene almeno una chiave campo per l'ambiente dato
/// (None = default non prefissato).
fn env_exists(lines: &[String], name: Option<&str>) -> bool {
    lines.iter().any(|line| {
        match parse_line(line) {
            Some((key, _)) => match parse_key(&key) {
                ParsedKey::Field(n, _) => n.as_deref() == name,
                _ => false,
            },
            None => false,
        }
    })
}

/// Valore corrente del selettore CROSSPILOT_ENV nel file (se presente).
fn selector_value(lines: &[String]) -> Option<String> {
    for line in lines {
        if let Some((key, value)) = parse_line(line) {
            if parse_key(&key) == ParsedKey::Selector {
                return Some(value);
            }
        }
    }
    None
}

/// Scrive (o aggiorna in place) una riga KEY=VALUE per il campo di un env.
/// Se la chiave esiste già la riga viene sostituita mantenendo la posizione,
/// altrimenti viene aggiunta in coda al file.
fn upsert_field(lines: &mut Vec<String>, name: Option<&str>, field: &str, value: &str) {
    let key = key_for(name, field);
    let new_line = format!("{}={}", key, quote_value(value));
    for line in lines.iter_mut() {
        if let Some((k, _)) = parse_line(line) {
            if k == key {
                *line = new_line;
                return;
            }
        }
    }
    lines.push(new_line);
}

/// Scrive (o rimuove) il selettore CROSSPILOT_ENV. value=None -> rimozione.
fn upsert_selector(lines: &mut Vec<String>, value: Option<&str>) {
    let mut found = false;
    lines.retain_mut(|line| {
        if let Some((k, _)) = parse_line(line) {
            if parse_key(&k) == ParsedKey::Selector {
                found = true;
                if let Some(v) = value {
                    *line = format!("{}={}", SELECTOR_KEY, quote_value(v));
                    return true;
                }
                return false;
            }
        }
        true
    });
    if !found {
        if let Some(v) = value {
            lines.push(format!("{}={}", SELECTOR_KEY, quote_value(v)));
        }
    }
}

/// Rimuove tutte le righe campo dell'ambiente dato, piu' l'eventuale commento
/// header `# env: <NOME>` generato da `env add`.
/// Non tocca il selettore, gli altri env, commenti e righe non CROSSPILOT_*.
fn remove_env_lines(lines: &mut Vec<String>, name: Option<&str>) -> usize {
    // Commento header generato da cmd_add (solo per env nominati).
    let header = name.map(|n| format!("# env: {}", n));
    let before = lines.len();
    lines.retain(|line| {
        // Rimuovi l'header di blocco se corrisponde esattamente.
        if let Some(h) = &header {
            if line.trim() == h {
                return false;
            }
        }
        match parse_line(line) {
            Some((key, _)) => match parse_key(&key) {
                ParsedKey::Field(n, _) => n.as_deref() != name,
                _ => true,
            },
            None => true,
        }
    });
    before - lines.len()
}

// ---------------------------------------------------------------------------
// CLI: `crosspilot env ...`
// ---------------------------------------------------------------------------

/// Campi opzionali condivisi da `env add` e `env set`.
#[derive(Args, Debug, Default)]
pub struct EnvFields {
    /// Porta WinRM (campo PORT, es. 5985 o la porta mappata 47320).
    #[arg(long)]
    pub winrm_port: Option<u16>,
    /// Utente WinRM (campo USER).
    #[arg(long)]
    pub user: Option<String>,
    /// Password WinRM (campo PASS).
    #[arg(long)]
    pub pass: Option<String>,
    /// Path di crosspilot.exe sul target (campo EXE_PATH).
    #[arg(long)]
    pub exe_path: Option<String>,
    /// Porta di connessione lato client (campo CLIENT_PORT).
    #[arg(long)]
    pub client_port: Option<u16>,
    /// Porta di ascolto del server remoto (campo SERVER_PORT).
    #[arg(long)]
    pub server_port: Option<u16>,
    /// Path del log del server remoto (campo LOG_PATH).
    #[arg(long)]
    pub log_path: Option<String>,
    /// Path del log errori del server remoto (campo ERR_PATH).
    #[arg(long)]
    pub err_path: Option<String>,
    /// Dimensione segmento transfer delta in byte (campo SEGMENT_SIZE, 1MB-256MB).
    #[arg(long)]
    pub segment_size: Option<u64>,
}

impl EnvFields {
    /// Coppie (campo, valore) dei flag effettivamente passati.
    fn provided(&self) -> Vec<(&'static str, String)> {
        let mut out: Vec<(&'static str, String)> = Vec::new();
        if let Some(v) = self.winrm_port {
            out.push(("PORT", v.to_string()));
        }
        if let Some(v) = &self.user {
            out.push(("USER", v.clone()));
        }
        if let Some(v) = &self.pass {
            out.push(("PASS", v.clone()));
        }
        if let Some(v) = &self.exe_path {
            out.push(("EXE_PATH", v.clone()));
        }
        if let Some(v) = self.client_port {
            out.push(("CLIENT_PORT", v.to_string()));
        }
        if let Some(v) = self.server_port {
            out.push(("SERVER_PORT", v.to_string()));
        }
        if let Some(v) = &self.log_path {
            out.push(("LOG_PATH", v.clone()));
        }
        if let Some(v) = &self.err_path {
            out.push(("ERR_PATH", v.clone()));
        }
        if let Some(v) = self.segment_size {
            out.push(("SEGMENT_SIZE", v.to_string()));
        }
        out
    }
}

/// Azioni del sottocomando `env`.
#[derive(Subcommand, Debug)]
pub enum EnvAction {
    /// Elenca gli ambienti definiti nel .env (* = attivo).
    List,
    /// Mostra la configurazione effettiva di un ambiente.
    Show {
        /// Nome ambiente (es. prod) oppure "default".
        name: String,
        /// Mostra la password in chiaro (default: mascherata).
        #[arg(long)]
        reveal: bool,
    },
    /// Crea un nuovo ambiente (richiede almeno --host).
    Add {
        /// Nome ambiente (lettere, cifre, underscore).
        name: String,
        /// Hostname/IP del target Windows.
        #[arg(long)]
        host: String,
        #[command(flatten)]
        fields: EnvFields,
    },
    /// Aggiorna uno o più campi di un ambiente esistente.
    Set {
        /// Nome ambiente (es. prod) oppure "default".
        name: String,
        /// Hostname/IP del target Windows.
        #[arg(long)]
        host: Option<String>,
        #[command(flatten)]
        fields: EnvFields,
    },
    /// Elimina un ambiente dal .env.
    Remove {
        /// Nome ambiente (es. prod) oppure "default".
        name: String,
    },
    /// Imposta l'ambiente attivo scrivendo CROSSPILOT_ENV nel .env.
    /// "default" rimuove il selettore (chiavi non prefissate).
    Use {
        /// Nome ambiente (es. prod) oppure "default".
        name: String,
    },
}

/// Entry point del sottocomando `env`: legge il .env, applica l'azione e
/// salva (solo per le operazioni di scrittura).
pub fn run(action: &EnvAction) -> Result<()> {
    let path = env_file_path();
    let content = if path.exists() {
        fs::read_to_string(&path)
            .with_context(|| format!("lettura {}", path.display()))?
    } else {
        String::new()
    };
    let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();

    match action {
        EnvAction::List => cmd_list(&path, &lines)?,
        EnvAction::Show { name, reveal } => cmd_show(&lines, name, *reveal)?,
        EnvAction::Add { name, host, fields } => {
            cmd_add(&mut lines, name, host, fields)?;
            save(&path, &lines)?;
        }
        EnvAction::Set { name, host, fields } => {
            cmd_set(&mut lines, name, host, fields)?;
            save(&path, &lines)?;
        }
        EnvAction::Remove { name } => {
            cmd_remove(&mut lines, name)?;
            save(&path, &lines)?;
        }
        EnvAction::Use { name } => {
            cmd_use(&mut lines, name)?;
            save(&path, &lines)?;
        }
    }
    Ok(())
}

/// Salvataggio atomico del .env (temp file + rename) per evitare file
/// corrotti in caso di interruzione durante la scrittura.
fn save(path: &Path, lines: &[String]) -> Result<()> {
    let mut content = lines.join("\n");
    content.push('\n');

    let tmp = path.with_extension("env.tmp");
    fs::write(&tmp, &content)
        .with_context(|| format!("scrittura {}", tmp.display()))?;
    fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    eprintln!("[DEBUG] .env salvato: {}", path.display());
    Ok(())
}

// --- list -----------------------------------------------------------------

fn cmd_list(path: &Path, lines: &[String]) -> Result<()> {
    let names = collect_names(lines);
    let has_default = env_exists(lines, None);
    let active = selector_value(lines)
        .map(|v| v.to_uppercase());

    println!("File .env: {}", path.display());
    if names.is_empty() && !has_default {
        println!("Nessun ambiente definito.");
        println!("Crea il primo con: crosspilot env add <nome> --host <ip>");
        return Ok(());
    }

    let map = values_map(lines);
    println!("Ambienti definiti:");
    if has_default {
        let mark = if active.is_none() { "*" } else { " " };
        println!("{} default", mark);
    }
    for name in names {
        let mark = if active.as_deref() == Some(name.as_str()) { "*" } else { " " };
        let host = map
            .get(&key_for(Some(&name), "HOST"))
            .cloned()
            .unwrap_or_else(|| "-".to_string());
        println!("{} {:<16} host={}", mark, name, host);
    }
    if let Some(a) = &active {
        println!();
        println!("Ambiente attivo: {} (CROSSPILOT_ENV)", a);
    }
    Ok(())
}

// --- show -----------------------------------------------------------------

fn cmd_show(lines: &[String], name: &str, reveal: bool) -> Result<()> {
    let name_opt = parse_name_arg(name)?;
    let map = values_map(lines);
    let label = name_opt.clone().unwrap_or_else(|| "default".to_string());
    let active = selector_value(lines).map(|v| v.to_uppercase());
    let is_active = active.as_deref() == name_opt.as_deref()
        || (active.is_none() && name_opt.is_none());

    println!("Ambiente: {}{}", label, if is_active { " (attivo)" } else { "" });
    for field in FIELD_ORDER {
        let specific = name_opt
            .as_ref()
            .and_then(|n| map.get(&key_for(Some(n), field)));
        let fallback = map.get(&key_for(None, field));
        let (value, note) = match (specific, fallback) {
            (Some(v), _) => (v.clone(), String::new()),
            (None, Some(v)) => (
                v.clone(),
                format!("(fallback {})", key_for(None, field)),
            ),
            (None, None) => ("-".to_string(), "(non impostato)".to_string()),
        };
        let shown = if *field == "PASS" && !reveal && value != "-" {
            "********".to_string()
        } else {
            value
        };
        println!("  {:<12} = {:<40} {}", field, shown, note);
    }
    if !reveal {
        println!();
        println!("(--reveal per mostrare la password)");
    }
    Ok(())
}

// --- add ------------------------------------------------------------------

fn cmd_add(lines: &mut Vec<String>, name: &str, host: &str, fields: &EnvFields) -> Result<()> {
    let upper = validate_name(name)?;
    if env_exists(lines, Some(&upper)) {
        bail!(
            "ambiente '{}' già definito nel .env (usa 'env set {}' per modificarlo)",
            upper,
            name
        );
    }

    // Blocco nuovo in coda al file: commento + righe campo.
    lines.push(format!("# env: {}", upper));
    upsert_field(lines, Some(&upper), "HOST", host);
    for (field, value) in fields.provided() {
        upsert_field(lines, Some(&upper), field, &value);
    }

    println!(
        "Ambiente '{}' creato ({} campi).",
        upper,
        1 + fields.provided().len()
    );
    println!("Attivalo con: crosspilot env use {}", name);
    Ok(())
}

// --- set ------------------------------------------------------------------

fn cmd_set(
    lines: &mut Vec<String>,
    name: &str,
    host: &Option<String>,
    fields: &EnvFields,
) -> Result<()> {
    let name_opt = parse_name_arg(name)?;
    let label = name_opt.clone().unwrap_or_else(|| "default".to_string());
    if !env_exists(lines, name_opt.as_deref()) {
        bail!(
            "ambiente '{}' non definito nel .env (usa 'env add {}' per crearlo)",
            label,
            name
        );
    }

    let mut updates = fields.provided();
    if let Some(h) = host {
        updates.push(("HOST", h.clone()));
    }
    if updates.is_empty() {
        bail!("nessun campo da aggiornare: passare almeno un flag (es. --host, --user, ...)");
    }
    for (field, value) in &updates {
        upsert_field(lines, name_opt.as_deref(), field, value);
    }
    println!("Ambiente '{}' aggiornato ({} campi).", label, updates.len());
    Ok(())
}

// --- remove ---------------------------------------------------------------

fn cmd_remove(lines: &mut Vec<String>, name: &str) -> Result<()> {
    let name_opt = parse_name_arg(name)?;
    let label = name_opt.clone().unwrap_or_else(|| "default".to_string());
    if !env_exists(lines, name_opt.as_deref()) {
        bail!("ambiente '{}' non definito nel .env", label);
    }

    let removed = remove_env_lines(lines, name_opt.as_deref());

    // Se l'env rimosso era quello attivo, elimina anche il selettore:
    // altrimenti CROSSPILOT_ENV punterebbe ad un ambiente inesistente e ogni
    // campo ricadrebbe silenziosamente sulle chiavi non prefissate.
    let active = selector_value(lines).map(|v| v.to_uppercase());
    if let (Some(a), Some(n)) = (active, &name_opt) {
        if a == *n {
            upsert_selector(lines, None);
            println!("Nota: '{}' era l'ambiente attivo: CROSSPILOT_ENV rimosso.", label);
        }
    }

    println!("Ambiente '{}' eliminato ({} righe rimosse).", label, removed);
    Ok(())
}

// --- use ------------------------------------------------------------------

fn cmd_use(lines: &mut Vec<String>, name: &str) -> Result<()> {
    let name_opt = parse_name_arg(name)?;
    match &name_opt {
        Some(n) => {
            if !env_exists(lines, Some(n)) {
                bail!(
                    "ambiente '{}' non definito nel .env (crearlo con 'env add {}')",
                    n,
                    name
                );
            }
            upsert_selector(lines, Some(n));
            println!("Ambiente attivo: {} (CROSSPILOT_ENV={})", n, n);
        }
        None => {
            upsert_selector(lines, None);
            println!("Ambiente attivo: default (CROSSPILOT_ENV rimosso, chiavi non prefissate)");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_key_campi_non_prefissati() {
        assert_eq!(parse_key("CROSSPILOT_HOST"), ParsedKey::Field(None, "HOST"));
        assert_eq!(parse_key("CROSSPILOT_PORT"), ParsedKey::Field(None, "PORT"));
        assert_eq!(parse_key("CROSSPILOT_EXE_PATH"), ParsedKey::Field(None, "EXE_PATH"));
        assert_eq!(parse_key("CROSSPILOT_CLIENT_PORT"), ParsedKey::Field(None, "CLIENT_PORT"));
        assert_eq!(parse_key("CROSSPILOT_SERVER_PORT"), ParsedKey::Field(None, "SERVER_PORT"));
    }

    #[test]
    fn parse_key_campi_prefissati() {
        assert_eq!(
            parse_key("CROSSPILOT_PROD_HOST"),
            ParsedKey::Field(Some("PROD".to_string()), "HOST")
        );
        // Suffisso longest-first: EU + CLIENT_PORT (non EU_CLIENT + PORT).
        assert_eq!(
            parse_key("CROSSPILOT_EU_CLIENT_PORT"),
            ParsedKey::Field(Some("EU".to_string()), "CLIENT_PORT")
        );
        assert_eq!(
            parse_key("CROSSPILOT_PROD_EXE_PATH"),
            ParsedKey::Field(Some("PROD".to_string()), "EXE_PATH")
        );
    }

    #[test]
    fn parse_key_selettore_e_altro() {
        assert_eq!(parse_key("CROSSPILOT_ENV"), ParsedKey::Selector);
        assert_eq!(parse_key("CROSSPILOT_DEBUG"), ParsedKey::Other);
        assert_eq!(parse_key("PATH"), ParsedKey::Other);
        assert_eq!(parse_key("CROSSPILOT_"), ParsedKey::Other);
    }

    #[test]
    fn validate_name_ok_e_errori() {
        assert_eq!(validate_name("prod").unwrap(), "PROD");
        assert_eq!(validate_name("Prod_Eu2").unwrap(), "PROD_EU2");
        assert!(validate_name("server").is_err());
        assert!(validate_name("client").is_err());
        assert!(validate_name("env").is_err());
        assert!(validate_name("default").is_err());
        assert!(validate_name("prod-eu").is_err());
        assert!(validate_name("").is_err());
        assert_eq!(parse_name_arg("DEFAULT").unwrap(), None);
        assert_eq!(parse_name_arg("prod").unwrap(), Some("PROD".to_string()));
    }

    #[test]
    fn parse_line_gestisce_export_e_quote() {
        assert_eq!(
            parse_line("CROSSPILOT_HOST=1.2.3.4"),
            Some(("CROSSPILOT_HOST".to_string(), "1.2.3.4".to_string()))
        );
        assert_eq!(
            parse_line("export CROSSPILOT_PASS=\"a b\""),
            Some(("CROSSPILOT_PASS".to_string(), "a b".to_string()))
        );
        // Double-quoted: escape \\ -> \ come dotenvy.
        assert_eq!(
            parse_line("CROSSPILOT_EXE_PATH=\"C:\\\\Users\\\\x\""),
            Some(("CROSSPILOT_EXE_PATH".to_string(), "C:\\Users\\x".to_string()))
        );
        // Single-quoted: letterale.
        assert_eq!(
            parse_line("CROSSPILOT_PASS='a\\b'"),
            Some(("CROSSPILOT_PASS".to_string(), "a\\b".to_string()))
        );
        assert_eq!(parse_line("# commento"), None);
        assert_eq!(parse_line(""), None);
    }

    #[test]
    fn parse_line_commento_inline_non_quotato() {
        // Come dotenvy: ` #` apre un commento nei valori non quotati.
        assert_eq!(
            parse_line("CROSSPILOT_PORT=5330   # porta WinRM"),
            Some(("CROSSPILOT_PORT".to_string(), "5330".to_string()))
        );
        // `#` attaccato al valore resta parte del valore.
        assert_eq!(
            parse_line("CROSSPILOT_PASS=abc#def"),
            Some(("CROSSPILOT_PASS".to_string(), "abc#def".to_string()))
        );
        // Valore quotato: `#` letterale.
        assert_eq!(
            parse_line("CROSSPILOT_PASS=\"a # b\""),
            Some(("CROSSPILOT_PASS".to_string(), "a # b".to_string()))
        );
    }

    #[test]
    fn quote_value_solo_quando_necessario() {
        assert_eq!(quote_value("gianca"), "gianca");
        assert_eq!(quote_value("a b"), "\"a b\"");
        assert_eq!(quote_value("C:\\Users\\x"), "\"C:\\\\Users\\\\x\"");
    }

    #[test]
    fn collect_names_e_env_exists() {
        let lines: Vec<String> = vec![
            "# test".to_string(),
            "CROSSPILOT_HOST=127.0.0.1".to_string(),
            "CROSSPILOT_PROD_HOST=10.0.0.1".to_string(),
            "CROSSPILOT_PROD_USER=u".to_string(),
            "CROSSPILOT_STAGING_HOST=10.0.0.2".to_string(),
            "CROSSPILOT_ENV=PROD".to_string(),
        ];
        assert_eq!(collect_names(&lines), vec!["PROD", "STAGING"]);
        assert!(env_exists(&lines, Some("PROD")));
        assert!(env_exists(&lines, None));
        assert!(!env_exists(&lines, Some("DEV")));
        assert_eq!(selector_value(&lines), Some("PROD".to_string()));
    }

    #[test]
    fn upsert_field_replace_in_place_e_append() {
        let mut lines: Vec<String> = vec![
            "CROSSPILOT_HOST=127.0.0.1".to_string(),
            "# env: PROD".to_string(),
            "CROSSPILOT_PROD_HOST=10.0.0.1".to_string(),
        ];
        // Update in place: la posizione (e il commento) restano.
        upsert_field(&mut lines, Some("PROD"), "HOST", "10.0.0.9");
        assert_eq!(lines[2], "CROSSPILOT_PROD_HOST=10.0.0.9");
        assert_eq!(lines.len(), 3);
        // Campo nuovo: append.
        upsert_field(&mut lines, Some("PROD"), "USER", "admin");
        assert_eq!(lines[3], "CROSSPILOT_PROD_USER=admin");
        // Chiave non prefissata (default).
        upsert_field(&mut lines, None, "HOST", "192.168.0.1");
        assert_eq!(lines[0], "CROSSPILOT_HOST=192.168.0.1");
    }

    #[test]
    fn upsert_selector_set_e_remove() {
        let mut lines: Vec<String> = vec!["CROSSPILOT_HOST=1".to_string()];
        upsert_selector(&mut lines, Some("PROD"));
        assert_eq!(lines[1], "CROSSPILOT_ENV=PROD");
        upsert_selector(&mut lines, Some("DEV"));
        assert_eq!(lines[1], "CROSSPILOT_ENV=DEV");
        upsert_selector(&mut lines, None);
        assert_eq!(lines, vec!["CROSSPILOT_HOST=1".to_string()]);
    }

    #[test]
    fn remove_env_lines_solo_env_target() {
        let mut lines: Vec<String> = vec![
            "# default".to_string(),
            "CROSSPILOT_HOST=127.0.0.1".to_string(),
            "# env: PROD".to_string(),
            "CROSSPILOT_PROD_HOST=10.0.0.1".to_string(),
            "CROSSPILOT_PROD_PASS=secret".to_string(),
            "CROSSPILOT_DEV_HOST=10.0.0.2".to_string(),
            "CROSSPILOT_ENV=PROD".to_string(),
        ];
        let removed = remove_env_lines(&mut lines, Some("PROD"));
        // 2 righe campo + commento header `# env: PROD`.
        assert_eq!(removed, 3);
        // Restano: commento default, default, DEV e il selettore
        // (il selettore e' gestito da cmd_remove).
        assert_eq!(lines.len(), 4);
        assert!(!env_exists(&lines, Some("PROD")));
        assert!(env_exists(&lines, Some("DEV")));
        assert!(env_exists(&lines, None));
    }
}
