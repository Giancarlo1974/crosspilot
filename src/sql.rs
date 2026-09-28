// Modulo sql: subcomando `crosspilot sql` — query MySQL read-only.
//
// Port del tool Dart "SafeQuery" (~/progetti/flutter/sql): stesse
// garanzie (solo lettura, niente multi-statement, auto-LIMIT, output
// AI-optimized) ma connessione nativa via mysql_async — niente processo
// esterno, niente runtime Dart.
//
// Configurazione nel .env (caricato da envs::load_dotenv prima del
// dispatch) con chiavi namespaced riservate ai DB:
//
//   CROSSPILOT_DB_<NOME>_HOST=10.1.0.172
//   CROSSPILOT_DB_<NOME>_PORT=3306          # default 3306
//   CROSSPILOT_DB_<NOME>_USER=root          # default root
//   CROSSPILOT_DB_<NOME>_PASSWORD=secret    # default vuota
//   CROSSPILOT_DB_<NOME>_NAME=schema        # schema di default (opz.)
//   CROSSPILOT_DB_<NOME>_SSL=auto           # auto|0|off|1|on|insecure
//
// Il namespace CROSSPILOT_DB_* e' carved-out in envs::parse_key: non
// genera ambienti fantasma e `env` CRUD non lo tocca.
// Fallback globale: ~/.config/crosspilot/.env (letto qui, non-overriding).
//
// La connessione e' DIRETTA dalla macchina locale: nessun server
// crosspilot coinvolto, niente handshake/reconcile. Un DB raggiungibile
// solo dal remote resta coperto da `crosspilot -- mysql -e ...` / `run`.

use anyhow::{bail, Context, Result};
use mysql_async::consts::ColumnType;
use mysql_async::prelude::Queryable;
use mysql_async::{Conn, Opts, OptsBuilder, Row, SslOpts, Value};
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::io::{IsTerminal, Read};
use std::net::IpAddr;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Config: CROSSPILOT_DB_<NOME>_<CAMPO>
// ---------------------------------------------------------------------------

const DB_PREFIX: &str = "CROSSPILOT_DB_";

/// Chiave completa di un campo per un dato DB (nome gia' uppercase).
fn db_key(name: &str, field: &str) -> String {
    format!("{}{}_{}", DB_PREFIX, name, field)
}

/// Carica il .env globale dedicato (non-overriding, stessa semantica di
/// dotenvy gia' usata per il .env principale). Chiamata solo nel path sql:
/// il .env primario e' gia' caricato da envs::load_dotenv in main.
fn load_global_env() {
    let home = env::var_os("HOME").or_else(|| env::var_os("USERPROFILE"));
    if let Some(home) = home {
        let global = PathBuf::from(home).join(".config/crosspilot/.env");
        if global.exists() {
            let _ = dotenvy::from_path(&global);
        }
    }
}

/// Nomi dei DB configurati: ogni CROSSPILOT_DB_<NOME>_HOST in process env
/// (il .env e' gia' caricato) definisce un DB <NOME>.
pub fn list_databases() -> Vec<String> {
    let mut names = BTreeSet::new();
    for (key, _) in env::vars() {
        if let Some(rest) = key.strip_prefix(DB_PREFIX) {
            if let Some(name) = rest.strip_suffix("_HOST") {
                if !name.is_empty() {
                    names.insert(name.to_string());
                }
            }
        }
    }
    names.into_iter().collect()
}

/// Modalita' TLS (campo SSL). Auto = TLS solo su hostname DNS: rustls non
/// accetta un IP come SNI e i DB tipicamente girano su host LAN per IP.
#[derive(Debug, Clone, Copy, PartialEq)]
enum SslMode {
    Auto,
    Disabled,
    Required,
    /// TLS senza validazione del cert (server self-signed su LAN).
    Insecure,
}

struct DbConfig {
    host: String,
    port: u16,
    user: String,
    password: String,
    database: Option<String>,
    ssl: SslMode,
}

fn db_var(name: &str, field: &str) -> Option<String> {
    env::var(db_key(name, field))
        .ok()
        .filter(|v| !v.is_empty())
}

fn resolve_db(name: &str) -> Result<DbConfig> {
    let host = match db_var(name, "HOST") {
        Some(h) => h,
        None => bail!(
            "Database \"{}\" non trovato nella configurazione \
             (manca {} nel .env)",
            name,
            db_key(name, "HOST")
        ),
    };
    let port = db_var(name, "PORT")
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(3306);
    let user = db_var(name, "USER").unwrap_or_else(|| "root".to_string());
    let password = db_var(name, "PASSWORD").unwrap_or_default();
    let database = db_var(name, "NAME");
    let ssl = match db_var(name, "SSL")
        .unwrap_or_else(|| "auto".to_string())
        .to_lowercase()
        .as_str()
    {
        "0" | "off" | "disabled" | "disable" => SslMode::Disabled,
        "1" | "on" | "required" | "require" => SslMode::Required,
        "insecure" => SslMode::Insecure,
        _ => SslMode::Auto,
    };
    Ok(DbConfig {
        host,
        port,
        user,
        password,
        database,
        ssl,
    })
}

fn ssl_opts_for(cfg: &DbConfig) -> Option<SslOpts> {
    match cfg.ssl {
        SslMode::Disabled => None,
        SslMode::Required => Some(SslOpts::default()),
        SslMode::Insecure => Some(
            SslOpts::default()
                .with_danger_skip_domain_validation(true)
                .with_danger_accept_invalid_certs(true),
        ),
        // Auto: TLS solo se l'host e' un nome DNS (gli IP non sono un SNI
        // valido per rustls e i cert MySQL LAN sono tipicamente per nome).
        SslMode::Auto => {
            if cfg.host.parse::<IpAddr>().is_ok() {
                None
            } else {
                Some(SslOpts::default())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Sanitizer (port di query_sanitizer.dart, con fix falsi positivi)
// ---------------------------------------------------------------------------

/// Keyword che indicano operazioni di scrittura/pericolose.
const FORBIDDEN_KEYWORDS: &[&str] = &[
    "insert", "update", "delete", "drop", "truncate", "replace", "alter",
];

/// Limite righe auto-aggiunto ai SELECT senza LIMIT.
const DEFAULT_ROW_LIMIT: usize = 100;

/// Timeout del connect TCP+handshake MySQL (la query non ha timeout).
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Esito del sanitizer.
#[derive(Debug)]
pub struct Sanitized {
    pub query: String,
    /// True se LIMIT 100 e' stato aggiunto automaticamente.
    pub auto_limited: bool,
}

/// Errore di sanitizzazione con prefisso (stderr) ed exit code come il
/// tool Dart: ERROR_SECURITY -> 2, ERROR_SQL -> 1.
#[derive(Debug)]
pub struct SanitizeError {
    pub message: String,
    pub prefix: &'static str,
    pub exit_code: i32,
}

/// Carattere ammesso dentro un identificatore SQL: decide i confini di
/// parola per il match delle keyword (evita falsi positivi tipo
/// `last_update`, `unlimited`, `inserted_at` — bug del tool Dart che
/// usava `contains()` sul substring).
fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '$'
}

/// True se `word` occorre in `text` come parola intera (confini non
/// identificatore). `text` deve essere gia' lowercase e con i letterali
/// sbiancati (vedi blank_literals).
fn contains_word(text: &str, word: &str) -> bool {
    for (i, _) in text.match_indices(word) {
        let before_ok = text[..i]
            .chars()
            .next_back()
            .is_none_or(|c| !is_ident_char(c));
        let after_ok = text[i + word.len()..]
            .chars()
            .next()
            .is_none_or(|c| !is_ident_char(c));
        if before_ok && after_ok {
            return true;
        }
    }
    false
}

/// Copia della query con letterali 'str', "str", `ident` e commenti
/// (--, #, /* */) sbiancati a spazi: i check di sicurezza girano sul
/// testo sbiancato cosi' keyword e ';' dentro stringhe non danno falsi
/// positivi (es. SELECT 'a;b' o colonna `delete`). La query ORIGINALE
/// e' quella inviata al server.
fn blank_literals(q: &str) -> String {
    let mut out = String::with_capacity(q.len());
    let mut it = q.chars().peekable();
    while let Some(c) = it.next() {
        match c {
            '\'' | '"' | '`' => {
                out.push(' ');
                while let Some(n) = it.next() {
                    out.push(' ');
                    if n == '\\' {
                        if it.next().is_some() {
                            out.push(' ');
                        }
                        continue;
                    }
                    if n == c {
                        // ''/""/`` raddoppiati = quote letterale escaped.
                        if it.peek() == Some(&c) {
                            it.next();
                            out.push(' ');
                            continue;
                        }
                        break;
                    }
                }
            }
            '#' => {
                out.push(' ');
                for n in it.by_ref() {
                    out.push(if n == '\n' { '\n' } else { ' ' });
                    if n == '\n' {
                        break;
                    }
                }
            }
            '-' if it.peek() == Some(&'-') => {
                // Commento -- solo se seguito da whitespace (sintassi MySQL).
                out.push(' ');
                it.next();
                out.push(' ');
                match it.peek() {
                    Some(&n) if n.is_whitespace() => {
                        for n in it.by_ref() {
                            out.push(if n == '\n' { '\n' } else { ' ' });
                            if n == '\n' {
                                break;
                            }
                        }
                    }
                    _ => {}
                }
            }
            '/' if it.peek() == Some(&'*') => {
                out.push(' ');
                it.next();
                out.push(' ');
                let mut prev = '\0';
                for n in it.by_ref() {
                    out.push(if n == '\n' { '\n' } else { ' ' });
                    if prev == '*' && n == '/' {
                        break;
                    }
                    prev = n;
                }
            }
            _ => out.push(c),
        }
    }
    out
}

/// Valida la query grezza: solo lettura, statement singolo, auto-LIMIT.
/// Ritorna la query da eseguire (originale, mai la copia sbiancata).
pub fn sanitize_query(raw: &str) -> std::result::Result<Sanitized, SanitizeError> {
    let mut q = raw.trim().to_string();
    if q.ends_with(';') {
        q.pop();
        q = q.trim().to_string();
    }

    let blanked = blank_literals(&q);
    let lower = blanked.to_lowercase();

    for word in FORBIDDEN_KEYWORDS {
        if contains_word(&lower, word) {
            return Err(SanitizeError {
                message: format!("Query non permessa ({})", word.to_uppercase()),
                prefix: "ERROR_SECURITY",
                exit_code: 2,
            });
        }
    }

    // Statement singolo: ';' residuo in mezzo (i ';' nei letterali sono
    // gia' sbiancati) — stesso blocco del tool Dart.
    if blanked.contains(';') {
        return Err(SanitizeError {
            message: "Query multiple non permesse (trovato \";\")".to_string(),
            prefix: "ERROR_SQL",
            exit_code: 1,
        });
    }

    // Auto-LIMIT solo per SELECT (WITH inclusa: le forme UPDATE/DELETE
    // sono comunque interdette dalle keyword sopra).
    if (lower.starts_with("select") || lower.starts_with("with"))
        && !contains_word(&lower, "limit")
    {
        return Ok(Sanitized {
            query: format!("{} LIMIT {}", q, DEFAULT_ROW_LIMIT),
            auto_limited: true,
        });
    }

    Ok(Sanitized {
        query: q,
        auto_limited: false,
    })
}

// ---------------------------------------------------------------------------
// Sanitizzazione celle + renderer AI-optimized (port di query_sanitizer.dart)
// ---------------------------------------------------------------------------

/// Lunghezza max dei campi testo in output.
const MAX_TEXT_LEN: usize = 250;
/// Oltre queste soglie l'output passa da tabella Markdown a CSV.
const MAX_MARKDOWN_ROWS: usize = 20;
const MAX_OUTPUT_CHARS: usize = 2000;

/// Tipi colonna nascosti in output (BLOB/GEOMETRY -> [BINARY_DATA]).
fn is_hidden_type(t: ColumnType) -> bool {
    matches!(
        t,
        ColumnType::MYSQL_TYPE_TINY_BLOB
            | ColumnType::MYSQL_TYPE_MEDIUM_BLOB
            | ColumnType::MYSQL_TYPE_LONG_BLOB
            | ColumnType::MYSQL_TYPE_BLOB
            | ColumnType::MYSQL_TYPE_GEOMETRY
    )
}

/// Value -> stringa grezza (il tipo colonna decide poi se nascondere).
fn value_to_string(v: &Value) -> String {
    match v {
        Value::NULL => "NULL".to_string(),
        Value::Bytes(b) => String::from_utf8_lossy(b).into_owned(),
        Value::Int(i) => i.to_string(),
        Value::UInt(u) => u.to_string(),
        Value::Float(f) => f.to_string(),
        Value::Double(d) => d.to_string(),
        Value::Date(y, mo, d, h, mi, s, micro) => {
            let mut out = format!("{:04}-{:02}-{:02}", y, mo, d);
            if *h != 0 || *mi != 0 || *s != 0 || *micro != 0 {
                out.push_str(&format!(" {:02}:{:02}:{:02}", h, mi, s));
                if *micro != 0 {
                    out.push_str(&format!(".{:06}", micro));
                }
            }
            out
        }
        Value::Time(neg, days, h, mi, s, micro) => {
            let total_h = days * 24 + *h as u32;
            let mut out = format!(
                "{}{:02}:{:02}:{:02}",
                if *neg { "-" } else { "" },
                total_h,
                mi,
                s
            );
            if *micro != 0 {
                out.push_str(&format!(".{:06}", micro));
            }
            out
        }
    }
}

/// Sembra JSON (inizia con { o [) — i valori JSON vengono minificati.
fn looks_like_json(s: &str) -> bool {
    let t = s.trim_start();
    t.starts_with('{') || t.starts_with('[')
}

/// Minifica una stringa JSON senza dipendenze extra: rimuove whitespace
/// fuori dai letterali. Se non e' JSON valido ritorna l'originale.
fn minify_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_str = false;
    let mut escaped = false;
    for c in s.trim().chars() {
        if in_str {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_str = false;
            }
        } else if c == '"' {
            in_str = true;
            out.push(c);
        } else if !c.is_whitespace() {
            out.push(c);
        }
    }
    // Euristica: JSON valido minificato non perde/carica token; se la
    // struttura base non regge (stringa non chiusa) teniamo l'originale.
    if in_str {
        return s.to_string();
    }
    out
}

/// Sanitizza un valore cella per l'output AI:
/// NULL -> "NULL", BLOB/GEOMETRY -> "[BINARY_DATA]", JSON minificato,
/// newline -> spazio, testi lunghi troncati a MAX_TEXT_LEN.
fn sanitize_cell(v: &Value, col_type: ColumnType) -> String {
    if matches!(v, Value::NULL) {
        return "NULL".to_string();
    }
    if is_hidden_type(col_type) {
        return "[BINARY_DATA]".to_string();
    }
    let mut s = value_to_string(v);
    if looks_like_json(&s) {
        s = minify_json(&s);
    }
    s = s.replace("\r\n", " ").replace(['\n', '\r'], " ");
    if s.chars().count() > MAX_TEXT_LEN {
        let truncated: String = s.chars().take(MAX_TEXT_LEN - 3).collect();
        return format!("{}...", truncated);
    }
    s
}

/// Escape CSV (quote se contiene virgola, virgolette o newline).
fn csv_escape(v: &str) -> String {
    if v.contains(',') || v.contains('"') || v.contains('\n') {
        format!("\"{}\"", v.replace('"', "\"\""))
    } else {
        v.to_string()
    }
}

fn build_markdown(keys: &[String], rows: &[Vec<String>]) -> String {
    let mut out = String::new();
    out.push_str("| ");
    out.push_str(&keys.join(" | "));
    out.push_str(" |\n| ");
    out.push_str(
        &keys
            .iter()
            .map(|_| "---")
            .collect::<Vec<_>>()
            .join(" | "),
    );
    out.push_str(" |\n");
    for row in rows {
        out.push_str("| ");
        out.push_str(&row.join(" | "));
        out.push_str(" |\n");
    }
    out.trim_end().to_string()
}

fn build_csv(keys: &[String], rows: &[Vec<String>]) -> String {
    let mut out = String::new();
    out.push_str(&keys.join(","));
    out.push('\n');
    for row in rows {
        out.push_str(
            &row.iter()
                .map(|v| csv_escape(v))
                .collect::<Vec<_>>()
                .join(","),
        );
        out.push('\n');
    }
    out.trim_end().to_string()
}

/// Output AI-optimized (stessa euristica del tool Dart):
/// A) 1 riga, 1 colonna -> scalare; B) 1 colonna -> CSV-like comma-sep;
/// C) <=20 righe e <=2000 char -> Markdown; D) altrimenti CSV.
pub fn render_ai_output(keys: &[String], rows: &[Vec<String>]) -> String {
    if rows.is_empty() {
        return String::new();
    }
    let num_cols = keys.len();
    let num_rows = rows.len();

    if num_rows == 1 && num_cols == 1 {
        return rows[0][0].clone();
    }
    if num_cols == 1 {
        return rows
            .iter()
            .map(|r| r[0].as_str())
            .collect::<Vec<_>>()
            .join(", ");
    }

    let markdown = build_markdown(keys, rows);
    if num_rows <= MAX_MARKDOWN_ROWS && markdown.len() <= MAX_OUTPUT_CHARS {
        return markdown;
    }
    build_csv(keys, rows)
}

/// Errore su stderr con prefisso standardizzato (compat tool Dart).
fn format_error(prefix: &str, message: &str) -> String {
    format!("[{}]: {}", prefix, message)
}

// ---------------------------------------------------------------------------
// Entry point del subcomando
// ---------------------------------------------------------------------------

/// Stampa la lista dei DB configurati (no args / errore di uso).
fn print_databases() {
    let dbs = list_databases();
    if dbs.is_empty() {
        println!("Nessun database configurato.");
        println!("Aggiungi nel .env: CROSSPILOT_DB_<NOME>_HOST=... (vedi sql.rs / AGENTS.md)");
    } else {
        println!("Database disponibili:");
        for d in dbs {
            println!("  {}", d);
        }
    }
}

/// Legge la query dalla sorgente: file, "-" per stdin, -e per inline.
fn read_query(source: Option<&str>, exec: Option<&str>) -> Result<(String, Option<PathBuf>)> {
    if let Some(q) = exec {
        return Ok((q.to_string(), None));
    }
    match source {
        Some("-") | None => {
            // Source omessa: stdin solo se piped (su TTY sarebbe un hang).
            if source.is_none() && std::io::stdin().is_terminal() {
                bail!(
                    "nessuna query: passa un file .sql, -e '<query>', oppure '-' / pipe su stdin"
                );
            }
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .context("lettura query da stdin")?;
            Ok((buf, None))
        }
        Some(path) => {
            let content = fs::read_to_string(path)
                .with_context(|| format!("Impossibile leggere il file: {}", path))?;
            Ok((content, Some(PathBuf::from(path))))
        }
    }
}

/// Entry point `crosspilot sql [DB] [SOURCE|-] [-e QUERY]`.
/// Connessione diretta MySQL dalla macchina locale: nessun contatto col
/// server crosspilot remoto.
pub async fn run(db: Option<&str>, source: Option<&str>, exec: Option<&str>) -> Result<()> {
    load_global_env();

    let db = match db {
        Some(d) => d.to_uppercase(),
        None => {
            // `crosspilot sql` senza argomenti = lista dei DB configurati;
            // ma con una query senza DB (-e/file) e' un errore d'uso:
            // la query verrebbe silenziosamente ignorata.
            if source.is_some() || exec.is_some() {
                eprintln!(
                    "{}",
                    format_error("ERROR_SQL", "manca il nome del DB (es. crosspilot sql NEXTCLOUD -e '...')")
                );
                std::process::exit(1);
            }
            print_databases();
            return Ok(());
        }
    };

    let (raw, src_file) = match read_query(source, exec) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{}", format_error("ERROR_SQL", &format!("{:#}", e)));
            std::process::exit(1);
        }
    };

    let sanitized = match sanitize_query(&raw) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{}", format_error(e.prefix, &e.message));
            std::process::exit(e.exit_code);
        }
    };

    let cfg = match resolve_db(&db) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}", format_error("ERROR_SQL", &format!("{:#}", e)));
            std::process::exit(1);
        }
    };

    let mut builder = OptsBuilder::default()
        .ip_or_hostname(cfg.host.clone())
        .tcp_port(cfg.port)
        .user(Some(cfg.user.clone()))
        .pass(Some(cfg.password.clone()))
        .ssl_opts(ssl_opts_for(&cfg));
    if let Some(name) = &cfg.database {
        builder = builder.db_name(Some(name.clone()));
    }

    crate::qprintln!(
        "[DEBUG] sql: {} -> {}:{} (db={:?}, ssl={:?})",
        db,
        cfg.host,
        cfg.port,
        cfg.database,
        cfg.ssl
    );

    // mysql_async non espone un connect timeout: un host irraggiungibile
    // resterebbe appeso al SYN. Wrappiamo il connect in un timeout fisso
    // (la query invece no: un SELECT lento e' legittimo).
    let result = async {
        let mut conn = tokio::time::timeout(CONNECT_TIMEOUT, Conn::new(Opts::from(builder)))
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "timeout connessione a {}:{} ({}s)",
                    cfg.host,
                    cfg.port,
                    CONNECT_TIMEOUT.as_secs()
                )
            })??;
        let rows: Vec<Row> = conn.query(sanitized.query.as_str()).await?;
        conn.disconnect().await?;
        Ok::<_, anyhow::Error>(rows)
    }
    .await;

    let rows = match result {
        Ok(r) => r,
        Err(e) => {
            // La chain anyhow di mysql_async ripete l'io error ad ogni
            // livello ("Input/output error: ...: Connection refused"):
            // si stampa la FOGLIA (la causa piu' profonda), non {:#}.
            let mut msg = e.to_string();
            let mut cur: &dyn std::error::Error = e.as_ref();
            while let Some(src) = cur.source() {
                msg = src.to_string();
                cur = src;
            }
            eprintln!("{}", format_error("ERROR_SQL", &msg));
            std::process::exit(1);
        }
    };

    let keys: Vec<String> = rows
        .first()
        .map(|r| {
            r.columns_ref()
                .iter()
                .map(|c| c.name_str().into_owned())
                .collect()
        })
        .unwrap_or_default();
    let col_types: Vec<ColumnType> = rows
        .first()
        .map(|r| r.columns_ref().iter().map(|c| c.column_type()).collect())
        .unwrap_or_default();

    let table: Vec<Vec<String>> = rows
        .iter()
        .map(|r| {
            let values = r.clone().unwrap();
            values
                .iter()
                .enumerate()
                .map(|(i, v)| {
                    sanitize_cell(
                        v,
                        col_types.get(i).copied().unwrap_or(ColumnType::MYSQL_TYPE_STRING),
                    )
                })
                .collect()
        })
        .collect();

    let output = render_ai_output(&keys, &table);
    let truncated = sanitized.auto_limited && table.len() >= DEFAULT_ROW_LIMIT;

    // Parita' col tool Dart: risultato troncato da auto-LIMIT su input da
    // file -> l'output completo va in <file>.out e stdout riporta il path.
    // Su -e/stdin non c'e' un file sorgente: stdout + warning su stderr.
    if truncated {
        if let Some(path) = &src_file {
            let out_path = PathBuf::from(format!("{}.out", path.display()));
            fs::write(&out_path, &output)
                .with_context(|| format!("scrittura {}", out_path.display()))?;
            println!("Output salvato in: {}", out_path.display());
        } else {
            println!("{}", output);
            eprintln!(
                "[WARN] auto-LIMIT {} raggiunto: il risultato e' probabilmente troncato",
                DEFAULT_ROW_LIMIT
            );
        }
    } else {
        println!("{}", output);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(q: &str) -> Sanitized {
        sanitize_query(q).expect("query dovrebbe passare")
    }
    fn err(q: &str) -> SanitizeError {
        sanitize_query(q).expect_err("query dovrebbe fallire")
    }

    #[test]
    fn select_semplice_passa_con_auto_limit() {
        let s = ok("SELECT * FROM utenti");
        assert!(s.auto_limited);
        assert_eq!(s.query, "SELECT * FROM utenti LIMIT 100");
    }

    #[test]
    fn select_con_limit_non_modificata() {
        let s = ok("select * from t limit 5;");
        assert!(!s.auto_limited);
        assert_eq!(s.query, "select * from t limit 5");
    }

    #[test]
    fn scritture_bloccate() {
        for q in [
            "INSERT INTO t VALUES (1)",
            "update t set a=1",
            "DELETE FROM t",
            "DROP TABLE t",
            "TRUNCATE t",
            "REPLACE INTO t VALUES (1)",
            "ALTER TABLE t ADD c int",
        ] {
            let e = err(q);
            assert_eq!(e.prefix, "ERROR_SECURITY");
            assert_eq!(e.exit_code, 2);
        }
    }

    #[test]
    fn keyword_dentro_identificatori_non_blocca() {
        // Falsi positivi del tool Dart (contains su substring).
        assert!(ok("SELECT last_update, inserted_at FROM t").auto_limited);
        assert!(ok("SELECT unlimited FROM t LIMIT 1").query.contains("unlimited"));
    }

    #[test]
    fn keyword_dentro_stringhe_non_blocca() {
        let s = ok("SELECT 'drop table x' AS nota");
        assert!(s.query.contains("'drop table x'"));
    }

    #[test]
    fn semicolon_in_stringa_ok_in_mezzo_no() {
        assert!(ok("SELECT 'a;b'").auto_limited);
        let e = err("SELECT 1; SELECT 2");
        assert_eq!(e.prefix, "ERROR_SQL");
        assert_eq!(e.exit_code, 1);
    }

    #[test]
    fn commenti_non_bloccano() {
        assert!(ok("SELECT 1 -- delete i vecchi").auto_limited);
        assert!(ok("SELECT 1 # drop everything\n").auto_limited);
        assert!(ok("SELECT /* update: no */ 1").auto_limited);
    }

    #[test]
    fn show_e_describe_passano_senza_limit() {
        assert!(!ok("SHOW TABLES").auto_limited);
        assert!(!ok("DESCRIBE t").auto_limited);
    }

    #[test]
    fn blank_literals_preserva_newline_e_lunghezza() {
        let b = blank_literals("SELECT 'a\nb' -- x\nFROM t");
        assert!(b.contains('\n'));
        assert_eq!(b.len(), "SELECT 'a\nb' -- x\nFROM t".len());
    }

    #[test]
    fn render_scalare() {
        let out = render_ai_output(&["n".to_string()], &[vec!["42".to_string()]]);
        assert_eq!(out, "42");
    }

    #[test]
    fn render_colonna_singola() {
        let out = render_ai_output(
            &["name".to_string()],
            &[vec!["a".to_string()], vec!["b".to_string()]],
        );
        assert_eq!(out, "a, b");
    }

    #[test]
    fn render_markdown_piccolo() {
        let out = render_ai_output(
            &["id".to_string(), "name".to_string()],
            &[vec!["1".to_string(), "x".to_string()]],
        );
        assert!(out.starts_with("| id | name |"));
        assert!(out.contains("| 1 | x |"));
    }

    #[test]
    fn render_csv_oltre_soglia() {
        let keys = vec!["a".to_string(), "b".to_string()];
        let rows: Vec<Vec<String>> = (0..25)
            .map(|i| vec![i.to_string(), "v".to_string()])
            .collect();
        let out = render_ai_output(&keys, &rows);
        assert!(out.starts_with("a,b\n0,v"));
    }

    #[test]
    fn sanitize_cell_null_blob_truncate() {
        assert_eq!(sanitize_cell(&Value::NULL, ColumnType::MYSQL_TYPE_STRING), "NULL");
        assert_eq!(
            sanitize_cell(&Value::Bytes(vec![1, 2, 3]), ColumnType::MYSQL_TYPE_BLOB),
            "[BINARY_DATA]"
        );
        let long = Value::Bytes(vec![b'x'; 300]);
        let s = sanitize_cell(&long, ColumnType::MYSQL_TYPE_VAR_STRING);
        assert_eq!(s.chars().count(), MAX_TEXT_LEN);
        assert!(s.ends_with("..."));
    }

    #[test]
    fn sanitize_cell_json_minificato_e_newline() {
        let v = Value::Bytes(b"{ \"a\": 1,\n \"b\": 2 }".to_vec());
        let s = sanitize_cell(&v, ColumnType::MYSQL_TYPE_VAR_STRING);
        assert_eq!(s, "{\"a\":1,\"b\":2}");
        let v2 = Value::Bytes("riga1\nriga2".as_bytes().to_vec());
        assert_eq!(sanitize_cell(&v2, ColumnType::MYSQL_TYPE_VARCHAR), "riga1 riga2");
    }

    #[test]
    fn value_to_string_date_time() {
        assert_eq!(
            value_to_string(&Value::Date(2024, 1, 2, 0, 0, 0, 0)),
            "2024-01-02"
        );
        assert_eq!(
            value_to_string(&Value::Date(2024, 1, 2, 3, 4, 5, 0)),
            "2024-01-02 03:04:05"
        );
        assert_eq!(
            value_to_string(&Value::Time(false, 1, 2, 3, 4, 0)),
            "26:03:04"
        );
        assert_eq!(
            value_to_string(&Value::Time(true, 0, 1, 0, 0, 500)),
            "-01:00:00.000500"
        );
    }

    #[test]
    fn csv_escape_quote_e_virgole() {
        assert_eq!(csv_escape("a,b"), "\"a,b\"");
        assert_eq!(csv_escape("d\"x"), "\"d\"\"x\"");
        assert_eq!(csv_escape("plain"), "plain");
    }
}
