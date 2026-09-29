use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::io::ErrorKind;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command;
use tokio::sync::Notify;
// Solo nel path Windows (retry loop AddrInUse in server_mode).
#[cfg(target_os = "windows")]
use std::time::Instant;

// Moduli del transfer file (vedi docs/transfer-spec.md).
mod path;
mod proto;
mod verify;
// transfer.rs resta invariato rispetto alla spec (§12): i warning clippy
// di stile si silenziano qui invece di toccare il file.
#[allow(clippy::manual_range_contains, clippy::manual_div_ceil)]
mod transfer;
// Modulo directory sync (vedi docs/sync-spec.md).
mod sync;
// Download ricorsivo di directory remote (`get` dir-aware, pull.rs).
mod pull;
// File .crosspilotignore nel source (pattern di esclusione automatici).
mod sync_ignore;
// Handler server per sync (separato da sync.rs per dimensione, best-practice < 1000 righe).
mod sync_server;
// Modulo bootstrap: selezione canale (prescan+candidati) + path WinRM
// (separato da main.rs per dimensione, best-practice < 1000 righe).
mod bootstrap;
// Prescan TCP delle porte management + lista candidati ordinata
// (docs/ssh-unified-prescan-bootstrap-spec.md §2).
mod bootstrap_prescan;
// Trasporto SSH unificato su russh+russh-sftp (spec §1.3).
mod ssh_transport;
// Bootstrap via SSH unificato (remote unix E Windows — dialetti in
// bootstrap_ssh_cmds, spec §1.4).
mod bootstrap_ssh;
mod bootstrap_ssh_cmds;
// Bootstrap via SMB/SCM per remote Windows senza WinRM
// (docs/smb-scm-bootstrap-spec.md; deploy separato per dimensione).
mod bootstrap_smb;
mod bootstrap_smb_deploy;
mod deploy;
// Modulo ambienti host multipli nel .env (CRUD via sottocomando `env`).
mod envs;
// Metadati di build (BUILD_TS, TARGET) + parsing .ver per l'auto-update.
mod version;
// Self-update del client Linux quando il remote e' piu' nuovo.
mod self_update;
// Self-describe del server (INFO_REQ/RES) + identita' remota risolta
// (spec selfdescribe-guardrail §2-§4).
mod server_info;
// Auto-update bidirezionale via TCP (READY <ts> + UPDATE_REQ + updater).
mod update;
// TLS 1.3 post-quantum sul canale TCP (spec docs/tls-pq-spec.md):
// Link unificato plaintext/TLS, cert rcgen, pinning TOFU, AUTH.
mod tls;
// Gate dell'output diagnostico per il flag globale -q/--quiet (log.rs).
mod log;
// Costruzione command-line remota: quoting POSIX, tmp path di `run`,
// marker exit-code (runcmd.rs).
mod runcmd;
// Subcomando `sql`: query MySQL read-only su DB configurati via
// CROSSPILOT_DB_<NOME>_* (connessione diretta locale, sql.rs).
mod sql;

#[cfg(target_os = "windows")]
mod win_job {
    use anyhow::Result;
    use std::mem;
    use std::ptr;
    use winapi::um::jobapi2::{
        AssignProcessToJobObject, CreateJobObjectW, SetInformationJobObject,
    };
    use winapi::um::winnt::{
        JobObjectExtendedLimitInformation, HANDLE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };

    // Returns the Job Handle. The Job Object is closed when the handle is dropped (if not leaked),
    // but we want it to persist until we drop it or the process ends.
    // Actually, if we drop the handle, and LIMIT_KILL_ON_JOB_CLOSE is set, the process dies?
    // Yes, "If the job has the JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE flag, closing the last handle to the job object terminates all processes associated with the job."
    // So we need to keep this handle alive as long as the child is alive.
    pub struct JobHandle(HANDLE);

    // Send/Sync for Arc? HANDLE is raw pointer basically.
    unsafe impl Send for JobHandle {}
    unsafe impl Sync for JobHandle {}

    impl Drop for JobHandle {
        fn drop(&mut self) {
            unsafe {
                winapi::um::handleapi::CloseHandle(self.0);
            }
        }
    }

    pub fn assign_to_new_job(process_handle: std::os::windows::io::RawHandle) -> Result<JobHandle> {
        unsafe {
            let job = CreateJobObjectW(ptr::null_mut(), ptr::null());
            if job.is_null() {
                return Err(anyhow::anyhow!("Failed to create job object"));
            }

            let handle_wrapper = JobHandle(job);

            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

            let ret = SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &mut info as *mut _ as *mut _,
                mem::size_of_val(&info) as u32,
            );

            if ret == 0 {
                return Err(anyhow::anyhow!("Failed to set job info"));
            }

            let ret = AssignProcessToJobObject(job, process_handle as HANDLE);
            if ret == 0 {
                return Err(anyhow::anyhow!("Failed to assign process to job"));
            }

            Ok(handle_wrapper)
        }
    }
}

#[derive(Parser)]
#[command(name = "crosspilot")]
// NOTA: niente flag clap `version`: il positional raw_cmd ha
// allow_hyphen_values e catturerebbe `--version` come comando remoto.
// --version/-V e' gestito manualmente in main() prima di Cli::parse()
// (stampa "<semver>+<build_ts> (<target>)", usato come functional check
// da deploy staged e self-update).
#[command(about = "Bridge to execute commands on CrossPilot container via TCP")]
#[command(
    long_about = "CrossPilot - Remote Command Executor for Windows Containers\n\n\
    This tool allows you to execute commands on a Windows container from Linux.\n\
    It operates in two modes: Server (runs on Windows) and Client (runs on Linux).\n\n\
    Configuration via Environment Variables:\n\
      CROSSPILOT_EXE_PATH      - Path to crosspilot.exe on Windows\n\
      CROSSPILOT_HOST          - WinRM host (default: 127.0.0.1)\n\
      CROSSPILOT_PORT          - WinRM port (default: 47320)\n\
      CROSSPILOT_USER          - WinRM username\n\
      CROSSPILOT_PASS          - WinRM password\n\
      CROSSPILOT_LOG_PATH      - Server log output path (default: C:\\\\Users\\\\gianca\\\\server.log)\n\
      CROSSPILOT_ERR_PATH      - Server error output path (default: C:\\\\Users\\\\gianca\\\\server.err)\n\
      CROSSPILOT_SERVER_PORT   - Server listening port (default: 5330)\n\
      CROSSPILOT_CLIENT_PORT   - Client connection port (default: 47330)\n\
      CROSSPILOT_ENV           - Active environment name (see below)\n\n\
    Multiple environments: the .env can hold N named host configs as\n\
      CROSSPILOT_<NAME>_<FIELD> (e.g. CROSSPILOT_PROD_HOST). CROSSPILOT_ENV selects\n\
      the active one; unprefixed keys are the fallback for missing fields.\n\
      Fields: HOST PORT USER PASS EXE_PATH CLIENT_PORT SERVER_PORT\n\
      LOG_PATH ERR_PATH SEGMENT_SIZE OS SSH_HOST SSH_PORT SSH_USER\n\
      BOOTSTRAP (=smb: SMB/SCM channel for Windows remotes without WinRM).\n\
      Manage them with: crosspilot env list|show|add|set|remove|use\n\
      (details: crosspilot env -h / crosspilot env <action> -h)\n\n\
    Usage:\n\
      crosspilot -- <COMMAND>   Execute a command on the remote Windows server\n\
      crosspilot --server       Run in server mode (Windows side)\n\
      crosspilot put|get|status|sync  File transfer and directory sync\n\
      crosspilot quit           Shut down the remote server\n\
      crosspilot --ephemeral -- <CMD>  Run, then server self-shuts down (agentless)\n\n\
    The -- form passes the tokens to cmd.exe on the remote Windows host.\n\
    Tokens containing spaces are auto-wrapped in double quotes — single\n\
    quotes are NOT grouping for cmd.exe: crosspilot -- dir 'D:\\a b'\n\
    Inside powershell -Command use SINGLE quotes for remote paths (double\n\
    quotes are lost in PowerShell's -Command rejoin). For complex scripts\n\
    prefer: crosspilot run script.ps1  or  powershell -EncodedCommand."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Run as server (listens for incoming commands)
    #[arg(
        long,
        help = "Run in server mode - listens for incoming command requests"
    )]
    server: bool,

    /// Esecuzione effimera ("agentless"): al termine dell'operazione il
    /// server remoto si spegne da solo.
    ///
    /// Con la forma `--` il vincolo e' atomico: il client invia il
    /// prefisso di protocollo QUIT_AFTER_PREFIX e il server si auto-
    /// spegne a fine comando a QUALUNQUE esito — anche se il client si
    /// interrompe a meta' (l'agente non resta mai appeso). Con i
    /// sottocomandi framed (put/get/status/sync) il client invia `quit`
    /// su connessione fresca dopo l'operazione.
    ///
    /// Senza altri argomenti equivale a `crosspilot quit`: solo
    /// spegnimento, nessuna operazione eseguita.
    ///
    ///   crosspilot --ephemeral -- make test
    ///   crosspilot --ephemeral sync ./dist C:\\ci\\dist
    ///   crosspilot --ephemeral            # == crosspilot quit
    #[arg(
        long,
        global = true,
        help = "Shut down the remote server when the operation completes (ephemeral/agentless mode; alone = quit only)"
    )]
    ephemeral: bool,

    /// Diagnostica minima su stderr: E' GIA' IL DEFAULT. Il flag resta per
    /// compat con script/CI scritti quando il default era verbose —
    /// esplicitarlo forza quiet anche in combinazione con -v.
    /// Warning ed errori restano sempre visibili; stdout e' invariato.
    #[arg(
        short = 'q',
        long,
        global = true,
        help = "Quiet: suppress debug/progress diagnostics on stderr (already the default)"
    )]
    quiet: bool,

    /// Riabilita l'output diagnostico su stderr ([DEBUG], progressi e
    /// messaggi di connessione), soppresso di default (v. log.rs).
    /// Warning ed errori sono comunque sempre visibili.
    #[arg(
        short = 'v',
        long,
        global = true,
        help = "Verbose: show debug/progress diagnostics on stderr (suppressed by default)"
    )]
    verbose: bool,

    /// Write-back nel .env delle chiavi divergenti dall'identita' remota
    /// (spec selfdescribe-guardrail §4): senza questo flag il drift
    /// OS/EXE_PATH e' solo segnalato. Equivalente a CROSSPILOT_FIX_ENV=1.
    #[arg(
        long,
        global = true,
        help = "Write remote-discovered OS/EXE_PATH back to .env when they drift (opt-in)"
    )]
    fix_env: bool,

    /// Comando da eseguire sul server remoto.
    ///
    /// Tutto ciò che segue `--` viene preso letteralmente. Su remote UNIX
    /// i token sono ri-quotati stile POSIX (il raggruppamento fatto dalla
    /// shell locale sopravvive: `crosspilot -- sh -c "sleep 8; docker ps"`
    /// funziona). Su remote Windows i token con spazi sono ri-quotati coi
    /// doppi apici (i single quote NON raggruppano per cmd.exe); dentro
    /// `powershell -Command` usare single quote per i path remoti — i
    /// doppi apici vanno persi nel re-join di PowerShell. Per script
    /// complessi: `crosspilot run file.ps1` o `powershell -EncodedCommand`.
    ///
    /// Esempi:
    ///   crosspilot -- dir 'c:\\'
    ///   crosspilot -- dir 'D:\\Progetti\\DELPHI SORGENTI'
    ///   crosspilot -- sh -c "sleep 8; docker ps"
    ///   crosspilot -- docker ps --format '{{.Names}} {{.Status}}'
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        num_args = 1..,
        value_name = "COMMAND",
        help = "Command to execute on the remote server (use -- to pass it)"
    )]
    raw_cmd: Vec<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the server (explicit subcommand)
    Server {
        /// Port to listen on (can also be set via CROSSPILOT_SERVER_PORT env var)
        #[arg(
            short,
            long,
            default_value = "5330",
            help = "TCP port for server to listen on"
        )]
        port: u16,
    },
    /// Upload (put) di un file locale verso il server remoto (transfer delta stile rsync).
    Put {
        /// Path sorgente locale (Linux).
        local_src: String,
        /// Path destinazione remoto (Windows, es. C:\ci\app.exe).
        remote_dst: String,
        /// Dopo l'upload rende il file eseguibile sul remote (chmod a+x;
        /// solo remote unix — su Windows e' un no-op con warning).
        #[arg(long)]
        exec: bool,
    },
    /// Download (get) di un file O directory remota verso un path locale
    /// (transfer delta stile rsync; le directory sono scaricate
    /// ricorsivamente: local_dst diventa il mirror del contenuto remoto).
    Get {
        /// Path sorgente remoto (Windows, es. C:\ci\log.txt o C:\dir).
        remote_src: String,
        /// Path destinazione locale (file o directory specchio).
        local_dst: String,
    },
    /// Diff read-only tra directory locale e remota (vedi docs/sync-spec.md).
    Status {
        /// Directory locale (Linux). Deve esistere.
        local_dir: String,
        /// Directory remota (Windows, path assoluto).
        remote_dir: String,
        /// Confronta via SHA-256 invece di size (accurato, rileva corruzione).
        #[arg(long)]
        checksum: bool,
        /// Output minimo (solo riepilogo numerico su stderr, per CI).
        #[arg(long)]
        quiet: bool,
        /// Esclude i path che matchano il pattern glob (ripetibile:
        /// --exclude 'data/postgres' --exclude '*.log'). Un path escluso
        /// non e' ne' confrontato ne' candidato a sync/delete.
        /// Si aggiunge al file .crosspilotignore del source (stesso
        /// formato, un pattern per riga, '#' commenti) caricato sempre.
        #[arg(long)]
        exclude: Vec<String>,
    },
    /// Mirror one-way upload (Linux -> remoto) della directory.
    /// Accetta anche un FILE singolo come sorgente (dispatch interno a put):
    /// in quel caso remote_dir puo' essere una directory (esistente o con
    /// '/' finale -> dir/basename) oppure il path file completo di
    /// destinazione — semantica rsync, rename incluso.
    /// Directory remote non leggibili: warning + continua (non abortisce);
    /// in quel caso --delete viene sospeso per sicurezza.
    Sync {
        /// Directory sorgente locale (Linux) oppure file singolo.
        /// Se contiene .crosspilotignore, i suoi pattern glob (uno per
        /// riga, '#' commenti) sono esclusi automaticamente.
        local_dir: String,
        /// Directory destinazione remota (path assoluto). Con sorgente
        /// FILE: directory esistente/'/' finale -> <dir>/<basename>,
        /// altrimenti path file di destinazione.
        remote_dir: String,
        /// Cancella su dest i file/directory non presenti nel source (default OFF).
        #[arg(long)]
        delete: bool,
        /// Mostra cosa farebbe senza eseguire (nessun file scritto/cancellato).
        #[arg(long)]
        dry_run: bool,
        /// Confronta via SHA-256 invece di size (accurato, rileva corruzione).
        #[arg(long)]
        checksum: bool,
        /// Output minimo (solo riepilogo numerico su stderr, per CI).
        #[arg(long)]
        quiet: bool,
        /// Esclude i path che matchano il pattern glob (ripetibile).
        #[arg(long)]
        exclude: Vec<String>,
    },
    /// Spegne il server remoto senza eseguire altro: invia `quit` su una
    /// connessione shell-mode. Equivale a `crosspilot --ephemeral` senza
    /// comando e a `crosspilot -- quit`.
    #[command(visible_alias = "shutdown", alias = "stop")]
    Quit,
    /// Esegue uno script locale sul remote: upload in tmp + esecuzione +
    /// cleanup, in una sola operazione ("agentless" per script).
    ///
    /// Su remote unix: script con shebang -> chmod +x ed esecuzione diretta
    /// (l'interprete dichiarato dallo script e' rispettato); senza shebang
    /// -> `sh`. Su remote Windows: .ps1 -> powershell, altro -> cmd /c call.
    /// L'exit code dello script diventa l'exit code di crosspilot.
    Run {
        /// Script locale da eseguire (.sh, .ps1, .bat, ...).
        script: String,
        /// Argomenti passati allo script remoto.
        args: Vec<String>,
    },
    /// (interno) Updater staged: attende la morte del server, fa lo swap
    /// exe -> exe.old / staged -> exe, poi rilancia `exe --server`.
    /// Lanciato detached dal server (MSG_UPDATE_REQ) o via schtasks/setsid
    /// (server legacy). Non e' pensato per l'uso diretto.
    #[command(hide = true)]
    Update {
        /// Path dell'exe da sostituire (default: crosspilot[.exe] nella dir dello staged)
        #[arg(long)]
        target: Option<String>,
        /// PID del server da attendere prima dello swap
        #[arg(long)]
        wait_pid: Option<u32>,
        /// Porta TCP del server da attendere libera (fallback senza pid)
        #[arg(long)]
        port: Option<u16>,
        /// Timeout attesa morte server (secondi)
        #[arg(long, default_value = "60")]
        wait_secs: u64,
        /// Argomento con cui rilanciare l'exe dopo lo swap (ripetibile;
        /// default: --server). Il self-update client Windows rilancia argv.
        #[arg(long = "arg")]
        relaunch_args: Vec<String>,
        /// Su Windows rilancia l'exe con una console nuova (output visibile)
        #[arg(long)]
        console: bool,
    },
    /// Interroga un database MySQL configurato nel .env come
    /// CROSSPILOT_DB_<NOME>_{HOST,PORT,USER,PASSWORD,NAME,SSL}.
    /// Connessione diretta dalla macchina locale (nessun server remoto);
    /// solo query di lettura: keyword di scrittura e multi-statement
    /// rifiutate, LIMIT 100 auto-aggiunto ai SELECT senza limite.
    ///
    ///   crosspilot sql                          # elenca i DB configurati
    ///   crosspilot sql NEXTCLOUD query.sql      # query da file
    ///   crosspilot sql NEXTCLOUD -e "select 1"  # query inline
    ///   cat q.sql | crosspilot sql NEXTCLOUD -  # query da stdin
    Sql {
        /// Nome del DB (case-insensitive). Omesso -> lista dei configurati.
        db: Option<String>,
        /// File .sql con la query, oppure '-' per stdin. Omesso con stdin
        /// in pipe -> lettura da stdin.
        source: Option<String>,
        /// Query inline (alternativa a file/stdin).
        #[arg(short = 'e', long = "exec", value_name = "QUERY")]
        exec: Option<String>,
    },
    /// Gestione degli ambienti (configurazioni host) nel file .env.
    ///
    /// Il .env può contenere N ambienti come CROSSPILOT_<NOME>_<CAMPO>
    /// (es. CROSSPILOT_PROD_HOST). CROSSPILOT_ENV seleziona l'ambiente attivo;
    /// le chiavi non prefissate (ambiente "default") fanno da fallback.
    Env {
        // Box: EnvAction (con EnvFields) e' la variante piu' grande di
        // Commands — senza indirection clippy segnala large_enum_variant.
        #[command(subcommand)]
        action: Box<envs::EnvAction>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // --version/-V gestito PRIMA di clap e del caricamento .env:
    // 1. raw_cmd (allow_hyphen_values) catturerebbe il flag come comando
    //    remoto e lo manderebbe a cmd.exe ("--version is not recognized");
    // 2. deve essere veloce e side-effect-free: e' il functional check
    //    invocato da deploy staged (remoto) e self_update (locale) per
    //    provare che un binario appena scritto esegue e riporta il
    //    build_ts atteso.
    {
        let mut argv = std::env::args();
        let _ = argv.next();
        let first = argv.next();
        let rest = argv.next();
        if matches!(first.as_deref(), Some("--version" | "-V")) && rest.is_none() {
            println!("crosspilot {}", version::VERSION_STR);
            return Ok(());
        }
    }

    // Parse CLI + setup quiet PRIMA di sweep/dotenv/debug-ambiente:
    // quiet e' ATTIVO di default (i diagnostici qprintln! sono opt-in
    // via -v/--verbose); il parse anticipato permette a -v di mostrare
    // anche i [DEBUG] emessi durante l'avvio (sweep, .env, ambiente).
    // -q resta accettato per compat e forza quiet anche in presenza di -v.
    let cli = Cli::parse();
    log::set_quiet(cli.quiet || !cli.verbose);
    // -q ESPLICITO: l'auto-verbose dell'auto-update non deve mai
    // scavalcarlo (contratto machine-readable per script/CI).
    log::set_quiet_forced(cli.quiet);
    // Write-back .env opt-in per il drift identita' remota (spec §4).
    if cli.fix_env {
        envs::set_fix_env(true);
    }

    // Igiene d'avvio: se questo exe ha il nome canonico (crosspilot[.exe])
    // spazza gli artefatti staged/residui dell'auto-update nella sua dir.
    // Uno staged crosspilot-<ts> in esecuzione non sweeps mai (ne' se'
    // stesso ne' i fratelli del proprio update). Best-effort, mai fatale.
    update::startup_sweep();

    // Carica il .env dal primo path candidato disponibile
    // (cwd -> exe dir -> project root). Vedi envs.rs.
    envs::load_dotenv();

    // Debug: quale ambiente host e' attivo (CROSSPILOT_ENV -> CROSSPILOT_<NOME>_*),
    // con i valori effettivamente risolti (prefisso -> fallback -> default).
    let env_label = envs::active_name()
        .map(|n| format!("{} (CROSSPILOT_{}_*)", n, n))
        .unwrap_or_else(|| "default (CROSSPILOT_*)".to_string());
    let env_host = envs::var("HOST").unwrap_or_else(|| "127.0.0.1".to_string());
    let env_winrm = envs::var("PORT").unwrap_or_else(|| "5985".to_string());
    let env_client = envs::var("CLIENT_PORT").unwrap_or_else(|| "5330".to_string());
    crate::qprintln!(
        "[DEBUG] ambiente attivo: {} -> host={} winrm={} client={}",
        env_label,
        env_host,
        env_winrm,
        env_client
    );

    if cli.server || matches!(cli.command, Some(Commands::Server { .. })) {
        let port = if let Some(Commands::Server { port }) = cli.command {
            port
        } else {
            5330
        };
        server_mode(port).await?;
    } else if !cli.raw_cmd.is_empty() {
        // Forma raw: `crosspilot -- dir c:\`. I token dopo `--` sono presi
        // letteralmente da clap; la ricomposizione della command-line
        // dipende dall'OS remoto (POSIX-quote su unix, join su Windows —
        // vedi runcmd::rejoin_command, deciso dentro client_mode).
        client_mode(&cli.raw_cmd, cli.ephemeral).await?;
    } else {
        match cli.command {
            // Transfer file: upload (put) lato client.
            Some(Commands::Put {
                local_src,
                remote_dst,
                exec,
            }) => {
                client_transfer_put(&local_src, &remote_dst, exec, cli.ephemeral).await?;
            }
            // Transfer file: download (get) lato client.
            Some(Commands::Get {
                remote_src,
                local_dst,
            }) => {
                client_transfer_get(&remote_src, &local_dst, cli.ephemeral).await?;
            }
            // Directory sync: status (diff read-only) lato client.
            Some(Commands::Status {
                local_dir,
                remote_dir,
                checksum,
                quiet,
                exclude,
            }) => {
                // Il report minimale segue solo i flag ESPLICITI (subcommand
                // --quiet o -q globale): il default quiet di log.rs NON deve
                // collassare il report — righe per-entry restano il default.
                client_sync_status(
                    &local_dir,
                    &remote_dir,
                    checksum,
                    quiet || cli.quiet,
                    &exclude,
                    cli.ephemeral,
                )
                .await?;
            }
            // Directory sync: sync (mirror one-way upload) lato client.
            // I flag sono gia' raggruppati in SyncParams (clippy too_many_arguments).
            Some(Commands::Sync {
                local_dir,
                remote_dir,
                delete,
                dry_run,
                checksum,
                quiet,
                exclude,
            }) => {
                let params = sync::SyncParams {
                    local_dir,
                    remote_dir,
                    delete,
                    dry_run,
                    quiet: quiet || cli.quiet,
                };
                client_sync(params, checksum, &exclude, cli.ephemeral).await?;
            }
            // Esecuzione script remota (upload tmp + run + cleanup).
            Some(Commands::Run { script, args }) => {
                client_run(&script, &args, cli.ephemeral).await?;
            }
            // Spegnimento esplicito del server remoto (nessuna operazione).
            Some(Commands::Quit) => {
                client_quit().await?;
            }
            // Updater staged (auto-update via TCP): uso interno.
            Some(Commands::Update {
                target,
                wait_pid,
                port,
                wait_secs,
                relaunch_args,
                console,
            }) => {
                update::run_updater(target, wait_pid, port, wait_secs, relaunch_args, console)
                    .await?;
            }
            // Query MySQL read-only sui DB CROSSPILOT_DB_* (connessione
            // diretta locale: nessun handshake/connessione al server remoto).
            Some(Commands::Sql { db, source, exec }) => {
                sql::run(db.as_deref(), source.as_deref(), exec.as_deref()).await?;
            }
            // CRUD ambienti host nel .env (nessuna connessione richiesta).
            Some(Commands::Env { action }) => {
                envs::run(&action)?;
            }
            _ => {
                if cli.ephemeral {
                    // `--ephemeral` senza comando ne' sottocomando: il
                    // flag stesso e' la richiesta di shutdown ("chiuditi
                    // e basta"). Equivale a `crosspilot quit`.
                    client_quit().await?;
                    return Ok(());
                }
                println!("CrossPilot - Remote Command Executor for Windows Containers");
                println!("---------------------------------------------------------------");
                // Ambiente attivo ben visibile: e' il target di TUTTI i comandi.
                println!(
                    "Ambiente attivo: {} -> host {} (winrm:{}, client:{})",
                    envs::active_name().unwrap_or_else(|| "default".to_string()),
                    env_host,
                    env_winrm,
                    env_client
                );
                println!("Usage:");
                println!("  crosspilot -- <COMMAND>   # Execute command remotely (Linux side)");
                println!("  crosspilot --server       # Run in Server Mode (Windows side)");
                println!("  crosspilot put <local> <remote>   # Upload file (rsync delta)");
                println!("  crosspilot get <remote> <local>   # Download file/dir (rsync delta, ricorsivo)");
                println!("  crosspilot status <local> <remote>  # Diff directory (read-only)");
                println!("  crosspilot sync   <local> <remote>  # Mirror directory (upload)");
                println!("  crosspilot quit                 # Shut down the remote server");
                println!("  crosspilot --ephemeral -- <CMD> # Run, then server self-shuts down (agentless)");
                println!();
                println!("Environments (.env multi-host):");
                println!("  crosspilot env list                  # ambienti definiti (* = attivo)");
                println!("  crosspilot env show <nome>           # config effettiva + fallback");
                println!("  crosspilot env add <nome> --host IP  # nuovo ambiente");
                println!("  crosspilot env set <nome> --user ..  # modifica campi");
                println!("  crosspilot env use <nome>            # seleziona l'attivo");
                println!("  crosspilot env remove <nome>         # elimina ambiente");
                println!("  (dettagli: crosspilot env -h; override ad-hoc: CROSSPILOT_ENV=<nome>)");
                println!();
                println!("MySQL (CROSSPILOT_DB_<NOME>_* nel .env, connessione diretta):");
                println!("  crosspilot sql                       # database configurati");
                println!("  crosspilot sql <DB> <file.sql|-|-e 'query'>  # query read-only");
                println!();
                println!("The -- form passes the tokens to cmd.exe on the remote Windows host.");
                println!("Tokens containing spaces are auto-wrapped in double quotes (single");
                println!("quotes are NOT grouping for cmd.exe). Inside powershell -Command use");
                println!("single quotes for remote paths; for complex scripts: run file.ps1");
                println!();
                println!("Examples:");
                println!("  1. Check remote IP:");
                println!("     crosspilot -- ipconfig");
                println!();
                println!("  2. List remote directory (note: single quotes around the path):");
                println!("     crosspilot -- dir 'c:\\'");
                println!();
                println!("  3. Run PowerShell script:");
                println!("     crosspilot -- powershell -File C:\\Scripts\\test.ps1");
                println!();
                println!("  4. Close remote server:");
                println!("     crosspilot quit        (o: crosspilot --ephemeral)");
                println!();
                println!("  4b. Agentless: run a command, then the server self-shuts down:");
                println!("     crosspilot --ephemeral -- make test");
                println!();
                println!("  5. Upload a file:");
                println!("     crosspilot put ./app.exe C:\\ci\\app.exe");
                println!();
                println!("  6. Download a file or directory (recursive pull):");
                println!("     crosspilot get  C:\\ci\\log.txt ./log.txt");
                println!("     crosspilot get  C:\\ci\\artifacts ./artifacts");
                println!();
                println!("  7. Diff directory (status):");
                println!("     crosspilot status ./artifacts C:\\ci\\artifacts");
                println!();
                println!("  8. Mirror directory (sync):");
                println!("     crosspilot sync   ./artifacts C:\\ci\\artifacts --delete");
                println!();
                println!("  9. Seleziona un altro host configurato:");
                println!("     crosspilot env use h102   &&   crosspilot -- hostname");
                println!();
                println!(" 10. Aggiungi un nuovo host:");
                println!("     crosspilot env add srv2 --host 10.0.0.9 --user admin --pass secret");
                println!("-------------------------------------");
                println!("For detailed help on all parameters, run:");
                println!("  crosspilot -h");
            }
        }
    }

    Ok(())
}

/// Finestra di pazienza del bind su AddrInUse (Windows, BUG-13): la
/// socket listening del server appena morto puo' restare bound per
/// decine di secondi (socket zombie). 300s > vita residua massima
/// dell'updater (~4min worst-case): se lo zombie e' un handle ereditato
/// dall'updater, si libera solo all'uscita dell'updater — il server in
/// retry DEVE sopravvivere fino a quel momento per bindare e restare su.
#[cfg(target_os = "windows")]
const ADDRINUSE_RETRY_SECS: u64 = 300;

async fn server_mode(port: u16) -> Result<()> {
    // Force UTF-8 code page on Windows
    #[cfg(target_os = "windows")]
    {
        let _ = Command::new("cmd")
            .args(["/C", "chcp 65001"])
            .output()
            .await;
    }

    let actual_port = envs::var("SERVER_PORT")
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(port);

    let addr = format!("0.0.0.0:{}", actual_port);

    // Bind with Windows-friendly recovery on AddrInUse (os error 10048)
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) if e.kind() == ErrorKind::AddrInUse => {
            #[cfg(target_os = "windows")]
            {
                // BUG-13 ROOT CAUSE (H166, provata da crosspilot-server.log):
                // il socket listening del server appena morto resta BOUND
                // per decine di secondi — netstat lo mostra LISTENING col
                // pid morto e i connect ci riescono pure (backlog kernel),
                // ma nessuno risponde READY. Il server rilanciato trovava
                // AddrInUse, il taskkill falliva ("processo non trovato")
                // e il processo USCIVA: la "morte misteriosa ~3-7s dopo il
                // bind" era il nostro exit, non un killer esterno.
                //
                // Fix: MAI uscire al primo AddrInUse. Loop paziente:
                // 1. probe READY — un crosspilot VIVO non si tocca mai
                //    (fix precedente: il taskkill cieco ammazzava
                //    l'incumbent sano);
                // 2. taskkill best-effort del pid occupante (sul pid morto
                //    fallisce in modo innocuo);
                // 3. retry del bind fino ad ADDRINUSE_RETRY_SECS — la
                //    socket zombie si libera e il bind va a buon fine.
                //    La finestra deve superare la vita residua
                //    dell'updater: se lo zombie e' un handle ereditato
                //    dall'updater, muore solo quando l'updater esce —
                //    e a quel punto il server DEVE essere ancora in retry.
                let deadline = Instant::now() + Duration::from_secs(ADDRINUSE_RETRY_SECS);
                let mut attempt = 0u32;
                loop {
                    if listener_is_live_crosspilot(actual_port).await {
                        return Err(anyhow::anyhow!(
                            "Port {} is already served by a RUNNING crosspilot server. \
                             Refusing to kill it — stop the existing instance first.",
                            actual_port
                        ));
                    }
                    attempt += 1;
                    eprintln!(
                        "Port {} occupied by a dead/foreign listener (tentativo {}): reclaim + retry bind...",
                        actual_port, attempt
                    );
                    // Best-effort: sul socket zombie il pid e' gia' morto e
                    // il taskkill fallisce ("processo non trovato") —
                    // l'errore non deve interrompere il retry del bind.
                    if let Err(ke) = kill_listener_on_port_windows(actual_port).await {
                        eprintln!("[kill_listener] WARNING: {}", ke);
                    }
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                    match TcpListener::bind(&addr).await {
                        Ok(l) => break l,
                        Err(e2) if e2.kind() == ErrorKind::AddrInUse => {
                            if Instant::now() >= deadline {
                                return Err(anyhow::anyhow!(
                                    "Port {} is still in use after {}s of retries (socket zombie persistente). \
                                     Please close the existing process and retry. Underlying error: {}",
                                    actual_port,
                                    ADDRINUSE_RETRY_SECS,
                                    e2
                                ));
                            }
                        }
                        Err(e2) => return Err(e2.into()),
                    }
                }
            }
            #[cfg(not(target_os = "windows"))]
            {
                return Err(e.into());
            }
        }
        Err(e) => return Err(e.into()),
    };
    println!("Server listening on {}", addr);

    // Self-ensure firewall inbound (spec smb-scm §2): le regole create
    // dal client durante bootstrap/update possono sparire dopo (GPO
    // refresh, cleanup admin). Un server che binda ma e' filtrato e'
    // indistinguibile da uno spento: il server — che gira elevato —
    // riassicura la regola da se' ad OGNI avvio (anche quelli via
    // updater). Best-effort, mai fatale.
    update::ensure_inbound_allow_local(actual_port).await;

    // Self-describing: (ri)scrive crosspilot.ver (ts + hash exe + sidecar)
    // e ripulisce gli artefatti staged/residui dell'auto-update via TCP.
    update::self_describe();

    // Warm-up della cache INFO_RES: l'hash dell'exe (costoso su binari
    // grandi) si paga qui, non dentro il budget INFO_TIMEOUT del primo
    // client che chiede self-describe (bug e2e: debug build ~250MB ->
    // ~12s di hashing -> il client scadeva a 5s e droppava -> Broken pipe
    // lato server + fetch() cacheava None per sempre).
    server_info::warm_up();

    // TLS 1.3 post-quantum (spec tls-pq): cert self-signed generato alla
    // prima esecuzione (crosspilot-server.{key,crt} accanto all'exe) e
    // acceptor condiviso per le connessioni. Se la generazione fallisce
    // il server resta plaintext-only (dual-stack di rollout, spec §5).
    let tls_acceptor = match tls::init_server_tls() {
        Ok(a) => Some(a),
        Err(e) => {
            eprintln!(
                "[server] WARNING: TLS non disponibile ({:#}) — solo connessioni plaintext",
                e
            );
            None
        }
    };

    // Persistent Server Mode
    let shutdown_signal = Arc::new(Notify::new());

    loop {
        let shutdown_signal = shutdown_signal.clone();
        tokio::select! {
            _ = shutdown_signal.notified() => {
                println!("Shutdown signal received. stopping server.");
                break;
            }
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((mut socket, _)) => {
                        let tls_acceptor = tls_acceptor.clone();
                        tokio::spawn(async move {
                            // Handshake: "READY <BUILD_TS>" — il ts rende il
                            // server self-describing per l'auto-update via TCP
                            // (i client legacy leggono 6 byte "READY " e
                            // falliscono -> bootstrap WinRM -> self-update).
                            // NOTA DEFINITIVA (spec selfdescribe §1.1): il tag
                            // OS come terzo token NON verra' MAI inviato —
                            // i client attuali lo leggerebbero come ts=0 ->
                            // update forzato. L'identita' del server (OS,
                            // exe_path, hash) viaggia su INFO_RES.
                            let hello = format!("READY {}\n", version::BUILD_TS);
                            if let Err(e) = socket.write_all(hello.as_bytes()).await {
                                eprintln!("Failed to send handshake: {}", e);
                                return;
                            }
                            let _ = socket.flush().await;

                            if let Err(e) = handle_connection(socket, tls_acceptor, shutdown_signal).await {
                                eprintln!("Connection error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        eprintln!("Accept error: {}", e);
                    }
                }
            }
        }
    }

    println!("Server shutting down.");
    Ok(())
}

/// True se sulla porta risponde un server crosspilot VIVO (handshake
/// READY entro 2s). Chiamata PRIMA di kill_listener su AddrInUse:
/// un incumbent sano non si tocca — il taskkill resta riservato a
/// listener zombie/estranei (socket tenuto da processo che non parla
/// il nostro protocollo). Riutilizza read_ready_line del handshake
/// client. Best-effort: qualunque errore -> false (-> reclaim).
#[cfg(target_os = "windows")]
async fn listener_is_live_crosspilot(port: u16) -> bool {
    let addr = format!("127.0.0.1:{}", port);
    let conn = tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(&addr)).await;
    let mut stream = match conn {
        Ok(Ok(s)) => s,
        // Nessuna connessione accettata: listener zombie (bind senza
        // accept loop) o porta gia' liberata -> si puo' reclamare.
        _ => return false,
    };
    let hello = tokio::time::timeout(Duration::from_secs(2), read_ready_line(&mut stream)).await;
    let alive = matches!(hello, Ok(Ok(_)));
    eprintln!(
        "[kill_listener] probe READY su {}: {}",
        addr,
        if alive {
            "server crosspilot VIVO (niente kill)"
        } else {
            "nessuna risposta valida (reclaim)"
        }
    );
    alive
}

#[cfg(target_os = "windows")]
async fn kill_listener_on_port_windows(port: u16) -> Result<()> {
    // Find PID(s) listening on a port and terminate them.
    // netstat output example:
    // TCP    0.0.0.0:5330   0.0.0.0:0   LISTENING   12345
    let find_cmd = format!("netstat -a -n -o | findstr LISTENING | findstr :{}", port);

    let out = Command::new("cmd")
        .args(["/C", &find_cmd])
        .output()
        .await
        .context("Failed to run netstat to locate PID")?;

    // If nothing found, maybe the port was released in the meantime.
    if out.stdout.is_empty() {
        println!(
            "[kill_listener] netstat returned no LISTENING lines for port {}",
            port
        );
        tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
        return Ok(());
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    println!("[kill_listener] netstat raw output:\n{}", stdout);
    let mut pids: Vec<u32> = stdout
        .lines()
        .filter_map(|line| line.split_whitespace().last())
        .filter_map(|pid| pid.parse::<u32>().ok())
        .collect();
    pids.sort_unstable();
    pids.dedup();

    if pids.is_empty() {
        println!(
            "[kill_listener] No PIDs parsed from netstat output for port {}",
            port
        );
        tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
        return Ok(());
    }

    println!("[kill_listener] PIDs to kill: {:?}", pids);
    for pid in pids {
        let kill = Command::new("taskkill")
            .args(["/F", "/PID", &pid.to_string()])
            .output()
            .await
            .with_context(|| format!("Failed to run taskkill for PID {}", pid))?;

        if !kill.status.success() {
            let stderr = String::from_utf8_lossy(&kill.stderr);
            // If it already exited between netstat and taskkill, treat as non-fatal.
            eprintln!(
                "[kill_listener] Warning: taskkill failed for PID {}: {}",
                pid,
                stderr.trim()
            );
        } else {
            let stdout_kill = String::from_utf8_lossy(&kill.stdout);
            println!(
                "[kill_listener] taskkill success for PID {}: {}",
                pid,
                stdout_kill.trim()
            );
        }
    }

    // Give Windows a moment to release the socket
    println!("[kill_listener] Sleeping 800ms for socket release...");
    tokio::time::sleep(tokio::time::Duration::from_millis(800)).await;
    Ok(())
}

/// Dispatch di una connessione appena accettata (dopo `READY`).
///
/// Rilevamento transport/mode sui primi byte (spec tls-pq §3):
/// - `0x16 0x03` -> TLS ClientHello -> handshake TLS + AUTH + stessa
///   mode-detection ripetuta DENTRO il record layer;
/// - `DFB1`      -> file mode framed in chiaro;
/// - altro       -> shell mode in chiaro.
///
/// Con CROSSPILOT_REQUIRE_TLS=1 il plaintext resta accettato solo per la
/// whitelist GET §5.1 (grace window per l'auto-update dei client vecchi).
async fn handle_connection(
    mut socket: TcpStream,
    tls_acceptor: Option<tokio_rustls::TlsAcceptor>,
    shutdown_signal: Arc<Notify>,
) -> Result<()> {
    // Detection modalità (spec §5): peek cumulativo fino a 4 byte.
    // Se i 4 byte == magic "DFB1" -> modo file (transfer). Altrimenti -> modo shell.
    // peek (non read) non consuma i byte: il socket è intatto per entrambe le modalità.
    let mut peek_buf = [0u8; 4];
    let mut filled = 0;
    let mut timed_out = false;
    loop {
        let peek_result =
            tokio::time::timeout(Duration::from_secs(2), socket.peek(&mut peek_buf[filled..]))
                .await;
        match peek_result {
            Ok(Ok(0)) => {
                // Client disconnesso prima di inviare dati.
                return Ok(());
            }
            Ok(Ok(k)) => {
                filled += k;
                if filled >= 4 {
                    break;
                }
            }
            Ok(Err(_)) => break,
            Err(_) => {
                // Timeout: tratta come shell mode.
                timed_out = true;
                break;
            }
        }
    }

    // TLS ClientHello: entra nel ramo cifrato. REQUIRE_TLS o dual-stack
    // e' indifferente — il TLS e' sempre accettato appena lo si riconosce.
    if tls::looks_like_tls_hello(&peek_buf, filled) {
        return handle_tls_connection(socket, tls_acceptor, shutdown_signal).await;
    }

    // Grace plaintext (spec §5.1): con REQUIRE_TLS solo le GET whitelisted
    // degli artefatti pubblici passano ancora in chiaro — serve al client
    // vecchio per scaricare .ver+binario e auto-aggiornarsi.
    let grace_only = tls::require_tls();

    // Se abbiamo 4 byte e corrispondono al magic "DFB1" -> modo file transfer.
    if filled == 4 && peek_buf == *b"DFB1" {
        crate::qprintln!("[DEBUG] handle_connection: rilevata modalità file transfer (magic DFB1)");
        // Delega al modulo transfer. Il socket non è stato consumato (peek).
        let link = tls::Link::plain(socket);
        if let Err(e) = handle_file_mode(link, grace_only).await {
            eprintln!("[ERROR] file transfer fallito: {}", e);
        }
        return Ok(());
    }

    // Shell mode in chiaro: con REQUIRE_TLS vietato (spec §5.1) — si
    // risponde una riga d'errore leggibile e si chiude, cosi' un client
    // nuovo vede il motivo invece di un EOF muto.
    if grace_only {
        eprintln!("[server] REQUIRE_TLS: rifiutata connessione shell in chiaro");
        let _ = socket
            .write_all(b"ERR plaintext disabilitato (CROSSPILOT_REQUIRE_TLS)\n")
            .await;
        let _ = socket.flush().await;
        return Ok(());
    }

    // Altrimenti -> modo shell (comportamento invariato). Se il peek è incompleto
    // (meno di 4 byte in 2s), avvisa: un client file-mode routato per sbaglio in
    // shell mode produce errori incomprensibili ("sh: DFB1: command not found").
    if filled < 4 {
        eprintln!(
            "[WARN] peek incomplete ({} bytes in 2s), falling back to shell mode",
            filled
        );
    }
    if timed_out {
        crate::qprintln!("[DEBUG] handle_connection: peek timeout, modalità shell");
    }

    let link = tls::Link::plain(socket);
    shell_flow(link, shutdown_signal).await
}

/// Ramo TLS della dispatch (spec tls-pq §3): handshake, AUTH, poi la
/// STESSA mode-detection ripetuta dentro il record layer (su TLS non
/// esiste peek: i byte letti vengono ri-accodati in `Link.head`, resi
/// invisibili al resto del protocollo).
async fn handle_tls_connection(
    socket: TcpStream,
    tls_acceptor: Option<tokio_rustls::TlsAcceptor>,
    shutdown_signal: Arc<Notify>,
) -> Result<()> {
    let acceptor = match tls_acceptor {
        Some(a) => a,
        None => {
            eprintln!("[server] TLS ClientHello ma cert non disponibile — connessione chiusa");
            return Ok(());
        }
    };
    let stream = match tls::accept_tls(acceptor, socket).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[server] handshake TLS fallito: {}", e);
            return Ok(());
        }
    };
    let mut link = tls::Link::tls_server(stream);
    crate::qprintln!("[DEBUG] TLS handshake ok (TLS 1.3, X25519MLKEM768)");

    // AUTH dentro TLS (spec §8): prima operazione dopo l'handshake —
    // token errato o assente -> chiusura immediata, nessuno stato
    // consumato (rigetto pulito).
    match tls::read_auth_line(&mut link).await {
        Ok(line) => {
            if let Err(e) = tls::check_auth_line(&line) {
                eprintln!("[server] AUTH rifiutata: {}", e);
                // Chiusura graziosa: poll_shutdown invia close_notify —
                // senza di esso il client vede un brutto "unexpected EOF"
                // di rustls invece dell'EOF pulito atteso dalla spec §8.
                let _ = link.shutdown().await;
                return Ok(());
            }
        }
        Err(e) => {
            eprintln!("[server] AUTH mancante/malformata: {}", e);
            let _ = link.shutdown().await;
            return Ok(());
        }
    }

    // Mode-detection dentro TLS: leggiamo fino a 4 byte (stesso budget
    // dei 2s del peek in chiaro); i byte restano ri-accedibili al
    // protocollo sottostante via Link::prepend.
    let mut det = Vec::with_capacity(4);
    loop {
        let mut chunk = [0u8; 4];
        let read_result =
            tokio::time::timeout(tls::MODE_DETECT_TIMEOUT, link.read(&mut chunk)).await;
        match read_result {
            Ok(Ok(0)) => break, // peer chiuso
            Ok(Ok(n)) => {
                det.extend_from_slice(&chunk[..n]);
                if det.len() >= 4 {
                    break;
                }
            }
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => break, // timeout -> shell mode
        }
    }
    if det.is_empty() {
        // Connessione chiusa subito dopo AUTH: niente da dispatchare.
        return Ok(());
    }
    link.prepend(&det);

    if det.as_slice() == b"DFB1" {
        crate::qprintln!("[DEBUG] handle_tls_connection: file transfer (magic DFB1) dentro TLS");
        if let Err(e) = handle_file_mode(link, false).await {
            eprintln!("[ERROR] file transfer TLS fallito: {}", e);
        }
        return Ok(());
    }
    crate::qprintln!("[DEBUG] handle_tls_connection: shell mode dentro TLS");
    shell_flow(link, shutdown_signal).await
}

/// Flusso shell-mode condiviso dai rami plaintext e TLS: legge la riga
/// di comando (i byte gia' visti nel mode-detection rientrano via
/// Link::prepend), gestisce quit/exit e il prefisso effimero, poi
/// esegue e streamma l'output.
async fn shell_flow(link: tls::Link, shutdown_signal: Arc<Notify>) -> Result<()> {
    let mut socket = link;

    // 1. Read command (la testa dello stream riporta i byte gia' letti
    //    nel mode-detection TLS; su plaintext nulla e' stato consumato).
    let mut buf = [0; 1024];
    let n = socket.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }
    let mut command_line = String::from_utf8_lossy(&buf[..n]).trim().to_string();
    println!("Received command: {}", command_line);

    // Check for quit/exit command
    if command_line.eq_ignore_ascii_case("quit") || command_line.eq_ignore_ascii_case("exit") {
        println!("Quit command received. notifying shutdown.");
        // Chiusura graziosa del link (close_notify su TLS): senza di essa
        // il client che streamma riceve UnexpectedEof e il quit riuscito
        // esce con codice 1 (bug visto in e2e su `crosspilot -- quit`).
        let _ = socket.shutdown().await;
        shutdown_signal.notify_one();
        return Ok(());
    }

    // Esecuzione effimera ("agentless", flag --ephemeral del client): il
    // prefisso QUIT_AFTER_PREFIX marca la richiesta come "run-and-die" —
    // il server esegue il comando e si auto-spegne a QUALUNQUE esito
    // (ok, errore di spawn, client disconnesso a meta' stream). La
    // decisione e' presa dal server alla ricezione della richiesta: a
    // differenza di un `quit` inviato dal client a fine stream, qui
    // l'agente non puo' restare appeso se il client muore in corsa.
    let mut quit_after = false;
    if let Some(rest) = command_line.strip_prefix(QUIT_AFTER_PREFIX) {
        command_line = rest.trim().to_string();
        if command_line.is_empty() {
            // Prefisso senza comando: solo shutdown (equivale a `quit`).
            println!("Ephemeral quit received. notifying shutdown.");
            let _ = socket.shutdown().await;
            shutdown_signal.notify_one();
            return Ok(());
        }
        quit_after = true;
        crate::qprintln!(
            "[DEBUG] ephemeral request: shutdown del server a fine comando ({})",
            command_line
        );
    }

    // Prefisso-sentinel exit-code (EXIT_CODE_PREFIX): il client chiede
    // l'exit status del comando — a fine stream il server accoda la riga
    // `CROSSPILOT_EXIT_CODE=<n>`. Inviato solo da client dello stesso
    // build (un server pre-feature lo passerebbe a cmd.exe come testo).
    let mut want_exit_code = false;
    if let Some(rest) = command_line.strip_prefix(runcmd::EXIT_CODE_PREFIX) {
        command_line = rest.trim().to_string();
        want_exit_code = true;
        if command_line.is_empty() {
            // Prefisso senza comando: solo il marker (exit code 0).
            let _ = socket
                .write_all(format!("{}{}\n", runcmd::EXIT_MARKER, 0).as_bytes())
                .await;
            let _ = socket.shutdown().await;
            if quit_after {
                shutdown_signal.notify_one();
            }
            return Ok(());
        }
    }

    // Ri-check quit/exit DOPO lo strip dei prefissi: `crosspilot -- quit`
    // arriva ora come "crosspilot:exit-code quit" (il client antepone il
    // sentinel a ogni comando dello stesso build) — senza questo check il
    // comando finirebbe a sh/cmd come testo ignoto e il server resterebbe
    // su (regressione rispetto al quit nudo intercettato sopra).
    if command_line.eq_ignore_ascii_case("quit") || command_line.eq_ignore_ascii_case("exit") {
        println!("Quit command received (con prefissi). notifying shutdown.");
        // Chiusura graziosa: vedi il quit nudo sopra.
        let _ = socket.shutdown().await;
        shutdown_signal.notify_one();
        return Ok(());
    }

    // 2. Esegue il comando e streamma stdout+stderr sul socket.
    let run_result = run_shell_command(socket, &command_line, want_exit_code).await;

    // 3. Ephemeral: a richiesta conclusa — a qualunque esito — il server
    // deve spegnersi. La notify arriva DOPO il flush del writer interno
    // a run_shell_command: il client riceve tutto l'output prima che il
    // processo server esca.
    if quit_after {
        let outcome = if run_result.is_ok() { "ok" } else { "errore" };
        println!(
            "Ephemeral request terminata ({}). notifying shutdown.",
            outcome
        );
        shutdown_signal.notify_one();
    }
    run_result
}

/// Sentinella del protocollo shell-mode per l'esecuzione effimera
/// ("agentless"): il client la prepone al comando (`--ephemeral -- <cmd>`)
/// e il server — riconoscendola — si auto-spegne alla fine dell'esecuzione
/// a qualunque esito. Token di protocollo (case-sensitive, non destinato
/// all'uso manuale); un server pre-feature lo passerebbe a cmd.exe come
/// testo ignoto, ma reconcile (update.rs) allinea client/server allo
/// stesso BUILD_TS prima dell'invio — salvo CROSSPILOT_NO_UPDATE=1.
const QUIT_AFTER_PREFIX: &str = "crosspilot:quit-after ";

/// Esegue `command_line` nella shell del remote e streamma stdout+stderr
/// sul socket fino a EOF (comando terminato) o fino alla disconnessione
/// del client (il processo viene ucciso). Estratto da handle_connection
/// (best-practice: unita' piccole): il caller decide il post-esecuzione —
/// la modalita' effimera notifica lo shutdown del server a qualunque esito.
/// `socket` e' un Link: funziona identico su plaintext e dentro TLS.
async fn run_shell_command(
    socket: tls::Link,
    command_line: &str,
    want_exit_code: bool,
) -> Result<()> {
    // 2. Spawn process
    // ... rest of implementation matches previous logic
    // Detect OS for shell execution
    #[cfg(target_os = "windows")]
    let (shell, flag) = ("cmd", "/C");
    #[cfg(not(target_os = "windows"))]
    let (shell, flag) = ("sh", "-c");

    // BUG FIX: su Windows usiamo raw_arg per il command line, altrimenti
    // std::process::Command auto-quota gli argomenti che contengono spazi
    // (es. `dir c:\` diventa `cmd /C "dir c:\"`) e cmd.exe interpreta il
    // backslash finale come escape della quote → "filename syntax incorrect".
    // raw_arg passa la stringa così com'è a cmd.exe, consentendo di scrivere
    // `crosspilot -c "dir c:\"` esattamente come su una console Windows.
    #[cfg(target_os = "windows")]
    let mut child = Command::new(shell)
        .arg(flag)
        .raw_arg(command_line)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // .stdin(Stdio::piped()) // Future improvement for interactive
        .spawn()
        .context("Failed to spawn command")?;
    #[cfg(not(target_os = "windows"))]
    let mut child = Command::new(shell)
        .arg(flag)
        .arg(command_line)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // .stdin(Stdio::piped()) // Future improvement for interactive
        .spawn()
        .context("Failed to spawn command")?;

    // On Windows, assign to Job Object
    #[cfg(target_os = "windows")]
    let _job_handle = {
        if let Some(handle) = child.raw_handle() {
            win_job::assign_to_new_job(handle)?
        } else {
            // Should not happen on Windows unless process already exited
            return Err(anyhow::anyhow!("Failed to get child process handle"));
        }
    };

    let stdout = child.stdout.take().context("Failed to open stdout")?;
    let stderr = child.stderr.take().context("Failed to open stderr")?;

    // 3. Stream output
    // tokio::io::split funziona su qualunque AsyncRead+AsyncWrite: TcpStream
    // in chiaro e Link/TLS sono trattati allo stesso modo.
    let (mut socket_reader, mut socket_writer) = tokio::io::split(socket);

    // Notification to kill child if socket drops
    let kill_notify = Arc::new(Notify::new());
    let kill_notify_clone_read = kill_notify.clone();
    let kill_notify_clone_write = kill_notify.clone();

    // Monitor socket for disconnection (Read EOF)
    let monitor_handle = tokio::spawn(async move {
        let mut buf = [0; 1024];
        // We don't expect any more data from client, so any read returning 0 means EOF (disconnect).
        loop {
            match socket_reader.read(&mut buf).await {
                Ok(0) => {
                    kill_notify_clone_read.notify_one();
                    break;
                }
                Ok(_) => {} // Ignore extra data
                Err(_) => {
                    kill_notify_clone_read.notify_one();
                    break;
                }
            }
        }
    });

    // Stream stdout to socket
    let mut stdout_reader = tokio::io::BufReader::new(stdout);
    let mut stderr_reader = tokio::io::BufReader::new(stderr);

    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
    let tx_stderr = tx.clone();
    // Sender tenuto da parte per il marker di exit code (EXIT_CODE_PREFIX):
    // tx e tx_stderr vengono mossi nei task reader — questo resta per
    // l'append finale DOPO che tutto l'output e' stato consegnato.
    let tx_marker = tx.clone();

    let stdout_handle = tokio::spawn(async move {
        let mut buf = [0; 1024];
        loop {
            match stdout_reader.read(&mut buf).await {
                Ok(0) => break, // EOF
                Ok(n) => {
                    if tx.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let stderr_handle = tokio::spawn(async move {
        let mut buf = [0; 1024];
        loop {
            match stderr_reader.read(&mut buf).await {
                Ok(0) => break, // EOF
                Ok(n) => {
                    if tx_stderr.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Write loop: receive from channel, write to socket
    let writer_handle = tokio::spawn(async move {
        while let Some(data) = rx.recv().await {
            if socket_writer.write_all(&data).await.is_err() {
                kill_notify_clone_write.notify_one();
                break;
            }
        }
        let _ = socket_writer.flush().await;
        // Chiusura esplicita del lato scrittura: con tokio::io::split il
        // drop NON fa shutdown (a differenza di TcpStream::into_split) —
        // senza di questo il client non vedrebbe mai l'EOF (plaintext) o
        // il close_notify (TLS) e resterebbe appeso a fine comando.
        let _ = socket_writer.shutdown().await;
    });

    // Wait for child to exit OR kill signal
    let mut exit_code: Option<i32> = None;
    tokio::select! {
        status = child.wait() => {
            // Process finished normally: cattura l'exit status (per il
            // marker richiesto via EXIT_CODE_PREFIX — prima era ignorato).
            exit_code = status.ok().and_then(|s| s.code());
        }
        _ = kill_notify.notified() => {
            println!("Client disconnected, killing process...");
            let _ = child.kill().await;
        }
    }

    // Cleanup
    let _ = stdout_handle.await;
    let _ = stderr_handle.await;

    // Marker di exit code richiesto dal client (sentinel EXIT_CODE_PREFIX):
    // va DOPO tutto l'output — si invia sul canale ordinato SOLO dopo che
    // i reader stdout/stderr hanno chiuso (EOF dei pipe = child uscito).
    // exit_code None (processo killato/nessun code) -> 255.
    if want_exit_code {
        let marker = format!("\n{}{}\n", runcmd::EXIT_MARKER, exit_code.unwrap_or(255));
        let _ = tx_marker.send(marker.into_bytes()).await;
    }
    // Chiude l'ultimo sender: il writer svuota la coda e fa shutdown —
    // senza drop(tx_marker) rx.recv() resterebbe appeso all'infinito.
    drop(tx_marker);

    let _ = writer_handle.await;

    // Il task monitor (lettura EOF sul lato read dello split) resterebbe
    // appeso per sempre se il client non chiude per primo la connessione:
    // il suo ReadHalf trattiene un Arc verso lo stream condiviso, quindi
    // la socket resterebbe aperta — un leak fd+task per OGNI comando,
    // piu' marcato su TLS dove il close_notify non chiude il read side.
    // A comando terminato il monitor non ha piu' scopo (serve solo a
    // uccidere il child se il client sparisce a meta'): abort esplicito.
    monitor_handle.abort();

    Ok(())
}

/// Gestisce la modalità file transfer lato server (spec §5, §6).
/// Legge il primo messaggio framed (PUT_REQ o GET_REQ) e delega al modulo transfer.
///
/// `grace_only` = connessione plaintext + CROSSPILOT_REQUIRE_TLS (spec
/// tls-pq §5.1): passa SOLO GET_REQ whitelisted (artefatti pubblici per
/// l'auto-update dei client vecchi) e INFO_REQ (self-describe — dati
/// pubblici di identita', serve anche pre-TLS per il fallback §7);
/// qualunque altro msg framed — PUT, LIST/MKDIR/DELETE, UPDATE_REQ —
/// riceve ERR_PROTO e chiude.
async fn handle_file_mode(mut socket: tls::Link, grace_only: bool) -> Result<()> {
    // LOOP di messaggi sulla STESSA connessione (sessione persistente):
    // prima il server chiudeva dopo UNA operazione — il sync apriva una
    // connessione TCP+TLS per OGNI file (handshake ripetuto, lento e
    // rumoroso). Ora si resta nel loop finche' il client chiude o un
    // handler fallisce: i messaggi framed sono auto-delimitati (magic
    // "DFB1" per messaggio), quindi PUT/LIST/MKDIR/DELETE consecutivi si
    // incolonnano naturalmente. I client vecchi (un msg per connessione)
    // funzionano identici: al secondo read_msg si ottiene EOF -> uscita.
    //
    // Il primo messaggio: il magic "DFB1" e' gia' stato peek-ato ma non
    // consumato, quindi read_msg lo rilegge da capo insieme a
    // version/msg_type/payload.
    let mut ops_served = 0u32;
    loop {
        let (msg_type, payload) = match proto::read_msg(&mut socket).await {
            Ok(v) => v,
            Err(e) => {
                // Qualunque errore di lettura dopo >=1 op servita (EOF del
                // client a fine sync, reset, framing corrotto): la sessione
                // si chiude senza risposta — gli handler delle op precedenti
                // hanno gia' risposto e non esiste un peer affidabile a cui
                // mandare un ERR. Log di debug e uscita pulita.
                let is_eof = e.chain().any(|c| {
                    c.downcast_ref::<std::io::Error>()
                        .map(|io| io.kind() == std::io::ErrorKind::UnexpectedEof)
                        .unwrap_or(false)
                });
                if is_eof || ops_served > 0 {
                    crate::qprintln!(
                        "[DEBUG] handle_file_mode: chiusura dopo {} op ({})",
                        ops_served,
                        e
                    );
                    return Ok(());
                }
                // Errore di framing sul PRIMO messaggio (magic/versione/
                // payload invalidi): si tenta PRIMA un ERR best-effort e
                // poi si chiude — senza di esso il client vede solo "early
                // eof" (sintomo del server H101 zombificato, build
                // intermedia con VERSION=2 che rifiutava ogni messaggio).
                let err = proto::ErrMsg {
                    code: proto::ERR_PROTO,
                    message: format!("framing non valido: {}", e),
                };
                let _ = proto::send_err(&mut socket, &err).await;
                return Err(e);
            }
        };

        // Grace plaintext §5.1: vietato tutto tranne GET_REQ e INFO_REQ
        // in chiaro quando REQUIRE_TLS e' attivo (la whitelist del
        // basename sta in transfer::get_server). INFO_REQ e' whitelisted
        // perche' e' la fonte primaria dell'identita' remota (§2/§3):
        // senza di essa il client su canale grace non saprebbe che il
        // remote e' Windows vs Linux.
        if grace_only && msg_type != proto::MSG_GET_REQ && msg_type != proto::MSG_INFO_REQ {
            let err = proto::ErrMsg {
                code: proto::ERR_PROTO,
                message: format!(
                    "msg type {} non consentito in plaintext con REQUIRE_TLS",
                    msg_type
                ),
            };
            let _ = proto::send_err(&mut socket, &err).await;
            bail!(
                "operazione framed {} rifiutata in chiaro (REQUIRE_TLS)",
                msg_type
            );
        }

        match msg_type {
            proto::MSG_PUT_REQ => {
                let req = proto::decode_put_req(&payload)?;
                crate::qprintln!(
                    "[DEBUG] handle_file_mode: PUT_REQ dst={} ({} byte)",
                    req.path,
                    req.total_new_size
                );
                transfer::put_server(&mut socket, req).await?;
            }
            proto::MSG_GET_REQ => {
                let req = proto::decode_get_req(&payload)?;
                crate::qprintln!(
                    "[DEBUG] handle_file_mode: GET_REQ src={} grace={}",
                    req.path,
                    grace_only
                );
                transfer::get_server(&mut socket, req, grace_only).await?;
            }
            // Directory sync (sync-spec §5): messaggi LIST/MKDIR_BATCH/DELETE_BATCH.
            proto::MSG_LIST_REQ => {
                let req = proto::decode_list_req(&payload)?;
                crate::qprintln!(
                    "[DEBUG] handle_file_mode: LIST_REQ path={} recursive={} with_hash={}",
                    req.path,
                    req.recursive,
                    req.with_hash
                );
                sync_server::list_server(&mut socket, &req).await?;
            }
            proto::MSG_MKDIR_BATCH_REQ => {
                let req = proto::decode_mkdir_batch_req(&payload)?;
                crate::qprintln!(
                    "[DEBUG] handle_file_mode: MKDIR_BATCH_REQ count={}",
                    req.paths.len()
                );
                sync_server::mkdir_batch_server(&mut socket, &req).await?;
            }
            proto::MSG_DELETE_BATCH_REQ => {
                let req = proto::decode_delete_batch_req(&payload)?;
                crate::qprintln!(
                    "[DEBUG] handle_file_mode: DELETE_BATCH_REQ count={}",
                    req.items.len()
                );
                sync_server::delete_batch_server(&mut socket, &req).await?;
            }
            // Self-update via TCP (update-spec): spawn updater staged + uscita.
            proto::MSG_UPDATE_REQ => {
                let req = proto::decode_update_req(&payload)?;
                crate::qprintln!(
                    "[DEBUG] handle_file_mode: UPDATE_REQ staged={}",
                    req.staged_path
                );
                update::server_apply_update(&mut socket, &req).await?;
            }
            // Self-describe (spec selfdescribe §2): il server dichiara
            // la PROPRIA identita' (OS + exe canonico + ts + hash) — il
            // client non deve mai dedurla dall'env.
            proto::MSG_INFO_REQ => match server_info::info_res_payload() {
                Ok(res) => {
                    crate::qprintln!(
                        "[DEBUG] handle_file_mode: INFO_REQ -> {} {} ts={}",
                        res.os_tag,
                        res.exe_path,
                        res.build_ts
                    );
                    proto::send_info_res(&mut socket, res).await?;
                }
                Err(e) => {
                    let err = proto::ErrMsg {
                        code: proto::ERR_IO,
                        message: format!("info_res_payload fallito: {}", e),
                    };
                    let _ = proto::send_err(&mut socket, &err).await;
                    return Err(e);
                }
            },
            _ => {
                // Tipo di messaggio non riconosciuto: invia ERR protocollo.
                let err = proto::ErrMsg {
                    code: proto::ERR_PROTO,
                    message: format!("tipo di messaggio non valido per apertura: {}", msg_type),
                };
                let _ = proto::send_err(&mut socket, &err).await;
                bail!("tipo di messaggio non valido: {}", msg_type);
            }
        }
        ops_served += 1;
    }
}

/// Errore finale del retry loop di connessione. Se il bootstrap ha rilevato
/// l'endpoint WinRM irraggiungibile, allega il remediation (abilitare WinRM
/// sull'host remoto) invece del messaggio generico.
fn final_connect_error(addr: &str) -> anyhow::Error {
    // Remote Unix/Linux: il canale di bootstrap e' SSH unificato (russh —
    // mai WinRM). L'evidenza del prescan (incl. porta SSH) e l'ultimo
    // errore reale vanno sempre allegati (spec ssh-unified §2.4).
    if bootstrap::remote_is_unix() {
        let mut msg = format!(
            "Failed to connect to {} after bootstrap attempt.\n\
             Remote Linux/Unix (EXE_PATH unix-style o OS=linux): bootstrap SSH fallito.\n\
             Campi SSH_HOST/SSH_PORT/SSH_USER/SSH_KEY/SSH_PASS dell'ambiente \
             (vedi 'crosspilot env show'); auth a catena agent->key->password,\n\
             host key verificata TOFU in crosspilot_known_hosts accanto al .env.",
            addr
        );
        if let Some(evidence) = bootstrap::mgmt_evidence() {
            msg.push_str("\nEvidenza probe TCP:\n");
            msg.push_str(&evidence);
        }
        if let Some(e) = bootstrap::last_bootstrap_error() {
            msg.push_str("\nUltimo errore: ");
            msg.push_str(&e);
        }
        return anyhow::anyhow!(msg);
    }
    if bootstrap::winrm_unreachable() || bootstrap_smb::smb_unreachable() {
        // Remote Windows: il bootstrap ha provato i canali di management
        // (WinRM / SSH / SMB-SCM nell'ordine dettato dal prescan). Il
        // messaggio finale riporta l'EVIDENZA delle probe TCP raccolta
        // dal prescan (spec ssh-unified §2.4 + smb-scm §3.3) — non il
        // remediation generico "Enable-PSRemoting" che su H166 era
        // fuorviante (host vivo, SMB operativo).
        let mut msg = format!(
            "Failed to connect to {} after bootstrap attempts.\n\
             Canali di bootstrap non utilizzabili sull'host remoto (WinRM, SSH, SMB/SCM).",
            addr
        );
        if let Some(evidence) = bootstrap::mgmt_evidence() {
            msg.push_str("\nEvidenza probe TCP:\n");
            msg.push_str(&evidence);
        }
        if let Some(e) = bootstrap::last_bootstrap_error() {
            msg.push_str("\nUltimo errore: ");
            msg.push_str(&e);
        }
        msg.push_str(
            "\nRemediation: il canale che risponde nell'evidenza e' utilizzabile \
             (BOOTSTRAP=smb|ssh|winrm per forzarlo); altrimenti abilitare WinRM \
             (Enable-PSRemoting -Force / winrm quickconfig) o OpenSSH sulla \
             macchina remota, o verificare che l'host sia acceso e raggiungibile.",
        );
        return anyhow::anyhow!(msg);
    }
    if update::update_attempted() {
        // Se e' partito un update e il server non e' mai tornato, il
        // diagnoser #1 e' il log persistente dell'updater sul remote.
        return anyhow::anyhow!(
            "Failed to connect to {} after bootstrap attempt.\n\
             NOTA: un update del server era in corso. Sul remote leggi \
             'crosspilot-update.log' accanto all'exe (l'updater logga ogni \
             passo: attesa morte server, swap, rilancio, rollback).",
            addr
        );
    }
    anyhow::anyhow!("Failed to connect to server after bootstrap attempt")
}

/// Legge la riga di handshake del server fino a '\n' (cap 256 byte,
/// cumulativo su `line`) e la parsa (parse_ready_line). Errore su
/// EOF/riga sconosciuta (zombie). Il buffer e' del chiamante: permette a
/// read_ready_line_grace di riprendere la lettura dopo un timeout senza
/// perdere i byte parziali gia' arrivati (un "READY" spezzato in due
/// segmenti TCP a cavallo delle due finestre non si corrompe).
async fn read_ready_line_into(
    s: &mut TcpStream,
    line: &mut Vec<u8>,
) -> Result<version::ServerHello> {
    let mut byte = [0u8; 1];
    loop {
        let n = s.read(&mut byte).await?;
        if n == 0 {
            bail!("connessione chiusa durante l'handshake");
        }
        if byte[0] == b'\n' {
            break;
        }
        line.push(byte[0]);
        if line.len() > 256 {
            bail!("handshake troppo lungo (>256 byte)");
        }
    }
    let text = String::from_utf8_lossy(line);
    parse_ready_line(text.trim_end())
}

/// Wrapper a buffer interno per i probe one-shot (listener_is_live,
/// poll_server_startup, remote_build_info): li' nessuna ripresa dopo il
/// timeout, il buffer puo' essere ricreato a ogni chiamata.
async fn read_ready_line(s: &mut TcpStream) -> Result<version::ServerHello> {
    let mut line = Vec::with_capacity(32);
    read_ready_line_into(s, &mut line).await
}

/// Timeout della prima attesa READY: un server gia' dentro l'accept loop
/// risponde in pochi ms. Corto di proposito, cosi' la detection di
/// listener estranei/zombie (porta occupata da un processo che non parla
/// il nostro protocollo) non rallenta il fallback al bootstrap.
const READY_FAST: Duration = Duration::from_millis(1500);

/// Finestra extra di attesa READY quando il connect e' riuscito ma la
/// riga non arriva (race di cold-start, bug report #0): il listener fa
/// bind PRIMA dell'init (firewall self-ensure, self_describe, cert TLS)
/// e l'accept loop parte solo dopo — nella finestra il kernel completa
/// il TCP handshake (connect ok, connessione in backlog) ma READY non e'
/// ancora scritto. L'attesa avviene sulla STESSA socket: quando l'accept
/// loop parte, il server scrive READY anche alle connessioni accumulate
/// in backlog. Prima di questo fix il primo comando dopo l'avvio del
/// server scadeva l'handshake a 1.5s e cadeva in bootstrap pur essendo
/// il server vivo.
const READY_COLD_START: Duration = Duration::from_secs(30);

/// Attesa READY in due fasi (v. READY_COLD_START): prima `fast`, poi — a
/// connect gia' riuscito — `cold` sulla STESSA socket e sullo stesso
/// buffer `line`. Un peer che parla ma non dice READY esce subito col
/// suo errore di parse (nessuna attesa extra per i listener estranei
/// "loquaci"); solo il peer silenzioso consuma la finestra intera.
async fn read_ready_line_grace(
    s: &mut TcpStream,
    line: &mut Vec<u8>,
    fast: Duration,
    cold: Duration,
    addr: &str,
) -> Result<version::ServerHello> {
    let first = tokio::time::timeout(fast, read_ready_line_into(s, line)).await;
    match first {
        Ok(done) => return done,
        Err(_) => {
            // Debug log a dimostrazione della tesi: se il server era in
            // cold-start questa riga appare e la fase 2 riceve il READY.
            crate::qprintln!(
                "[DEBUG] {}: nessun READY entro {:?} — server in init? attesa cold-start (max {:?})...",
                addr, fast, cold
            );
        }
    }
    let second = tokio::time::timeout(cold, read_ready_line_into(s, line)).await;
    match second {
        Ok(done) => done,
        Err(_) => bail!(
            "handshake timeout (inclusi {:?} di attesa cold-start)",
            cold
        ),
    }
}

/// Parsa la riga di handshake del server:
///   "READY"          -> ServerHello { ts: None } (server legacy)
///   "READY <ts>"     -> ServerHello { ts: Some(ts) }
///   "READY <ts> <extra...>" -> i token oltre il ts sono IGNORATI
///
/// Spec §1.1 (selfdescribe-guardrail): il terzo token (tag OS L|W)
/// NON viene piu' parsato — READY porta solo il build ts, l'identita'
/// del server (OS, exe_path) arriva da INFO_RES. Un server che mandasse
/// il tag verrebbe comunque accettato (parsing token-aware), ma il tag
/// non ha piu' effetto. Funzione pura (unit-testabile).
fn parse_ready_line(text: &str) -> Result<version::ServerHello> {
    if text == "READY" {
        return Ok(version::ServerHello::default());
    }
    if let Some(rest) = text.strip_prefix("READY ") {
        // Primo token: BUILD_TS. Non numerico -> 0 (server "ignoto",
        // trattato come piu' vecchio di qualsiasi build versionato).
        // I token oltre il primo sono ignorati (forward-compat).
        let ts = rest
            .split_whitespace()
            .next()
            .and_then(|t| t.parse::<u64>().ok())
            .unwrap_or(0);
        return Ok(version::ServerHello { ts: Some(ts) });
    }
    bail!("handshake sconosciuto: {:?}", text);
}

/// Una connessione TCP + lettura handshake "READY <ts>" (singolo
/// tentativo, niente retry/bootstrap/update; attesa READY in due fasi
/// fast+cold-start, v. read_ready_line_grace), poi il gate TLS §4/§5:
/// server nuovo -> TLS 1.3+PQ con pinning e AUTH; server vecchio ->
/// plaintext grace (o fatale con REQUIRE_TLS / pin preesistente).
/// Ritorna il Link finale e il ServerHello remoto (ts None = server
/// legacy; READY porta SOLO il ts — §1.1). Usata da connect_and_handshake
/// e dall'interno dell'orchestrazione update (le connessioni di
/// PUT/GET/shell non devono ri-triggerare il confronto di versione).
pub(crate) async fn connect_raw(addr: &str) -> Result<(tls::Link, version::ServerHello)> {
    let conn = tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(addr)).await;
    let mut s = conn.context("connect timeout")??;
    // Buffer READY allocato una volta: sopravvive al timeout della fase
    // "fast" e riaccoglie i byte parziali nella finestra cold-start
    // (read_ready_line_grace) — niente perdita di segmenti a cavallo.
    let mut line = Vec::with_capacity(32);
    let hello =
        read_ready_line_grace(&mut s, &mut line, READY_FAST, READY_COLD_START, addr).await?;
    let link = tls::client_wrap(s, &hello, addr).await?;
    Ok((link, hello))
}

/// Stabilisce la connessione al server (Link: TLS o plaintext grace),
/// verifica l'handshake "READY <ts>" e orchestra l'auto-update via TCP
/// sul version skew (update::reconcile). Bootstrap solo se il server
/// non risponde. Gli errori TLS fatali (pin mismatch, downgrade,
/// handshake fallito) NON rientrano nel retry bootstrap: propagano
/// subito come HostKeyMismatch.
/// Riutilizzata dai comandi shell (--), transfer file (put/get) e sync.
async fn connect_and_handshake() -> Result<tls::Link> {
    let (link, _hello) = connect_and_handshake_hello().await?;
    Ok(link)
}

/// Come connect_and_handshake ma ritorna anche il ServerHello remoto
/// (ts; l'OS remoto e' risolto via INFO_RES da remote_is_unix_resolved):
/// serve a client_mode/run per l'exit-code marker e per
/// attivare il marker exit-code SOLO su server dello stesso BUILD_TS
/// (il prefisso-sentinel e' compreso solo da build uguali).
async fn connect_and_handshake_hello() -> Result<(tls::Link, version::ServerHello)> {
    // Risoluzione via envs: CROSSPILOT_<ENV>_<CAMPO> -> fallback CROSSPILOT_<CAMPO>.
    let host = envs::var("HOST").unwrap_or_else(|| "127.0.0.1".to_string());
    let client_port = envs::var("CLIENT_PORT").unwrap_or_else(|| "47330".to_string());
    let addr = format!("{}:{}", host, client_port);

    let mut attempt = 0;
    let max_attempts = 5;
    // Dopo un update triggerato il server e' in restart: solo polling TCP
    // (MAI bootstrap WinRM in questa fase — il remote_build_info vedrebbe
    // lo stato pre-swap e scatenerebbe un deploy WinRM inutile/dannoso).
    let mut update_deadline: Option<std::time::Instant> = None;
    loop {
        attempt += 1;
        crate::qprintln!("Connecting to {} (Attempt {})...", addr, attempt);

        let conn = connect_raw(&addr).await;
        let (s, hello) = match conn {
            Ok(v) => v,
            Err(e) => {
                // Errori TLS fatali: nessun retry, nessun bootstrap —
                // propagano subito (pin mismatch = possibile MITM,
                // downgrade = rollback attack, REQUIRE_TLS violato).
                if e.downcast_ref::<tls::TlsFatal>().is_some() {
                    return Err(e);
                }
                if let Some(dl) = update_deadline {
                    if std::time::Instant::now() < dl {
                        crate::qprintln!("[DEBUG] update in corso, retry... ({})", e);
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                    // L'updater non ha rialzato il server entro la deadline:
                    // caduta al bootstrap WinRM come ultima spiaggia.
                    eprintln!(
                        "[update] nuovo server non salito entro la deadline; fallback bootstrap."
                    );
                    update_deadline = None;
                    attempt = 0;
                }
                if attempt >= max_attempts {
                    return Err(final_connect_error(&addr));
                }
                // Logga l'errore reale: prima era ingoiato dal loop e al
                // suo posto partiva solo il bootstrap — diagnosi cieca
                // (visto in e2e: handshake TLS fallito, output muto).
                crate::qprintln!("Connection failed or timed out ({}). Bootstrapping...", e);
                match bootstrap::bootstrap_server().await {
                    Ok(()) => {}
                    Err(e) => {
                        // Fail-fast (bug B1): canale di bootstrap
                        // deterministicamente morto (WinRM/SSH down o auth
                        // rifiutata). Ogni attempt ulteriore ripeterebbe
                        // gli stessi timeout identici (~40s cad. su WinRM):
                        // uscita immediata col remediation gia' stampato.
                        if e.downcast_ref::<bootstrap::ChannelUnreachable>().is_some()
                            || bootstrap::winrm_unreachable()
                        {
                            let err = final_connect_error(&addr);
                            if e.downcast_ref::<bootstrap::ChannelUnreachable>().is_some() {
                                return Err(err);
                            }
                            // WinRM morto ma il canale di fallback (SMB/SCM)
                            // ha fallito con un errore DIVERSO da
                            // ChannelUnreachable: quello e' l'errore reale —
                            // non va ingoiato dal messaggio evidence-based
                            // (caso H166: un fallimento SMB spariva dietro
                            // "canali non utilizzabili" e la diagnosi era
                            // impossibile).
                            return Err(err.context(format!("{:#}", e)));
                        }
                        return Err(e);
                    }
                }
                continue;
            }
        };

        // §1.1: READY porta solo il ts — l'OS del remote non e' piu' nel
        // saluto (mai fidarsi dell'inferenza su path/env): la fonte e'
        // INFO_RES/discovery (server_info::remote_identity).
        crate::qprintln!(
            "[DEBUG] handshake: remote_ts={:?} locale={}",
            hello.ts,
            version::BUILD_TS
        );
        match update::reconcile(hello).await {
            update::Reconcile::Proceed => {
                // Se la connessione sopravvive in plaintext e' solo
                // perche' il server e' pre-TLS e l'update non si e'
                // applicato (NO_UPDATE, UPDATE_TRIED o update fallito):
                // spec §5.2 — le operazioni utente proseguono ma la
                // mancanza di cifratura va detta chiaramente.
                if !s.is_tls() {
                    eprintln!(
                        "[WARN] connessione NON cifrata verso {} — server pre-TLS, considerare l'aggiornamento",
                        addr
                    );
                }
                crate::qprintln!("Connected and verified.");
                return Ok((s, hello));
            }
            update::Reconcile::Reconnect => {
                crate::qprintln!("[update] server in aggiornamento: attesa restart (max 90s)...");
                // Prima di riconnettersi: attendere la MORTE del vecchio
                // server (porta giu'). Senza questa attesa la riconnessione
                // puo' cadere nei ~100ms di grace post-UPDATE_REQ e parlare
                // col binario VECCHIO (race osservata in e2e: comando
                // eseguito dal server pre-swap).
                update::wait_remote_restart_begin(&addr).await;
                update_deadline = Some(std::time::Instant::now() + Duration::from_secs(90));
                attempt = 0;
                continue;
            }
            update::Reconcile::ReconnectNoWait => {
                // Fallback sul canale di bootstrap (WinRM/SSH): il vecchio
                // server e' gia' stato fermato (quit) e quello nuovo e'
                // gia' in ascolto (atteso dal polling di bootstrap_server).
                // Riconnessione immediata, con deadline di sicurezza.
                crate::qprintln!(
                    "[update] server aggiornato via fallback bootstrap: riconnessione..."
                );
                update_deadline = Some(std::time::Instant::now() + Duration::from_secs(90));
                attempt = 0;
                continue;
            }
        }
    }
}

/// Lato client: PUT (upload) di un file locale verso il server.
/// Stabilisce la connessione, handshake, poi delega a transfer::put_client.
/// Con `exec` il file remoto riceve chmod a+x post-upload (solo remote
/// unix — il PUT lascia 644; su Windows il flag e' un no-op con warning).
/// Exit code: 0 ok, 1 errore protocollo/IO, 2 path invalido.
async fn client_transfer_put(
    local_src: &str,
    remote_dst: &str,
    exec: bool,
    quit_after: bool,
) -> Result<()> {
    // Valida il path sorgente locale prima di connettersi (fail-fast, exit code 2).
    if let Err(e) = path::require_local_file_exists(local_src) {
        eprintln!("[ERROR] put: {}", e);
        std::process::exit(2);
    }

    let mut socket = connect_and_handshake().await?;
    let result = transfer::put_client(&mut socket, local_src, remote_dst).await;

    // --exec: chmod +x sul file appena caricato (remote unix). La shell-mode
    // e' un canale separato: connessione fresca dedicata. Solo a put riuscito.
    if result.is_ok() && exec {
        remote_chmod_exec(remote_dst).await;
    }

    // --ephemeral: lo shutdown va inviato a QUALUNQUE esito del transfer
    // (stessa semantica del prefisso shell-mode: l'agente non resta appeso).
    if quit_after {
        ephemeral_quit_best_effort().await;
    }
    result?;
    // Riga di conferma SEMPRE visibile (println = risultato, non
    // diagnostica — vedi bug report sul download silenzioso in quiet).
    let bytes = std::fs::metadata(local_src).map(|m| m.len()).unwrap_or(0);
    println!(
        "put: trasferimento completato ({} -> {}, {} byte)",
        local_src, remote_dst, bytes
    );
    Ok(())
}

/// `chmod a+x` su un file remoto via shell-mode (canale separato dal
/// transfer framed). Best-effort: un fallimento del chmod non fa
/// fallire il put — warning + proseguimento. Solo remote unix.
/// Il comando attende il file staged: il rename .part->dest sul server
/// puo' arrivare dopo questa connessione (race osservata in e2e).
async fn remote_chmod_exec(remote_dst: &str) {
    if !bootstrap::remote_is_unix() {
        eprintln!("[WARN] put --exec: remote non unix, chmod ignorato");
        return;
    }
    let mut cmd = runcmd::wait_for_file_prefix(remote_dst, true);
    cmd.push_str("chmod a+x ");
    cmd.push_str(&runcmd::posix_quote(remote_dst));
    match shell_once(&cmd).await {
        Ok(Some(0)) | Ok(None) => {}
        Ok(Some(code)) => {
            eprintln!("[WARN] put --exec: chmod remoto fallito (exit {})", code);
        }
        Err(e) => {
            eprintln!("[WARN] put --exec: chmod remoto fallito: {}", e);
        }
    }
}

/// Lato client: GET (download) di un path remoto verso un path locale.
/// Stabilisce la connessione, handshake, poi:
/// - remote FILE      -> transfer::get_client (delta rsync, invariato);
/// - remote DIRECTORY -> pull ricorsivo (pull.rs): LIST + mkdir locali +
///   GET per file (bug report: `get` su directory rispondeva ERR 2
///   "file non trovato" pur essendo la dir esistente).
///   La stessa connessione del probe e' riusata dalla sessione di pull.
///   Exit code: 0 ok, 1 errore protocollo/IO (o errori per-file nel pull),
///   2 path invalido.
async fn client_transfer_get(remote_src: &str, local_dst: &str, quit_after: bool) -> Result<()> {
    let mut socket = connect_and_handshake().await?;

    // Probe del tipo remoto: LIST non-ricorsiva del parent (la stessa
    // risoluzione di `sync <file>`: '/' finale o dir esistente -> Dir;
    // inesistente/file -> File e l'eventuale errore emerge alla GET).
    let resolved = sync::resolve_remote_file_dest(&mut socket, remote_src).await;
    let remote_dir = match resolved {
        // Dir(porta il path NORMALIZZATO, senza il separatore finale).
        Ok(sync::RemoteFileDest::Dir(dir)) => Some(dir),
        Ok(sync::RemoteFileDest::File(_)) => None,
        Err(e) => {
            // Probe LIST non riuscito: un server legacy (pre-LIST) risponde
            // ERR_PROTO. Compat: NON e' fatale — si ricade sul GET singolo
            // come faceva il client vecchio. La connessione del probe puo'
            // essere gia' chiusa dal server -> reconnect fresco.
            crate::qprintln!(
                "[DEBUG] get: probe LIST fallita ({}) — fallback GET singolo",
                e
            );
            socket = connect_and_handshake().await?;
            None
        }
    };

    // Remote file (o probe fallita su server legacy): GET singolo.
    let Some(remote_dir) = remote_dir else {
        let result = transfer::get_client(&mut socket, remote_src, local_dst).await;
        if quit_after {
            ephemeral_quit_best_effort().await;
        }
        result?;
        // Riga di conferma SEMPRE visibile (println = risultato
        // dell'operazione, non diagnostica — bug report: download da
        // 300+ MB terminava a schermo vuoto in quiet di default).
        let bytes = std::fs::metadata(local_dst).map(|m| m.len()).unwrap_or(0);
        println!(
            "get: trasferimento completato ({} -> {}, {} byte)",
            remote_src, local_dst, bytes
        );
        return Ok(());
    };

    // Remote e' una directory -> download ricorsivo. local_dst E' la
    // directory specchio del contenuto remoto (semantica rovesciata di
    // `sync <local> <remote>`). `remote_dir` e' il path normalizzato.
    let local_path = std::path::Path::new(local_dst);
    if local_path.exists() && !local_path.is_dir() {
        if quit_after {
            ephemeral_quit_best_effort().await;
        }
        eprintln!(
            "[ERROR] get: la destinazione locale esiste e non e' una directory: {}",
            local_dst
        );
        std::process::exit(2);
    }
    // OS remoto per il join dei path (INFO_RES poi env).
    let remote_unix = remote_is_unix_resolved().await;
    let mut session = sync::SyncSession::new_with_link(socket, || async {
        connect_and_handshake().await
    });
    let result = pull::pull_remote_dir(&mut session, &remote_dir, local_path, remote_unix).await;
    if quit_after {
        ephemeral_quit_best_effort().await;
    }
    let report = result?;
    pull::print_pull_report(&report, &remote_dir, local_path);
    if !report.errors.is_empty() {
        std::process::exit(1);
    }
    Ok(())
}

/// Lato client: status (diff read-only) tra directory locale e remota.
/// sync-spec §6. Exit code: 0 ok (anche con differenze), 1 errore, 2 path invalido.
async fn client_sync_status(
    local_dir: &str,
    remote_dir: &str,
    checksum: bool,
    quiet: bool,
    exclude: &[String],
    quit_after: bool,
) -> Result<()> {
    // Valida local_dir prima di connettersi (fail-fast, exit code 2).
    if let Err(e) = path::require_local_dir_exists(local_dir) {
        eprintln!("[ERROR] status: {}", e);
        std::process::exit(2);
    }

    // 1 connessione per LIST (una connessione serve tutto il sync).
    let mut socket = connect_and_handshake().await?;
    let outcome = sync::list_remote_dir(&mut socket, remote_dir, checksum, true).await?;

    // Walk locale (skip non-UTF8 + riservati Windows + dir illeggibili).
    let local_path = std::path::Path::new(local_dir);
    let mut local_walk = sync::walk_local_dir(local_path)?;

    // Esclusioni: .crosspilotignore (nel source) + --exclude CLI, filtrano
    // entrambi i lati PRIMA del diff (esclusi = ignorati).
    let mut all_excludes = sync_ignore::load_ignore_patterns(local_path);
    for pat in exclude {
        all_excludes.push(pat.clone());
    }
    let mut remote_entries = outcome.entries;
    sync::apply_exclusions(&mut local_walk, &mut remote_entries, &all_excludes);

    // Diff (con lowercase per case-insensitivity Windows, sync-spec §8.1).
    let mut diff = sync::compute_diff(
        &local_walk,
        &remote_entries,
        checksum,
        std::path::Path::new(local_dir),
    );
    // Le dir remote illeggibili arrivano nel trailer LIST_RES: il contenuto
    // e' sconosciuto, va mostrato come warning (non come "identico").
    diff.skipped_remote = outcome.skipped;

    // Caveat size-only: senza --checksum i file "identici" lo sono solo
    // per dimensione — il caso diverso-contenuto non e' piu' silenzioso.
    if !checksum {
        let identical_files = sync::count_identical_files(&diff);
        if identical_files > 0 {
            eprintln!(
                "[WARN] {} file considerati identici per sola dimensione — \
                 usa --checksum per confronto contenuto",
                identical_files
            );
        }
    }

    // Output testuale (o riepilogo numerico se --quiet esplicito:
    // subcommand o -q globale — NON is_quiet(), che ora e' default-on).
    sync::print_status(&diff, quiet);

    if quit_after {
        ephemeral_quit_best_effort().await;
    }
    Ok(())
}

/// Lato client: sync (mirror one-way upload) della directory.
/// sync-spec §7. Exit code: 0 se tutto ok, 1 se almeno un errore (ma sync completa
/// tutti i file possibili), 2 path invalido.
async fn client_sync(
    params: sync::SyncParams,
    checksum: bool,
    exclude: &[String],
    quit_after: bool,
) -> Result<()> {
    let local_dir = params.local_dir.as_str();
    let remote_dir = params.remote_dir.as_str();
    // Sorgente FILE singolo (richiesta utente): dispatch a put.
    // Bug fix (report utente): remote_dir era SEMPRE trattata come
    // directory -> sync a.conf .../a.conf produceva .../a.conf/a.conf e
    // ERR 3 su .part. Ora il dest si risolve con semantica rsync:
    // directory esistente (o '/' finale) -> dir/basename, altrimenti il
    // remote arg E' il path file di destinazione (rename incluso).
    let local_path = std::path::Path::new(local_dir);
    if local_path.is_file() {
        let base = local_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if base.is_empty() {
            eprintln!("[ERROR] sync: basename non ricavabile da {}", local_dir);
            std::process::exit(2);
        }
        // Una sola connessione: probe LIST del parent + PUT (file-mode
        // persistente, i messaggi si incolonnano sulla stessa sessione).
        let mut socket = connect_and_handshake().await?;
        let resolved = sync::resolve_remote_file_dest(&mut socket, remote_dir).await?;
        let remote_dst = match resolved {
            sync::RemoteFileDest::Dir(dir) => {
                // '/' finale o directory esistente: dest = dir/basename.
                // La crea se mancante (mkdir -p idempotente).
                sync::ensure_remote_dir(&mut socket, &dir).await?;
                let joined = sync::join_remote_path(&dir, &base);
                eprintln!("[sync] destinazione remota (directory): {}", joined);
                joined
            }
            sync::RemoteFileDest::File(p) => {
                eprintln!("[sync] destinazione remota (file): {}", p);
                p
            }
        };
        let put_result = transfer::put_client(&mut socket, local_dir, &remote_dst).await;
        if quit_after {
            ephemeral_quit_best_effort().await;
        }
        put_result?;
        println!(
            "sync file: trasferimento completato ({} -> {})",
            local_dir, remote_dst
        );
        return Ok(());
    }

    // Valida local_dir prima di connettersi (fail-fast, exit code 2).
    if let Err(e) = path::require_local_dir_exists(local_dir) {
        eprintln!("[ERROR] sync: {}", e);
        std::process::exit(2);
    }

    // 1 connessione per LIST (la sessione persistente la riusa per il sync).
    let mut socket = connect_and_handshake().await?;
    let outcome = sync::list_remote_dir(&mut socket, remote_dir, checksum, true).await?;

    // Walk locale.
    let mut local_walk = sync::walk_local_dir(std::path::Path::new(local_dir))?;

    // Esclusioni: pattern di .crosspilotignore (nel source) + --exclude
    // CLI. Filtra entrambi i lati PRIMA del diff (esclusi = ignorati).
    let mut all_excludes = sync_ignore::load_ignore_patterns(local_path);
    for pat in exclude {
        all_excludes.push(pat.clone());
    }
    let mut remote_entries = outcome.entries;
    sync::apply_exclusions(&mut local_walk, &mut remote_entries, &all_excludes);

    // Diff + piano.
    let mut diff = sync::compute_diff(
        &local_walk,
        &remote_entries,
        checksum,
        std::path::Path::new(local_dir),
    );
    diff.skipped_remote = outcome.skipped;

    // Caveat size-only (report utente): senza --checksum un file con
    // stessa dimensione ma contenuto diverso passa inosservato come
    // IDENTICAL. Il default resta size (veloce, spec §6) ma il caso non
    // deve piu' essere silenzioso: warn esplicita se ci sono file marcati
    // identici per sola dimensione.
    if !checksum {
        let identical_files = sync::count_identical_files(&diff);
        if identical_files > 0 {
            eprintln!(
                "[WARN] {} file considerati identici per sola dimensione — \
                 usa --checksum per confronto contenuto",
                identical_files
            );
        }
    }
    let plan = sync::build_plan(&diff, params.delete);

    // Esecuzione: connect_and_handshake è la callback di connessione della
    // SyncSession (riusata; reconnect-on-drop). Niente parallele.
    let report =
        sync::execute_sync(&plan, &params, || async { connect_and_handshake().await }).await?;

    // Report finale.
    sync::print_sync_report(&report, params.quiet, params.dry_run);

    // --ephemeral: il quit va inviato PRIMA dell'eventuale exit(1) per
    // errori di sync — un agente effimero non deve restare appeso per
    // un job fallito.
    if quit_after {
        ephemeral_quit_best_effort().await;
    }

    // Exit code 1 se almeno un errore (sync-spec §11).
    if report.error_count > 0 {
        std::process::exit(1);
    }
    Ok(())
}

/// OS del remote per il quoting dei comandi shell (`--` form): INFO_RES
/// quando il server si descrive (spec §3 — il remote sa chi e'), poi
/// l'euristica env bootstrap::remote_is_unix come fallback per i server
/// pre-selfdescribe. Il fetch e' cacheato per processo: qui il server
/// e' appena stato connesso, quindi la richiesta e' quasi sempre
/// rispondibile e a costo nullo dopo reconcile.
async fn remote_is_unix_resolved() -> bool {
    if let Some(info) = server_info::fetch().await {
        return info.os == version::RemoteOs::Linux;
    }
    bootstrap::remote_is_unix()
}

/// Lato client, forma `--`: invia il comando shell-mode e streamma la
/// risposta su stdout fino a EOF. Con `quit_after` (flag --ephemeral)
/// il comando parte col prefisso QUIT_AFTER_PREFIX: e' il SERVER a
/// spegnersi a fine esecuzione (a qualunque esito — vedi
/// handle_connection), non il client a inviare un `quit` dopo.
///
/// I token sono ricomposti in base all'OS remoto: POSIX-quote su unix
/// (il raggruppamento della shell locale sopravvive — fix "sleep: missing
/// operand"), join con spazi su Windows (semantica cmd.exe).
/// Su server dello stesso BUILD_TS si chiede il marker di exit code
/// (EXIT_CODE_PREFIX) e l'exit code remoto diventa quello del processo.
async fn client_mode(tokens: &[String], quit_after: bool) -> Result<()> {
    // Connessione + handshake + auto-update (stessa logica di put/get/sync:
    // connect_and_handshake orchestra retry, bootstrap e version skew).
    let (mut socket, hello) = connect_and_handshake_hello().await?;
    // OS remoto per il quoting: identita' risolta (INFO_RES) poi env.
    let remote_unix = remote_is_unix_resolved().await;
    let cmd = runcmd::rejoin_command(tokens, remote_unix);

    // Exit-code marker: il prefisso-sentinel e' compreso SOLO da server
    // dello stesso build — su server diversi il comando resta come oggi
    // (il ts e' allineato da reconcile, quindi diverso => update fallito
    // o NO_UPDATE: in quel caso meglio il comportamento legacy).
    let want_exit_code = hello.ts == Some(version::BUILD_TS);

    let mut wire_cmd = String::new();
    if quit_after {
        wire_cmd.push_str(QUIT_AFTER_PREFIX);
    }
    if want_exit_code {
        wire_cmd.push_str(runcmd::EXIT_CODE_PREFIX);
    }
    wire_cmd.push_str(&cmd);
    socket.write_all(wire_cmd.as_bytes()).await?;

    let exit_code = stream_shell_output(&mut socket, want_exit_code, true).await?;
    if let Some(code) = exit_code {
        if code != 0 {
            std::process::exit(code);
        }
    }
    Ok(())
}

/// Streamma l'output shell-mode su stdout fino a EOF (`echo=false`:
/// drena e scarta — comandi interni come cleanup). Con `want_exit_code`
/// tiene in coda gli ultimi EXIT_MARKER_TAIL byte senza stamparli: se la
/// coda termina col marker `CROSSPILOT_EXIT_CODE=<n>` lo estrae (e non lo
/// stampa) e ne ritorna il valore; altrimenti stampa la coda e torna None
/// (server senza marker = exit code ignoto -> trattato come 0).
async fn stream_shell_output(
    socket: &mut tls::Link,
    want_exit_code: bool,
    echo: bool,
) -> Result<Option<i32>> {
    let mut stdout = tokio::io::stdout();
    let mut buf = [0; 1024];
    let mut tail: Vec<u8> = Vec::new();
    loop {
        let n = socket.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        if want_exit_code {
            // Accumula in coda e stampa solo l'eccesso: il marker puo'
            // arrivare spezzato su piu' chunk, lo troviamo sempre intero.
            tail.extend_from_slice(&buf[..n]);
            if tail.len() > runcmd::EXIT_MARKER_TAIL {
                let flush_n = tail.len() - runcmd::EXIT_MARKER_TAIL;
                if echo {
                    stdout.write_all(&tail[..flush_n]).await?;
                }
                tail.drain(..flush_n);
            }
        } else if echo {
            stdout.write_all(&buf[..n]).await?;
        }
        if echo {
            stdout.flush().await?;
        }
    }
    if want_exit_code {
        let (rest, code) = runcmd::extract_exit_marker(&tail);
        if echo && !rest.is_empty() {
            stdout.write_all(rest).await?;
            stdout.flush().await?;
        }
        return Ok(code);
    }
    Ok(None)
}

/// Un comando shell-mode "one-shot" su connessione fresca: usato dai
/// path interni (chmod post-put, cleanup di `run`) dove non serve il
/// quoting da token — la command-line e' gia' completa. L'output remoto
/// e' scartato; ritorna l'exit code quando il server e' dello stesso
/// build (prefisso-sentinel compreso), None altrove.
async fn shell_once(cmd: &str) -> Result<Option<i32>> {
    let (mut socket, hello) = connect_and_handshake_hello().await?;
    let want_exit_code = hello.ts == Some(version::BUILD_TS);
    let mut wire_cmd = String::new();
    if want_exit_code {
        wire_cmd.push_str(runcmd::EXIT_CODE_PREFIX);
    }
    wire_cmd.push_str(cmd);
    socket.write_all(wire_cmd.as_bytes()).await?;
    stream_shell_output(&mut socket, want_exit_code, false).await
}

/// Lato client, subcommand `run`: upload dello script in tmp remoto,
/// esecuzione via shell-mode (exit code propagato) e cleanup dello staged.
/// Con `quit_after` (--ephemeral) il quit finale e' best-effort DOPO il
/// cleanup (un quit nel comando di esecuzione impedirebbe il cleanup).
async fn client_run(script: &str, args: &[String], quit_after: bool) -> Result<()> {
    // Valida lo script locale (fail-fast, exit code 2 come put).
    if let Err(e) = path::require_local_file_exists(script) {
        eprintln!("[ERROR] run: {}", e);
        std::process::exit(2);
    }

    // OS remoto per la scelta di tmp/interprete: serve l'handshake, ma
    // la connessione e' per-op — uso l'euristica env-based (coerente con
    // la scelta dei dialetti bootstrap, mai in contraddizione col remote).
    let remote_unix = bootstrap::remote_is_unix();
    let remote_tmp = runcmd::remote_tmp_script_path(script, remote_unix)?;
    runcmd::check_remote_path(&remote_tmp)?;

    // 1) Upload dello script (connessione framed dedicata).
    let mut socket = connect_and_handshake().await?;
    transfer::put_client(&mut socket, script, &remote_tmp).await?;

    // 2) Esecuzione via shell-mode (connessione fresca: i modi sono
    //    per-connessione, non mixabili). Chiede il marker di exit code
    //    solo se il server e' dello stesso build (prefisso compreso).
    let exec_cmd = runcmd::build_exec_command(script, &remote_tmp, args, remote_unix)?;
    let cleanup_cmd = runcmd::build_cleanup_command(&remote_tmp, remote_unix);
    let mut exec_socket = connect_and_handshake_hello().await?;
    let want_exit_code = exec_socket.1.ts == Some(version::BUILD_TS);
    let mut wire_cmd = String::new();
    if want_exit_code {
        wire_cmd.push_str(runcmd::EXIT_CODE_PREFIX);
    }
    wire_cmd.push_str(&exec_cmd);
    exec_socket.0.write_all(wire_cmd.as_bytes()).await?;
    let exec_outcome = stream_shell_output(&mut exec_socket.0, want_exit_code, true).await;

    // 3) Cleanup dello staged remoto: SEMPRE tentato (anche a exec
    //    fallita), best-effort — lo script in tmp non deve sopravvivere.
    if let Err(e) = shell_once(&cleanup_cmd).await {
        eprintln!("[WARN] run: cleanup remoto fallito ({}): {}", remote_tmp, e);
    }

    // --ephemeral: shutdown finale a operazione conclusa.
    if quit_after {
        ephemeral_quit_best_effort().await;
    }

    let exit_code = exec_outcome?;
    if let Some(code) = exit_code {
        if code != 0 {
            std::process::exit(code);
        }
    }
    crate::qprintln!("run: {} eseguito sul remote ({})", script, remote_tmp);
    Ok(())
}

/// Lato client: spegnimento esplicito del server remoto. Apre una
/// connessione shell-mode fresca (connect_and_handshake = handshake +
/// auto-update, nessuna operazione intermedia) e invia `quit` — il
/// comando che handle_connection riconosce gia' oggi. Usata dal
/// sottocomando `quit`, da `--ephemeral` senza comando e come
/// post-operazione dei comandi framed (put/get/status/sync).
async fn client_quit() -> Result<()> {
    let mut socket = connect_and_handshake().await?;
    socket.write_all(b"quit").await?;
    let _ = socket.flush().await;
    // Attende l'EOF: il server chiude il socket subito dopo la notify di
    // shutdown (handle_connection ritorna, il task droppa il socket) —
    // conferma che la richiesta e' stata consegnata. Timeout di guardia:
    // su un remote anomalo il client non deve restare appeso.
    let mut buf = [0u8; 64];
    let eof = tokio::time::timeout(Duration::from_secs(5), socket.read(&mut buf)).await;
    match eof {
        Ok(Ok(0)) => crate::qprintln!("[DEBUG] quit consegnato: server in shutdown."),
        _ => eprintln!(
            "[WARN] quit inviato ma nessun EOF entro 5s: il server potrebbe non spegnersi."
        ),
    }
    Ok(())
}

/// `quit` post-operazione per --ephemeral sui comandi framed
/// (put/get/status/sync): la shell-mode non copre quei messaggi, quindi
/// lo shutdown e' guidato dal client su connessione fresca. Best-effort:
/// un fallimento del quit NON deve mascherare l'esito dell'operazione
/// principale — il warning resta nel log.
async fn ephemeral_quit_best_effort() {
    crate::qprintln!("[ephemeral] operazione conclusa: invio quit al server...");
    if let Err(e) = client_quit().await {
        eprintln!("[WARN] --ephemeral: quit post-operazione fallito: {:#}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ready_line_legacy() {
        // "READY" secco: server pre auto-update -> ts assente.
        let hello = parse_ready_line("READY").unwrap();
        assert_eq!(hello.ts, None);
    }

    #[test]
    fn parse_ready_line_ts_senza_os() {
        // Formato attuale: "READY <ts>" (READY porta SOLO il ts — §1.1).
        let hello = parse_ready_line("READY 1758530400").unwrap();
        assert_eq!(hello.ts, Some(1758530400));
    }

    #[test]
    fn parse_ready_line_tag_extra_ignorati() {
        // §1.1: i token oltre il ts (il vecchio tag OS L|W o qualunque
        // extra futuro) sono IGNORATI — l'handshake non fallisce mai
        // per un tag non capito, ma il tag non ha piu' effetto.
        let hello = parse_ready_line("READY 1758530400 L").unwrap();
        assert_eq!(hello.ts, Some(1758530400));
        let hello = parse_ready_line("READY 7 X y z").unwrap();
        assert_eq!(hello.ts, Some(7));
    }

    #[test]
    fn parse_ready_line_ts_malformato_e_sconosciuto() {
        // ts non numerico -> 0 (server "piu' vecchio di tutti").
        let hello = parse_ready_line("READY abc").unwrap();
        assert_eq!(hello.ts, Some(0));
        // Righe non-READY: zombie/protocollo diverso -> errore.
        assert!(parse_ready_line("HELLO").is_err());
        assert!(parse_ready_line("").is_err());
    }

    #[tokio::test]
    async fn ready_grace_cold_start_delayed() {
        // Race di cold-start (bug report #0): il listener accetta subito
        // (backlog kernel) ma scrive READY solo dopo l'init — oltre la
        // finestra "fast". La fase 2 sulla stessa socket deve riceverlo.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let acc = listener.accept().await;
            let (mut srv, _) = acc.unwrap();
            // Ritardo > fast(50ms): simula l'init del server pre-accept.
            tokio::time::sleep(Duration::from_millis(200)).await;
            // READY spezzato in due write: verifica anche che i byte
            // parziali della prima fase sopravvivano alla seconda
            // (buffer condiviso, niente perdita di segmenti a cavallo).
            let w1 = srv.write_all(b"READY 1758").await;
            w1.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            let w2 = srv.write_all(b"530400 L\n").await;
            w2.unwrap();
        });
        let addr = format!("127.0.0.1:{}", port);
        let mut s = TcpStream::connect(&addr).await.unwrap();
        let mut line = Vec::new();
        let hello = read_ready_line_grace(
            &mut s,
            &mut line,
            Duration::from_millis(50),
            Duration::from_secs(2),
            "test",
        )
        .await
        .unwrap();
        // Il tag OS (o qualunque token extra) e' ignorato (§1.1).
        assert_eq!(hello.ts, Some(1758530400));
    }

    #[tokio::test]
    async fn ready_grace_listener_silenzioso_timeout() {
        // Listener estraneo che accetta ma non parla mai: la finestra
        // cold-start scade comunque e l'errore resta "handshake timeout"
        // (segnale corretto per il fallback al bootstrap).
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let acc = listener.accept().await;
            let (_srv, _) = acc.unwrap();
            // Tiene la connessione aperta senza mai scrivere.
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let addr = format!("127.0.0.1:{}", port);
        let mut s = TcpStream::connect(&addr).await.unwrap();
        let mut line = Vec::new();
        let res = read_ready_line_grace(
            &mut s,
            &mut line,
            Duration::from_millis(30),
            Duration::from_millis(120),
            "test",
        )
        .await;
        let err = res.unwrap_err().to_string();
        assert!(err.contains("handshake timeout"), "err={}", err);
    }
}
