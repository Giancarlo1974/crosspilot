use clap::{Parser, Subcommand};
use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command;
use std::process::Stdio;
use std::sync::Arc;
use tokio::sync::Notify;
use std::io::ErrorKind;
use std::time::Duration;
// Solo nel path Windows (retry loop AddrInUse in server_mode).
#[cfg(target_os = "windows")]
use std::time::Instant;

// Moduli del transfer file (vedi docs/transfer-spec.md).
mod proto;
mod path;
mod verify;
// transfer.rs resta invariato rispetto alla spec (§12): i warning clippy
// di stile si silenziano qui invece di toccare il file.
#[allow(clippy::manual_range_contains, clippy::manual_div_ceil)]
mod transfer;
// Modulo directory sync (vedi docs/sync-spec.md).
mod sync;
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
// Auto-update bidirezionale via TCP (READY <ts> + UPDATE_REQ + updater).
mod update;

#[cfg(target_os = "windows")]
mod win_job {
    use winapi::um::jobapi2::{CreateJobObjectW, AssignProcessToJobObject, SetInformationJobObject};
    use winapi::um::winnt::{JobObjectExtendedLimitInformation, JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, HANDLE};
    use std::ptr;
    use std::mem;
    use anyhow::Result;

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
            unsafe { winapi::um::handleapi::CloseHandle(self.0); }
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
#[command(long_about = "CrossPilot - Remote Command Executor for Windows Containers\n\n\
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
      crosspilot put|get|status|sync  File transfer and directory sync\n\n\
    The -- form passes everything after it literally to cmd.exe on the remote\n\
    Windows host, with no shell escaping. Use single quotes around paths with\n\
    trailing backslashes: crosspilot -- dir 'c:\\'")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Run as server (listens for incoming commands)
    #[arg(long, help = "Run in server mode - listens for incoming command requests")]
    server: bool,

    /// Comando da eseguire sul server Windows remoto.
    ///
    /// Tutto ciò che segue `--` viene preso letteralmente (i token sono uniti
    /// con spazi) e inviato a cmd.exe sul server Windows. Evita l'escaping
    /// della shell Linux.
    ///
    /// Esempi:
    ///   crosspilot -- dir 'c:\\'
    ///   crosspilot -- powershell -Command "Get-ChildItem 'C:\\Program Files'"
    ///   crosspilot -- echo "hello 'world' \"test\""
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        num_args = 1..,
        value_name = "COMMAND",
        help = "Command to execute on the remote Windows server (use -- to pass it)"
    )]
    raw_cmd: Vec<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the server (explicit subcommand)
    Server {
        /// Port to listen on (can also be set via CROSSPILOT_SERVER_PORT env var)
        #[arg(short, long, default_value = "5330", help = "TCP port for server to listen on")]
        port: u16,
    },
    /// Upload (put) di un file locale verso il server remoto (transfer delta stile rsync).
    Put {
        /// Path sorgente locale (Linux).
        local_src: String,
        /// Path destinazione remoto (Windows, es. C:\ci\app.exe).
        remote_dst: String,
    },
    /// Download (get) di un file remoto verso un path locale (transfer delta stile rsync).
    Get {
        /// Path sorgente remoto (Windows, es. C:\ci\log.txt).
        remote_src: String,
        /// Path destinazione locale (Linux).
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
    },
    /// Mirror one-way upload (Linux -> Windows) della directory.
    Sync {
        /// Directory sorgente locale (Linux). Deve esistere.
        local_dir: String,
        /// Directory destinazione remota (Windows, path assoluto).
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
    eprintln!(
        "[DEBUG] ambiente attivo: {} -> host={} winrm={} client={}",
        env_label, env_host, env_winrm, env_client
    );

    let cli = Cli::parse();

    if cli.server || matches!(cli.command, Some(Commands::Server { .. })) {
        let port = if let Some(Commands::Server { port }) = cli.command {
            port
        } else {
            5330
        };
        server_mode(port).await?;
    } else if !cli.raw_cmd.is_empty() {
        // Forma raw: `crosspilot -- dir c:\`. I token dopo `--` sono
        // presi letteralmente da clap (allow_hyphen_values + trailing_var_arg)
        // e uniti con spazi per ricostruire il comando cmd.exe.
        let cmd = cli.raw_cmd.join(" ");
        client_mode(&cmd).await?;
    } else {
        match cli.command {
            // Transfer file: upload (put) lato client.
            Some(Commands::Put { local_src, remote_dst }) => {
                client_transfer_put(&local_src, &remote_dst).await?;
            }
            // Transfer file: download (get) lato client.
            Some(Commands::Get { remote_src, local_dst }) => {
                client_transfer_get(&remote_src, &local_dst).await?;
            }
            // Directory sync: status (diff read-only) lato client.
            Some(Commands::Status { local_dir, remote_dir, checksum, quiet }) => {
                client_sync_status(&local_dir, &remote_dir, checksum, quiet).await?;
            }
            // Directory sync: sync (mirror one-way upload) lato client.
            Some(Commands::Sync { local_dir, remote_dir, delete, dry_run, checksum, quiet }) => {
                client_sync(&local_dir, &remote_dir, delete, dry_run, checksum, quiet).await?;
            }
            // Updater staged (auto-update via TCP): uso interno.
            Some(Commands::Update { target, wait_pid, port, wait_secs, relaunch_args, console }) => {
                update::run_updater(target, wait_pid, port, wait_secs, relaunch_args, console).await?;
            }
            // CRUD ambienti host nel .env (nessuna connessione richiesta).
            Some(Commands::Env { action }) => {
                envs::run(&action)?;
            }
            _ => {
                println!("CrossPilot - Remote Command Executor for Windows Containers");
                println!("---------------------------------------------------------------");
                // Ambiente attivo ben visibile: e' il target di TUTTI i comandi.
                println!("Ambiente attivo: {} -> host {} (winrm:{}, client:{})",
                    envs::active_name().unwrap_or_else(|| "default".to_string()),
                    env_host, env_winrm, env_client);
                println!("Usage:");
                println!("  crosspilot -- <COMMAND>   # Execute command remotely (Linux side)");
                println!("  crosspilot --server       # Run in Server Mode (Windows side)");
                println!("  crosspilot put <local> <remote>   # Upload file (rsync delta)");
                println!("  crosspilot get <remote> <local>   # Download file (rsync delta)");
                println!("  crosspilot status <local> <remote>  # Diff directory (read-only)");
                println!("  crosspilot sync   <local> <remote>  # Mirror directory (upload)");
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
                println!("The -- form passes everything after it literally to cmd.exe on the");
                println!("remote Windows host, with no shell escaping. Use single quotes around");
                println!("paths with trailing backslashes.");
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
                println!("     crosspilot -- quit");
                println!();
                println!("  5. Upload a file:");
                println!("     crosspilot put ./app.exe C:\\ci\\app.exe");
                println!();
                println!("  6. Download a file:");
                println!("     crosspilot get  C:\\ci\\log.txt ./log.txt");
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
        let _ = Command::new("cmd").args(["/C", "chcp 65001"]).output().await;
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
                        tokio::spawn(async move {
                            // Handshake: "READY <BUILD_TS>" — il ts rende il
                            // server self-describing per l'auto-update via TCP
                            // (i client legacy leggono 6 byte "READY " e
                            // falliscono -> bootstrap WinRM -> self-update).
                            // TODO: in futuro inviare anche il tag OS del
                            // server come terzo token — "READY <ts> L" su
                            // unix, "READY <ts> W" su Windows. Il client
                            // parsa gia' il token opzionale
                            // (version::ServerHello.os) e lo usa per la
                            // scelta del payload di update al posto
                            // dell'euristica EXE_PATH. NON inviarlo finche'
                            // circolano client attuali: "READY <ts> L"
                            // verrebbe letto come ts non parsabile -> 0 ->
                            // update forzato del server.
                            let hello = format!("READY {}\n", version::BUILD_TS);
                            if let Err(e) = socket.write_all(hello.as_bytes()).await {
                                eprintln!("Failed to send handshake: {}", e);
                                return;
                            }
                            let _ = socket.flush().await;
            
                            if let Err(e) = handle_connection(socket, shutdown_signal).await {
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
        if alive { "server crosspilot VIVO (niente kill)" } else { "nessuna risposta valida (reclaim)" }
    );
    alive
}

#[cfg(target_os = "windows")]
async fn kill_listener_on_port_windows(port: u16) -> Result<()> {
    // Find PID(s) listening on a port and terminate them.
    // netstat output example:
    // TCP    0.0.0.0:5330   0.0.0.0:0   LISTENING   12345
    let find_cmd = format!(
        "netstat -a -n -o | findstr LISTENING | findstr :{}",
        port
    );

    let out = Command::new("cmd")
        .args(["/C", &find_cmd])
        .output()
        .await
        .context("Failed to run netstat to locate PID")?;

    // If nothing found, maybe the port was released in the meantime.
    if out.stdout.is_empty() {
        println!("[kill_listener] netstat returned no LISTENING lines for port {}", port);
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
        println!("[kill_listener] No PIDs parsed from netstat output for port {}", port);
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
            eprintln!("[kill_listener] Warning: taskkill failed for PID {}: {}", pid, stderr.trim());
        } else {
            let stdout_kill = String::from_utf8_lossy(&kill.stdout);
            println!("[kill_listener] taskkill success for PID {}: {}", pid, stdout_kill.trim());
        }
    }

    // Give Windows a moment to release the socket
    println!("[kill_listener] Sleeping 800ms for socket release...");
    tokio::time::sleep(tokio::time::Duration::from_millis(800)).await;
    Ok(())
}

async fn handle_connection(mut socket: TcpStream, shutdown_signal: Arc<Notify>) -> Result<()> {
    // Detection modalità (spec §5): peek cumulativo fino a 4 byte.
    // Se i 4 byte == magic "DFB1" -> modo file (transfer). Altrimenti -> modo shell.
    // peek (non read) non consuma i byte: il socket è intatto per entrambe le modalità.
    let mut peek_buf = [0u8; 4];
    let mut filled = 0;
    let mut timed_out = false;
    loop {
        let peek_result = tokio::time::timeout(
            Duration::from_secs(2),
            socket.peek(&mut peek_buf[filled..]),
        )
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

    // Se abbiamo 4 byte e corrispondono al magic "DFB1" -> modo file transfer.
    if filled == 4 && peek_buf == *b"DFB1" {
        eprintln!("[DEBUG] handle_connection: rilevata modalità file transfer (magic DFB1)");
        // Delega al modulo transfer. Il socket non è stato consumato (peek).
        if let Err(e) = handle_file_mode(socket).await {
            eprintln!("[ERROR] file transfer fallito: {}", e);
        }
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
        eprintln!("[DEBUG] handle_connection: peek timeout, modalità shell");
    }

    // 1. Read command (read riparte dall'inizio: peek non ha consumato i byte).
    let mut buf = [0; 1024];
    let n = socket.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }
    let command_line = String::from_utf8_lossy(&buf[..n]).trim().to_string();
    println!("Received command: {}", command_line);

    // Check for quit/exit command
    if command_line.eq_ignore_ascii_case("quit") || command_line.eq_ignore_ascii_case("exit") {
        println!("Quit command received. notifying shutdown.");
        shutdown_signal.notify_one();
        return Ok(());
    }

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
        .raw_arg(&command_line)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // .stdin(Stdio::piped()) // Future improvement for interactive
        .spawn()
        .context("Failed to spawn command")?;
    #[cfg(not(target_os = "windows"))]
    let mut child = Command::new(shell)
        .arg(flag)
        .arg(&command_line)
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
    let (mut socket_reader, mut socket_writer) = socket.into_split();
    
    // Notification to kill child if socket drops
    let kill_notify = Arc::new(Notify::new());
    let kill_notify_clone_read = kill_notify.clone();
    let kill_notify_clone_write = kill_notify.clone();

    // Monitor socket for disconnection (Read EOF)
    tokio::spawn(async move {
        let mut buf = [0; 1024];
        // We don't expect any more data from client, so any read returning 0 means EOF (disconnect).
        loop {
            match socket_reader.read(&mut buf).await {
                Ok(0) => {
                    kill_notify_clone_read.notify_one();
                    break;
                }
                Ok(_) => { } // Ignore extra data
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

    let stdout_handle = tokio::spawn(async move {
        let mut buf = [0; 1024];
        loop {
            match stdout_reader.read(&mut buf).await {
                Ok(0) => break, // EOF
                Ok(n) => {
                    if tx.send(buf[..n].to_vec()).await.is_err() { break; }
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
                    if tx_stderr.send(buf[..n].to_vec()).await.is_err() { break; }
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
    });

    // Wait for child to exit OR kill signal
    tokio::select! {
        _ = child.wait() => {
            // Process finished normally
        }
        _ = kill_notify.notified() => {
            println!("Client disconnected, killing process...");
            let _ = child.kill().await;
        }
    }

    // Cleanup
    let _ = stdout_handle.await;
    let _ = stderr_handle.await;
    let _ = writer_handle.await;

    Ok(())
}

/// Gestisce la modalità file transfer lato server (spec §5, §6).
/// Legge il primo messaggio framed (PUT_REQ o GET_REQ) e delega al modulo transfer.
async fn handle_file_mode(mut socket: TcpStream) -> Result<()> {
    // Legge il primo messaggio: il magic "DFB1" è già stato peek-ato ma non consumato,
    // quindi read_msg lo rilegge da capo insieme a version/msg_type/payload.
    //
    // Su errore di framing (magic/versione/payload invalidi) si tenta PRIMA un
    // ERR best-effort e poi si chiude: senza di esso il client vede solo
    // "early eof" (socket chiuso senza spiegazione). E' il sintomo del server
    // H101 zombificato (build intermedia con VERSION=2) che rifiutava ogni
    // messaggio framed chiudendo in silenzio.
    let (msg_type, payload) = match proto::read_msg(&mut socket).await {
        Ok(v) => v,
        Err(e) => {
            let err = proto::ErrMsg {
                code: proto::ERR_PROTO,
                message: format!("framing non valido: {}", e),
            };
            // Best-effort: se il socket e' gia' rotto la scrittura fallisce
            // silenziosamente e il client vedra' comunque early eof.
            let _ = proto::send_err(&mut socket, &err).await;
            return Err(e);
        }
    };

    match msg_type {
        proto::MSG_PUT_REQ => {
            let req = proto::decode_put_req(&payload)?;
            eprintln!("[DEBUG] handle_file_mode: PUT_REQ dst={} ({} byte)", req.path, req.total_new_size);
            transfer::put_server(&mut socket, req).await?;
        }
        proto::MSG_GET_REQ => {
            let req = proto::decode_get_req(&payload)?;
            eprintln!("[DEBUG] handle_file_mode: GET_REQ src={}", req.path);
            transfer::get_server(&mut socket, req).await?;
        }
        // Directory sync (sync-spec §5): messaggi LIST/MKDIR_BATCH/DELETE_BATCH.
        proto::MSG_LIST_REQ => {
            let req = proto::decode_list_req(&payload)?;
            eprintln!("[DEBUG] handle_file_mode: LIST_REQ path={} recursive={} with_hash={}", req.path, req.recursive, req.with_hash);
            sync_server::list_server(&mut socket, &req).await?;
        }
        proto::MSG_MKDIR_BATCH_REQ => {
            let req = proto::decode_mkdir_batch_req(&payload)?;
            eprintln!("[DEBUG] handle_file_mode: MKDIR_BATCH_REQ count={}", req.paths.len());
            sync_server::mkdir_batch_server(&mut socket, &req).await?;
        }
        proto::MSG_DELETE_BATCH_REQ => {
            let req = proto::decode_delete_batch_req(&payload)?;
            eprintln!("[DEBUG] handle_file_mode: DELETE_BATCH_REQ count={}", req.items.len());
            sync_server::delete_batch_server(&mut socket, &req).await?;
        }
        // Self-update via TCP (update-spec): spawn updater staged + uscita.
        proto::MSG_UPDATE_REQ => {
            let req = proto::decode_update_req(&payload)?;
            eprintln!("[DEBUG] handle_file_mode: UPDATE_REQ staged={}", req.staged_path);
            update::server_apply_update(&mut socket, &req).await?;
        }
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
    Ok(())
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

/// Legge la riga di handshake del server fino a '\n' (cap 256 byte) e la
/// parsa (parse_ready_line). Errore su EOF/riga sconosciuta (zombie).
async fn read_ready_line(s: &mut TcpStream) -> Result<version::ServerHello> {
    let mut line = Vec::with_capacity(32);
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
    let text = String::from_utf8_lossy(&line);
    parse_ready_line(text.trim_end())
}

/// Parsa la riga di handshake del server:
///   "READY"          -> ServerHello { ts: None, os: None } (server legacy)
///   "READY <ts>"     -> ServerHello { ts: Some(ts), os: None }
///   "READY <ts> L"   -> os = Some(Linux)   (server futuri)
///   "READY <ts> W"   -> os = Some(Windows) (server futuri)
///
/// Il terzo token (tag OS) e' OPZIONALE e forward-compatible: i server
/// attuali non lo inviano, quelli futuri dichiareranno il proprio OS e
/// il client lo usera' al posto dell'euristica EXE_PATH per scegliere
/// il payload dell'update (binario linux vs PE). Token sconosciuti sono
/// tollerati come "non dichiarato" — mai rifiutare l'handshake per un
/// tag che non capiamo.
/// Funzione pura (separata dalla lettura socket per essere unit-testabile).
fn parse_ready_line(text: &str) -> Result<version::ServerHello> {
    if text == "READY" {
        return Ok(version::ServerHello::default());
    }
    if let Some(rest) = text.strip_prefix("READY ") {
        let mut tokens = rest.split_whitespace();
        // Primo token: BUILD_TS. Non numerico -> 0 (server "ignoto",
        // trattato come piu' vecchio di qualsiasi build versionato).
        let ts = tokens
            .next()
            .and_then(|t| t.parse::<u64>().ok())
            .unwrap_or(0);
        // Secondo token (opzionale): tag OS "L"|"W".
        let os = tokens.next().and_then(version::RemoteOs::from_tag);
        return Ok(version::ServerHello {
            ts: Some(ts),
            os,
        });
    }
    bail!("handshake sconosciuto: {:?}", text);
}

/// Una connessione TCP + lettura handshake "READY <ts> [<os>]" (singolo
/// tentativo, niente retry/bootstrap/update). Ritorna il socket e il
/// ServerHello remoto (ts None = server legacy; os None = OS non
/// dichiarato). Usata da connect_and_handshake e dall'interno
/// dell'orchestrazione update (le connessioni di PUT/GET/shell non devono
/// ri-triggerare il confronto di versione).
pub(crate) async fn connect_raw(addr: &str) -> Result<(TcpStream, version::ServerHello)> {
    let mut s = tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(addr))
        .await
        .context("connect timeout")??;
    let hello = tokio::time::timeout(Duration::from_millis(1500), read_ready_line(&mut s))
        .await
        .context("handshake timeout")??;
    Ok((s, hello))
}

/// Stabilisce la connessione TCP al server, verifica l'handshake
/// "READY <ts>" e orchestra l'auto-update via TCP sul version skew
/// (update::reconcile). Bootstrap WinRM solo se il server non risponde.
/// Riutilizzata dai comandi shell (--), transfer file (put/get) e sync.
async fn connect_and_handshake() -> Result<TcpStream> {
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
        eprintln!("Connecting to {} (Attempt {})...", addr, attempt);

        let conn = connect_raw(&addr).await;
        let (s, hello) = match conn {
            Ok(v) => v,
            Err(e) => {
                if let Some(dl) = update_deadline {
                    if std::time::Instant::now() < dl {
                        eprintln!("[DEBUG] update in corso, retry... ({})", e);
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                    // L'updater non ha rialzato il server entro la deadline:
                    // caduta al bootstrap WinRM come ultima spiaggia.
                    eprintln!("[update] nuovo server non salito entro la deadline; fallback bootstrap.");
                    update_deadline = None;
                    attempt = 0;
                }
                if attempt >= max_attempts {
                    return Err(final_connect_error(&addr));
                }
                eprintln!("Connection failed or timed out. Bootstrapping...");
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

        eprintln!(
            "[DEBUG] handshake: remote_ts={:?} remote_os={:?} locale={}",
            hello.ts,
            hello.os,
            version::BUILD_TS
        );
        match update::reconcile(hello).await {
            update::Reconcile::Proceed => {
                eprintln!("Connected and verified.");
                return Ok(s);
            }
            update::Reconcile::Reconnect => {
                eprintln!("[update] server in aggiornamento: attesa restart (max 90s)...");
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
                eprintln!("[update] server aggiornato via fallback bootstrap: riconnessione...");
                update_deadline = Some(std::time::Instant::now() + Duration::from_secs(90));
                attempt = 0;
                continue;
            }
        }
    }
}

/// Lato client: PUT (upload) di un file locale verso il server.
/// Stabilisce la connessione, handshake, poi delega a transfer::put_client.
/// Exit code: 0 ok, 1 errore protocollo/IO, 2 path invalido.
async fn client_transfer_put(local_src: &str, remote_dst: &str) -> Result<()> {
    // Valida il path sorgente locale prima di connettersi (fail-fast, exit code 2).
    if let Err(e) = path::require_local_file_exists(local_src) {
        eprintln!("[ERROR] put: {}", e);
        std::process::exit(2);
    }

    let mut socket = connect_and_handshake().await?;
    transfer::put_client(&mut socket, local_src, remote_dst).await?;
    eprintln!("put: trasferimento completato ({} -> {})", local_src, remote_dst);
    Ok(())
}

/// Lato client: GET (download) di un file remoto verso un path locale.
/// Stabilisce la connessione, handshake, poi delega a transfer::get_client.
/// Exit code: 0 ok, 1 errore protocollo/IO, 2 path invalido.
async fn client_transfer_get(remote_src: &str, local_dst: &str) -> Result<()> {
    let mut socket = connect_and_handshake().await?;
    transfer::get_client(&mut socket, remote_src, local_dst).await?;
    eprintln!("get: trasferimento completato ({} -> {})", remote_src, local_dst);
    Ok(())
}

/// Lato client: status (diff read-only) tra directory locale e remota.
/// sync-spec §6. Exit code: 0 ok (anche con differenze), 1 errore, 2 path invalido.
async fn client_sync_status(local_dir: &str, remote_dir: &str, checksum: bool, quiet: bool) -> Result<()> {
    // Valida local_dir prima di connettersi (fail-fast, exit code 2).
    if let Err(e) = path::require_local_dir_exists(local_dir) {
        eprintln!("[ERROR] status: {}", e);
        std::process::exit(2);
    }

    // 1 connessione per LIST (sync-spec §5: una connessione = una operazione).
    let mut socket = connect_and_handshake().await?;
    let remote_entries = sync::list_remote_dir(&mut socket, remote_dir, checksum).await?;

    // Walk locale (skip non-UTF8 + nomi riservati Windows, sync-spec §8.3).
    let local_walk = sync::walk_local_dir(std::path::Path::new(local_dir))?;

    // Diff (con lowercase per case-insensitivity Windows, sync-spec §8.1).
    let diff = sync::compute_diff(&local_walk, &remote_entries, checksum, std::path::Path::new(local_dir));

    // Output testuale (o riepilogo numerico se --quiet).
    sync::print_status(&diff, quiet);

    Ok(())
}

/// Lato client: sync (mirror one-way upload) della directory.
/// sync-spec §7. Exit code: 0 se tutto ok, 1 se almeno un errore (ma sync completa
/// tutti i file possibili), 2 path invalido.
async fn client_sync(
    local_dir: &str,
    remote_dir: &str,
    delete: bool,
    dry_run: bool,
    checksum: bool,
    quiet: bool,
) -> Result<()> {
    // Valida local_dir prima di connettersi (fail-fast, exit code 2).
    if let Err(e) = path::require_local_dir_exists(local_dir) {
        eprintln!("[ERROR] sync: {}", e);
        std::process::exit(2);
    }

    // 1 connessione per LIST (sync-spec §5).
    let mut socket = connect_and_handshake().await?;
    let remote_entries = sync::list_remote_dir(&mut socket, remote_dir, checksum).await?;

    // Walk locale.
    let local_walk = sync::walk_local_dir(std::path::Path::new(local_dir))?;

    // Diff + piano.
    let diff = sync::compute_diff(&local_walk, &remote_entries, checksum, std::path::Path::new(local_dir));
    let plan = sync::build_plan(&diff, delete);

    // Esecuzione: connect_and_handshake è la callback per ogni nuova connessione
    // (LIST, put, MKDIR, DELETE). Niente parallele (best-practice).
    let params = sync::SyncParams {
        local_dir: local_dir.to_string(),
        remote_dir: remote_dir.to_string(),
        delete,
        dry_run,
        quiet,
    };
    let report = sync::execute_sync(&plan, &params, || async { connect_and_handshake().await }).await?;

    // Report finale.
    sync::print_sync_report(&report, quiet);

    // Exit code 1 se almeno un errore (sync-spec §11).
    if report.error_count > 0 {
        std::process::exit(1);
    }
    Ok(())
}

async fn client_mode(cmd: &str) -> Result<()> {
    // Connessione + handshake + auto-update (stessa logica di put/get/sync:
    // connect_and_handshake orchestra retry, bootstrap e version skew).
    let mut socket = connect_and_handshake().await?;

    // Send command
    socket.write_all(cmd.as_bytes()).await?;
    
    // Stream output to stdout
    let mut stdout = tokio::io::stdout();
    let mut buf = [0; 1024];
    loop {
        let n = socket.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        stdout.write_all(&buf[..n]).await?;
        stdout.flush().await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ready_line_legacy() {
        // "READY" secco: server pre auto-update -> ts/os assenti.
        let hello = parse_ready_line("READY").unwrap();
        assert_eq!(hello.ts, None);
        assert_eq!(hello.os, None);
    }

    #[test]
    fn parse_ready_line_ts_senza_os() {
        // Formato attuale: "READY <ts>" senza tag OS.
        let hello = parse_ready_line("READY 1758530400").unwrap();
        assert_eq!(hello.ts, Some(1758530400));
        assert_eq!(hello.os, None);
    }

    #[test]
    fn parse_ready_line_ts_con_os() {
        // Formato futuro: "READY <ts> L|W" — il client deve capire il
        // tag OS gia' oggi (i server lo invieranno piu' avanti).
        let hello = parse_ready_line("READY 1758530400 L").unwrap();
        assert_eq!(hello.ts, Some(1758530400));
        assert_eq!(hello.os, Some(version::RemoteOs::Linux));

        let hello = parse_ready_line("READY 1758530400 W").unwrap();
        assert_eq!(hello.ts, Some(1758530400));
        assert_eq!(hello.os, Some(version::RemoteOs::Windows));
    }

    #[test]
    fn parse_ready_line_tag_sconosciuto_tollerato() {
        // Tag OS non riconosciuto: tollerato come "non dichiarato",
        // l'handshake NON deve fallire (forward-compat).
        let hello = parse_ready_line("READY 7 X").unwrap();
        assert_eq!(hello.ts, Some(7));
        assert_eq!(hello.os, None);
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
}
