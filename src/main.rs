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

// Moduli del transfer file (vedi docs/transfer-spec.md).
mod proto;
mod path;
mod verify;
mod transfer;
// Modulo directory sync v2 (vedi docs/sync-spec.md).
mod sync;
// Handler server per sync v2 (separato da sync.rs per dimensione, best-practice < 1000 righe).
mod sync_server;
// Modulo bootstrap WinRM (separato da main.rs per dimensione, best-practice < 1000 righe).
mod bootstrap;
mod deploy;
// Modulo ambienti host multipli nel .env (CRUD via sottocomando `env`).
mod envs;

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
#[command(name = "winboat-bridge")]
#[command(about = "Bridge to execute commands on WinBoat container via TCP")]
#[command(long_about = "WinBoat Bridge - Remote Command Executor for Windows Containers\n\n\
    This tool allows you to execute commands on a Windows container from Linux.\n\
    It operates in two modes: Server (runs on Windows) and Client (runs on Linux).\n\n\
    Configuration via Environment Variables:\n\
      WINBOAT_EXE_PATH      - Path to winboat-bridge.exe on Windows\n\
      WINBOAT_HOST          - WinRM host (default: 127.0.0.1)\n\
      WINBOAT_PORT          - WinRM port (default: 47320)\n\
      WINBOAT_USER          - WinRM username\n\
      WINBOAT_PASS          - WinRM password\n\
      WINBOAT_LOG_PATH      - Server log output path (default: C:\\\\Users\\\\gianca\\\\server.log)\n\
      WINBOAT_ERR_PATH      - Server error output path (default: C:\\\\Users\\\\gianca\\\\server.err)\n\
      WINBOAT_SERVER_PORT   - Server listening port (default: 5330)\n\
      WINBOAT_CLIENT_PORT   - Client connection port (default: 47330)\n\
      WINBOAT_ENV           - Active environment name (see below)\n\n\
    Multiple environments: the .env can hold N named host configs as\n\
      WINBOAT_<NAME>_<FIELD> (e.g. WINBOAT_PROD_HOST). WINBOAT_ENV selects\n\
      the active one; unprefixed keys are the fallback. Manage them with:\n\
      winboat-bridge env list|show|add|set|remove|use\n\n\
    Usage:\n\
      winboat-bridge -- <COMMAND>   Execute a command on the remote Windows server\n\
      winboat-bridge --server       Run in server mode (Windows side)\n\
      winboat-bridge put|get|status|sync  File transfer and directory sync\n\n\
    The -- form passes everything after it literally to cmd.exe on the remote\n\
    Windows host, with no shell escaping. Use single quotes around paths with\n\
    trailing backslashes: winboat-bridge -- dir 'c:\\'")]
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
    ///   winboat-bridge -- dir 'c:\\'
    ///   winboat-bridge -- powershell -Command "Get-ChildItem 'C:\\Program Files'"
    ///   winboat-bridge -- echo "hello 'world' \"test\""
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
        /// Port to listen on (can also be set via WINBOAT_SERVER_PORT env var)
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
    /// Diff read-only tra directory locale e remota (sync v2, vedi docs/sync-spec.md).
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
    /// Mirror one-way upload (Linux -> Windows) della directory (sync v2).
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
    /// Gestione degli ambienti (configurazioni host) nel file .env.
    ///
    /// Il .env può contenere N ambienti come WINBOAT_<NOME>_<CAMPO>
    /// (es. WINBOAT_PROD_HOST). WINBOAT_ENV seleziona l'ambiente attivo;
    /// le chiavi non prefissate (ambiente "default") fanno da fallback.
    Env {
        #[command(subcommand)]
        action: envs::EnvAction,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Carica il .env dal primo path candidato disponibile
    // (cwd -> exe dir -> project root). Vedi envs.rs.
    envs::load_dotenv();

    // Debug: quale ambiente host e' attivo (WINBOAT_ENV -> WINBOAT_<NOME>_*).
    match envs::active_name() {
        Some(name) => eprintln!("[DEBUG] ambiente attivo: {} (variabili WINBOAT_{}_*)", name, name),
        None => eprintln!("[DEBUG] ambiente attivo: default (variabili WINBOAT_*)"),
    }

    let cli = Cli::parse();

    if cli.server || matches!(cli.command, Some(Commands::Server { .. })) {
        let port = if let Some(Commands::Server { port }) = cli.command {
            port
        } else {
            5330
        };
        server_mode(port).await?;
    } else if !cli.raw_cmd.is_empty() {
        // Forma raw: `winboat-bridge -- dir c:\`. I token dopo `--` sono
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
            // Directory sync v2: status (diff read-only) lato client.
            Some(Commands::Status { local_dir, remote_dir, checksum, quiet }) => {
                client_sync_status(&local_dir, &remote_dir, checksum, quiet).await?;
            }
            // Directory sync v2: sync (mirror one-way upload) lato client.
            Some(Commands::Sync { local_dir, remote_dir, delete, dry_run, checksum, quiet }) => {
                client_sync(&local_dir, &remote_dir, delete, dry_run, checksum, quiet).await?;
            }
            // CRUD ambienti host nel .env (nessuna connessione richiesta).
            Some(Commands::Env { action }) => {
                envs::run(&action)?;
            }
            _ => {
                println!("WinBoat Bridge - Remote Command Executor for Windows Containers");
                println!("---------------------------------------------------------------");
                println!("Usage:");
                println!("  winboat-bridge -- <COMMAND>   # Execute command remotely (Linux side)");
                println!("  winboat-bridge --server       # Run in Server Mode (Windows side)");
                println!("  winboat-bridge put <local> <remote>   # Upload file (rsync delta)");
                println!("  winboat-bridge get <remote> <local>   # Download file (rsync delta)");
                println!("  winboat-bridge status <local> <remote>  # Diff directory (read-only)");
                println!("  winboat-bridge sync   <local> <remote>  # Mirror directory (upload)");
                println!("  winboat-bridge env <list|show|add|set|remove|use>  # Manage .env hosts");
                println!();
                println!("The -- form passes everything after it literally to cmd.exe on the");
                println!("remote Windows host, with no shell escaping. Use single quotes around");
                println!("paths with trailing backslashes.");
                println!();
                println!("Examples:");
                println!("  1. Check remote IP:");
                println!("     winboat-bridge -- ipconfig");
                println!();
                println!("  2. List remote directory (note: single quotes around the path):");
                println!("     winboat-bridge -- dir 'c:\\'");
                println!();
                println!("  3. Run PowerShell script:");
                println!("     winboat-bridge -- powershell -File C:\\Scripts\\test.ps1");
                println!();
                println!("  4. Close remote server:");
                println!("     winboat-bridge -- quit");
                println!();
                println!("  5. Upload a file:");
                println!("     winboat-bridge put ./app.exe C:\\ci\\app.exe");
                println!();
                println!("  6. Download a file:");
                println!("     winboat-bridge get  C:\\ci\\log.txt ./log.txt");
                println!();
                println!("  7. Diff directory (status):");
                println!("     winboat-bridge status ./artifacts C:\\ci\\artifacts");
                println!();
                println!("  8. Mirror directory (sync):");
                println!("     winboat-bridge sync   ./artifacts C:\\ci\\artifacts --delete");
                println!("-------------------------------------");
                println!("For detailed help on all parameters, run:");
                println!("  winboat-bridge -h");
            }
        }
    }

    Ok(())
}

async fn server_mode(port: u16) -> Result<()> {
    // Force UTF-8 code page on Windows
    #[cfg(target_os = "windows")]
    {
        let _ = Command::new("cmd").args(&["/C", "chcp 65001"]).output().await;
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
                eprintln!("Port {} already in use. Attempting to terminate existing listener and retry...", actual_port);
                kill_listener_on_port_windows(actual_port).await?;
                
                // Wait a bit more for socket to be fully released
                println!("Waiting additional 1 second for socket release...");
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                
                match TcpListener::bind(&addr).await {
                    Ok(l) => l,
                    Err(e2) if e2.kind() == ErrorKind::AddrInUse => {
                        return Err(anyhow::anyhow!(
                            "Port {} is still in use after kill attempt. Please close the existing process and retry. Underlying error: {}",
                            actual_port,
                            e2
                        ));
                    }
                    Err(e2) => return Err(e2.into()),
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
                            // Handshake: Send READY
                            if let Err(e) = socket.write_all(b"READY\n").await {
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
    // `winboat-bridge -c "dir c:\"` esattamente come su una console Windows.
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
    let (msg_type, payload) = proto::read_msg(&mut socket).await?;

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
        // Directory sync v2 (sync-spec §5): nuovi messaggi server.
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
    if bootstrap::winrm_unreachable() {
        return anyhow::anyhow!(
            "Failed to connect to {} after bootstrap attempts.\n\
             WinRM non raggiungibile sull'host remoto. Per abilitarlo, sulla macchina\n\
             Windows eseguire da PowerShell come amministratore:\n  Enable-PSRemoting -Force\n\
             (oppure: winrm quickconfig)",
            addr
        );
    }
    anyhow::anyhow!("Failed to connect to server after bootstrap attempt")
}

/// Stabilisce la connessione TCP al server e verifica l'handshake READY.
/// Riutilizzata sia dai comandi shell (-c) che dal transfer file (put/get).
async fn connect_and_handshake() -> Result<TcpStream> {
    // Risoluzione via envs: WINBOAT_<ENV>_<CAMPO> -> fallback WINBOAT_<CAMPO>.
    let host = envs::var("HOST").unwrap_or_else(|| "127.0.0.1".to_string());
    let client_port = envs::var("CLIENT_PORT").unwrap_or_else(|| "47330".to_string());
    let addr = format!("{}:{}", host, client_port);

    // Loop di tentativi con bootstrap (come client_mode esistente).
    let mut attempt = 0;
    let max_attempts = 5;
    let socket = loop {
        attempt += 1;
        eprintln!("Connecting to {} (Attempt {})...", addr, attempt);

        let connect_result = tokio::time::timeout(
            Duration::from_secs(2),
            TcpStream::connect(addr.as_str()),
        )
        .await;

        let mut s = match connect_result {
            Ok(Ok(s)) => s,
            _ => {
                if attempt >= max_attempts {
                    return Err(final_connect_error(&addr));
                }
                eprintln!("Connection failed or timed out. Bootstrapping...");
                bootstrap::bootstrap_server().await?;
                continue;
            }
        };

        // Handshake: legge "READY\n".
        let mut buf = [0u8; 6];
        let handshake_result = tokio::time::timeout(
            Duration::from_millis(1000),
            s.read_exact(&mut buf),
        )
        .await;

        match handshake_result {
            Ok(Ok(_)) if &buf == b"READY\n" => {
                eprintln!("Connected and verified.");
                break s;
            }
            _ => {
                if attempt >= max_attempts {
                    return Err(anyhow::anyhow!("Handshake failed (Zombie connection?)"));
                }
                eprintln!("Connected but no READY signal (likely Docker zombie port). Bootstrapping...");
                bootstrap::bootstrap_server().await?;
                continue;
            }
        }
    };

    Ok(socket)
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
    // Same host as bootstrap (WinRM): WINBOAT_HOST. Only the port differs.
    // Risoluzione via envs: WINBOAT_<ENV>_<CAMPO> -> fallback WINBOAT_<CAMPO>.
    let host = envs::var("HOST")
        .unwrap_or_else(|| "127.0.0.1".to_string());
    // Port mapped on host: 47330 -> Container: 5330
    let client_port = envs::var("CLIENT_PORT")
        .unwrap_or_else(|| "47330".to_string());
    let addr = format!("{}:{}", host, client_port);
    
    // Attempt connection loop (Connect -> Handshake -> if fail -> Bootstrap -> Retry)
    // Il bootstrap usa winrm-rs (puro Rust, NTLMv2) — vedi bootstrap::bootstrap_server().
    let mut attempt = 0;
    let max_attempts = 5;
    
    let mut socket = loop {
        attempt += 1;
        println!("Connecting to {} (Attempt {})...", addr, attempt);
        
        let connect_result = tokio::time::timeout(
            tokio::time::Duration::from_secs(2),
            TcpStream::connect(addr.as_str())
        ).await;

        let mut s = match connect_result {
            Ok(Ok(s)) => s,
            _ => {
                if attempt >= max_attempts {
                     return Err(final_connect_error(&addr));
                }
                eprintln!("Connection failed or timed out. Bootstrapping...");
                bootstrap::bootstrap_server().await?;
                continue;
            }
        };

        // Handshake Check
        let mut buf = [0; 6]; // "READY\n"
        let handshake_result = tokio::time::timeout(
             tokio::time::Duration::from_millis(1000),
             s.read_exact(&mut buf)
        ).await;

        match handshake_result {
            Ok(Ok(_)) if &buf == b"READY\n" => {
                println!("Connected and verified.");
                break s;
            }
            _ => {
                 if attempt >= max_attempts {
                     return Err(anyhow::anyhow!("Handshake failed (Zombie connection?)"));
                }
                println!("Connected but no READY signal (likely Docker zombie port). Bootstrapping...");
                bootstrap::bootstrap_server().await?;
                continue;
            }
        }
    };

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
