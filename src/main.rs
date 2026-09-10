use clap::{Parser, Subcommand};
use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command;
use std::process::Stdio;
use std::sync::Arc;
use tokio::sync::Notify;
use std::env;
use std::io::ErrorKind;

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
      WINBOAT_CLIENT_PORT   - Client connection port (default: 47330)")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Run as server (listens for incoming commands)
    #[arg(long, help = "Run in server mode - listens for incoming command requests")]
    server: bool,

    /// Command to execute on remote server (Client mode)
    #[arg(short, long, help = "Execute a command on the remote Windows server", value_name = "COMMAND")]
    cmd: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the server (explicit subcommand)
    Server {
        /// Port to listen on (can also be set via WINBOAT_SERVER_PORT env var)
        #[arg(short, long, default_value = "5330", help = "TCP port for server to listen on")]
        port: u16,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Try loading .env from multiple locations
    let mut env_loaded = false;
    let mut tried_paths = Vec::new();
    
    // 1. Try current working directory
    let cwd_env = std::env::current_dir().ok().map(|p| p.join(".env"));
    if let Some(ref path) = cwd_env {
        tried_paths.push(path.display().to_string());
        if path.exists() {
            match dotenvy::from_path(path) {
                Ok(_) => {
                    eprintln!("[DEBUG] Loaded .env from: {}", path.display());
                    env_loaded = true;
                }
                Err(e) => {
                    eprintln!("[DEBUG] Failed to load .env from {}: {}", path.display(), e);
                }
            }
        }
    }
    
    // 2. Try executable directory
    if !env_loaded {
        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                let env_path = exe_dir.join(".env");
                tried_paths.push(env_path.display().to_string());
                if env_path.exists() {
                    match dotenvy::from_path(&env_path) {
                        Ok(_) => {
                            eprintln!("[DEBUG] Loaded .env from: {}", env_path.display());
                            env_loaded = true;
                        }
                        Err(e) => {
                            eprintln!("[DEBUG] Failed to load .env from {}: {}", env_path.display(), e);
                        }
                    }
                }
            }
        }
    }
    
    // 3. Try project root (parent of target/release or target/debug)
    if !env_loaded {
        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                // If we're in target/release or target/debug, go up two levels
                if exe_dir.ends_with("release") || exe_dir.ends_with("debug") {
                    if let Some(target_dir) = exe_dir.parent() {
                        if let Some(project_root) = target_dir.parent() {
                            let env_path = project_root.join(".env");
                            tried_paths.push(env_path.display().to_string());
                            if env_path.exists() {
                                match dotenvy::from_path(&env_path) {
                                    Ok(_) => {
                                        eprintln!("[DEBUG] Loaded .env from: {}", env_path.display());
                                        env_loaded = true;
                                    }
                                    Err(e) => {
                                        eprintln!("[DEBUG] Failed to load .env from {}: {}", env_path.display(), e);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    if !env_loaded {
        eprintln!("[WARNING] No .env file found in any of these locations:");
        for path in tried_paths {
            eprintln!("  - {}", path);
        }
        eprintln!("Using defaults or system environment variables.");
    }
    
    let cli = Cli::parse();

    if cli.server || matches!(cli.command, Some(Commands::Server { .. })) {
        let port = if let Some(Commands::Server { port }) = cli.command {
            port
        } else {
            5330
        };
        server_mode(port).await?;
    } else if let Some(cmd) = cli.cmd {
        client_mode(&cmd).await?;
    } else {
        println!("WinBoat Bridge - Remote Command Executor for Windows Containers");
        println!("---------------------------------------------------------------");
        println!("Usage:");
        println!("  winboat-bridge --server          # Run in Server Mode (Windows side)");
        println!("  winboat-bridge -c <COMMAND>      # Execute command remotely (Linux side)");
        println!("");
        println!("Examples:");
        println!("  1. Check remote IP:");
        println!("     winboat-bridge -c \"ipconfig\"");
        println!("");
        println!("  2. List remote directory:");
        println!("     winboat-bridge -c \"dir C:\\Users\"");
        println!("");
        println!("  3. Run PowerShell script:");
        println!("     winboat-bridge -c \"powershell -File C:\\Scripts\\test.ps1\"");
        println!("");
        println!("  4. Close remote server:");
        println!("     winboat-bridge -c \"quit\"");
        println!("-------------------------------------");
        println!("For detailed help on all parameters, run:");
        println!("  winboat-bridge -h");
    }

    Ok(())
}

async fn server_mode(port: u16) -> Result<()> {
    // Force UTF-8 code page on Windows
    #[cfg(target_os = "windows")]
    {
        let _ = Command::new("cmd").args(&["/C", "chcp 65001"]).output().await;
    }

    let actual_port = env::var("WINBOAT_SERVER_PORT")
        .ok()
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
    // 1. Read command
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

async fn client_mode(cmd: &str) -> Result<()> {
    // Same host as bootstrap (WinRM): WINBOAT_HOST. Only the port differs.
    let host = env::var("WINBOAT_HOST")
        .unwrap_or_else(|_| "127.0.0.1".to_string());
    // Port mapped on host: 47330 -> Container: 5330
    let client_port = env::var("WINBOAT_CLIENT_PORT")
        .unwrap_or_else(|_| "47330".to_string());
    let addr = format!("{}:{}", host, client_port);
    
    // Attempt connection loop (Connect -> Handshake -> if fail -> Bootstrap -> Retry)
    let mut attempt = 0;
    let max_attempts = 2;
    
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
                     return Err(anyhow::anyhow!("Failed to connect to server after bootstrap attempt"));
                }
                eprintln!("Connection failed or timed out. Bootstrapping...");
                bootstrap_server().await?;
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
                bootstrap_server().await?;
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

async fn bootstrap_server() -> Result<()> {
    let exe_path = env::var("WINBOAT_EXE_PATH")
        .context("WINBOAT_EXE_PATH must be set in the .env file")?;
    
    let log_path = env::var("WINBOAT_LOG_PATH")
        .unwrap_or_else(|_| r"C:\Users\gianca\server.log".to_string());
    
    let err_path = env::var("WINBOAT_ERR_PATH")
        .unwrap_or_else(|_| r"C:\Users\gianca\server.err".to_string());
    
    // Use PowerShell Start-Process to spawn the process in a detached state.
    // -WindowStyle Hidden: Hides the window
    // -PassThru: Returns the process object (useful for debugging, though we ignore it here)
    // We direct output to files for debugging since we can't see it easily in detached mode.
    let ps_command = format!(
        "Start-Process -FilePath '{}' -ArgumentList '--server' -WindowStyle Hidden -RedirectStandardOutput '{}' -RedirectStandardError '{}'",
        exe_path, log_path, err_path
    );
    
    // Direct evil-winrm invocation details
    let host = env::var("WINBOAT_HOST")
        .unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = env::var("WINBOAT_PORT")
        .unwrap_or_else(|_| "47320".to_string());
    let user = env::var("WINBOAT_USER")
        .unwrap_or_else(|_| "gianca".to_string());
    let pass = env::var("WINBOAT_PASS")
        .unwrap_or_else(|_| "gianca".to_string());

    println!("Bootstrapping server via evil-winrm...");
    println!("PowerShell Command: {}", ps_command);

    // We pipe the command to evil-winrm stdin, similar to how the shell script did it.
    // This avoids complex escaping issues with passing the command as an argument to evil-winrm directly.
    let mut child = Command::new("evil-winrm")
        .arg("-i").arg(host)
        .arg("-P").arg(port)
        .arg("-u").arg(user)
        .arg("-p").arg(pass)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Failed to spawn evil-winrm")?;

    let mut stdin = child.stdin.take().context("Failed to open evil-winrm stdin")?;
    
    // Wrap the command in powershell execution
    let full_command = format!("powershell -Command \"{}\"", ps_command);
    stdin.write_all(full_command.as_bytes()).await?;
    stdin.write_all(b"\n").await?; // Add newline to execute command
    stdin.write_all(b"exit\n").await?; // Ensure shell exits
    drop(stdin); // Close stdin to signal we're done sending the command

    // Consume stdout and stderr concurrently to prevent deadlocks
    let mut stdout = child.stdout.take().context("Failed to open stdout")?;
    let mut stderr = child.stderr.take().context("Failed to open stderr")?;

    let stdout_handle = tokio::spawn(async move {
        let mut data = Vec::new();
        let _ = stdout.read_to_end(&mut data).await;
        data
    });

    let stderr_handle = tokio::spawn(async move {
        let mut data = Vec::new();
        let _ = stderr.read_to_end(&mut data).await;
        data
    });

    // Wait for evil-winrm to exit, with a timeout
    println!("Waiting for bootstrap command to complete...");
    let wait_result = tokio::time::timeout(
        tokio::time::Duration::from_secs(15),
        child.wait()
    ).await;

    match wait_result {
        Ok(Ok(status)) => {
            // Wait for I/O to finish
            let _ = stdout_handle.await; 
            let stderr_data = stderr_handle.await.unwrap_or_default();
            
             if !status.success() {
                let stderr_str = String::from_utf8_lossy(&stderr_data);
                println!("Bootstrap returned non-zero. Stderr: {}", stderr_str);
            } else {
                println!("Bootstrap command executed successfully.");
            }
        },
        Ok(Err(e)) => return Err(anyhow::anyhow!("Failed to wait for evil-winrm: {}", e)),
        Err(_) => {
            println!("Bootstrap command timed out (evil-winrm hang). Killing local process and assuming remote started.");
            let _ = child.kill().await;
        }
    }

    println!("Waiting for server to start...");
    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    Ok(())
}
