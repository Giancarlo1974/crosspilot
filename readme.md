# WinBoat Bridge [![GitHub stars](https://img.shields.io/github/stars/Giancarlo1974/winboat-bridge.svg?style=social)](https://github.com/Giancarlo1974/winboat-bridge/stargazers)


![Windows server running with .env configuration](docs/quickstart-images/header.png)

WinBoat Bridge is an orchestration tool that allows a Linux system to run commands inside a Windows environment transparently.

It was born for [WinBoat](https://github.com/Giancarlo1974/winboat) (a virtualized Windows container), but works with **any Windows machine** reachable over the network: a local Docker container, a VM, a bare-metal server, or a remote host on your LAN.

Unlike standard solutions like SSH or WinRM (used only for bootstrap), WinBoat Bridge provides a direct and fast channel, ideal for Continuous Integration (CI) pipelines and test automation.

If you are in a hurry and want to skip building from source, check the simple quickstart at [docs/quickstart.md](docs/quickstart.md) for using the ready-made binaries.

## 1. Configuration (.env File)

The project uses a .env file to manage paths and credentials.
Copy the example file and customize it before you start:

```bash
cp .env.example .env
```

**⚠️ IMPORTANT - .env File Syntax:**
- Use **double backslashes** (`\\`) for Windows paths
- **DO NOT use quotes** for values

Correct example:
```bash
WINBOAT_EXE_PATH=C:\\Users\\gianca\\Desktop\\Shared\\progetti\\rust\\winboat-bridge\\target\\release\\winboat-bridge.exe
WINBOAT_LOG_PATH=C:\\Users\\gianca\\server.log
```

Main parameters:
- **WINBOAT_EXE_PATH**: Absolute path (on Windows side) where the server is located
- **WINBOAT_HOST / PORT**: Address and port for bootstrap (WinRM). The same host is used by the client for the TCP bridge connection
- **WINBOAT_CLIENT_PORT**: Port on the Linux system (Host) mapped to the container
- **WINBOAT_SERVER_PORT**: Internal port of the Windows container that the server listens on

The .env file is automatically searched in:
1. Current working directory
2. Executable directory
3. Project root (if executable in `target/release`)

## 2. Compilation

The project generates a single binary. It must be compiled for Windows (Server) and Linux (Client).

### A. Build for Windows (Server)

You have two options, depending on where you are:

#### Option 1: Cross-compilation from Linux (Recommended for CI/CD)

If you're working on NixOS or Linux, use the dedicated script:

```bash
./build_windows.sh
```

#### Option 2: Native compilation on Windows

If you have direct access to a Windows system with Rust installed:
1. Open a PowerShell in the project root.
2. Run: `cargo build --release`
3. You'll find the file in `target\release\winboat-bridge.exe`.

Make sure the file is in the shared folder and that the path in .env (WINBOAT_EXE_PATH) points correctly to this binary.

### B. Build for Linux (Client)

On your Linux machine, compile normally:

```bash
cargo build --release
```

## 3. Global Installation (Linux)

Once you have compiled the Linux client (`cargo build --release`), copy the resulting binary into
`~/.local/bin` so that the executable stays available even if you delete or move the repository later.

```bash
# Create the directory if it doesn't exist
mkdir -p ~/.local/bin

# Remove any stale symlink left over from previous attempts
rm -f ~/.local/bin/winboat-bridge

# Copy the freshly built binary into place with the correct permissions
install -Dm755 target/release/winboat-bridge ~/.local/bin/winboat-bridge
```

This guarantees `/home/gianca/.local/bin/winboat-bridge` is a real executable and avoids "required file not found"
errors when the project directory disappears. Make sure `~/.local/bin` is in your `$PATH` (check `~/.bashrc` or `~/.zshrc`).

## 4. Docker Compose Integration

Configure port mapping in your docker-compose.yml to expose the necessary services:

```yaml
services:
  windows:
    ports:
      - "127.0.0.1:47320:5985"  # WinRM (For automatic bootstrap)
      - "127.0.0.1:47330:5330"  # WinBoat Bridge (Client-Server communication)
```

## 5. Usage Examples

Once the .env file is configured, the Linux client will handle everything automatically (including starting the Windows server if it's off).

### A. Local WinBoat container (default)

Default configuration points to a local Docker-mapped WinBoat container (`127.0.0.1`):

```bash
winboat-bridge -c "ipconfig"
```

Run a PowerShell script inside the container:

```bash
winboat-bridge -c "powershell -File C:\Scripts\Setup-Test.ps1"
```

### B. Remote Windows host

Point `WINBOAT_HOST` to the remote machine and `WINBOAT_CLIENT_PORT` to the port the bridge server is listening on. Both the bootstrap (WinRM) and the TCP data channel use the same host, only the ports differ.

`.env` for a remote host at `172.16.0.101`:

```bash
WINBOAT_HOST=172.16.0.101
WINBOAT_PORT=5985              # WinRM port on the remote host (for bootstrap)
WINBOAT_CLIENT_PORT=5330       # TCP bridge port on the remote host
```

Verify the connection to the remote host:

```bash
winboat-bridge -c "hostname"
```

Run a command on the remote Windows machine:

```bash
winboat-bridge -c "dir C:\Users"
```

Run a PowerShell script remotely:

```bash
winboat-bridge -c "powershell -File C:\Scripts\Setup-Test.ps1"
```

> **Note:** If the bridge server is already running on the remote host, the client connects directly. If it's down, the client will try to bootstrap it via WinRM using `WINBOAT_HOST`/`WINBOAT_PORT`/`WINBOAT_USER`/`WINBOAT_PASS` — make sure those credentials are valid for the remote machine.

## 6. Support the project (aka "The Star Section" ⭐)

Building tools like this is fun, but seeing stars is better! 

If this tool saved you time or just made your life easier, please **drop a star** on this repository. It costs you $0.00, but it gives me the fuel (and the dopamine) to keep building and sharing more cool stuff for free. 

Go on, click that star. You know you want to! 😉

## Troubleshooting

| Problem              | Possible Cause          | Solution |
|-----------------------|--------------------------|-----------|
| The command "hangs" | Zombie connection       | Ctrl+C and restart; the client will force a new bootstrap. |
| Connection Refused    | Wrong port mapping     | Check with `docker ps` that port 47330 is open (local) or `nc -zv <host> 5330` (remote). |
| "WINBOAT_EXE_PATH must be set" | .env file not found or wrong syntax | Verify that the .env file exists and uses double backslashes (`\\`) without quotes. Run with `--help` to see the message `[DEBUG] Loaded .env from: ...` |
| .env parsing error   | Wrong syntax          | Use double backslashes (`\\`) for Windows paths and DO NOT use quotes. |
| Bootstrap succeeds but client still can't connect | `WINBOAT_EXE_PATH` points to a non-existent file on the remote host | Run `Test-Path "<path>"` on the remote host via WinRM/PowerShell to verify the executable exists at the configured path. |
| Bootstrap fails with "Connection refused" | WinRM not enabled on the remote host | Run `Enable-PSRemoting -Force` on the remote Windows host and open port 5985 in the firewall (`Set-NetFirewallRule -Name "WINRM-HTTP-In-TCP" -RemoteAddress Any`). |
| Bootstrap fails with auth error | Wrong user/domain format | Use the UPN format `user@domain` in `WINBOAT_USER` (e.g. `user@domain.com`). Avoid `DOMAIN\user` (backslash escaping issues in .env). |
| Wrong .env loaded (points to `127.0.0.1`) | A stale `.env` exists in `target/release/` and takes precedence | Check the `[DEBUG] Loaded .env from: ...` line. If it points to `target/release/.env`, update that file too (or remove it to fall back to the project root `.env`). |
| `WINBOAT_CLIENT_PORT` mismatch on remote host | Remote host doesn't use Docker port mapping | Set `WINBOAT_CLIENT_PORT` to the actual port the server listens on (default `5330`), not the Docker-mapped `47330`. |

### .env Loading Debug

To verify that the .env file is loaded correctly, run:

```bash
./target/release/winboat-bridge --help 2>&1 | grep DEBUG
```

You should see:
```
[DEBUG] Loaded .env from: /path/to/.env
```

If you see `[WARNING] No .env file found`, check that:
1. The .env file exists in the current directory, executable directory, or project root
2. The syntax is correct (double backslashes, no quotes)
3. The file has correct read permissions
