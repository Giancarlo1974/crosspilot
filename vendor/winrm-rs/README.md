# winrm-rs

Async WinRM (WS-Management) client for Rust.

[![Crates.io](https://img.shields.io/crates/v/winrm-rs.svg)](https://crates.io/crates/winrm-rs)
[![docs.rs](https://img.shields.io/docsrs/winrm-rs)](https://docs.rs/winrm-rs)
[![CI](https://github.com/muchiny/winrm-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/muchiny/winrm-rs/actions)
[![License](https://img.shields.io/crates/l/winrm-rs.svg)](LICENSE-MIT)
[![MSRV](https://img.shields.io/badge/MSRV-1.98-blue.svg)](https://blog.rust-lang.org/2026/08/18/Rust-1.98.0.html)

```rust
use winrm_rs::{WinrmClient, WinrmConfig, WinrmCredentials};

#[tokio::main]
async fn main() -> Result<(), winrm_rs::WinrmError> {
    let client = WinrmClient::new(
        WinrmConfig::default(),
        WinrmCredentials::new("administrator", "secret", ""),
    )?;

    let output = client
        .run_powershell("win-server", "Get-Service | ConvertTo-Json")
        .await?;
    println!("{}", String::from_utf8_lossy(&output.stdout));
    Ok(())
}
```

## Features

- **NTLMv2 authentication** -- pure Rust, no OpenSSL or system SSPI required
- **Basic authentication** -- for test environments or HTTPS-secured endpoints
- **Kerberos authentication** -- via `cross-krb5`, feature-gated (`--features kerberos`)
- **Certificate authentication** -- TLS client certificate auth
- **PowerShell execution** -- scripts auto-encoded as UTF-16LE Base64 (`-EncodedCommand`)
- **Raw command execution** -- `cmd.exe` or any executable with arbitrary arguments
- **Full shell lifecycle** -- create, execute, receive, signal, delete
- **Streaming output** -- `start_command` + `receive_next` for incremental polling
- **File transfer** -- upload/download files via PowerShell base64 chunking
- **Proxy support** -- HTTP proxy for all WinRM requests
- **Async/await** -- built on `tokio` and `reqwest`
- **TLS support** -- `rustls` backend, optional invalid cert acceptance
- **Cross-platform** -- runs from Linux, macOS, or Windows

## Installation

```sh
cargo add winrm-rs
# For Kerberos support:
cargo add winrm-rs --features kerberos
```

## Usage

### Basic authentication

```rust
use winrm_rs::{AuthMethod, WinrmClient, WinrmConfig, WinrmCredentials};

let client = WinrmClient::new(
    WinrmConfig {
        auth_method: AuthMethod::Basic,
        use_tls: true,
        port: 5986,
        ..WinrmConfig::default()
    },
    WinrmCredentials::new("admin", "password", ""),
)?;
```

### NTLM authentication (default)

```rust
let client = WinrmClient::new(
    WinrmConfig::default(), // port 5985, NTLM, no TLS
    WinrmCredentials::new("admin", "password", "MYDOMAIN"),
)?;
```

### Kerberos authentication

```rust
// Requires: cargo add winrm-rs --features kerberos
// Requires: kinit user@REALM has been run
let client = WinrmClient::new(
    WinrmConfig {
        auth_method: AuthMethod::Kerberos,
        ..WinrmConfig::default()
    },
    WinrmCredentials::new("user", "", ""),
)?;
```

### Certificate authentication

```rust
let client = WinrmClient::new(
    WinrmConfig {
        auth_method: AuthMethod::Certificate,
        use_tls: true,
        port: 5986,
        client_cert_pem: Some("/path/to/cert.pem".into()),
        client_key_pem: Some("/path/to/key.pem".into()),
        ..WinrmConfig::default()
    },
    WinrmCredentials::new("admin", "", ""),
)?;
```

### PowerShell execution

```rust
let output = client.run_powershell("win-server", "$PSVersionTable | ConvertTo-Json").await?;
assert_eq!(output.exit_code, 0);
println!("{}", String::from_utf8_lossy(&output.stdout));
```

### Raw command execution

```rust
let output = client.run_command("win-server", "ipconfig", &["/all"]).await?;
println!("{}", String::from_utf8_lossy(&output.stdout));
```

### Streaming output

```rust
let shell = client.open_shell("win-server").await?;
let cmd_id = shell.start_command("ping", &["-t", "10.0.0.1"]).await?;
loop {
    let chunk = shell.receive_next(&cmd_id).await?;
    print!("{}", String::from_utf8_lossy(&chunk.stdout));
    if chunk.done { break; }
}
shell.close().await?;
```

### File transfer

```rust
use std::path::Path;

// Upload
let bytes = client.upload_file("win-server", Path::new("local.bin"), "C:\\remote\\file.bin").await?;

// Download
let bytes = client.download_file("win-server", "C:\\remote\\file.bin", Path::new("local.bin")).await?;
```

## Configuration

`WinrmConfig` fields:

| Field | Default | Description |
|---|---|---|
| `port` | `5985` | WinRM HTTP(S) port |
| `use_tls` | `false` | Use HTTPS instead of HTTP |
| `accept_invalid_certs` | `false` | Skip TLS certificate validation |
| `connect_timeout_secs` | `30` | TCP connection timeout |
| `operation_timeout_secs` | `60` | WinRM operation timeout (SOAP-level) |
| `auth_method` | `Ntlm` | `Basic`, `Ntlm`, `Kerberos`, or `Certificate` |
| `max_envelope_size` | `153600` | Maximum SOAP envelope size in bytes |
| `max_retries` | `0` | Retries for transient HTTP errors (exponential backoff) |
| `client_cert_pem` | `None` | Path to client cert PEM (Certificate auth) |
| `client_key_pem` | `None` | Path to client key PEM (Certificate auth) |
| `proxy` | `None` | HTTP proxy URL (e.g. `http://proxy:8080`) |

## Roadmap

| Version | Milestone | Status |
|---|---|---|
| **v0.1** | NTLMv2 + Basic auth, command execution | Done |
| **v0.2** | Shell reuse + stdin piping | Done |
| **v0.3** | NTLM sealing, credentials security, retry | Done |
| **v0.4** | Kerberos + Certificate auth | Done |
| **v0.5** | File transfer, streaming output, proxy | Done |
| **v1.0** | Stable public API, TLS channel binding, CI/CD | **Current** |
| **v1.x** | CredSSP stabilization (`--features credssp`) | Planned |

## Comparison

| | **winrm-rs** | **pywinrm** (Python) | **go-winrm** (Go) |
|---|---|---|---|
| Async | native async/await | no | no |
| NTLM | pure Rust (NTLMv2) | via requests-ntlm | built-in |
| Kerberos | via cross-krb5 (v0.4) | via requests-kerberos | built-in |
| Certificate | built-in (v0.4) | yes | yes |
| Encryption | NTLM sealing (v0.3) | via pywinrm[credssp] | built-in |
| TLS backend | rustls | OpenSSL | Go stdlib |
| PowerShell encoding | built-in | built-in | built-in |
| Shell reuse | yes (v0.2) | yes | yes |
| File transfer | base64 chunked (v0.5) | yes | yes |
| Streaming | poll-based (v0.5) | no | no |
| Binary size | single static binary | interpreter | single binary |

## Contributing

Contributions are welcome. Please open an issue to discuss larger changes before submitting a PR.

```sh
cargo test --workspace    # run tests
cargo clippy --workspace  # lint
cargo fmt --check         # format check
```

## Fuzzing

Everything the crate parses off the network — NTLM messages, WS-Management
SOAP responses, CredSSP DER — and everything it splices into an outgoing
request is covered by 18 libFuzzer targets. They assert protocol invariants
(no input can inject XML markup into an envelope, no Type 3 security buffer
escapes its message, `encode`/`decode` roundtrip) rather than only the absence
of panics.

```sh
scripts/fuzz.sh list                          # targets and dictionaries
scripts/fuzz.sh smoke                         # replay the committed seeds
scripts/fuzz.sh run                           # 60s per target
scripts/fuzz.sh run fuzz_asn1_ts_request 900  # one target, 15 minutes
```

Requires the nightly toolchain and `cargo-fuzz`. See
[`fuzz/README.md`](fuzz/README.md) for the full target table. Every PR runs a
short pass; a longer campaign runs nightly in CI.

## Integration tests

Most tests run against `wiremock` and need no external setup. The file
[`tests/integration_real.rs`](tests/integration_real.rs) targets a real
Windows host and is ignored by default. To run it, set the following
environment variables and use `--ignored`:

| Variable | Required | Default | Description |
|---|---|---|---|
| `WINRM_TEST_HOST` | yes | — | Hostname or IP of the target Windows box |
| `WINRM_TEST_PASS` | yes | — | Password for the test account |
| `WINRM_TEST_USER` | no | `vagrant` | Username |
| `WINRM_TEST_PORT` | no | `5985` | WinRM port (`5985` = HTTP, `5986` = HTTPS) |

```sh
WINRM_TEST_HOST=192.0.2.10 \
WINRM_TEST_USER=Administrator \
WINRM_TEST_PASS='secret' \
cargo test --test integration_real -- --ignored
```

## Cargo features

| Feature | Status | Notes |
|---|---|---|
| *(default)* | stable | NTLMv2, Basic, Certificate auth; no optional deps |
| `kerberos` | stable | Pulls `cross-krb5`; requires a working `kinit` |
| `credssp` | **experimental** | Double-hop delegation. Validated end-to-end against Windows Server 2025 (live `credssp_run_command_whoami`); not yet exercised on other host generations. Pulls `openssl` (C dep: `libssl-dev` on Debian). |

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT License](LICENSE-MIT) at your option.
