//! Async `WinRM` (WS-Management) client for Rust.
//!
//! Provides remote command execution on Windows hosts via the `WinRM` protocol
//! with `NTLMv2`, Basic, Kerberos, and Certificate authentication support.
//!
//! # Architecture
//!
//! The crate is structured in three layers:
//!
//! - **[`WinrmClient`]** -- high-level async API that manages shell lifecycle,
//!   command execution, and output polling. Callers interact exclusively with
//!   this type and its associated config/credential structs.
//!
//! - **`soap`** (internal) -- builds WS-Management XML envelopes for Create,
//!   Execute, Receive, Signal, and Delete operations, and parses the
//!   corresponding responses. Envelope construction uses raw `format!` strings
//!   rather than a full XML library to keep dependencies minimal.
//!
//! - **`ntlm`** (internal) -- implements the `NTLMv2` challenge/response handshake
//!   per MS-NLMP. Only `NTLMv2` is supported; `NTLMv1` is intentionally excluded.
//!
//! HTTP transport is provided by `reqwest` with `rustls-tls`.
//!
//! # Authentication methods
//!
//! | Method | Enum variant | Notes |
//! |--------|-------------|-------|
//! | HTTP Basic | [`AuthMethod::Basic`] | Credentials sent base64-encoded per request. Use only over HTTPS. |
//! | `NTLMv2` | [`AuthMethod::Ntlm`] | Three-step handshake (negotiate / challenge / authenticate). Default. |
//! | Kerberos | [`AuthMethod::Kerberos`] | SPNEGO Negotiate via system Kerberos. Requires `kerberos` feature + `kinit`. |
//! | Certificate | [`AuthMethod::Certificate`] | TLS client certificate. Set `client_cert_pem` and `client_key_pem` on config. |
//!
//! # Error handling
//!
//! All fallible operations return `Result<T, WinrmError>`. The top-level
//! [`WinrmError`] enum wraps transport errors ([`reqwest::Error`]), SOAP faults
//! ([`SoapError`]), NTLM failures ([`NtlmError`]), and authentication
//! rejections. Errors are designed for programmatic matching via `match` and
//! for human-readable display via their [`Display`](std::fmt::Display) impls.
//!
//! # Shell reuse
//!
//! For running multiple commands on the same host, use [`WinrmClient::open_shell`]
//! to create a [`Shell`] that persists across commands, avoiding the overhead of
//! shell creation and deletion per command.
//!
//! # Cargo features
//!
//! - **`kerberos`** -- Enables Kerberos authentication via `cross-krb5`.
//! - **`credssp`** -- *Experimental.* Enables `CredSSP` authentication for
//!   double-hop delegation. Pulls in `openssl` as a C dependency
//!   (required because Microsoft's `CredSSP` server has proven incompatible
//!   with `rustls` in-memory TLS — see `src/auth/credssp.rs`).
//!   Validated end-to-end against Windows Server 2025; not yet exercised
//!   on other host generations.
//!
//! # Re-exports
//!
//! A few third-party types appear in this crate's public API and are
//! re-exported for convenience:
//!
//! - [`SecretString`] / [`ExposeSecret`] from the `secrecy` crate —
//!   used for the `password` field of [`WinrmCredentials`].
//! - [`CancellationToken`] from `tokio_util` — used as a parameter to
//!   the `*_with_cancel` methods of [`WinrmClient`] so callers can
//!   cooperatively cancel in-flight operations.
//!
//! # Example
//! ```no_run
//! use winrm_rs::{WinrmClient, WinrmConfig, WinrmCredentials};
//!
//! # async fn example() -> Result<(), winrm_rs::WinrmError> {
//! let client = WinrmClient::new(
//!     WinrmConfig::default(),
//!     WinrmCredentials::new("administrator", "password", ""),
//! )?;
//!
//! let output = client.run_powershell("win-server", "Get-Process | ConvertTo-Json").await?;
//! println!("stdout: {}", String::from_utf8_lossy(&output.stdout));
//! # Ok(())
//! # }
//! ```

#[cfg(feature = "credssp")]
mod asn1;
mod auth;
mod builder;
mod client;
mod command;
mod config;
mod error;
mod ntlm;
mod shell;
mod soap;
mod tls;
mod transfer;
mod transport;

pub use builder::{NeedsCredentials, Ready, WinrmClientBuilder};
pub use client::WinrmClient;
pub use command::{CommandOutput, encode_powershell_command};
pub use config::{AuthMethod, EncryptionMode, WinrmConfig, WinrmCredentials};
pub use error::{CredSspError, NtlmError, SoapError, WinrmError};
pub use ntlm::NtlmSession;
pub use secrecy::{ExposeSecret, SecretString};
pub use shell::Shell;
pub use soap::namespaces::RESOURCE_URI_PSRP;
pub use tokio_util::sync::CancellationToken;
// Re-export soap types that are part of the public API
pub use soap::ReceiveOutput;

// Internal surface for the in-tree fuzz targets and property tests. NOT
// part of the public API: anything in `__fuzz` may be removed or changed
// at any time without a SemVer bump. Enabled via the `__internal` feature.
#[cfg(feature = "__internal")]
#[doc(hidden)]
pub mod __fuzz;
