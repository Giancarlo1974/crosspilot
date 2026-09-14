// Consolidated error types for the winrm-rs crate.
//
// All error enums live here to avoid circular dependencies between modules.

/// Errors that can occur during WinRM operations.
///
/// Variants cover the full error surface: HTTP transport, authentication
/// handshake, NTLM protocol, SOAP-level faults, and operation timeouts.
#[derive(Debug, thiserror::Error)]
pub enum WinrmError {
    /// HTTP transport error from `reqwest` (connection refused, timeout, TLS, etc.).
    #[error("WinRM HTTP error: {0}")]
    Http(reqwest::Error),
    /// Authentication was rejected by the server (bad credentials, unexpected
    /// HTTP status during NTLM handshake, missing headers).
    #[error("WinRM auth failed: {0}")]
    AuthFailed(String),
    /// NTLM protocol error (malformed challenge message, bad signature, etc.).
    #[error("WinRM NTLM error: {0}")]
    Ntlm(NtlmError),
    /// SOAP-level fault or XML parsing error returned by the WinRM service.
    #[error("WinRM SOAP error: {0}")]
    Soap(SoapError),
    /// The operation exceeded the configured timeout.
    #[error("WinRM operation timed out after {0}s")]
    Timeout(u64),
    /// File transfer error (upload or download failure).
    #[error("file transfer error: {0}")]
    Transfer(String),
    /// The operation was cancelled via a [`CancellationToken`](tokio_util::sync::CancellationToken).
    #[error("operation cancelled")]
    Cancelled,
    /// CredSSP protocol error.
    #[error("CredSSP error: {0}")]
    CredSsp(CredSspError),
}

/// Errors from the CredSSP authentication protocol (MS-CSSP).
#[derive(Debug, thiserror::Error)]
pub enum CredSspError {
    /// ASN.1 DER encoding or decoding error.
    #[error("ASN.1 decode error: {0}")]
    Asn1Decode(String),
    /// Server public key verification failed (possible MiTM).
    #[error("server public key mismatch")]
    PublicKeyMismatch,
    /// Server returned an NTSTATUS error code.
    #[error("server error: {0:#010x}")]
    ServerError(u32),
}

/// Errors from SOAP envelope parsing or WS-Management fault responses.
#[derive(Debug, thiserror::Error)]
pub enum SoapError {
    /// A required XML element (e.g. `ShellId`, `CommandId`) was not found in
    /// the response body.
    #[error("missing element: {0}")]
    MissingElement(String),
    /// The response body could not be parsed (e.g. invalid base64 in a stream).
    #[error("parse error: {0}")]
    ParseError(String),
    /// The WinRM service returned a SOAP fault with the given code and reason.
    #[error("SOAP fault [{code}]: {reason}")]
    Fault {
        /// Fault code, typically a WS-Addressing or WS-Management URI.
        code: String,
        /// Human-readable fault reason from the server.
        reason: String,
    },
}

/// Errors from the NTLM authentication protocol layer.
#[derive(Debug, thiserror::Error)]
pub enum NtlmError {
    /// The NTLM message is structurally invalid: too short, bad signature,
    /// wrong message type, or corrupt base64.
    #[error("NTLM error: {0}")]
    InvalidMessage(String),
}
