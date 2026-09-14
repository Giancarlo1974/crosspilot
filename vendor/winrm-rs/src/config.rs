// Configuration types for the winrm-rs crate.
//
// Contains WinrmConfig, AuthMethod, and WinrmCredentials extracted from client.rs.

use secrecy::SecretString;

/// Configuration for a [`WinrmClient`](crate::WinrmClient) connection.
///
/// Controls the transport (HTTP vs HTTPS), timeouts, and authentication
/// method. Use [`Default::default()`] for sensible defaults (HTTP on port
/// 5985, NTLM auth, 30 s connect / 60 s operation timeouts).
#[derive(Debug, Clone)]
pub struct WinrmConfig {
    /// TCP port of the WinRM listener (default: 5985 for HTTP, 5986 for HTTPS).
    pub port: u16,
    /// Whether to connect over HTTPS. When `true`, the endpoint URL uses `https://`.
    pub use_tls: bool,
    /// Accept invalid or self-signed TLS certificates.
    ///
    /// # Security
    ///
    /// Setting this to `true` disables chain verification on **both** the
    /// regular HTTPS transport and the CredSSP outer TLS leg, leaving the
    /// connection vulnerable to MITM. Credentials transmitted over Basic,
    /// NTLM, or CredSSP can then be intercepted.
    ///
    /// Use **only** in test environments. The constructor logs a
    /// `tracing::warn` when this flag is enabled.
    pub accept_invalid_certs: bool,
    /// TCP connect timeout in seconds (default: 30).
    pub connect_timeout_secs: u64,
    /// WS-Management `OperationTimeout` in seconds (default: 60). The HTTP
    /// client timeout is set to this value plus 10 seconds to allow the server
    /// to respond before the transport gives up.
    pub operation_timeout_secs: u64,
    /// Authentication method to use for all requests (default: [`AuthMethod::Ntlm`]).
    pub auth_method: AuthMethod,
    /// Maximum SOAP envelope size in bytes (default: 153600).
    ///
    /// Controls the `MaxEnvelopeSize` header sent in every WS-Management request.
    /// Increase this for hosts that return large responses.
    pub max_envelope_size: u32,
    /// Maximum number of retries for transient HTTP errors (default: 0 = no retry).
    ///
    /// Uses exponential backoff starting at 100 ms (100, 200, 400, ...).
    /// Only `WinrmError::Http` errors trigger a retry; authentication and
    /// SOAP faults are returned immediately.
    pub max_retries: u32,
    /// Path to client certificate PEM file (for `AuthMethod::Certificate`).
    pub client_cert_pem: Option<String>,
    /// Path to client private key PEM file (for `AuthMethod::Certificate`).
    pub client_key_pem: Option<String>,
    /// HTTP proxy URL (e.g. `"http://proxy:8080"`).
    ///
    /// When set, all WinRM HTTP(S) requests are routed through this proxy.
    pub proxy: Option<String>,
    /// Console output code page (default: 65001 = UTF-8).
    ///
    /// Controls the `WINRS_CODEPAGE` option in the shell creation envelope.
    /// Common values: 65001 (UTF-8), 437 (US), 850 (Western European).
    pub codepage: u32,
    /// Initial working directory for the remote shell (default: `None`).
    ///
    /// When set, the shell starts in this directory. Equivalent to running
    /// `cd <path>` before any command.
    pub working_directory: Option<String>,
    /// Environment variables to set in the remote shell (default: empty).
    ///
    /// Each `(key, value)` pair is injected into the shell's environment
    /// at creation time via `<rsp:Environment>`.
    pub env_vars: Vec<(String, String)>,
    /// Message encryption mode for NTLM (default: [`EncryptionMode::Auto`]).
    ///
    /// Controls whether NTLM sealing is applied to SOAP message bodies.
    pub encryption: EncryptionMode,
    /// Custom HTTP `User-Agent` header (default: `None` = `winrm-rs/<version>`).
    pub user_agent: Option<String>,
    /// Shell idle timeout in seconds (default: `None` = server default).
    ///
    /// When set, the shell will be automatically closed by the server
    /// after this many seconds of inactivity.
    pub idle_timeout_secs: Option<u64>,
    /// Maximum cumulative bytes accepted from the server for a single command's
    /// stdout+stderr (default: `Some(64 * 1024 * 1024)` = 64 MiB).
    ///
    /// Prevents a malicious or runaway server from exhausting client memory
    /// by streaming an unbounded base64 chunk sequence. When the cap is
    /// reached, the operation returns [`crate::error::WinrmError::Transfer`]
    /// and the shell is best-effort closed. Set to `None` to disable the
    /// cap (pre-1.1 behaviour).
    pub max_output_bytes: Option<usize>,
}

impl Default for WinrmConfig {
    fn default() -> Self {
        Self {
            port: 5985,
            use_tls: false,
            accept_invalid_certs: false,
            connect_timeout_secs: 30,
            operation_timeout_secs: 60,
            auth_method: AuthMethod::Ntlm,
            max_envelope_size: 153_600,
            max_retries: 0,
            client_cert_pem: None,
            client_key_pem: None,
            proxy: None,
            encryption: EncryptionMode::Auto,
            user_agent: None,
            codepage: 65001,
            working_directory: None,
            env_vars: Vec::new(),
            idle_timeout_secs: None,
            max_output_bytes: Some(64 * 1024 * 1024),
        }
    }
}

/// Controls whether NTLM message encryption (sealing) is applied to SOAP bodies.
///
/// When using HTTP (not HTTPS), NTLM sealing encrypts the SOAP body to prevent
/// eavesdropping. When using HTTPS, the TLS layer provides encryption, making
/// sealing redundant.
#[derive(Debug, Clone, Default, PartialEq)]
pub enum EncryptionMode {
    /// Encrypt when using HTTP, skip when using HTTPS (default).
    #[default]
    Auto,
    /// Always encrypt SOAP bodies, even over HTTPS.
    Always,
    /// Never encrypt SOAP bodies. **Use only for debugging.**
    Never,
}

/// Authentication method for the WinRM HTTP transport.
#[derive(Debug, Clone)]
pub enum AuthMethod {
    /// HTTP Basic authentication. Credentials are sent as a base64-encoded
    /// `Authorization` header on every request. Only safe over HTTPS.
    Basic,
    /// NTLMv2 challenge/response authentication (default). Performs a three-step
    /// handshake (negotiate, challenge, authenticate) per request.
    Ntlm,
    /// Kerberos authentication (requires `kerberos` feature and prior `kinit`).
    ///
    /// Uses SPNEGO Negotiate tokens via the system Kerberos library.
    /// The service principal is derived as `HTTP/<hostname>`.
    Kerberos,
    /// TLS client certificate authentication.
    ///
    /// The `reqwest::Client` is configured with the client cert at construction
    /// time. No `Authorization` header is sent; the TLS handshake authenticates.
    Certificate,
    /// CredSSP authentication for double-hop credential delegation.
    ///
    /// Wraps NTLM or Kerberos inside a TLS channel, allowing credentials
    /// to be delegated to the remote host for accessing network resources.
    /// Requires HTTPS (`use_tls = true`).
    ///
    /// **Not yet implemented** — will return an error at runtime.
    CredSsp,
}

/// Credentials for WinRM authentication.
///
/// The password is stored as a [`SecretString`] — zeroized on drop and
/// redacted in `Debug` output. Use [`WinrmCredentials::new`] to construct.
///
/// For NTLM, if [`domain`](Self::domain) is empty the client will use the
/// domain advertised by the server in its Type 2 challenge message.
#[derive(Clone)]
pub struct WinrmCredentials {
    /// Windows account name (e.g. `"administrator"`).
    pub username: String,
    /// Password — stored as SecretString, zeroized on drop, redacted in Debug.
    pub password: SecretString,
    /// Optional NetBIOS domain. Leave empty to auto-detect from the NTLM
    /// challenge.
    pub domain: String,
}

impl WinrmCredentials {
    /// Create new credentials.
    ///
    /// Wraps the password in a [`SecretString`] for automatic zeroization.
    pub fn new(
        username: impl Into<String>,
        password: impl Into<String>,
        domain: impl Into<String>,
    ) -> Self {
        Self {
            username: username.into(),
            password: SecretString::from(password.into()),
            domain: domain.into(),
        }
    }
}

impl std::fmt::Debug for WinrmCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WinrmCredentials")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field("domain", &self.domain)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn default_config_uses_http_and_ntlm() {
        let config = WinrmConfig::default();
        assert_eq!(config.port, 5985);
        assert!(!config.use_tls);
        assert!(matches!(config.auth_method, AuthMethod::Ntlm));
    }

    #[test]
    fn default_config_max_envelope_size() {
        let config = WinrmConfig::default();
        assert_eq!(config.max_envelope_size, 153_600);
    }

    #[test]
    fn custom_max_envelope_size() {
        let config = WinrmConfig {
            max_envelope_size: 512_000,
            ..Default::default()
        };
        assert_eq!(config.max_envelope_size, 512_000);
    }

    #[test]
    fn default_config_max_retries_is_zero() {
        let config = WinrmConfig::default();
        assert_eq!(config.max_retries, 0);
    }

    #[test]
    fn default_config_has_no_proxy() {
        let config = WinrmConfig::default();
        assert!(config.proxy.is_none());
    }

    #[test]
    fn default_config_has_no_cert_paths() {
        let config = WinrmConfig::default();
        assert!(config.client_cert_pem.is_none());
        assert!(config.client_key_pem.is_none());
    }

    #[test]
    fn credentials_new_constructor() {
        let creds = WinrmCredentials::new("admin", "s3cret", "DOMAIN");
        assert_eq!(creds.username, "admin");
        assert_eq!(creds.password.expose_secret(), "s3cret");
        assert_eq!(creds.domain, "DOMAIN");
    }

    #[test]
    fn credentials_debug_redacts_password() {
        let creds = WinrmCredentials::new("admin", "super-secret-password", "DOM");
        let debug_output = format!("{creds:?}");
        assert!(debug_output.contains("admin"));
        assert!(debug_output.contains("DOM"));
        assert!(debug_output.contains("[REDACTED]"));
        assert!(!debug_output.contains("super-secret-password"));
    }

    #[test]
    fn credentials_expose_secret_works() {
        let creds = WinrmCredentials::new("user", "my-password", "");
        let exposed: &str = creds.password.expose_secret();
        assert_eq!(exposed, "my-password");
    }

    #[test]
    fn auth_method_kerberos_variant_exists() {
        let method = AuthMethod::Kerberos;
        let debug = format!("{method:?}");
        assert!(debug.contains("Kerberos"));
    }

    #[test]
    fn auth_method_certificate_variant_exists() {
        let method = AuthMethod::Certificate;
        let debug = format!("{method:?}");
        assert!(debug.contains("Certificate"));
    }
}
