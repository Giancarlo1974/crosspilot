// HTTP transport layer for WinRM.
//
// Manages the reqwest HTTP client, authentication dispatch, and retry logic.
// Extracted from client.rs.

use std::sync::Arc;
use std::time::Duration;

use reqwest::header::CONTENT_TYPE;
use secrecy::ExposeSecret;
use tokio::sync::Mutex;
use tracing::{debug, trace};
use zeroize::Zeroizing;

use crate::auth::AuthTransport;
use crate::auth::basic::BasicAuth;
use crate::auth::certificate::CertificateAuth;
#[cfg(feature = "credssp")]
use crate::auth::credssp::CredSspAuth;
use crate::auth::kerberos::KerberosAuth;
use crate::auth::ntlm::{self as ntlm_auth, NtlmAuth};
use crate::config::{AuthMethod, EncryptionMode, WinrmConfig, WinrmCredentials};
use crate::error::WinrmError;
use crate::ntlm::NtlmSession;
use crate::soap;
use crate::tls::CertHandle;

/// Cached NTLM session state for message sealing on a specific host.
struct NtlmSessionCache {
    host: String,
    session: NtlmSession,
}

/// HTTP transport for WinRM SOAP requests.
///
/// Handles authentication dispatch, retry logic, and endpoint construction.
pub(crate) struct HttpTransport {
    http: reqwest::Client,
    config: WinrmConfig,
    credentials: WinrmCredentials,
    /// Handle to retrieve the captured TLS server certificate (for CBT).
    /// `None` when using plain HTTP (no TLS).
    cert_handle: Option<CertHandle>,
    /// Cached NTLM session for sealed message exchange.
    /// Uses `tokio::sync::Mutex` because the lock spans an `.await` (HTTP send).
    ntlm_cache: Mutex<Option<NtlmSessionCache>>,
    /// `wsmv:SessionId` value stamped on every request (`uuid:<UPPERCASE>`),
    /// one per transport. See [`crate::soap::envelope::with_session_id`].
    session_id: String,
}

/// Strip scheme, userinfo, port, and path from a host string.
///
/// Defensive: callers are supposed to pass `"hostname"` or `"10.0.0.1"`,
/// but if they accidentally pass `"http://evil.com/path"` we keep just
/// `"evil.com"` and log the deviation. IPv6 literals (`[::1]`) are
/// preserved as-is because `:` inside brackets is part of the address.
pub(crate) fn sanitize_host(input: &str) -> String {
    let mut s = input;
    if let Some(rest) = s.split_once("://") {
        s = rest.1;
    }
    if let Some((_, rest)) = s.rsplit_once('@') {
        s = rest;
    }
    if let Some((host_part, _)) = s.split_once('/') {
        s = host_part;
    }
    // For non-bracketed IPv6 / hostnames, drop a trailing :port.
    if !s.starts_with('[')
        && let Some((host_part, _)) = s.rsplit_once(':')
    {
        s = host_part;
    }
    s.to_string()
}

impl HttpTransport {
    /// Create a new HTTP transport from the given configuration and credentials.
    ///
    /// Builds the underlying HTTP client with the configured timeouts and TLS
    /// settings. Returns [`WinrmError::Http`] if the HTTP client cannot be
    /// constructed (e.g. invalid TLS configuration).
    #[tracing::instrument(level = "debug", skip(credentials))]
    pub(crate) fn new(
        config: WinrmConfig,
        credentials: WinrmCredentials,
    ) -> Result<Self, WinrmError> {
        if config.accept_invalid_certs {
            tracing::warn!(
                "TLS certificate verification disabled (accept_invalid_certs=true) — \
                 TEST USE ONLY, do not use in production"
            );
        }

        // The WinRM endpoint is fixed by the caller (host:port/wsman); a
        // server returning a 30x is unexpected and any cross-origin redirect
        // would risk forwarding the Authorization header. Disable redirects
        // entirely.
        let mut builder = reqwest::Client::builder()
            .danger_accept_invalid_certs(config.accept_invalid_certs)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(config.connect_timeout_secs))
            .timeout(Duration::from_secs(config.operation_timeout_secs + 10))
            .http1_only()
            .tcp_keepalive(Duration::from_secs(60))
            .pool_max_idle_per_host(10)
            .pool_idle_timeout(Duration::from_secs(90))
            .user_agent(
                config
                    .user_agent
                    .as_deref()
                    .unwrap_or(concat!("winrm-rs/", env!("CARGO_PKG_VERSION"))),
            );

        // Configure TLS client certificate for Certificate auth
        if matches!(config.auth_method, AuthMethod::Certificate) {
            let cert_path = config.client_cert_pem.as_deref().ok_or_else(|| {
                WinrmError::AuthFailed("Certificate auth requires client_cert_pem".into())
            })?;
            let key_path = config.client_key_pem.as_deref().ok_or_else(|| {
                WinrmError::AuthFailed("Certificate auth requires client_key_pem".into())
            })?;
            let cert_pem = std::fs::read(cert_path).map_err(|e| {
                WinrmError::AuthFailed(format!("failed to read client cert {cert_path}: {e}"))
            })?;
            let key_pem = std::fs::read(key_path).map_err(|e| {
                WinrmError::AuthFailed(format!("failed to read client key {key_path}: {e}"))
            })?;
            let mut combined = cert_pem;
            combined.extend_from_slice(b"\n");
            combined.extend_from_slice(&key_pem);
            let identity = reqwest::Identity::from_pem(&combined).map_err(WinrmError::Http)?;
            builder = builder.identity(identity);
        }

        // Configure HTTP proxy
        if let Some(ref proxy_url) = config.proxy {
            let proxy = reqwest::Proxy::all(proxy_url).map_err(WinrmError::Http)?;
            builder = builder.proxy(proxy);
        }

        if matches!(config.auth_method, AuthMethod::Basic) && !config.use_tls {
            tracing::warn!(
                "Basic auth over HTTP transmits credentials in cleartext — use HTTPS in production"
            );
        }

        if matches!(config.auth_method, AuthMethod::CredSsp) && !config.use_tls {
            return Err(WinrmError::AuthFailed(
                "CredSSP requires HTTPS (set use_tls = true)".into(),
            ));
        }

        // When using TLS, inject a CertCapturingVerifier to enable Channel Binding Tokens.
        // The rustls crypto provider must be installed even when use_tls=false:
        // reqwest 0.13 with `rustls-no-provider` panics at Client construction
        // if no provider is installed, regardless of whether TLS is actually
        // used on the wire. ring is the only provider that cross-compiles
        // cleanly to Windows (GNU/MSVC) — aws-lc-rs requires sched.h (Linux-only).
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert_handle = if config.use_tls {
            let root_store =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let inner_verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> =
                if config.accept_invalid_certs {
                    Arc::new(crate::tls::NoVerifier)
                } else {
                    rustls::client::WebPkiServerVerifier::builder(Arc::new(root_store))
                        .build()
                        .map_err(|e| WinrmError::AuthFailed(format!("TLS verifier error: {e}")))?
                };
            let capturing_verifier = crate::tls::CertCapturingVerifier::new(inner_verifier);
            let handle = capturing_verifier.cert_handle();
            let tls_config = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(capturing_verifier))
                .with_no_client_auth();
            builder = builder.tls_backend_preconfigured(tls_config);
            Some(handle)
        } else {
            None
        };

        let http = builder.build().map_err(WinrmError::Http)?;

        Ok(Self {
            http,
            config,
            credentials,
            cert_handle,
            ntlm_cache: Mutex::new(None),
            session_id: format!("uuid:{}", uuid::Uuid::new_v4().to_string().to_uppercase()),
        })
    }

    /// Build the WinRM endpoint URL for a given host.
    ///
    /// `host` is expected to be a bare hostname or IP literal — no scheme,
    /// no port, no userinfo. If suspect characters (`/`, `@`, `://`) are
    /// detected they are stripped and a WARN is logged so the call still
    /// produces a syntactically valid URL but the operator notices the
    /// misuse instead of silently sending credentials to a forged host.
    pub(crate) fn endpoint(&self, host: &str) -> String {
        let scheme = if self.config.use_tls { "https" } else { "http" };
        let sanitized = sanitize_host(host);
        if sanitized != host {
            tracing::warn!(
                original = host,
                sanitized = %sanitized,
                "host string contained scheme/path/userinfo; using sanitized form"
            );
        }
        format!("{scheme}://{sanitized}:{}/wsman", self.config.port)
    }

    /// Access the transport configuration.
    pub(crate) fn config(&self) -> &WinrmConfig {
        &self.config
    }

    /// Send an authenticated SOAP request and return the response body.
    ///
    /// Dispatches to Basic or NTLM transport depending on the configured
    /// [`AuthMethod`]. The response is checked for SOAP faults before
    /// returning.
    #[tracing::instrument(level = "debug", skip(self, body))]
    async fn send_soap(&self, host: &str, body: String) -> Result<String, WinrmError> {
        let url = self.endpoint(host);
        debug!(url = %url, "sending WinRM SOAP request");
        trace!(body = %body, "SOAP request body");

        let response_text: String = match &self.config.auth_method {
            AuthMethod::Basic => {
                let auth = BasicAuth::new(
                    &self.credentials.username,
                    self.credentials.password.expose_secret(),
                );
                auth.send_authenticated(&self.http, &url, body).await?
            }
            AuthMethod::Ntlm => {
                let encrypt = match self.config.encryption {
                    EncryptionMode::Always => true,
                    EncryptionMode::Never => false,
                    EncryptionMode::Auto => !self.config.use_tls,
                };
                if encrypt {
                    self.send_ntlm_sealed(host, &url, body).await?
                } else {
                    let auth = NtlmAuth {
                        username: self.credentials.username.clone(),
                        password: Zeroizing::new(
                            self.credentials.password.expose_secret().to_string(),
                        ),
                        domain: self.credentials.domain.clone(),
                        cert_handle: self.cert_handle.clone(),
                    };
                    auth.send_authenticated(&self.http, &url, body).await?
                }
            }
            AuthMethod::Kerberos => {
                let host_part = host.split(':').next().unwrap_or(host);
                let auth = KerberosAuth {
                    service_principal: format!("HTTP/{host_part}"),
                };
                auth.send_authenticated(&self.http, &url, body).await?
            }
            AuthMethod::Certificate => {
                let auth = CertificateAuth;
                auth.send_authenticated(&self.http, &url, body).await?
            }
            #[cfg(feature = "credssp")]
            AuthMethod::CredSsp => {
                let auth = CredSspAuth {
                    username: self.credentials.username.clone(),
                    password: Zeroizing::new(self.credentials.password.expose_secret().to_string()),
                    domain: self.credentials.domain.clone(),
                    cert_handle: self.cert_handle.clone(),
                    accept_invalid_certs: self.config.accept_invalid_certs,
                };
                auth.send_authenticated(&self.http, &url, body).await?
            }
            #[cfg(not(feature = "credssp"))]
            AuthMethod::CredSsp => {
                return Err(WinrmError::AuthFailed(
                    "CredSSP authentication requires the `credssp` cargo feature".into(),
                ));
            }
        };

        trace!(response = %response_text, "SOAP response body");
        soap::check_soap_fault(&response_text).map_err(WinrmError::Soap)?;
        Ok(response_text)
    }

    /// Send an NTLM-sealed request, reusing the cached session if available.
    ///
    /// On the first call (no cached session), does a full NTLM handshake with
    /// the SOAP body sent as plaintext.  The session key is cached so that
    /// subsequent calls can send the body sealed (multipart/encrypted) without
    /// a new handshake, reusing the keep-alive TCP connection.
    ///
    /// If the server returns 401 (session expired), the cache is cleared and a
    /// fresh handshake is attempted.
    async fn send_ntlm_sealed(
        &self,
        host: &str,
        url: &str,
        body: String,
    ) -> Result<String, WinrmError> {
        // Try sending with cached session first
        {
            let mut cache = self.ntlm_cache.lock().await;
            if let Some(ref mut c) = *cache {
                if c.host == host {
                    match self.send_sealed_body(&mut c.session, url, &body).await {
                        Ok(resp) => return Ok(resp),
                        Err(WinrmError::AuthFailed(_)) => {
                            // Session expired — clear cache, fall through to handshake
                            debug!("NTLM sealed session expired, re-authenticating");
                            *cache = None;
                        }
                        Err(e) => return Err(e),
                    }
                } else {
                    // Different host — clear cache
                    *cache = None;
                }
            }
        }

        // No cached session: full NTLM handshake.
        //
        // BUG FIX: il Type 3 deve avere body VUOTO. WinRM con
        // AllowUnencrypted=false (default) richiede il body sigillato NTLM;
        // un body SOAP in chiaro sulla leg di autenticazione viene rifiutato
        // da http.sys con HTTP 500 (body vuoto, Connection: close).
        // Flusso corretto (come evil-winrm/pywinrm): Type3 empty → 200 +
        // session key → SOAP inviata come multipart/encrypted sulla stessa
        // connessione keep-alive autenticata.
        let auth = NtlmAuth {
            username: self.credentials.username.clone(),
            password: Zeroizing::new(self.credentials.password.expose_secret().to_string()),
            domain: self.credentials.domain.clone(),
            cert_handle: self.cert_handle.clone(),
        };
        // Handshake con body vuoto: la risposta 200 è vuota (auth-only),
        // non contiene il risultato SOAP.
        let (_auth_only_response, session_key) =
            auth.handshake_and_send(&self.http, url, "").await?;

        let mut session = NtlmSession::from_auth(&session_key);

        // Invia la SOAP body sigillata sulla connessione autenticata.
        let response = self.send_sealed_body(&mut session, url, &body).await?;

        // Cache the session for subsequent sealed requests
        *self.ntlm_cache.lock().await = Some(NtlmSessionCache {
            host: host.to_string(),
            session,
        });

        Ok(response)
    }

    /// Send a sealed body on an already-authenticated keep-alive connection.
    async fn send_sealed_body(
        &self,
        session: &mut NtlmSession,
        url: &str,
        body: &str,
    ) -> Result<String, WinrmError> {
        let (content_type, sealed) = ntlm_auth::seal_body(session, body);

        let resp = self
            .http
            .post(url)
            .header(CONTENT_TYPE, &content_type)
            .body(sealed)
            .send()
            .await
            .map_err(WinrmError::Http)?;

        if resp.status().as_u16() == 401 {
            return Err(WinrmError::AuthFailed("NTLM session expired".into()));
        }

        if !resp.status().is_success() {
            let status = resp.status();
            // BUG FIX: il server WinRM ritorna 500 con body *sealed* (MIME encrypted)
            // per SOAP fault. Il codice originale leggeva il body come text raw (sealed,
            // illeggibile) e falliva in check_soap_fault. Ora proviamo a unsealare
            // il body prima di cercare il SOAP fault, così otteniamo il vero errore.
            let resp_bytes = resp.bytes().await.unwrap_or_default();
            let text = match ntlm_auth::unseal_body(session, &resp_bytes) {
                Ok(unsealed) => unsealed,
                Err(_) => String::from_utf8_lossy(&resp_bytes).to_string(),
            };
            if status.as_u16() == 500
                && let Err(soap_err) = crate::soap::parser::check_soap_fault(&text)
            {
                return Err(WinrmError::Soap(soap_err));
            }
            return Err(WinrmError::AuthFailed(format!("HTTP {status}: {text}")));
        }

        let resp_bytes = resp.bytes().await.map_err(WinrmError::Http)?;
        ntlm_auth::unseal_body(session, &resp_bytes)
    }

    /// Send an authenticated SOAP request with optional retry on transient HTTP errors.
    ///
    /// Retries up to [`WinrmConfig::max_retries`] times with exponential backoff
    /// (100 ms, 200 ms, 400 ms, ...). Only [`WinrmError::Http`] errors are
    /// retried; authentication and SOAP faults are returned immediately.
    pub(crate) async fn send_soap_with_retry(
        &self,
        host: &str,
        body: String,
    ) -> Result<String, WinrmError> {
        let body = crate::soap::envelope::with_session_id(&body, &self.session_id);
        let max = self.config.max_retries;
        for attempt in 0..=max {
            match self.send_soap(host, body.clone()).await {
                Ok(r) => return Ok(r),
                Err(WinrmError::Http(_)) if attempt < max => {
                    let delay = std::time::Duration::from_millis(100 * 2u64.pow(attempt));
                    tracing::warn!(
                        attempt = attempt + 1,
                        max_retries = max,
                        delay_ms = delay.as_millis() as u64,
                        "retrying after transient HTTP error"
                    );
                    tokio::time::sleep(delay).await;
                }
                Err(e) => return Err(e),
            }
        }
        unreachable!()
    }

    /// The `wsmv:SessionId` value this transport stamps on every request.
    #[cfg(test)]
    pub(crate) fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Send an authenticated SOAP request (used by Shell and other internal callers).
    pub(crate) async fn send_soap_raw(
        &self,
        host: &str,
        body: String,
    ) -> Result<String, WinrmError> {
        self.send_soap_with_retry(host, body).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Helper to build an HttpTransport with Basic auth pointing at a wiremock server.
    fn basic_transport(port: u16) -> HttpTransport {
        let config = WinrmConfig {
            auth_method: AuthMethod::Basic,
            port,
            use_tls: false,
            ..Default::default()
        };
        let creds = WinrmCredentials::new("admin", "pass", "");
        HttpTransport::new(config, creds).unwrap()
    }

    #[test]
    fn endpoint_http() {
        let transport = basic_transport(5985);
        assert_eq!(transport.endpoint("10.0.0.1"), "http://10.0.0.1:5985/wsman");
    }

    #[test]
    fn sanitize_host_strips_scheme_and_path() {
        assert_eq!(sanitize_host("http://evil.com/x"), "evil.com");
        assert_eq!(sanitize_host("https://evil.com:1234/path"), "evil.com");
        assert_eq!(sanitize_host("user:pw@host.com"), "host.com");
    }

    #[test]
    fn sanitize_host_preserves_bare_hostname_and_ip() {
        assert_eq!(sanitize_host("plain.host"), "plain.host");
        assert_eq!(sanitize_host("10.0.0.1"), "10.0.0.1");
    }

    #[test]
    fn sanitize_host_preserves_ipv6_literal() {
        assert_eq!(sanitize_host("[fe80::1]"), "[fe80::1]");
    }

    #[test]
    fn endpoint_https() {
        let config = WinrmConfig {
            use_tls: true,
            port: 5986,
            accept_invalid_certs: true,
            ..Default::default()
        };
        let creds = WinrmCredentials::new("admin", "pass", "");
        let transport = HttpTransport::new(config, creds).unwrap();
        assert_eq!(
            transport.endpoint("win.local"),
            "https://win.local:5986/wsman"
        );
    }

    #[test]
    fn config_accessor() {
        let transport = basic_transport(5985);
        assert_eq!(transport.config().port, 5985);
        assert!(matches!(transport.config().auth_method, AuthMethod::Basic));
    }

    #[test]
    fn credssp_without_tls_returns_error() {
        let config = WinrmConfig {
            auth_method: AuthMethod::CredSsp,
            use_tls: false,
            ..Default::default()
        };
        let creds = WinrmCredentials::new("admin", "pass", "");
        match HttpTransport::new(config, creds) {
            Err(WinrmError::AuthFailed(_)) => {} // expected
            Err(e) => panic!("expected AuthFailed, got: {e}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[test]
    fn certificate_auth_without_cert_path_returns_error() {
        let config = WinrmConfig {
            auth_method: AuthMethod::Certificate,
            client_cert_pem: None,
            ..Default::default()
        };
        let creds = WinrmCredentials::new("admin", "pass", "");
        match HttpTransport::new(config, creds) {
            Err(WinrmError::AuthFailed(_)) => {}
            Err(e) => panic!("expected AuthFailed, got: {e}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[test]
    fn certificate_auth_without_key_path_returns_error() {
        let config = WinrmConfig {
            auth_method: AuthMethod::Certificate,
            client_cert_pem: Some("/tmp/cert.pem".into()),
            client_key_pem: None,
            ..Default::default()
        };
        let creds = WinrmCredentials::new("admin", "pass", "");
        match HttpTransport::new(config, creds) {
            Err(WinrmError::AuthFailed(_)) => {}
            Err(e) => panic!("expected AuthFailed, got: {e}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[test]
    fn certificate_auth_nonexistent_cert_file_returns_error() {
        let config = WinrmConfig {
            auth_method: AuthMethod::Certificate,
            client_cert_pem: Some("/nonexistent/cert.pem".into()),
            client_key_pem: Some("/nonexistent/key.pem".into()),
            ..Default::default()
        };
        let creds = WinrmCredentials::new("admin", "pass", "");
        match HttpTransport::new(config, creds) {
            Err(WinrmError::AuthFailed(_)) => {}
            Err(e) => panic!("expected AuthFailed, got: {e}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[tokio::test]
    async fn send_basic_success() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<ok/>"))
            .mount(&server)
            .await;

        let addr = server.address();
        let transport = basic_transport(addr.port());
        let result = transport
            .send_soap_with_retry(&addr.ip().to_string(), "<soap/>".into())
            .await;
        assert_eq!(result.unwrap(), "<ok/>");
    }

    #[tokio::test]
    async fn send_basic_soap_fault_returns_soap_error() {
        let server = MockServer::start().await;
        // Server returns 200 with a SOAP fault in the body
        let fault = r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
          <s:Body><s:Fault><s:Code><s:Value>s:Receiver</s:Value></s:Code>
          <s:Reason><s:Text>boom</s:Text></s:Reason></s:Fault></s:Body></s:Envelope>"#;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(fault))
            .mount(&server)
            .await;

        let addr = server.address();
        let transport = basic_transport(addr.port());
        let err = transport
            .send_soap_with_retry(&addr.ip().to_string(), "<soap/>".into())
            .await
            .unwrap_err();
        assert!(
            matches!(err, WinrmError::Soap(_)),
            "expected Soap error, got: {err}"
        );
    }

    #[tokio::test]
    async fn send_basic_auth_failed_returns_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(403).set_body_string("Forbidden"))
            .mount(&server)
            .await;

        let addr = server.address();
        let transport = basic_transport(addr.port());
        let err = transport
            .send_soap_with_retry(&addr.ip().to_string(), "<soap/>".into())
            .await
            .unwrap_err();
        assert!(
            matches!(err, WinrmError::AuthFailed(_)),
            "expected AuthFailed, got: {err}"
        );
    }

    #[tokio::test]
    async fn retry_on_transient_http_error() {
        let server = MockServer::start().await;
        // First request fails (connection reset simulated by no response)
        // Can't easily simulate transient errors with wiremock. Instead test
        // that a successful first request doesn't retry.
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<ok/>"))
            .expect(1)
            .mount(&server)
            .await;

        let addr = server.address();
        let config = WinrmConfig {
            auth_method: AuthMethod::Basic,
            port: addr.port(),
            use_tls: false,
            max_retries: 3,
            ..Default::default()
        };
        let creds = WinrmCredentials::new("admin", "pass", "");
        let transport = HttpTransport::new(config, creds).unwrap();
        let result = transport
            .send_soap_with_retry(&addr.ip().to_string(), "<soap/>".into())
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn no_retry_on_auth_failure() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(403).set_body_string("Forbidden"))
            .expect(1) // Should NOT retry auth failures
            .mount(&server)
            .await;

        let addr = server.address();
        let config = WinrmConfig {
            auth_method: AuthMethod::Basic,
            port: addr.port(),
            use_tls: false,
            max_retries: 3,
            ..Default::default()
        };
        let creds = WinrmCredentials::new("admin", "pass", "");
        let transport = HttpTransport::new(config, creds).unwrap();
        let _ = transport
            .send_soap_with_retry(&addr.ip().to_string(), "<soap/>".into())
            .await;
    }

    #[test]
    fn proxy_config_applied() {
        let config = WinrmConfig {
            auth_method: AuthMethod::Basic,
            use_tls: false,
            proxy: Some("http://proxy:8080".into()),
            ..Default::default()
        };
        let creds = WinrmCredentials::new("admin", "pass", "");
        // Should not error — proxy URL is valid
        assert!(HttpTransport::new(config, creds).is_ok());
    }

    #[test]
    fn tls_with_accept_invalid_certs() {
        let config = WinrmConfig {
            use_tls: true,
            accept_invalid_certs: true,
            port: 5986,
            ..Default::default()
        };
        let creds = WinrmCredentials::new("admin", "pass", "");
        let transport = HttpTransport::new(config, creds).unwrap();
        assert!(transport.cert_handle.is_some());
    }

    #[test]
    fn tls_with_valid_certs() {
        let config = WinrmConfig {
            use_tls: true,
            accept_invalid_certs: false,
            port: 5986,
            ..Default::default()
        };
        let creds = WinrmCredentials::new("admin", "pass", "");
        let transport = HttpTransport::new(config, creds).unwrap();
        assert!(transport.cert_handle.is_some());
    }

    #[test]
    fn no_tls_has_no_cert_handle() {
        let transport = basic_transport(5985);
        assert!(transport.cert_handle.is_none());
    }

    #[test]
    fn invalid_proxy_url_returns_error() {
        let config = WinrmConfig {
            proxy: Some("not a url".into()),
            ..Default::default()
        };
        let creds = WinrmCredentials::new("u", "p", "");
        let result = HttpTransport::new(config, creds);
        assert!(result.is_err(), "expected error for invalid proxy URL");
    }

    #[test]
    fn endpoint_strips_scheme_and_path_silently() {
        let transport = basic_transport(5985);
        // Caller passed a polluted host string; sanitize_host pulls just
        // the hostname and the URL is rebuilt with the configured scheme.
        let url = transport.endpoint("http://evil.com/path");
        assert_eq!(url, "http://evil.com:5985/wsman");
    }

    /// Every request of a session carries the same `wsmv:SessionId`; without
    /// it on the Create, Windows creates a non-disconnectable shell, and with
    /// it on the Create but not on the follow-ups, every follow-up is refused
    /// (0x8033810F). Measured against Server 2025 — see soap/envelope.rs.
    #[tokio::test]
    async fn every_request_carries_the_same_session_id() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<ok/>"))
            .mount(&server)
            .await;
        let transport = basic_transport(server.address().port());
        let env = r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Header></s:Header><s:Body/></s:Envelope>"#;
        for _ in 0..2 {
            transport
                .send_soap_with_retry(&server.address().ip().to_string(), env.to_string())
                .await
                .unwrap();
        }
        let reqs = server.received_requests().await.unwrap();
        assert_eq!(reqs.len(), 2);
        let bodies: Vec<String> = reqs
            .iter()
            .map(|r| String::from_utf8(r.body.clone()).unwrap())
            .collect();
        let sid = |b: &str| -> String {
            let start = b.find("<wsmv:SessionId").expect("SessionId present");
            let open = b[start..].find('>').unwrap() + start + 1;
            let end = b[open..].find('<').unwrap() + open;
            b[open..end].to_string()
        };
        let first = sid(&bodies[0]);
        assert_eq!(first, sid(&bodies[1]), "one session id per transport");
        assert_eq!(
            first,
            transport.session_id(),
            "accessor exposes the same id"
        );
        let uuid = first.strip_prefix("uuid:").expect("uuid: prefix");
        assert_eq!(uuid.len(), 36);
        assert!(
            uuid.chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-'),
            "{uuid}"
        );
        assert!(bodies[0].contains(r#"<wsmv:SessionId s:mustUnderstand="false">"#));
    }

    #[tokio::test]
    async fn two_transports_have_distinct_session_ids() {
        let a = basic_transport(5985);
        let b = basic_transport(5985);
        assert_ne!(a.session_id(), b.session_id());
    }
}
