// CredSSP authentication transport for WinRM (MS-CSSP).
//
// **STATUS: EXPERIMENTAL — validated end-to-end against Windows Server 2025**
//
// A few helpers below (reqwest-header variants of the token extraction) are
// kept for the day the flow moves back onto reqwest and are not on the
// active path. Silence dead_code at module level rather than scattering
// attributes.
#![allow(dead_code)]
//
// This implements the CredSSP protocol with TLS-in-TLS architecture:
//
// - **Outer channel**: HTTPS via reqwest (regular WinRM connection)
// - **Inner channel**: rustls ClientConnection in memory-only mode, used to
//   tunnel TSRequest messages per MS-CSSP. The TLS handshake and all
//   subsequent CredSSP messages flow through Authorization: CredSSP headers.
//
// Architecture matches pyspnego (which uses `ssl.MemoryBIO`). No socket is
// needed for the inner TLS — bytes flow through HTTP.
//
// **Working:**
// - Primer request and CredSSP advertisement detection
// - Inner TLS handshake (rustls in memory mode) — completes in 2 rounds
// - NTLM Type 1 → Type 2 exchange wrapped in TLS-encrypted TSRequest
// - SubjectPublicKey extraction from inner TLS server cert
//
// **Working (validated against pywinrm reference capture):**
// - Inner TLS handshake (rustls in memory) — completes in 2 rounds
// - SubjectPublicKey extraction from inner TLS server cert
// - NTLM Type 1 with CredSSP flags (KEY_EXCH, SEAL, SIGN, 128, 56, VERSION)
// - NTLM Type 1 → 2 exchange wrapped in TLS-encrypted TSRequest
// - NTLM Type 3 with EncryptedRandomSessionKey (key exchange)
// - MIC computation over Type1 || Type2 || Type3
// - AV_TARGET_NAME (HTTP/<host>) and AV_FLAGS (MIC bit) injection
// - Type 3 structure exactly matches pywinrm's bytes byte-for-byte
//
// **Current status:**
// Validated end-to-end against Windows Server 2025 (live test
// `credssp_run_command_whoami`): TLS-in-TLS, NTLM inside SPNEGO with
// mechListMIC, v6 pubKeyAuth with client nonce, server pubKeyAuth
// verification, TSCredentials delegation. A byte-for-byte differential
// against pyspnego 0.12.1 on identical inputs (fixed client challenge,
// session key and nonce — see the `CREDSSP_FIXED_*` debug hooks) matches at
// every step.
//
// The last blocker was the SPNEGO mechListMIC RC4 reset: Windows re-keys the
// NTLM sealing handle right after the MIC is computed/verified (sequence
// number kept), so pubKeyAuth must be sealed at keystream offset 0 with
// seq 1. See `NtlmSession::sign_mech_list_mic` / `verify_mech_list_mic`.
// How the server reports each failure, measured on Server 2025:
//   - wrong password        → TSRequest errorCode STATUS_LOGON_FAILURE
//   - bad mechListMIC       → TSRequest errorCode 0x8009030C
//   - undecryptable pubKeyAuth → 401 with a token-less
//                              `WWW-Authenticate: CredSSP`, no TSRequest
//
// Still experimental: validated on a single host generation, and the inner
// TLS leg pulls OpenSSL.

#[cfg(feature = "credssp")]
use std::sync::Arc;

#[cfg(feature = "credssp")]
use base64::Engine;
#[cfg(feature = "credssp")]
use base64::engine::general_purpose::STANDARD as B64;
#[cfg(feature = "credssp")]
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[cfg(feature = "credssp")]
use crate::asn1;
use crate::auth::AuthTransport;
#[cfg(feature = "credssp")]
use crate::error::CredSspError;
use crate::error::WinrmError;
#[cfg(feature = "credssp")]
use crate::ntlm;
#[cfg(feature = "credssp")]
use crate::ntlm::NtlmSession;
use crate::tls::CertHandle;

/// CredSSP protocol version (v6 = modern Windows 10+).
#[cfg(feature = "credssp")]
const CREDSSP_VERSION: u32 = 6;

/// Extract a CredSSP token from a response's WWW-Authenticate headers.
#[cfg(feature = "credssp")]
fn extract_credssp_token(headers: &http::HeaderMap) -> Option<String> {
    let all: String = headers
        .get_all("WWW-Authenticate")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect::<Vec<_>>()
        .join(", ");

    let upper = all.to_uppercase();
    let pos = upper.find("CREDSSP ")?;
    let after = &all[pos + "CREDSSP ".len()..];
    let token: String = after
        .chars()
        .take_while(|c| !c.is_whitespace() && *c != ',')
        .collect();
    if token.is_empty() { None } else { Some(token) }
}

/// Check if the server advertises CredSSP in any WWW-Authenticate header.
#[cfg(feature = "credssp")]
fn advertises_credssp(headers: &http::HeaderMap) -> bool {
    headers
        .get_all("WWW-Authenticate")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| v.to_uppercase().contains("CREDSSP"))
}

// === Inner TLS helpers ===
//
// rustls operates in pure memory mode. We feed it bytes received from the
// network (read_tls + process_new_packets) and drain bytes it wants to send
// (write_tls). Plaintext flows through reader()/writer().

/// In-memory TLS 1.2 client built on OpenSSL — used for the **inner**
/// CredSSP channel. We tried rustls first but Microsoft's CredSSP server
/// quietly drops the context after Type3+pubKeyAuth, suggesting some
/// subtle TLS-level incompatibility. OpenSSL is what pyspnego uses.
#[cfg(feature = "credssp")]
struct OpenSslMemTls {
    ssl: openssl::ssl::SslStream<MemBio>,
}

#[cfg(feature = "credssp")]
struct MemBio {
    incoming: std::collections::VecDeque<u8>,
    outgoing: Vec<u8>,
}

#[cfg(feature = "credssp")]
impl std::io::Read for MemBio {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.incoming.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "no data",
            ));
        }
        let n = std::cmp::min(buf.len(), self.incoming.len());
        for slot in buf.iter_mut().take(n) {
            *slot = self.incoming.pop_front().unwrap();
        }
        Ok(n)
    }
}

#[cfg(feature = "credssp")]
impl std::io::Write for MemBio {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.outgoing.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(feature = "credssp")]
impl OpenSslMemTls {
    /// Drive the TLS handshake one step. Returns Ok(true) once handshake
    /// is complete, Ok(false) when more bytes are needed from the peer.
    fn handshake_step(&mut self) -> Result<bool, WinrmError> {
        // OpenSSL handshake is driven internally by SslStream::ssl_read /
        // ssl_write. We use the SSL_do_handshake equivalent: a no-op read.
        use openssl::ssl::ErrorCode;
        match self.ssl.do_handshake() {
            Ok(()) => Ok(true),
            Err(e) if e.code() == ErrorCode::WANT_READ || e.code() == ErrorCode::WANT_WRITE => {
                Ok(false)
            }
            Err(e) => Err(WinrmError::AuthFailed(format!("inner TLS handshake: {e}"))),
        }
    }

    fn drain_outgoing(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.ssl.get_mut().outgoing)
    }

    fn feed_incoming(&mut self, data: &[u8]) {
        self.ssl.get_mut().incoming.extend(data.iter().copied());
    }

    fn write_plaintext(&mut self, data: &[u8]) -> Result<(), WinrmError> {
        use std::io::Write;
        self.ssl
            .write_all(data)
            .map_err(|e| WinrmError::AuthFailed(format!("inner TLS write: {e}")))?;
        self.ssl
            .flush()
            .map_err(|e| WinrmError::AuthFailed(format!("inner TLS flush: {e}")))?;
        Ok(())
    }

    fn read_plaintext(&mut self) -> Result<Vec<u8>, WinrmError> {
        use openssl::ssl::ErrorCode;
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match self.ssl.ssl_read(&mut buf) {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(e) if e.code() == ErrorCode::WANT_READ || e.code() == ErrorCode::WANT_WRITE => {
                    break;
                }
                Err(e) => {
                    return Err(WinrmError::AuthFailed(format!("inner TLS read: {e}")));
                }
            }
        }
        Ok(out)
    }

    fn peer_cert_der(&self) -> Result<Vec<u8>, WinrmError> {
        let cert = self
            .ssl
            .ssl()
            .peer_certificate()
            .ok_or_else(|| WinrmError::AuthFailed("CredSSP: no peer cert".into()))?;
        cert.to_der()
            .map_err(|e| WinrmError::AuthFailed(format!("cert DER: {e}")))
    }
}

#[cfg(feature = "credssp")]
fn build_inner_openssl_tls() -> Result<OpenSslMemTls, WinrmError> {
    use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};

    let mut builder = SslConnector::builder(SslMethod::tls_client())
        .map_err(|e| WinrmError::AuthFailed(format!("SslConnector: {e}")))?;
    // SslVerifyMode::NONE is intentional and protocol-correct here.
    //
    // The CredSSP inner channel is authenticated by `pubKeyAuth`
    // (MS-CSSP §3.1.5.1): the client computes a hash over the server's
    // SubjectPublicKeyInfo + a nonce, the NTLM session seals it, and
    // the server is expected to echo the symmetric counter-hash. The
    // pubKeyAuth check is performed at line ~795 below; if it fails we
    // abort with `CredSspError::PublicKeyMismatch`. So an X.509 chain
    // check on this leg would be redundant — and crucially, the
    // outer/transport leg already validates the chain (see
    // CredSspConnection::connect / transport.rs CertCapturingVerifier).
    builder.set_verify(SslVerifyMode::NONE);
    // Force TLS 1.2 to match what Microsoft CredSSP server expects.
    builder
        .set_min_proto_version(Some(openssl::ssl::SslVersion::TLS1_2))
        .map_err(|e| WinrmError::AuthFailed(format!("min ver: {e}")))?;
    builder
        .set_max_proto_version(Some(openssl::ssl::SslVersion::TLS1_2))
        .map_err(|e| WinrmError::AuthFailed(format!("max ver: {e}")))?;
    let connector = builder.build();

    let mem_bio = MemBio {
        incoming: std::collections::VecDeque::new(),
        outgoing: Vec::new(),
    };

    // Configure() to disable hostname verification (we don't have one).
    let cfg = connector
        .configure()
        .map_err(|e| WinrmError::AuthFailed(format!("ssl configure: {e}")))?
        .verify_hostname(false)
        .use_server_name_indication(false);
    let mut mhss = cfg
        .into_ssl("credssp")
        .map_err(|e| WinrmError::AuthFailed(format!("into_ssl: {e}")))?;
    mhss.set_connect_state();

    let ssl = openssl::ssl::SslStream::new(mhss, mem_bio)
        .map_err(|e| WinrmError::AuthFailed(format!("SslStream::new: {e}")))?;

    Ok(OpenSslMemTls { ssl })
}

/// A persistent HTTPS connection used for the entire CredSSP exchange.
///
/// Bypasses reqwest because reqwest's connection pool may open a fresh TCP
/// socket between rounds, which destroys the server-side inner-TLS context
/// of CredSSP. Holds a single `TlsStream<TcpStream>` and writes raw HTTP/1.1
/// requests directly. Mirrors `urllib3`'s `response.connection.send(request)`
/// trick used by requests-credssp.
///
/// Implemented manually (not via hyper) for full control over byte
/// serialization and to keep the dep surface tiny — the CredSSP HTTP
/// dialect with WSMAN listener is finicky enough that we need to control
/// every header.
#[cfg(feature = "credssp")]
struct CredSspConnection {
    stream: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    host: String,
    port: u16,
    path: String,
}

#[cfg(feature = "credssp")]
impl CredSspConnection {
    /// Open a TCP+TLS connection to (host:port). The returned object owns
    /// the underlying socket; drop to close.
    ///
    /// `accept_invalid_certs=true` disables outer TLS verification — TEST USE
    /// ONLY. The inner CredSSP TLS is authenticated via pubKeyAuth (MS-CSSP
    /// §3.1.5.1), independent of the outer chain.
    async fn connect(
        host: &str,
        port: u16,
        path: &str,
        accept_invalid_certs: bool,
    ) -> Result<Self, WinrmError> {
        use tokio::net::TcpStream;
        use tokio_rustls::TlsConnector;

        let _ = rustls::crypto::ring::default_provider().install_default();

        let verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> = if accept_invalid_certs
        {
            tracing::warn!(
                "CredSSP outer TLS verification disabled (accept_invalid_certs=true) \
                     — credentials transit a MITM-vulnerable channel; do not use in production"
            );
            Arc::new(crate::tls::NoVerifier)
        } else {
            let root_store =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            rustls::client::WebPkiServerVerifier::builder(Arc::new(root_store))
                .build()
                .map_err(|e| WinrmError::AuthFailed(format!("CredSSP TLS verifier build: {e}")))?
        };

        // The `mut` is only needed when we honour SSLKEYLOGFILE — that is in
        // debug builds. In release the binding is immutable so rustc doesn't
        // emit an "unused mut" warning.
        #[cfg(debug_assertions)]
        let mut outer_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        #[cfg(not(debug_assertions))]
        let outer_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        // Honour SSLKEYLOGFILE only in debug builds. In release this env var
        // is ignored so a hostile environment cannot enable wireshark-style
        // session-key export of the outer CredSSP TLS leg.
        #[cfg(debug_assertions)]
        if std::env::var("SSLKEYLOGFILE").is_ok() {
            outer_config.key_log = Arc::new(rustls::KeyLogFile::new());
        }
        let connector = TlsConnector::from(Arc::new(outer_config));

        let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
            .map_err(|_| WinrmError::AuthFailed(format!("CredSSP: invalid SNI: {host}")))?;

        let tcp = TcpStream::connect((host, port))
            .await
            .map_err(|e| WinrmError::AuthFailed(format!("CredSSP TCP connect: {e}")))?;
        tcp.set_nodelay(true).ok();

        let stream = connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| WinrmError::AuthFailed(format!("CredSSP outer TLS: {e}")))?;

        Ok(Self {
            stream,
            host: host.to_string(),
            port,
            path: path.to_string(),
        })
    }

    /// Send one POST and return (status, headers, body bytes). Writes raw
    /// HTTP/1.1 onto the persistent TLS stream.
    async fn post(
        &mut self,
        auth_header: Option<&str>,
        body: &str,
    ) -> Result<(u16, std::collections::HashMap<String, String>, Vec<u8>), WinrmError> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // ---- Build the request bytes ----
        let mut req = String::with_capacity(512 + body.len() + auth_header.map_or(0, |a| a.len()));
        use std::fmt::Write as _;
        // pywinrm/urllib3 puts Authorization BEFORE Content-Type/Content-Length.
        // Microsoft HTTPAPI may rely on this ordering for CredSSP context tracking.
        write!(req, "POST {} HTTP/1.1\r\n", self.path).unwrap();
        write!(req, "Host: {}:{}\r\n", self.host, self.port).unwrap();
        write!(req, "User-Agent: Python WinRM client\r\n").unwrap();
        write!(req, "Accept-Encoding: gzip, deflate, zstd\r\n").unwrap();
        write!(req, "Accept: */*\r\n").unwrap();
        write!(req, "Connection: Keep-Alive\r\n").unwrap();
        if let Some(av) = auth_header {
            write!(req, "Authorization: {av}\r\n").unwrap();
        }
        write!(req, "Content-Type: application/soap+xml;charset=UTF-8\r\n").unwrap();
        write!(req, "Content-Length: {}\r\n", body.len()).unwrap();
        req.push_str("\r\n");

        tracing::trace!(target: "winrm_rs::credssp", head_len = req.len(), "POST {}", self.path);

        // ---- Send headers + body in a single write so the entire HTTP
        // request lands in one TLS record (matches what Python ssl + urllib3
        // do; helps Microsoft HTTPAPI parse the auth context correctly). ----
        let mut wire = Vec::with_capacity(req.len() + body.len());
        wire.extend_from_slice(req.as_bytes());
        wire.extend_from_slice(body.as_bytes());
        self.stream
            .write_all(&wire)
            .await
            .map_err(|e| WinrmError::AuthFailed(format!("CredSSP write: {e}")))?;
        self.stream
            .flush()
            .await
            .map_err(|e| WinrmError::AuthFailed(format!("CredSSP flush: {e}")))?;

        // ---- Read the response: status line + headers + body (Content-Length) ----
        let mut buf = Vec::with_capacity(8192);
        let head_end = loop {
            let mut chunk = [0u8; 4096];
            let n = self
                .stream
                .read(&mut chunk)
                .await
                .map_err(|e| WinrmError::AuthFailed(format!("CredSSP read: {e}")))?;
            if n == 0 {
                return Err(WinrmError::AuthFailed(
                    "CredSSP: server closed connection mid-response".into(),
                ));
            }
            buf.extend_from_slice(&chunk[..n]);
            if let Some(pos) = find_double_crlf(&buf) {
                break pos + 4;
            }
            if buf.len() > 1024 * 1024 {
                return Err(WinrmError::AuthFailed(
                    "CredSSP: response head too large".into(),
                ));
            }
        };

        let head_str = std::str::from_utf8(&buf[..head_end])
            .map_err(|_| WinrmError::AuthFailed("CredSSP: non-UTF8 response head".into()))?;
        let mut lines = head_str.split("\r\n");
        let status_line = lines.next().unwrap_or("");
        let status: u16 = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| {
                WinrmError::AuthFailed(format!("CredSSP: bad status line: {status_line}"))
            })?;

        let mut headers: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        for line in lines {
            if line.is_empty() {
                break;
            }
            if let Some((k, v)) = line.split_once(':') {
                let key = k.trim().to_ascii_lowercase();
                let val = v.trim().to_string();
                // Append for repeated headers (e.g. WWW-Authenticate)
                headers
                    .entry(key)
                    .and_modify(|e| {
                        e.push_str(", ");
                        e.push_str(&val);
                    })
                    .or_insert(val);
            }
        }

        // Determine body length: Content-Length only (we send Accept-Encoding: identity).
        let content_length: usize = headers
            .get("content-length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let mut body_bytes: Vec<u8> = buf[head_end..].to_vec();
        while body_bytes.len() < content_length {
            let mut chunk = [0u8; 4096];
            let n = self
                .stream
                .read(&mut chunk)
                .await
                .map_err(|e| WinrmError::AuthFailed(format!("CredSSP read body: {e}")))?;
            if n == 0 {
                break;
            }
            body_bytes.extend_from_slice(&chunk[..n]);
        }
        body_bytes.truncate(content_length);

        tracing::trace!(target: "winrm_rs::credssp", %status, body = body_bytes.len(), "credssp response");

        Ok((status, headers, body_bytes))
    }
}

#[cfg(feature = "credssp")]
fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Get the value of a header from a CredSspConnection response map (case-insensitive).
#[cfg(feature = "credssp")]
fn header_get<'a>(
    headers: &'a std::collections::HashMap<String, String>,
    name: &str,
) -> Option<&'a str> {
    headers.get(&name.to_ascii_lowercase()).map(|s| s.as_str())
}

/// Extract the CredSSP token from the WWW-Authenticate header (handles
/// "CredSSP <b64>" possibly mixed with other schemes).
#[cfg(feature = "credssp")]
fn extract_credssp_token_str(www_auth: &str) -> Option<String> {
    let upper = www_auth.to_uppercase();
    let pos = upper.find("CREDSSP ")?;
    let after = &www_auth[pos + "CREDSSP ".len()..];
    let token: String = after
        .chars()
        .take_while(|c| !c.is_whitespace() && *c != ',')
        .collect();
    if token.is_empty() { None } else { Some(token) }
}

/// Parse `https://host:port/path` into (host, port, path) for CredSspConnection.
#[cfg(feature = "credssp")]
fn parse_url(url: &str) -> Result<(String, u16, String), WinrmError> {
    let after_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .ok_or_else(|| WinrmError::AuthFailed(format!("CredSSP: bad URL {url}")))?;
    let (authority, path) = match after_scheme.find('/') {
        Some(i) => (&after_scheme[..i], &after_scheme[i..]),
        None => (after_scheme, "/"),
    };
    let (host, port) = match authority.rfind(':') {
        Some(i) => {
            let p: u16 = authority[i + 1..]
                .parse()
                .map_err(|_| WinrmError::AuthFailed(format!("CredSSP: bad port in {url}")))?;
            (authority[..i].to_string(), p)
        }
        None => (authority.to_string(), 5986),
    };
    Ok((host, port, path.to_string()))
}

/// CredSSP authentication transport.
///
/// Performs the MS-CSSP protocol: TLS-in-TLS handshake, NTLM negotiation,
/// public key binding, and encrypted credential delegation. Requires HTTPS.
pub(crate) struct CredSspAuth {
    pub(crate) username: String,
    pub(crate) password: Zeroizing<String>,
    pub(crate) domain: String,
    pub(crate) cert_handle: Option<CertHandle>,
    /// Mirrors `WinrmConfig.accept_invalid_certs`. When true, the outer TLS
    /// channel skips chain validation. Inner TLS authentication relies on
    /// pubKeyAuth regardless (MS-CSSP §3.1.5.1).
    pub(crate) accept_invalid_certs: bool,
}

#[cfg(feature = "credssp")]
impl AuthTransport for CredSspAuth {
    async fn send_authenticated(
        &self,
        _http: &reqwest::Client,
        url: &str,
        body: String,
    ) -> Result<String, WinrmError> {
        // CredSSP needs ONE TCP+TLS connection for the entire flow because
        // the server's inner-TLS state is bound to the socket. We bypass
        // reqwest entirely and drive raw HTTP/1.1 over a single tokio_rustls
        // TlsStream. See CredSspConnection above.
        let (host, port, path) = parse_url(url)?;
        let mut conn =
            CredSspConnection::connect(&host, port, &path, self.accept_invalid_certs).await?;

        // Pywinrm sends the SOAP body in every CredSSP round (which is what
        // Microsoft HTTPAPI on the WSMAN listener expects). The same body is
        // re-sent during the auth handshake AND on the final TSCredentials
        // delivery.
        let body_for_auth: &str = &body;

        let encode_auth = |bytes: &[u8]| format!("CredSSP {}", B64.encode(bytes));

        let _ = &header_get;

        // === Step 1: Initialize the INNER TLS connection (memory-only) ===
        // Use OpenSSL via in-memory BIO — pyspnego does the same and rustls
        // produces a TLS state Microsoft's CredSSP server silently rejects.
        let mut inner_tls = build_inner_openssl_tls()?;
        // Drive the TLS handshake one step to produce ClientHello.
        inner_tls.handshake_step()?;

        // === Step 3: Drive the TLS handshake through HTTP rounds ===
        // Each round:
        //   1. Drain outgoing TLS bytes (ClientHello, then key exchange...)
        //   2. POST to server with these bytes in Authorization header
        //   3. Receive server response (ServerHello, etc.) in WWW-Authenticate
        //   4. Feed back into rustls
        //   5. Repeat until !is_handshaking()
        let mut round = 0;
        loop {
            round += 1;
            if round > 10 {
                return Err(WinrmError::AuthFailed(
                    "CredSSP: TLS handshake did not complete in 10 rounds".into(),
                ));
            }

            let outgoing = inner_tls.drain_outgoing();
            if outgoing.is_empty() {
                if inner_tls.handshake_step()? {
                    break;
                }
                continue;
            }

            let (status, headers, _) = conn
                .post(Some(&encode_auth(&outgoing)), body_for_auth)
                .await?;
            if status != 401 {
                return Err(WinrmError::AuthFailed(format!(
                    "CredSSP: TLS handshake round {round}: expected 401, got {status}"
                )));
            }
            let server_token = header_get(&headers, "www-authenticate")
                .and_then(extract_credssp_token_str)
                .ok_or_else(|| {
                    WinrmError::AuthFailed(format!(
                        "CredSSP: TLS handshake round {round}: no CredSSP token in response"
                    ))
                })?;
            let server_bytes = B64.decode(server_token.trim_ascii()).map_err(|e| {
                WinrmError::AuthFailed(format!("CredSSP: bad base64 in handshake: {e}"))
            })?;
            inner_tls.feed_incoming(&server_bytes);
            if inner_tls.handshake_step()? {
                break;
            }
        }

        // === Extract SubjectPublicKey from the INNER TLS server cert ===
        let inner_cert_der = inner_tls.peer_cert_der()?;
        let inner_cert_der: &[u8] = &inner_cert_der;
        let subject_public_key = {
            use x509_cert::der::Decode;
            let cert = x509_cert::Certificate::from_der(inner_cert_der)
                .map_err(|e| WinrmError::AuthFailed(format!("CredSSP cert parse: {e}")))?;
            // Per MS-CSSP 2.2.2.5, pubKeyAuth is computed over the bit string
            // contents of subjectPublicKey (PKCS#1 RSAPublicKey for RSA certs).
            cert.tbs_certificate()
                .subject_public_key_info()
                .subject_public_key
                .raw_bytes()
                .to_vec()
        };

        // === Step 4: Inner TLS established. Build NTLM Type 1 in TSRequest ===
        // Use the CredSSP-specific Type 1 with KEY_EXCH/SEAL/SIGN flags required
        // for the sealing of pubKeyAuth and TSCredentials.
        let type1 = ntlm::create_negotiate_message_credssp();
        let spnego_init = asn1::encode_spnego_init(&type1);
        let ts_req1 =
            asn1::encode_ts_request(CREDSSP_VERSION, Some(&spnego_init), None, None, None);
        inner_tls.write_plaintext(&ts_req1)?;
        let outgoing = Ok::<_, WinrmError>(inner_tls.drain_outgoing())?;

        // Send through HTTP
        let (status, headers, _) = conn
            .post(Some(&encode_auth(&outgoing)), body_for_auth)
            .await?;
        if status != 401 {
            return Err(WinrmError::AuthFailed(format!(
                "CredSSP: NTLM negotiate: expected 401, got {status}"
            )));
        }
        let server_token = header_get(&headers, "www-authenticate")
            .and_then(extract_credssp_token_str)
            .ok_or_else(|| WinrmError::AuthFailed("CredSSP: NTLM nego: no CredSSP token".into()))?;
        let server_bytes = B64
            .decode(server_token.trim_ascii())
            .map_err(|e| WinrmError::AuthFailed(format!("CredSSP: bad b64 NTLM nego: {e}")))?;
        {
            inner_tls.feed_incoming(&server_bytes);
            Ok::<_, WinrmError>(())
        }?;
        let plaintext = inner_tls.read_plaintext()?;

        // === Step 5: Decode TSRequest containing NTLM Type 2 ===
        let ts_resp = asn1::decode_ts_request(&plaintext).map_err(WinrmError::CredSsp)?;
        let negotiated_version = std::cmp::min(ts_resp.version, CREDSSP_VERSION);
        tracing::debug!(
            server_version = ts_resp.version,
            negotiated = negotiated_version,
            "CredSSP version negotiation"
        );
        if let Some(code) = ts_resp.error_code {
            return Err(WinrmError::CredSsp(CredSspError::ServerError(code)));
        }
        let spnego_resp = ts_resp
            .nego_token
            .ok_or_else(|| WinrmError::AuthFailed("CredSSP: no negoToken from server".into()))?;
        let type2 = asn1::decode_spnego_token(&spnego_resp).map_err(WinrmError::CredSsp)?;
        let challenge = ntlm::parse_challenge(&type2).map_err(WinrmError::Ntlm)?;

        // === Step 6: Build NTLM Type 3 + pubKeyAuth + clientNonce ===
        // CONFIRMED via forensic hash analysis: pywinrm uses username.upper()+empty
        // for NTOWFv2 (NTProofStr matches when computed this way). Empty domain.
        let domain = self.domain.clone();
        // Compute SPN from URL hostname
        let host = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .unwrap_or(url);
        let host_part = host.split('/').next().unwrap_or(host);
        let host_only = host_part.split(':').next().unwrap_or(host_part);
        let spn = format!("HTTP/{host_only}");

        let (type3, session_key) = ntlm::create_authenticate_message_credssp(
            &challenge,
            &self.username,
            &self.password,
            &domain,
            &spn,
            &type1,
            &type2,
        );
        let mut ntlm_session = NtlmSession::from_auth(&session_key);
        // Compute mechListMIC over the SPNEGO mech_type_list. This MUST happen
        // before sealing pubKeyAuth so that the latter uses seq=1 (matches
        // pyspnego/Windows expectations). Without mechListMIC the server
        // returns STATUS_LOGON_FAILURE. `sign_mech_list_mic` also resets the
        // RC4 sealing handle afterwards, as Windows SPNEGO does — the
        // pubKeyAuth below must be sealed at keystream offset 0.
        let mech_list_mic = ntlm_session.sign_mech_list_mic(asn1::MECH_TYPE_LIST_NTLM);

        // Compute pubKeyAuth (v6): SHA256(magic + nonce + SubjectPublicKey).
        //
        // CREDSSP_FIXED_NONCE is a deterministic-test backdoor — only honoured
        // in debug builds. Production binaries always use the CSPRNG so a
        // hostile environment cannot collapse the v6 nonce defence against
        // cross-protocol relay.
        let nonce: [u8; 32] = {
            #[cfg(debug_assertions)]
            let from_env = std::env::var("CREDSSP_FIXED_NONCE").ok().and_then(|s| {
                let bytes = (0..s.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
                    .collect::<Option<Vec<_>>>()?;
                bytes.try_into().ok()
            });
            #[cfg(not(debug_assertions))]
            let from_env: Option<[u8; 32]> = None;
            from_env.unwrap_or_else(rand::random)
        };
        let client_hash = {
            let mut hasher = Sha256::new();
            hasher.update(b"CredSSP Client-To-Server Binding Hash\0");
            hasher.update(nonce);
            hasher.update(&subject_public_key);
            hasher.finalize().to_vec()
        };
        let encrypted_pub_key_auth = ntlm_session.seal(&client_hash);

        let spnego_authenticate = asn1::encode_spnego_response(&type3, Some(&mech_list_mic));
        let ts_req3 = asn1::encode_ts_request(
            CREDSSP_VERSION,
            Some(&spnego_authenticate),
            Some(&encrypted_pub_key_auth),
            None,
            Some(&nonce),
        );
        // CREDSSP_DUMP dumps every secret (nonce, public key bind, sealed
        // pubKeyAuth) to stderr — strictly a debug-build aid. Compiled out
        // of release binaries entirely.
        #[cfg(debug_assertions)]
        if std::env::var("CREDSSP_DUMP").is_ok() {
            let h = |b: &[u8]| b.iter().map(|x| format!("{:02x}", x)).collect::<String>();
            eprintln!(
                "[CREDSSP_DUMP] ts_req3 ({}B): {}",
                ts_req3.len(),
                h(&ts_req3)
            );
            eprintln!("[CREDSSP_DUMP] nonce: {}", h(&nonce));
            eprintln!("[CREDSSP_DUMP] inner_cert_der: {}", h(inner_cert_der));
            eprintln!("[CREDSSP_DUMP] type1: {}", h(&type1));
            eprintln!("[CREDSSP_DUMP] spnego_init: {}", h(&spnego_init));
            eprintln!("[CREDSSP_DUMP] type2: {}", h(&type2));
            eprintln!("[CREDSSP_DUMP] type3: {}", h(&type3));
            eprintln!("[CREDSSP_DUMP] mech_list_mic: {}", h(&mech_list_mic));
            eprintln!("[CREDSSP_DUMP] spn: {spn}");
            eprintln!(
                "[CREDSSP_DUMP] subject_public_key: {}",
                h(&subject_public_key)
            );
            eprintln!("[CREDSSP_DUMP] client_hash: {}", h(&client_hash));
            eprintln!(
                "[CREDSSP_DUMP] sealed_pub_key_auth: {}",
                h(&encrypted_pub_key_auth)
            );
        }
        inner_tls.write_plaintext(&ts_req3)?;
        let outgoing = Ok::<_, WinrmError>(inner_tls.drain_outgoing())?;

        let (status, headers, _) = conn
            .post(Some(&encode_auth(&outgoing)), body_for_auth)
            .await?;
        if status != 401 {
            return Err(WinrmError::AuthFailed(format!(
                "CredSSP: NTLM authenticate: expected 401, got {status}"
            )));
        }
        #[cfg(debug_assertions)]
        if std::env::var("CREDSSP_DUMP").is_ok() {
            eprintln!("[CREDSSP_DUMP] step6 response status={status} headers={headers:?}");
        }
        let server_token = header_get(&headers, "www-authenticate")
            .and_then(extract_credssp_token_str)
            .ok_or_else(|| {
                WinrmError::AuthFailed(
                    "CredSSP: server dropped the context after NTLM AUTHENTICATE + pubKeyAuth \
                     (401 without a CredSSP token is how Windows reports a rejected pubKeyAuth)"
                        .into(),
                )
            })?;
        let server_bytes = B64
            .decode(server_token.trim_ascii())
            .map_err(|e| WinrmError::AuthFailed(format!("CredSSP: bad b64 auth: {e}")))?;
        {
            inner_tls.feed_incoming(&server_bytes);
            Ok::<_, WinrmError>(())
        }?;
        let plaintext = inner_tls.read_plaintext()?;

        // === Step 7: Verify server pubKeyAuth ===
        let ts_resp = asn1::decode_ts_request(&plaintext).map_err(WinrmError::CredSsp)?;
        if let Some(code) = ts_resp.error_code {
            return Err(WinrmError::CredSsp(CredSspError::ServerError(code)));
        }
        // The server's final SPNEGO token carries its mechListMIC. Verify it
        // (GSS_VerifyMIC at server seq 0); this also re-initialises the server
        // RC4 handle, so the pubKeyAuth below unseals at seq 1, keystream
        // offset 0 — the same reset Windows applies on its side.
        if let Some(nego) = &ts_resp.nego_token
            && let Some(mic) =
                asn1::decode_spnego_mech_list_mic(nego).map_err(WinrmError::CredSsp)?
        {
            ntlm_session
                .verify_mech_list_mic(asn1::MECH_TYPE_LIST_NTLM, &mic)
                .map_err(WinrmError::Ntlm)?;
        }
        let server_pub_key_auth = ts_resp
            .pub_key_auth
            .ok_or_else(|| WinrmError::AuthFailed("CredSSP: no pubKeyAuth from server".into()))?;
        let decrypted_server_hash = ntlm_session
            .unseal(&server_pub_key_auth)
            .map_err(WinrmError::Ntlm)?;
        let expected_server_hash = {
            let mut hasher = Sha256::new();
            hasher.update(b"CredSSP Server-To-Client Binding Hash\0");
            hasher.update(nonce);
            hasher.update(&subject_public_key);
            hasher.finalize().to_vec()
        };
        if decrypted_server_hash != expected_server_hash {
            return Err(WinrmError::CredSsp(CredSspError::PublicKeyMismatch));
        }

        // === Step 8: Send encrypted TSCredentials ===
        let ts_creds = asn1::encode_ts_credentials(&domain, &self.username, &self.password);
        let encrypted_creds = ntlm_session.seal(&ts_creds);
        let ts_req5 =
            asn1::encode_ts_request(CREDSSP_VERSION, None, None, Some(&encrypted_creds), None);
        inner_tls.write_plaintext(&ts_req5)?;
        let outgoing = Ok::<_, WinrmError>(inner_tls.drain_outgoing())?;

        let (status, _headers, resp_body) = conn.post(Some(&encode_auth(&outgoing)), &body).await?;
        if status == 401 {
            return Err(WinrmError::AuthFailed(
                "CredSSP: credentials rejected after delegation".into(),
            ));
        }
        if !(200..300).contains(&status) {
            let body_text = String::from_utf8_lossy(&resp_body).into_owned();
            return Err(WinrmError::AuthFailed(format!(
                "CredSSP HTTP {status}: {body_text}"
            )));
        }
        Ok(String::from_utf8_lossy(&resp_body).into_owned())
    }
}

#[cfg(not(feature = "credssp"))]
impl AuthTransport for CredSspAuth {
    async fn send_authenticated(
        &self,
        _http: &reqwest::Client,
        _url: &str,
        _body: String,
    ) -> Result<String, WinrmError> {
        Err(WinrmError::AuthFailed(
            "CredSSP authentication requires the 'credssp' feature. \
             Enable it with: cargo add winrm-rs --features credssp"
                .into(),
        ))
    }
}

#[cfg(all(test, feature = "credssp"))]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue};

    fn make_headers(values: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for v in values {
            h.append("WWW-Authenticate", HeaderValue::from_str(v).unwrap());
        }
        h
    }

    #[test]
    fn extract_credssp_token_simple() {
        let h = make_headers(&["CredSSP YWJjZGVm"]);
        assert_eq!(extract_credssp_token(&h), Some("YWJjZGVm".to_string()));
    }

    #[test]
    fn extract_credssp_token_case_insensitive() {
        let h = make_headers(&["credssp YWJjZGVm"]);
        assert_eq!(extract_credssp_token(&h), Some("YWJjZGVm".to_string()));
        let h = make_headers(&["CREDSSP YWJjZGVm"]);
        assert_eq!(extract_credssp_token(&h), Some("YWJjZGVm".to_string()));
    }

    #[test]
    fn extract_credssp_token_multiple_schemes_one_header() {
        let h = make_headers(&["Negotiate, CredSSP TOKEN, Basic"]);
        assert_eq!(extract_credssp_token(&h), Some("TOKEN".to_string()));
    }

    #[test]
    fn extract_credssp_token_multiple_headers() {
        let h = make_headers(&["Negotiate", "Basic realm=\"WSMAN\"", "CredSSP MYTOKEN"]);
        assert_eq!(extract_credssp_token(&h), Some("MYTOKEN".to_string()));
    }

    #[test]
    fn extract_credssp_token_no_credssp() {
        let h = make_headers(&["Negotiate", "Basic realm=\"WSMAN\""]);
        assert_eq!(extract_credssp_token(&h), None);
    }

    #[test]
    fn extract_credssp_token_advertised_no_token() {
        // CredSSP advertised but without a token (e.g., initial 401)
        let h = make_headers(&["CredSSP"]);
        assert_eq!(extract_credssp_token(&h), None);
    }

    #[test]
    fn extract_credssp_token_empty_headers() {
        let h = HeaderMap::new();
        assert_eq!(extract_credssp_token(&h), None);
    }

    #[test]
    fn advertises_credssp_detects_scheme() {
        let h = make_headers(&["Negotiate", "Basic", "CredSSP"]);
        assert!(advertises_credssp(&h));
    }

    #[test]
    fn advertises_credssp_case_insensitive() {
        let h = make_headers(&["credssp"]);
        assert!(advertises_credssp(&h));
    }

    #[test]
    fn advertises_credssp_returns_false_when_absent() {
        let h = make_headers(&["Negotiate", "Basic"]);
        assert!(!advertises_credssp(&h));
    }

    #[test]
    fn advertises_credssp_works_with_token() {
        let h = make_headers(&["CredSSP YWJjZGVm"]);
        assert!(advertises_credssp(&h));
    }

    #[test]
    fn parse_url_https_with_port_and_path() {
        let (h, p, path) = parse_url("https://host.example:5986/wsman").unwrap();
        assert_eq!(h, "host.example");
        assert_eq!(p, 5986);
        assert_eq!(path, "/wsman");
    }

    #[test]
    fn parse_url_http_scheme_also_accepted() {
        let (h, p, path) = parse_url("http://h:80/x").unwrap();
        assert_eq!((h.as_str(), p, path.as_str()), ("h", 80, "/x"));
    }

    #[test]
    fn parse_url_defaults_port_5986_when_missing() {
        let (h, p, path) = parse_url("https://host/wsman").unwrap();
        assert_eq!(h, "host");
        assert_eq!(p, 5986);
        assert_eq!(path, "/wsman");
    }

    #[test]
    fn parse_url_defaults_path_when_missing() {
        let (h, p, path) = parse_url("https://host:5986").unwrap();
        assert_eq!((h.as_str(), p, path.as_str()), ("host", 5986, "/"));
    }

    #[test]
    fn parse_url_rejects_bad_scheme() {
        assert!(parse_url("ftp://host/path").is_err());
    }

    #[test]
    fn parse_url_rejects_bad_port() {
        assert!(parse_url("https://host:notaport/x").is_err());
    }

    #[test]
    fn extract_credssp_token_str_simple() {
        assert_eq!(
            extract_credssp_token_str("CredSSP YWJjZGVm"),
            Some("YWJjZGVm".to_string())
        );
    }

    #[test]
    fn extract_credssp_token_str_case_insensitive_and_mixed() {
        assert_eq!(
            extract_credssp_token_str("Negotiate, credssp ABCDEF, Basic"),
            Some("ABCDEF".to_string())
        );
    }

    #[test]
    fn extract_credssp_token_str_returns_none_when_no_token() {
        assert_eq!(extract_credssp_token_str("Negotiate, Basic"), None);
        assert_eq!(extract_credssp_token_str("CredSSP "), None);
    }

    #[test]
    fn find_double_crlf_locates_separator() {
        let buf = b"GET / HTTP/1.1\r\nHost: x\r\n\r\nbody";
        let pos = find_double_crlf(buf).unwrap();
        assert_eq!(&buf[pos..pos + 4], b"\r\n\r\n");
    }

    #[test]
    fn find_double_crlf_returns_none_when_absent() {
        assert!(find_double_crlf(b"no separator here").is_none());
        // Single CRLF only is not enough
        assert!(find_double_crlf(b"a\r\nb").is_none());
    }

    #[test]
    fn header_get_is_case_insensitive() {
        let mut h = std::collections::HashMap::new();
        h.insert("content-length".to_string(), "42".to_string());
        assert_eq!(header_get(&h, "Content-Length"), Some("42"));
        assert_eq!(header_get(&h, "CONTENT-LENGTH"), Some("42"));
        assert_eq!(header_get(&h, "missing"), None);
    }

    #[test]
    fn membio_write_appends_to_outgoing_and_read_drains_incoming() {
        use std::io::{Read, Write};
        let mut bio = MemBio {
            incoming: std::collections::VecDeque::new(),
            outgoing: Vec::new(),
        };
        // Write extends outgoing
        assert_eq!(bio.write(b"hello").unwrap(), 5);
        bio.flush().unwrap();
        assert_eq!(bio.outgoing, b"hello");

        // Read on empty incoming returns WouldBlock
        let mut buf = [0u8; 4];
        let err = bio.read(&mut buf).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);

        // Feed incoming and read it back
        bio.incoming.extend(b"abcdef".iter().copied());
        let n = bio.read(&mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(&buf, b"abcd");
        // Remaining 2 bytes still queued
        assert_eq!(bio.incoming.len(), 2);
    }

    #[test]
    fn openssl_inner_tls_peer_cert_before_handshake_errors() {
        let tls = build_inner_openssl_tls().expect("build inner tls");
        // No handshake completed → no peer cert available
        assert!(tls.peer_cert_der().is_err());
    }

    #[test]
    fn openssl_inner_tls_feed_incoming_then_drain_clears_outgoing() {
        let mut tls = build_inner_openssl_tls().expect("build inner tls");
        let _ = tls.handshake_step();
        let first = tls.drain_outgoing();
        assert!(!first.is_empty());
        // After draining, outgoing buffer should be empty
        assert!(tls.drain_outgoing().is_empty());
        // feed_incoming with garbage doesn't panic
        tls.feed_incoming(&[0u8; 8]);
    }

    #[test]
    fn openssl_inner_tls_handshake_starts() {
        let mut tls = build_inner_openssl_tls().expect("build inner tls");
        let _ = tls.handshake_step();
        let bytes = tls.drain_outgoing();
        assert!(!bytes.is_empty(), "should produce ClientHello bytes");
        // First byte of TLS record is 0x16 (Handshake)
        assert_eq!(bytes[0], 0x16);
    }
}
