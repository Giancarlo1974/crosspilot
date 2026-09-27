//! TLS 1.3 post-quantum sul canale TCP client<->server (docs/tls-pq-spec.md).
//!
//! - CryptoProvider rustls su `ring` (gia' compilato su tutti i target via
//!   winrm-rs/russh; workaround musl in .cargo/config.toml) con UNICO
//!   kx_group `X25519MLKEM768` (rustls-pq-addon vendored, portato a
//!   ml-kem 0.3 per convivere con russh — vedi Cargo.toml [patch]).
//! - Solo TLS 1.3, nessun fallback di versione: handshake fallito =
//!   errore fatale, mai downgrade silenzioso.
//! - Server: cert self-signed rcgen ECDSA-P256 persistito come
//!   `crosspilot-server.key`/`.crt` accanto all'exe (spec §7.1).
//! - Client: pinning del cert con semantica TOFU su
//!   `crosspilot_known_hosts` (linee `host:port tls-sha256:<b64>`,
//!   spec §7.2) — stesso modello della host key SSH.
//! - AUTH: token condiviso dentro TLS, confronto costante (spec §8).
//! - `Link`: astrazione dello stream (plaintext/TLS server/TLS client)
//!   usata da transfer/sync/update/shell, identica byte-per-byte
//!   sopra il record layer.

use std::collections::VecDeque;
use std::fmt;
use std::fs;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{anyhow, bail, Context as _, Result};
use base64::Engine;
use rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, ServerConfig, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::{envs, version};

// ---------------------------------------------------------------------------
// Costanti di protocollo (spec §4, §5, §8).
// ---------------------------------------------------------------------------

/// Cutoff TLS: il server e' TLS-capable se `READY <ts>` e' >= TLS_MIN_TS
/// (spec §4). Valore = BUILD_TS della prima release TLS-capable: i peer
/// pre-TLS deployati hanno ts strettamente minore, ogni build successiva
/// (ts piu' alto) resta TLS-capable.
pub const TLS_MIN_TS: u64 = 1_790_342_821;

/// Timeout dell'handshake TLS (record layer sul TCP appena accettato).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout per la lettura della riga AUTH dentro TLS (spec §8).
const AUTH_TIMEOUT: Duration = Duration::from_secs(5);

/// Cap della riga AUTH: token oltre questo limite sono malformed.
const MAX_AUTH_LINE: usize = 4096;

/// Timeout del mode-detection dentro TLS (mirror del peek 2s in chiaro).
pub const MODE_DETECT_TIMEOUT: Duration = Duration::from_secs(2);

/// Nome file della chiave privata del server (MAI servita via protocollo).
pub const SERVER_KEY_FILE: &str = "crosspilot-server.key";

/// Nome file del certificato self-signed del server.
pub const SERVER_CRT_FILE: &str = "crosspilot-server.crt";

/// Tag delle fingerprint TLS nel file crosspilot_known_hosts (spec §7.2).
const TLS_PIN_TAG: &str = "tls-sha256:";

/// DNS name statico usato nel ClientHello SNI: il pinning valida
/// l'identita' del server, non il nome — resta solo un placeholder.
const TLS_SERVER_NAME: &str = "crosspilot.local";

/// Warning "AUTH disabilitata" emesso una sola volta per processo.
static AUTH_DISABLED_WARNED: AtomicBool = AtomicBool::new(false);

// ---------------------------------------------------------------------------
// Errori fatali TLS (nessun retry, nessun bootstrap, nessun plaintext).
// ---------------------------------------------------------------------------

/// Errore fatale TLS: pin mismatch, downgrade, REQUIRE_TLS violato,
/// handshake fallito. Il chiamante deve propagare subito (come
/// HostKeyMismatch di ssh_transport): non si ritenta il bootstrap.
#[derive(Debug)]
pub struct TlsFatal(pub String);

impl fmt::Display for TlsFatal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for TlsFatal {}

// ---------------------------------------------------------------------------
// Link: stream unificato plaintext / TLS server / TLS client.
// ---------------------------------------------------------------------------

/// Varianti del trasporto sottostante di `Link`.
enum LinkInner {
    /// TCP nudo (rollout: server vecchio o REQUIRE_TLS assente).
    Plain(TcpStream),
    /// Record layer TLS lato server.
    TlsServer(Box<tokio_rustls::server::TlsStream<TcpStream>>),
    /// Record layer TLS lato client.
    TlsClient(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

/// Stream applicativo unificato usato da transfer/sync/update/shell.
///
/// `head` contiene i byte gia' consumati durante il mode-detection TLS
/// (su TLS non si puo' fare peek come su TcpStream): vengono riletti
/// prima dei byte di rete, rendendo il comportamento identico al peek.
pub struct Link {
    inner: LinkInner,
    head: VecDeque<u8>,
}

impl Link {
    /// Avvolge una connessione TCP in chiaro.
    pub fn plain(socket: TcpStream) -> Self {
        let inner = LinkInner::Plain(socket);
        let head = VecDeque::new();
        Self { inner, head }
    }

    /// Avvolge uno stream TLS accettato (lato server).
    pub fn tls_server(stream: tokio_rustls::server::TlsStream<TcpStream>) -> Self {
        let boxed = Box::new(stream);
        let inner = LinkInner::TlsServer(boxed);
        let head = VecDeque::new();
        Self { inner, head }
    }

    /// Avvolge uno stream TLS iniziato (lato client).
    pub fn tls_client(stream: tokio_rustls::client::TlsStream<TcpStream>) -> Self {
        let boxed = Box::new(stream);
        let inner = LinkInner::TlsClient(boxed);
        let head = VecDeque::new();
        Self { inner, head }
    }

    /// True se il canale e' cifrato (TLS); false sul plaintext di rollout.
    pub fn is_tls(&self) -> bool {
        match self.inner {
            LinkInner::Plain(_) => false,
            LinkInner::TlsServer(_) | LinkInner::TlsClient(_) => true,
        }
    }

    /// Indirizzo locale del socket (usato da server_apply_update per
    /// capire se l'updater gira sul server stesso).
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        match &self.inner {
            LinkInner::Plain(s) => s.local_addr(),
            LinkInner::TlsServer(s) => s.get_ref().0.local_addr(),
            LinkInner::TlsClient(s) => s.get_ref().0.local_addr(),
        }
    }

    /// Indirizzo del peer remoto (solo diagnostica/log).
    #[allow(dead_code)]
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        match &self.inner {
            LinkInner::Plain(s) => s.peer_addr(),
            LinkInner::TlsServer(s) => s.get_ref().0.peer_addr(),
            LinkInner::TlsClient(s) => s.get_ref().0.peer_addr(),
        }
    }

    /// Ri-accoda davanti allo stream i byte gia' letti (mode-detection):
    /// i read successivi li restituiscono come se non fossero mai stati
    /// consumati — l'equivalente TLS del `TcpStream::peek`.
    pub fn prepend(&mut self, bytes: &[u8]) {
        // Costruisce una nuova testa = bytes + head corrente.
        let mut new_head = VecDeque::with_capacity(bytes.len() + self.head.len());
        let mut idx = 0usize;
        while idx < bytes.len() {
            new_head.push_back(bytes[idx]);
            idx += 1;
        }
        new_head.append(&mut self.head);
        self.head = new_head;
    }
}

impl AsyncRead for Link {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // Prima svuota i byte ri-accodati dal mode-detection. Poi — se
        // resta spazio nel buffer — prova anche lo stream interno: il
        // resto del record TLS e' gia' decifrato nel buffer di rustls e
        // risponde Ready subito. E' il merge che riproduce la semantica
        // del read() plaintext ("un write del peer = un read pieno") —
        // senza di esso shell_flow leggerebbe solo i 4 byte di `head`.
        let mut drained = false;
        while !this.head.is_empty() && buf.remaining() > 0 {
            let b = match this.head.pop_front() {
                Some(b) => b,
                None => break,
            };
            buf.put_slice(&[b]);
            drained = true;
        }
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let inner_result = match &mut this.inner {
            LinkInner::Plain(s) => Pin::new(s).poll_read(cx, buf),
            LinkInner::TlsServer(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
            LinkInner::TlsClient(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        };
        // Se lo stream interno e' Pending ma abbiamo gia' prodotto i
        // byte di testa, rispondiamo Ready: i dati disponibili ci sono.
        match inner_result {
            Poll::Pending if drained => Poll::Ready(Ok(())),
            other => other,
        }
    }
}

impl AsyncWrite for Link {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match &mut this.inner {
            LinkInner::Plain(s) => Pin::new(s).poll_write(cx, data),
            LinkInner::TlsServer(s) => Pin::new(s.as_mut()).poll_write(cx, data),
            LinkInner::TlsClient(s) => Pin::new(s.as_mut()).poll_write(cx, data),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match &mut this.inner {
            LinkInner::Plain(s) => Pin::new(s).poll_flush(cx),
            LinkInner::TlsServer(s) => Pin::new(s.as_mut()).poll_flush(cx),
            LinkInner::TlsClient(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match &mut this.inner {
            LinkInner::Plain(s) => Pin::new(s).poll_shutdown(cx),
            LinkInner::TlsServer(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
            LinkInner::TlsClient(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers ambiente (spec §9).
// ---------------------------------------------------------------------------

/// CROSSPILOT_REQUIRE_TLS=1: il server accetta plaintext solo per la
/// whitelist GET §5.1; il client non usa MAI plaintext.
pub fn require_tls() -> bool {
    envs::var("REQUIRE_TLS").as_deref() == Some("1")
}

/// CROSSPILOT_TLS_NO_PIN=1: salta il pinning del cert (dev/edge).
fn tls_no_pin() -> bool {
    envs::var("TLS_NO_PIN").as_deref() == Some("1")
}

/// CROSSPILOT_TLS_PIN: pin pre-distribuito `sha256:<b64>` che salta il TOFU.
fn tls_pin_override() -> Option<String> {
    envs::var("TLS_PIN")
}

/// CROSSPILOT_AUTH_TOKEN: token condiviso per l'AUTH dentro TLS (spec §8).
fn auth_token() -> Option<String> {
    envs::var("AUTH_TOKEN")
}

// ---------------------------------------------------------------------------
// CryptoProvider: ring + unico kx_group ibrido X25519+ML-KEM-768.
// ---------------------------------------------------------------------------

/// Provider rustls: cipher suite TLS 1.3 di `ring`, key exchange
/// ristretto al solo gruppo ibrido post-quantum (spec §10: "unico"
/// tra peer nuovi — l'hardware e la rete sono uguali per entrambi).
fn pq_provider() -> rustls::crypto::CryptoProvider {
    let mut provider = rustls::crypto::ring::default_provider();
    let group: &'static dyn rustls::crypto::SupportedKxGroup = &rustls_pq_addon::X25519MLKEM768;
    provider.kx_groups = vec![group];
    provider
}

// ---------------------------------------------------------------------------
// Rilevamento dei primi byte sulla connessione (spec §3).
// ---------------------------------------------------------------------------

/// True se i primi byte assomigliano a un record TLS ClientHello
/// (`0x16 0x03`): il server li distingue da `DFB1` (file mode) e da
/// qualunque altro byte (shell mode) PRIMA di qualsiasi parsing.
pub fn looks_like_tls_hello(buf: &[u8], len: usize) -> bool {
    if len < 2 {
        return false;
    }
    buf[0] == 0x16 && buf[1] == 0x03
}

// ---------------------------------------------------------------------------
// Certificato self-signed del server (spec §7.1).
// ---------------------------------------------------------------------------

/// Path (key, crt) del materiale TLS del server: override via
/// CROSSPILOT_TLS_KEY / CROSSPILOT_TLS_CERT (entrambe richieste se
/// l'override e' usato), altrimenti accanto all'exe corrente.
fn server_cert_paths() -> Result<(PathBuf, PathBuf)> {
    let env_key = envs::var("TLS_KEY");
    let env_crt = envs::var("TLS_CERT");
    if env_key.is_some() || env_crt.is_some() {
        let key = env_key
            .ok_or_else(|| anyhow!("CROSSPILOT_TLS_CERT impostato ma manca CROSSPILOT_TLS_KEY"))?;
        let crt = env_crt
            .ok_or_else(|| anyhow!("CROSSPILOT_TLS_KEY impostato ma manca CROSSPILOT_TLS_CERT"))?;
        return Ok((PathBuf::from(key), PathBuf::from(crt)));
    }
    let exe = std::env::current_exe()
        .context("impossibile determinare il path dell'exe corrente")?;
    let dir = match exe.parent() {
        Some(d) => d.to_path_buf(),
        None => PathBuf::from("."),
    };
    let key = dir.join(SERVER_KEY_FILE);
    let crt = dir.join(SERVER_CRT_FILE);
    Ok((key, crt))
}

/// Genera la coppia cert+key self-signed se assente (spec §7.1):
/// ECDSA P-256, CN=crosspilot-agent, SAN crosspilot.local + 0.0.0.0,
/// validita' ampia (la rotazione e' fuori scope). La chiave e'
/// scritta con permessi 0600 su unix.
pub fn ensure_server_cert() -> Result<()> {
    let (key_path, crt_path) = server_cert_paths()?;
    if key_path.exists() && crt_path.exists() {
        return Ok(());
    }
    if key_path.exists() != crt_path.exists() {
        bail!(
            "materiale TLS incompleto: {} esiste ma {} no — rimuovere entrambi",
            key_path.display(),
            crt_path.display()
        );
    }

    // Genera chiave ECDSA P-256 e cert self-signed.
    // CertificateParams::new converte le stringhe in SAN: non-IP -> DnsName,
    // IP letterale -> IpAddress ("0.0.0.0" come SAN any).
    let sans = vec![
        TLS_SERVER_NAME.to_string(),
        Ipv4Addr::UNSPECIFIED.to_string(),
    ];
    let mut params = rcgen::CertificateParams::new(sans)
        .map_err(|e| anyhow!("SAN invalido: {}", e))?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "crosspilot-agent");
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| anyhow!("generazione chiave TLS fallita: {}", e))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| anyhow!("generazione cert TLS fallita: {}", e))?;

    // Persiste: chiave PEM (0600 unix), cert PEM (644).
    let key_pem = key_pair.serialize_pem();
    fs::write(&key_path, key_pem)
        .with_context(|| format!("scrittura {}", key_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(&key_path, perms)
            .with_context(|| format!("chmod 600 {}", key_path.display()))?;
    }
    let crt_pem = cert.pem();
    fs::write(&crt_path, crt_pem)
        .with_context(|| format!("scrittura {}", crt_path.display()))?;

    eprintln!(
        "[server] TLS: generata coppia self-signed {} + {}",
        key_path.display(),
        crt_path.display()
    );
    Ok(())
}

/// Costruisce la ServerConfig TLS dal materiale su disco.
fn build_server_config() -> Result<ServerConfig> {
    let (key_path, crt_path) = server_cert_paths()?;
    let key_pem = fs::read(&key_path)
        .with_context(|| format!("lettura {}", key_path.display()))?;
    let mut key_cursor = std::io::Cursor::new(key_pem);
    let key_der = rustls_pemfile::private_key(&mut key_cursor)
        .with_context(|| format!("parsing chiave {}", key_path.display()))?
        .ok_or_else(|| anyhow!("{} non contiene una chiave privata", key_path.display()))?;

    let crt_pem = fs::read(&crt_path)
        .with_context(|| format!("lettura {}", crt_path.display()))?;
    let mut crt_cursor = std::io::Cursor::new(crt_pem);
    let mut certs = Vec::new();
    let cert_iter = rustls_pemfile::certs(&mut crt_cursor);
    for item in cert_iter {
        let der = item.with_context(|| format!("parsing cert {}", crt_path.display()))?;
        certs.push(der);
    }
    if certs.is_empty() {
        bail!("{} non contiene certificati", crt_path.display());
    }

    let provider = pq_provider();
    let config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("config TLS 1.3 server")?
        .with_no_client_auth()
        .with_single_cert(certs, key_der)
        .context("ServerConfig con cert+key")?;
    Ok(config)
}

/// Inizializza il TLS lato server: garantisce il cert e costruisce
/// l'acceptor condiviso (chiamato una sola volta da server_mode).
pub fn init_server_tls() -> Result<TlsAcceptor> {
    ensure_server_cert()?;
    let config = build_server_config()?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Esegue l'handshake TLS lato server su una connessione appena
/// accettata. Errore => chiusura immediata (spec §3: nessun fallback).
pub async fn accept_tls(
    acceptor: TlsAcceptor,
    socket: TcpStream,
) -> Result<tokio_rustls::server::TlsStream<TcpStream>> {
    let handshake = acceptor.accept(socket);
    let result = timeout(HANDSHAKE_TIMEOUT, handshake).await;
    let stream = match result {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => bail!("handshake TLS fallito: {}", e),
        Err(_) => bail!("timeout handshake TLS"),
    };
    Ok(stream)
}

// ---------------------------------------------------------------------------
// Pinning del certificato server (spec §7.2): TOFU su known_hosts.
// ---------------------------------------------------------------------------

/// Fingerprint del cert: sha256 del DER, base64 (senza il tag `tls-sha256:`).
fn cert_fingerprint_b64(cert_der: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(cert_der);
    let digest = hasher.finalize();
    base64::engine::general_purpose::STANDARD.encode(digest)
}

/// Cerca una riga `addr tls-sha256:<b64>` nel known_hosts dato.
/// Ritorna il b64 memorizzato, se presente.
fn pin_lookup_in(kh_path: &Path, addr: &str) -> Option<String> {
    let content = fs::read_to_string(kh_path).ok()?;
    let mut found = None;
    for line in content.lines() {
        let mut parts = line.split_whitespace();
        let first = parts.next();
        let second = parts.next();
        if first != Some(addr) {
            continue;
        }
        let entry = match second {
            Some(s) => s,
            None => continue,
        };
        let b64 = match entry.strip_prefix(TLS_PIN_TAG) {
            Some(b) => b,
            None => continue,
        };
        found = Some(b64.to_string());
        break;
    }
    found
}

/// Path del known_hosts condiviso col pinning SSH (spec §7.2).
fn known_hosts_path() -> PathBuf {
    crate::ssh_transport::known_hosts_path()
}

/// Lookup del pin memorizzato per `addr` (forma "host:porta").
fn pin_lookup(addr: &str) -> Option<String> {
    let path = known_hosts_path();
    pin_lookup_in(&path, addr)
}

/// Apprende (TOFU) il pin `fp` per `addr` nel known_hosts dato.
fn learn_pin_in(kh_path: &Path, addr: &str, fp: &str) -> io::Result<()> {
    use std::io::Write;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(kh_path)?;
    let line = format!("{} {}{}\n", addr, TLS_PIN_TAG, fp);
    file.write_all(line.as_bytes())
}

/// Verifica il pin del cert del server (TOFU). Errori `TlsFatal`:
/// mismatch (possibile MITM) o pin manuale errato.
fn check_cert_pin_in(kh_path: &Path, addr: &str, cert_der: &[u8]) -> Result<()> {
    let fp = cert_fingerprint_b64(cert_der);

    // Pin pre-distribuito via CROSSPILOT_TLS_PIN (salta il TOFU).
    let override_raw = tls_pin_override();
    if let Some(raw) = override_raw {
        let trimmed = raw.trim();
        let expected = match trimmed.strip_prefix("sha256:") {
            Some(rest) => rest,
            None => trimmed.strip_prefix(TLS_PIN_TAG).unwrap_or(trimmed),
        };
        if expected == fp {
            return Ok(());
        }
        return Err(TlsFatal(format!(
            "TLS pin mismatch verso {}: il cert non corrisponde a CROSSPILOT_TLS_PIN",
            addr
        ))
        .into());
    }

    // Escape hatch dev: nessun pinning, warning ad ogni connessione.
    if tls_no_pin() {
        eprintln!(
            "[WARN] TLS: pinning del cert disabilitato (CROSSPILOT_TLS_NO_PIN=1) — nessuna autenticazione server"
        );
        return Ok(());
    }

    let stored = pin_lookup_in(kh_path, addr);
    match stored {
        Some(known) if known == fp => Ok(()),
        Some(_) => Err(TlsFatal(format!(
            "TLS pin mismatch verso {}: il certificato e' cambiato (possibile MITM).\n\
             Se il server e' stato rigenerato intenzionalmente, rimuovere la riga\n\
             `{} tls-sha256:...` da {}",
            addr,
            addr,
            kh_path.display()
        ))
        .into()),
        None => {
            let written = learn_pin_in(kh_path, addr, &fp);
            match written {
                Ok(()) => {
                    eprintln!(
                        "[WARN] TLS: primo contatto con {} — cert appreso (TOFU) in {}",
                        addr,
                        kh_path.display()
                    );
                }
                Err(e) => {
                    // Il TOFU non si e' registrato: la connessione resta
                    // valida ma la prossima sara' di nuovo sconosciuta.
                    eprintln!(
                        "[WARN] TLS: impossibile registrare il pin in {}: {}",
                        kh_path.display(),
                        e
                    );
                }
            }
            Ok(())
        }
    }
}

/// Wrapper su check_cert_pin_in che usa il known_hosts di progetto.
fn check_cert_pin(addr: &str, cert_der: &[u8]) -> Result<()> {
    let path = known_hosts_path();
    check_cert_pin_in(&path, addr, cert_der)
}

// ---------------------------------------------------------------------------
// Verifier client: accetta qualunque cert in handshake (l'identita' e'
/// autenticata dal pinning DOPO l'handshake), ma verifica SEMPRE la
/// firma del transcript con la chiave del cert presentato — senza di
/// questa, un MITM potrebbe replicare il cert pinnato senza possedere
/// la chiave privata.
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct PinnedCertVerifier {
    /// Algoritmi di verifica firma del provider (ring).
    algs: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        // Nessuna CA: l'autenticazione e' il pin post-handshake.
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// ClientConfig TLS 1.3 + PQ + verifier con pinning manuale.
fn build_client_config() -> Result<ClientConfig> {
    let provider = pq_provider();
    let algs = provider.signature_verification_algorithms;
    let verifier = PinnedCertVerifier { algs };
    let config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("config TLS 1.3 client")?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    Ok(config)
}

// ---------------------------------------------------------------------------
// AUTH dentro TLS (spec §8).
// ---------------------------------------------------------------------------

/// Riga AUTH inviata dal client subito dopo handshake+pin
/// (`AUTH <token>\n`, oppure `AUTH\n` se il token non e' configurato).
pub fn auth_client_line() -> String {
    match auth_token() {
        Some(t) => format!("AUTH {}\n", t),
        None => "AUTH\n".to_string(),
    }
}

/// Legge la riga AUTH dal peer (fino a '\n', cap MAX_AUTH_LINE,
/// timeout AUTH_TIMEOUT). Ritorna la riga senza '\n' finale.
pub async fn read_auth_line<R>(reader: &mut R) -> Result<String>
where
    R: AsyncRead + Unpin,
{
    let reader = timeout(AUTH_TIMEOUT, read_line_limited(reader, MAX_AUTH_LINE)).await;
    match reader {
        Ok(Ok(line)) => Ok(line),
        Ok(Err(e)) => Err(e),
        Err(_) => bail!("timeout in attesa della riga AUTH"),
    }
}

/// Legge una riga (byte-per-byte per non consumare oltre '\n'),
/// con cap sulla lunghezza.
async fn read_line_limited<R>(reader: &mut R, cap: usize) -> Result<String>
where
    R: AsyncRead + Unpin,
{
    let mut line = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    loop {
        let n = reader.read(&mut byte).await?;
        if n == 0 {
            bail!("connessione chiusa durante la lettura della riga");
        }
        if byte[0] == b'\n' {
            break;
        }
        line.push(byte[0]);
        if line.len() > cap {
            bail!("riga troppo lunga (> {} byte)", cap);
        }
    }
    let text = String::from_utf8(line)
        .map_err(|_| anyhow!("riga non UTF-8"))?;
    Ok(text)
}

/// Verifica la riga AUTH ricevuta contro il token atteso (confronto
/// in tempo costante). `expected` = token del server; `None` = AUTH
/// non configurata (accetta tutto, warn una volta — spec §8).
fn verify_auth_line(line: &str, expected: Option<&str>) -> Result<()> {
    // Parse: "AUTH" oppure "AUTH <token>".
    let rest = match line.strip_prefix("AUTH") {
        Some(r) => r,
        None => bail!("AUTH malformata: atteso prefisso AUTH"),
    };
    if !rest.is_empty() && !rest.starts_with(' ') {
        bail!("AUTH malformata");
    }
    let provided = rest.trim();

    match expected {
        Some(tok) => {
            if ct_eq(provided.as_bytes(), tok.as_bytes()) {
                Ok(())
            } else {
                bail!("AUTH fallita: token errato o assente")
            }
        }
        None => {
            if !AUTH_DISABLED_WARNED.swap(true, Ordering::Relaxed) {
                eprintln!(
                    "[server] WARNING: AUTH non configurata (CROSSPILOT_AUTH_TOKEN assente) — canale cifrato ma senza autenticazione"
                );
            }
            Ok(())
        }
    }
}

/// Wrapper su verify_auth_line che legge il token da CROSSPILOT_AUTH_TOKEN.
pub fn check_auth_line(line: &str) -> Result<()> {
    let expected = auth_token();
    verify_auth_line(line, expected.as_deref())
}

/// Confronto in tempo costante (token AUTH): nessun early-exit.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = a.len() ^ b.len();
    let mut i = 0usize;
    let max = if a.len() > b.len() { a.len() } else { b.len() };
    while i < max {
        let x = if i < a.len() { a[i] } else { 0 };
        let y = if i < b.len() { b[i] } else { 0 };
        diff |= (x ^ y) as usize;
        i += 1;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Decisione lato client + wrapping della connessione (spec §4, §5).
// ---------------------------------------------------------------------------

/// True se il server e' TLS-capable in base al ts annunciato in READY.
pub fn server_tls_capable(hello: &version::ServerHello) -> bool {
    match hello.ts {
        Some(ts) => ts >= TLS_MIN_TS,
        None => false,
    }
}

/// Trasforma il TcpStream post-READY nel Link finale:
///
/// - server TLS-capable -> handshake TLS 1.3 + pin check + riga AUTH.
/// - server vecchio -> plaintext, MA:
///   - CROSSPILOT_REQUIRE_TLS=1 -> fatale (niente plaintext mai);
///   - pin gia' registrato per questo endpoint -> fatale (sticky
///     anti-downgrade, spec §7.3: un endpoint visto TLS non puo'
///     tornare non-capable).
pub async fn client_wrap(
    socket: TcpStream,
    hello: &version::ServerHello,
    addr: &str,
) -> Result<Link> {
    if !server_tls_capable(hello) {
        if require_tls() {
            return Err(TlsFatal(format!(
                "server {} non TLS-capable e CROSSPILOT_REQUIRE_TLS=1: aggiornare il remote",
                addr
            ))
            .into());
        }
        let pinned = pin_lookup(addr);
        if !tls_no_pin() && pinned.is_some() {
            return Err(TlsFatal(format!(
                "downgrade TLS verso {}: endpoint con pin registrato ora dichiara ts pre-TLS (READY {})\n\
                 Possibile attacco di rollback. Se il server e' stato reinstallato vecchio\n\
                 intenzionalmente, rimuovere la riga `tls-sha256:` da {}",
                addr,
                hello
                    .ts
                    .map(|t| t.to_string())
                    .unwrap_or_else(|| "legacy".to_string()),
                known_hosts_path().display()
            ))
            .into());
        }
        return Ok(Link::plain(socket));
    }

    // Handshake TLS 1.3 (fallimento = fatale, mai retry in chiaro).
    let config = build_client_config().context("ClientConfig TLS")?;
    let connector = TlsConnector::from(Arc::new(config));
    let name = ServerName::try_from(TLS_SERVER_NAME)
        .map_err(|e| anyhow!("SNI invalido: {}", e))?
        .to_owned();
    let handshake = connector.connect(name, socket);
    let result = timeout(HANDSHAKE_TIMEOUT, handshake).await;
    let stream = match result {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return Err(TlsFatal(format!(
                "handshake TLS fallito verso {}: {}",
                addr, e
            ))
            .into())
        }
        Err(_) => {
            return Err(TlsFatal(format!(
                "timeout handshake TLS verso {}",
                addr
            ))
            .into())
        }
    };

    // Pin check sull'end-entity cert PRIMA di inviare qualsiasi cosa
    // (il token AUTH non deve viaggiare verso un endpoint non autenticato).
    let (_, conn) = stream.get_ref();
    let certs = conn.peer_certificates();
    let cert = match certs.and_then(|c| c.first()) {
        Some(c) => c,
        None => {
            return Err(TlsFatal(format!(
                "server {} non ha presentato certificati TLS",
                addr
            ))
            .into())
        }
    };
    check_cert_pin(addr, cert.as_ref())?;

    // AUTH subito dopo il pin (spec §8): il server la legge prima
    // del mode-detection.
    let mut link = Link::tls_client(stream);
    let auth_line = auth_client_line();
    link.write_all(auth_line.as_bytes())
        .await
        .context("invio riga AUTH")?;
    eprintln!("[DEBUG] tls: handshake+AUTH ok verso {} (pin verificato)", addr);
    Ok(link)
}

// ---------------------------------------------------------------------------
// Test.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::PrivateKeyDer;

    #[test]
    fn looks_like_tls_hello_detects_record() {
        // TLS record handshake: content-type 0x16, legacy version 0x03xx.
        assert!(looks_like_tls_hello(&[0x16, 0x03, 0x01, 0x02], 4));
        assert!(looks_like_tls_hello(&[0x16, 0x03], 2));
        // DFB1 e ASCII shell non sono TLS.
        assert!(!looks_like_tls_hello(b"DFB1", 4));
        assert!(!looks_like_tls_hello(b"dir ", 4));
        assert!(!looks_like_tls_hello(&[0x16], 1));
        assert!(!looks_like_tls_hello(&[0x16, 0x02], 2));
    }

    #[test]
    fn server_tls_capable_cutoff() {
        // ts >= TLS_MIN_TS -> TLS; ts minore o None -> plaintext.
        let hello = version::ServerHello {
            ts: Some(TLS_MIN_TS),
            os: None,
        };
        assert!(server_tls_capable(&hello));
        let old = version::ServerHello {
            ts: Some(TLS_MIN_TS - 1),
            os: None,
        };
        assert!(!server_tls_capable(&old));
        let legacy = version::ServerHello { ts: None, os: None };
        assert!(!server_tls_capable(&legacy));
    }

    #[test]
    fn pin_store_lookup_e_learn() {
        let dir = std::env::temp_dir().join("crosspilot_tls_pin_test");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let kh = dir.join("crosspilot_known_hosts");

        // Assenza -> None; learn -> ritrova.
        assert_eq!(pin_lookup_in(&kh, "h:1"), None);
        learn_pin_in(&kh, "h:1", "QUJD").unwrap();
        assert_eq!(pin_lookup_in(&kh, "h:1").as_deref(), Some("QUJD"));

        // Linee non-TLS (host key SSH) ignorate; altri addr non matchano.
        fs::write(&kh, "[h]:22 ssh-ed25519 AAAA\nh:1 tls-sha256:QUJD\n").unwrap();
        assert_eq!(pin_lookup_in(&kh, "h:1").as_deref(), Some("QUJD"));
        assert_eq!(pin_lookup_in(&kh, "h:2"), None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fingerprint_e_check_pin_tofu() {
        let dir = std::env::temp_dir().join("crosspilot_tls_fp_test");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let kh = dir.join("crosspilot_known_hosts");

        let cert_a = b"cert-der-di-prova-A";
        let cert_b = b"cert-der-di-prova-B";

        // Fingerprint: sha256(DER) in base64 — vettore noto su "abc".
        let fp_abc = cert_fingerprint_b64(b"abc");
        assert_eq!(fp_abc, "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=");

        // TLS_NO_PIN / TLS_PIN non impostati nei test -> TOFU puro.
        // Prima volta: apprende (Ok). Seconda: match (Ok).
        check_cert_pin_in(&kh, "s:1", cert_a).unwrap();
        check_cert_pin_in(&kh, "s:1", cert_a).unwrap();
        // Cert diverso su stesso addr: fatale (mismatch).
        let res = check_cert_pin_in(&kh, "s:1", cert_b);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert!(err.downcast_ref::<TlsFatal>().is_some());
        // Altro addr: TOFU indipendente.
        check_cert_pin_in(&kh, "s:2", cert_b).unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn auth_line_parse_e_verify() {
        // Token atteso configurato: match esatto richiesto.
        assert!(verify_auth_line("AUTH tok123", Some("tok123")).is_ok());
        assert!(verify_auth_line("AUTH  tok123 ", Some("tok123")).is_ok());
        assert!(verify_auth_line("AUTH", Some("tok123")).is_err());
        assert!(verify_auth_line("AUTH altro", Some("tok123")).is_err());
        assert!(verify_auth_line("PUT /x", Some("tok123")).is_err());
        assert!(verify_auth_line("AUTHx", Some("tok123")).is_err());
        // Nessun token configurato: qualunque AUTH ben formata passa.
        assert!(verify_auth_line("AUTH", None).is_ok());
        assert!(verify_auth_line("AUTH qualunque", None).is_ok());
        assert!(verify_auth_line("MALFORMED", None).is_err());
    }

    #[test]
    fn ct_eq_casi() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"abcd"));
        assert!(!ct_eq(b"", b"a"));
        assert!(ct_eq(b"", b""));
    }

    /// Handshake TLS completo su loopback: acceptor server + connector
    /// client con verifier pinned; poi AUTH + eco di un frame dati.
    #[tokio::test]
    async fn tls_loopback_handshake_e_dati() {
        // Cert self-signed di test via rcgen.
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let params = rcgen::CertificateParams::default();
        let cert = params.self_signed(&key_pair).unwrap();

        let provider = pq_provider();
        let server_cfg = ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                PrivateKeyDer::Pkcs8(key_pair.serialize_der().into()),
            )
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_cfg));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Task server: accepta TLS, legge AUTH, risponde "PONG".
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let stream = accept_tls(acceptor, sock).await.unwrap();
            let mut link = Link::tls_server(stream);
            let auth = read_auth_line(&mut link).await.unwrap();
            assert_eq!(auth.trim(), "AUTH");
            let mut buf = [0u8; 4];
            link.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"PING");
            link.write_all(b"PONG").await.unwrap();
        });

        // Client: handshake + AUTH + PING/PONG.
        let sock = TcpStream::connect(addr).await.unwrap();
        let config = build_client_config().unwrap();
        let connector = TlsConnector::from(Arc::new(config));
        let name = ServerName::try_from(TLS_SERVER_NAME).unwrap().to_owned();
        let stream = connector.connect(name, sock).await.unwrap();

        // Il pin e' saltato qui (check_cert_pin usa known_hosts reale);
        // il test verifica solo record layer + verifier cert.
        let mut link = Link::tls_client(stream);
        assert!(link.is_tls());
        let line = auth_client_line();
        link.write_all(line.as_bytes()).await.unwrap();
        link.write_all(b"PING").await.unwrap();
        let mut buf = [0u8; 4];
        link.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"PONG");

        server.await.unwrap();
    }

    /// Il verifier accetta qualunque cert in verify_server_cert ma
    /// richiede la firma del transcript valida (testata implicitamente
    /// dal loopback qui sopra, che fallirebbe senza).
    #[test]
    fn verifier_schemes_non_vuoti() {
        let provider = pq_provider();
        let algs = provider.signature_verification_algorithms;
        let schemes = algs.supported_schemes();
        assert!(!schemes.is_empty());
        // ECDSA P-256 deve esserci (firma del nostro cert rcgen).
        assert!(schemes.contains(&SignatureScheme::ECDSA_NISTP256_SHA256));
    }
}
