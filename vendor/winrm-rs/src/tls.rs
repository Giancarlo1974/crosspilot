// Custom TLS certificate verifier that captures the server certificate.
//
// Used for NTLM Channel Binding Tokens (CBT) — the server certificate
// hash is injected into the NTLM Type 3 message to bind authentication
// to the TLS channel, preventing relay attacks.

use std::sync::{Arc, Mutex};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};

/// A [`ServerCertVerifier`] wrapper that captures the server's end-entity
/// certificate (DER bytes) during the TLS handshake, then delegates all
/// verification to an inner verifier.
///
/// The captured certificate is used to compute NTLM Channel Binding Tokens.
#[derive(Debug)]
pub(crate) struct CertCapturingVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    captured_cert: Arc<Mutex<Option<Vec<u8>>>>,
}

impl CertCapturingVerifier {
    /// Wrap an existing verifier, capturing the server certificate on each handshake.
    pub(crate) fn new(inner: Arc<dyn ServerCertVerifier>) -> Self {
        Self {
            inner,
            captured_cert: Arc::new(Mutex::new(None)),
        }
    }

    /// Return a clone-able handle to retrieve the captured certificate.
    pub(crate) fn cert_handle(&self) -> CertHandle {
        CertHandle {
            captured_cert: Arc::clone(&self.captured_cert),
        }
    }
}

impl ServerCertVerifier for CertCapturingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        // Capture the end-entity certificate (DER bytes).
        //
        // Mutex poisoning is rare but possible if a previous handshake
        // panicked mid-capture. Log loudly because losing the cert here
        // means NTLM will fall back to non-CBT silently.
        match self.captured_cert.lock() {
            Ok(mut captured) => *captured = Some(end_entity.to_vec()),
            Err(_) => tracing::error!(
                "CertCapturingVerifier mutex poisoned — server cert not stored, \
                 NTLM Channel Binding will be skipped"
            ),
        }
        // Delegate actual verification to the inner verifier
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Clone-able handle to retrieve the captured server certificate.
#[derive(Clone, Debug)]
pub(crate) struct CertHandle {
    captured_cert: Arc<Mutex<Option<Vec<u8>>>>,
}

impl CertHandle {
    /// Return the DER-encoded server certificate, if one has been captured.
    pub(crate) fn get(&self) -> Option<Vec<u8>> {
        self.captured_cert.lock().ok()?.clone()
    }
}

/// A no-op verifier that accepts any certificate. Used as inner verifier when
/// `accept_invalid_certs` is enabled.
#[derive(Debug)]
pub(crate) struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::internal::msgs::codec::{Codec, Reader};

    /// Build a `DigitallySignedStruct` from raw wire bytes.
    /// Wire format: 2-byte scheme + 2-byte length + signature bytes.
    fn make_dss() -> DigitallySignedStruct {
        let mut buf = Vec::new();
        // RSA_PKCS1_SHA256 = 0x0401
        buf.extend_from_slice(&[0x04, 0x01]);
        // 64-byte signature, length prefix
        buf.extend_from_slice(&[0x00, 0x40]);
        buf.extend_from_slice(&[0u8; 64]);
        let mut reader = Reader::init(&buf);
        DigitallySignedStruct::read(&mut reader).unwrap()
    }

    /// Dummy verifier that always succeeds, for testing.
    #[derive(Debug)]
    struct AcceptAllVerifier;

    impl ServerCertVerifier for AcceptAllVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![SignatureScheme::RSA_PKCS1_SHA256]
        }
    }

    #[test]
    fn captures_server_certificate() {
        let inner = Arc::new(AcceptAllVerifier);
        let verifier = CertCapturingVerifier::new(inner);
        let handle = verifier.cert_handle();

        // No cert captured yet
        assert!(handle.get().is_none());

        // Simulate a handshake
        let fake_cert = CertificateDer::from(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let server_name = ServerName::try_from("example.com").unwrap();
        let result =
            verifier.verify_server_cert(&fake_cert, &[], &server_name, &[], UnixTime::now());
        assert!(result.is_ok());

        // Cert should be captured
        let captured = handle.get().unwrap();
        assert_eq!(captured, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn handle_is_cloneable() {
        let inner = Arc::new(AcceptAllVerifier);
        let verifier = CertCapturingVerifier::new(inner);
        let handle1 = verifier.cert_handle();
        let handle2 = handle1.clone();

        let fake_cert = CertificateDer::from(vec![1, 2, 3]);
        let server_name = ServerName::try_from("test.local").unwrap();
        let _ = verifier.verify_server_cert(&fake_cert, &[], &server_name, &[], UnixTime::now());

        assert_eq!(handle1.get(), handle2.get());
    }

    #[test]
    fn no_verifier_accepts_any_cert() {
        let verifier = NoVerifier;
        let cert = CertificateDer::from(vec![0xFF; 100]);
        let name = ServerName::try_from("any.host").unwrap();
        assert!(
            verifier
                .verify_server_cert(&cert, &[], &name, &[], UnixTime::now())
                .is_ok()
        );
    }

    #[test]
    fn no_verifier_supported_schemes_not_empty() {
        let verifier = NoVerifier;
        assert!(!verifier.supported_verify_schemes().is_empty());
    }

    #[test]
    fn cert_handle_returns_none_when_nothing_captured() {
        let inner = Arc::new(AcceptAllVerifier);
        let verifier = CertCapturingVerifier::new(inner);
        let handle = verifier.cert_handle();
        assert!(handle.get().is_none());
    }

    #[test]
    fn capturing_verifier_delegates_supported_schemes() {
        let inner = Arc::new(AcceptAllVerifier);
        let verifier = CertCapturingVerifier::new(inner);
        assert_eq!(
            verifier.supported_verify_schemes(),
            vec![SignatureScheme::RSA_PKCS1_SHA256]
        );
    }

    #[test]
    fn capturing_verifier_delegates_tls12_signature() {
        let inner = Arc::new(AcceptAllVerifier);
        let verifier = CertCapturingVerifier::new(inner);
        let cert = CertificateDer::from(vec![0xAA; 32]);
        let dss = make_dss();
        let result = verifier.verify_tls12_signature(b"hello", &cert, &dss);
        assert!(result.is_ok());
    }

    #[test]
    fn capturing_verifier_delegates_tls13_signature() {
        let inner = Arc::new(AcceptAllVerifier);
        let verifier = CertCapturingVerifier::new(inner);
        let cert = CertificateDer::from(vec![0xBB; 32]);
        let dss = make_dss();
        let result = verifier.verify_tls13_signature(b"hello", &cert, &dss);
        assert!(result.is_ok());
    }

    #[test]
    fn no_verifier_accepts_tls12_signature() {
        let verifier = NoVerifier;
        let cert = CertificateDer::from(vec![0xCC; 32]);
        let dss = make_dss();
        let result = verifier.verify_tls12_signature(b"message", &cert, &dss);
        assert!(result.is_ok());
    }

    #[test]
    fn no_verifier_accepts_tls13_signature() {
        let verifier = NoVerifier;
        let cert = CertificateDer::from(vec![0xDD; 32]);
        let dss = make_dss();
        let result = verifier.verify_tls13_signature(b"message", &cert, &dss);
        assert!(result.is_ok());
    }
}
