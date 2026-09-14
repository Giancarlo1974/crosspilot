// NTLM authentication transport for WinRM (3-step handshake).
//
// Supports optional NTLM message sealing (encryption) for SOAP bodies
// over HTTP, using the multipart/encrypted MIME format per MS-WSMV 2.2.9.1.

use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use zeroize::Zeroizing;

use crate::auth::AuthTransport;
use crate::error::WinrmError;
use crate::ntlm;

/// NTLM authentication transport.
///
/// Performs the `NTLMv2` three-step handshake (negotiate, challenge, authenticate)
/// for each SOAP request. The password is wrapped in [`Zeroizing`] to ensure
/// it is cleared from memory when dropped.
pub(crate) struct NtlmAuth {
    pub(crate) username: String,
    pub(crate) password: Zeroizing<String>,
    pub(crate) domain: String,
    /// TLS server certificate handle for computing Channel Binding Tokens.
    pub(crate) cert_handle: Option<crate::tls::CertHandle>,
}

const ENCRYPTED_BOUNDARY: &str = "--Encrypted Boundary";
const ENCRYPTED_CONTENT_TYPE: &str = "multipart/encrypted;protocol=\"application/HTTP-SPNEGO-session-encrypted\";boundary=\"Encrypted Boundary\"";

/// Wrap a SOAP body in NTLM-sealed multipart/encrypted format (MS-WSMV 2.2.9.1).
pub(crate) fn seal_body(session: &mut ntlm::NtlmSession, body: &str) -> (String, Vec<u8>) {
    let sealed = session.seal(body.as_bytes());
    // sealed = signature(16) + ciphertext
    let sig_len = 16u32;

    let mut payload = Vec::new();
    payload.extend_from_slice(&sig_len.to_le_bytes());
    payload.extend_from_slice(&sealed);

    // NOTA: niente indentazione (tab/spazi) prima degli header MIME — una riga
    // che inizia con whitespace è una folded-continuation e rende il multipart
    // malformato per il parser del server (http.sys → HTTP 400).
    // Formato identico a pywinrm/evil-winrm.
    let header_part = format!(
        "{ENCRYPTED_BOUNDARY}\r\n\
         Content-Type: application/HTTP-SPNEGO-session-encrypted\r\n\
         OriginalContent: type=application/soap+xml;charset=UTF-8;Length={}\r\n\
         {ENCRYPTED_BOUNDARY}\r\n\
         Content-Type: application/octet-stream\r\n",
        body.len()
    );

    let mut mime_body = header_part.into_bytes();
    mime_body.extend_from_slice(&payload);
    // BUG FIX: il ciphertext va attaccato direttamente al boundary finale,
    // SENZA \r\n in mezzo. pywinrm e evil-winrm emettono:
    //   <sig_len><sig><ciphertext>--Encrypted Boundary--\r\n
    // Mettere \r\n prima del closing boundary fa scartare la richiesta a
    // http.sys con HTTP 400 (body MIME malformato).
    mime_body.extend_from_slice(format!("{ENCRYPTED_BOUNDARY}--\r\n").as_bytes());

    (ENCRYPTED_CONTENT_TYPE.to_string(), mime_body)
}

/// Extract and unseal the SOAP body from a multipart/encrypted response.
pub(crate) fn unseal_body(
    session: &mut ntlm::NtlmSession,
    data: &[u8],
) -> Result<String, WinrmError> {
    // Find the octet-stream boundary
    let marker = b"application/octet-stream\r\n";
    let pos = data
        .windows(marker.len())
        .position(|w| w == marker)
        .ok_or_else(|| {
            WinrmError::AuthFailed("sealed response: missing octet-stream marker".into())
        })?;
    let encrypted_start = pos + marker.len();

    // First 4 bytes = signature length (LE u32)
    if encrypted_start + 4 > data.len() {
        return Err(WinrmError::AuthFailed("sealed response: truncated".into()));
    }
    let sig_len = u32::from_le_bytes([
        data[encrypted_start],
        data[encrypted_start + 1],
        data[encrypted_start + 2],
        data[encrypted_start + 3],
    ]) as usize;

    let sealed_start = encrypted_start + 4;

    // Find the end boundary.
    //
    // BUG FIX: il server Windows (come pywinrm/evil-winrm) attacca il
    // ciphertext direttamente al boundary finale, SENZA \r\n in mezzo:
    //   <sig_len><sig><ciphertext>--Encrypted Boundary--\r\n
    // Cerchiamo prima il marker con \r\n (formato standard RFC 2046),
    // poi, se non trovato, il marker senza \r\n (formato Windows/pywinrm).
    // Fallback a data.len() solo se nessuno dei due è presente.
    let end_marker_with_crlf = format!("\r\n{ENCRYPTED_BOUNDARY}--").into_bytes();
    let end_marker_no_crlf = format!("{ENCRYPTED_BOUNDARY}--").into_bytes();
    let sealed_end = data[sealed_start..]
        .windows(end_marker_with_crlf.len())
        .position(|w| w == end_marker_with_crlf.as_slice())
        .map(|p| sealed_start + p)
        .or_else(|| {
            data[sealed_start..]
                .windows(end_marker_no_crlf.len())
                .position(|w| w == end_marker_no_crlf.as_slice())
                .map(|p| sealed_start + p)
        })
        .unwrap_or(data.len());

    let sealed_data = &data[sealed_start..sealed_end];
    if sealed_data.len() < sig_len {
        return Err(WinrmError::AuthFailed(
            "sealed response: data too short for signature".into(),
        ));
    }

    let plaintext = session.unseal(sealed_data).map_err(WinrmError::Ntlm)?;
    String::from_utf8(plaintext)
        .map_err(|e| WinrmError::AuthFailed(format!("sealed response: invalid UTF-8: {e}")))
}

impl NtlmAuth {
    /// Perform the NTLM 3-step handshake and send the body as plaintext.
    ///
    /// Returns `(response_text, session_key)`. The session key can be used to
    /// create an [`NtlmSession`](crate::ntlm::NtlmSession) for sealing
    /// subsequent requests on the same keep-alive connection.
    pub(crate) async fn handshake_and_send(
        &self,
        http: &reqwest::Client,
        url: &str,
        body: &str,
    ) -> Result<(String, Zeroizing<[u8; 16]>), WinrmError> {
        let (response, session_key) = self.do_handshake(http, url, body, false).await?;
        Ok((response, session_key))
    }

    /// Core NTLM handshake: Type 1 → Type 2 → Type 3.
    ///
    /// If `seal` is true, the body is sealed in the Type 3 request (legacy path,
    /// does not work with WinRM — kept for `EncryptionMode::Always` error path).
    async fn do_handshake(
        &self,
        http: &reqwest::Client,
        url: &str,
        body: &str,
        seal: bool,
    ) -> Result<(String, Zeroizing<[u8; 16]>), WinrmError> {
        // Step 1: Send Type 1 (Negotiate) with empty body
        let type1 = ntlm::create_negotiate_message();
        let auth_header = ntlm::encode_authorization(&type1);

        let resp = http
            .post(url)
            .header(CONTENT_TYPE, "application/soap+xml;charset=UTF-8")
            .header(AUTHORIZATION, &auth_header)
            .header("Content-Length", "0")
            .send()
            .await
            .map_err(WinrmError::Http)?;

        // Step 2: Parse Type 2 (Challenge) from 401 response
        if resp.status().as_u16() != 401 {
            return Err(WinrmError::AuthFailed(format!(
                "expected 401 for NTLM negotiate, got {}",
                resp.status()
            )));
        }

        // DEBUG: log Type1 401 response headers — se il server chiude la
        // connessione (Connection: close), il Type 3 partira' su una nuova
        // connessione TCP dove http.sys non ha il contesto SSPI → 500.
        for (k, v) in resp.headers().iter() {
            tracing::debug!("NTLM Type1 resp header {:?} = {:?}", k, v);
        }

        let www_auth = resp
            .headers()
            .get("WWW-Authenticate")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| WinrmError::AuthFailed("missing WWW-Authenticate header in 401".into()))?
            .to_string();

        // Consume the response body to release the connection back to the pool
        let _ = resp.bytes().await;

        // Decode challenge and keep raw Type 2 bytes for MIC computation
        let type2_raw = {
            let token = www_auth.strip_prefix("Negotiate ").ok_or_else(|| {
                WinrmError::AuthFailed("missing Negotiate prefix in challenge".into())
            })?;
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(token.trim_ascii())
                .map_err(|e| WinrmError::AuthFailed(format!("base64 decode: {e}")))?
        };
        let challenge = ntlm::decode_challenge_header(&www_auth).map_err(WinrmError::Ntlm)?;

        // Step 3: Send Type 3 (Authenticate) with the actual SOAP body
        // The domain for NTLMv2Hash must match what the user provided.
        // When empty, keep it empty (local account) — do NOT substitute
        // the server's target_domain, as that changes the hash.
        let domain = self.domain.clone();

        // Build the SPN for AV_TARGET_NAME (used in MIC computation)
        let host_part = url
            .strip_prefix("http://")
            .or_else(|| url.strip_prefix("https://"))
            .and_then(|s| s.split('/').next())
            .unwrap_or(url);
        let target_name = format!("http/{host_part}");

        // Channel Binding Tokens (CBT) bind the NTLM auth to the TLS channel
        // and are the primary mitigation against NTLM-over-TLS relay attacks.
        // We can only compute the CBT when the rustls verifier successfully
        // captured the server cert (cert_handle is Some AND get() returns
        // Some). If TLS is active but the capture failed (e.g. mutex poison,
        // verifier swapped), we fall back to non-CBT NTLM — but log a WARN
        // so operators can investigate.
        let (type3, session_key) = match self.cert_handle.as_ref() {
            Some(handle) => match handle.get() {
                Some(cert_der) => {
                    let cbt = crate::ntlm::crypto::compute_channel_bindings(&cert_der);
                    ntlm::create_authenticate_message_with_cbt_and_key(
                        &challenge,
                        &self.username,
                        &self.password,
                        &domain,
                        cbt,
                    )
                }
                None => {
                    tracing::warn!(
                        "NTLM-over-TLS: server certificate capture returned None; \
                         falling back to non-CBT authentication. This weakens \
                         relay-attack protection — investigate verifier state."
                    );
                    ntlm::create_authenticate_message_with_key_and_mic(
                        &challenge,
                        &self.username,
                        &self.password,
                        &domain,
                        &type1,
                        &type2_raw,
                        &target_name,
                    )
                }
            },
            None => ntlm::create_authenticate_message_with_key_and_mic(
                &challenge,
                &self.username,
                &self.password,
                &domain,
                &type1,
                &type2_raw,
                &target_name,
            ),
        };
        let auth_header = ntlm::encode_authorization(&type3);
        // DEBUG: dump Type 3 base64 + Type 1 base64 per analisi offline
        tracing::debug!("NTLM Type1 b64: {}", ntlm::encode_authorization(&type1));
        tracing::debug!("NTLM Type3 b64: {}", auth_header);

        // Apply NTLM sealing if requested (legacy path — doesn't work with WinRM
        // servers since they can't process Auth + sealed body in one request).
        let (content_type, request_body) = if seal {
            let mut session = ntlm::NtlmSession::from_auth(&session_key);
            let (ct, sealed) = seal_body(&mut session, body);
            (ct, sealed)
        } else {
            (
                "application/soap+xml;charset=UTF-8".to_string(),
                body.as_bytes().to_vec(),
            )
        };

        let resp = http
            .post(url)
            .header(CONTENT_TYPE, &content_type)
            .header(AUTHORIZATION, &auth_header)
            // http.sys rifiuta POST senza Content-Length esplicito (411).
            // Quando il body è vuoto reqwest può ometterlo — lo forziamo.
            .header("Content-Length", request_body.len().to_string())
            .body(request_body)
            .send()
            .await
            .map_err(WinrmError::Http)?;

        if resp.status().as_u16() == 401 {
            return Err(WinrmError::AuthFailed(
                "NTLM authentication rejected (bad credentials or CBT mismatch)".into(),
            ));
        }

        if !resp.status().is_success() {
            let status = resp.status();
            // DEBUG: dump response headers to see what the server actually sent
            for (k, v) in resp.headers().iter() {
                tracing::debug!("NTLM Type3 resp header {:?} = {:?}", k, v);
            }
            tracing::debug!("NTLM Type3 resp status={} version={:?}", status, resp.version());
            let text = resp.text().await.unwrap_or_default();
            tracing::debug!("NTLM Type3 resp body len={} body={:?}", text.len(), &text[..text.len().min(2000)]);
            if status.as_u16() == 500
                && let Err(soap_err) = crate::soap::parser::check_soap_fault(&text)
            {
                return Err(WinrmError::Soap(soap_err));
            }
            return Err(WinrmError::AuthFailed(format!("HTTP {status}: {text}")));
        }

        let response_text = resp.text().await.map_err(WinrmError::Http)?;
        Ok((response_text, session_key))
    }
}

impl AuthTransport for NtlmAuth {
    async fn send_authenticated(
        &self,
        http: &reqwest::Client,
        url: &str,
        body: String,
    ) -> Result<String, WinrmError> {
        let (response, _session_key) = self.do_handshake(http, url, &body, false).await?;
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ntlm::NtlmSession;

    #[test]
    fn seal_body_produces_multipart_format() {
        let mut session = NtlmSession::from_auth(&[0xAB; 16]);
        let body = "<soap>hello</soap>";
        let (content_type, mime_body) = seal_body(&mut session, body);

        // Content-Type should be multipart/encrypted with HTTP-SPNEGO
        assert!(content_type.contains("multipart/encrypted"));
        assert!(content_type.contains("HTTP-SPNEGO-session-encrypted"));
        assert!(content_type.contains("Encrypted Boundary"));

        // Body should contain the boundary marker
        let body_str = String::from_utf8_lossy(&mime_body);
        assert!(body_str.contains("--Encrypted Boundary"));
        assert!(body_str.contains("application/HTTP-SPNEGO-session-encrypted"));
        assert!(body_str.contains("application/octet-stream"));
        assert!(body_str.contains(&format!("Length={}", body.len())));
    }

    #[test]
    fn seal_body_includes_signature_length_prefix() {
        let mut session = NtlmSession::from_auth(&[0xCD; 16]);
        let (_, mime_body) = seal_body(&mut session, "test");
        // Find the octet-stream marker, then 4 bytes = signature length (LE u32 = 16)
        let marker = b"application/octet-stream\r\n";
        let pos = mime_body
            .windows(marker.len())
            .position(|w| w == marker)
            .expect("octet-stream marker present");
        let sig_len_bytes = &mime_body[pos + marker.len()..pos + marker.len() + 4];
        let sig_len = u32::from_le_bytes([
            sig_len_bytes[0],
            sig_len_bytes[1],
            sig_len_bytes[2],
            sig_len_bytes[3],
        ]);
        assert_eq!(sig_len, 16, "NTLM signature is always 16 bytes");
    }

    #[test]
    fn seal_body_ends_with_closing_boundary() {
        let mut session = NtlmSession::from_auth(&[0xEF; 16]);
        let (_, mime_body) = seal_body(&mut session, "x");
        let body_str = String::from_utf8_lossy(&mime_body);
        assert!(body_str.trim_end().ends_with("--Encrypted Boundary--"));
    }

    // Tests that the sig_len field is correctly parsed from the 4-byte LE prefix.
    // With +→- or +→* on the offset arithmetic, the bytes read would be wrong.
    #[test]
    fn unseal_body_sig_len_parsing_is_correct() {
        let mut session = NtlmSession::from_auth(&[0x55; 16]);
        let (_, sealed) = seal_body(&mut session, "test");

        // Verify the sig_len bytes at the expected offset are 16, 0, 0, 0 (LE for 16)
        let marker = b"application/octet-stream\r\n";
        let pos = sealed
            .windows(marker.len())
            .position(|w| w == marker)
            .unwrap();
        let sig_len_offset = pos + marker.len();
        let sig_len = u32::from_le_bytes([
            sealed[sig_len_offset],
            sealed[sig_len_offset + 1],
            sealed[sig_len_offset + 2],
            sealed[sig_len_offset + 3],
        ]);
        assert_eq!(sig_len, 16);
    }

    // Kills unseal_body:91 — sealed_data.len() < sig_len comparison mutations
    #[test]
    fn unseal_body_rejects_short_data_with_exact_boundary() {
        let mut session = NtlmSession::from_auth(&[0u8; 16]);
        // Marker + sig_len=100 (LE) + only 10 bytes of data + end boundary
        let mut bad = b"application/octet-stream\r\n".to_vec();
        bad.extend_from_slice(&100u32.to_le_bytes()); // sig_len=100
        bad.extend_from_slice(&[0xAA; 10]); // only 10 bytes (< 100)
        bad.extend_from_slice(b"\r\n--Encrypted Boundary--\r\n");
        let err = unseal_body(&mut session, &bad).unwrap_err();
        assert!(format!("{err}").contains("too short"));
    }

    #[test]
    fn unseal_body_rejects_missing_octet_stream_marker() {
        let mut session = NtlmSession::from_auth(&[0u8; 16]);
        let bad = b"no marker here";
        let result = unseal_body(&mut session, bad);
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("octet-stream marker"));
    }

    #[test]
    fn unseal_body_rejects_truncated_signature_after_marker() {
        let mut session = NtlmSession::from_auth(&[0u8; 16]);
        // Marker + only 3 bytes of signature length (need 4)
        let bad = b"application/octet-stream\r\n\x10\x00\x00";
        let err = unseal_body(&mut session, bad).unwrap_err();
        assert!(format!("{err}").contains("truncated"));
    }

    #[test]
    fn unseal_body_rejects_data_too_short_for_signature() {
        // Marker + 4 bytes (sig_len = 100, claiming 100-byte sig) but no data after
        let mut session = NtlmSession::from_auth(&[0u8; 16]);
        let mut data = b"application/octet-stream\r\n".to_vec();
        data.extend_from_slice(&100u32.to_le_bytes());
        // Empty sealed payload — sealed_data.len() (0) < sig_len (100)
        data.extend_from_slice(format!("\r\n{ENCRYPTED_BOUNDARY}--").as_bytes());
        let err = unseal_body(&mut session, &data).unwrap_err();
        assert!(format!("{err}").contains("too short"));
    }

    #[test]
    fn unseal_body_rejects_truncated_data() {
        let mut session = NtlmSession::from_auth(&[0u8; 16]);
        // Has the marker but no signature length after
        let bad = b"application/octet-stream\r\n\x01\x02";
        let result = unseal_body(&mut session, bad);
        assert!(result.is_err());
    }
}
