//! NTLMv2 authentication for WinRM.
//!
//! Implements NTLM challenge/response per MS-NLMP. Structured as:
//! - `crypto` -- hash functions, RC4, AV_PAIR parsing
//! - `messages` -- Type 1/2/3 message construction and parsing

pub(crate) mod crypto;
pub(crate) mod messages;

// Re-export crate-internal API
pub(crate) use messages::{
    create_authenticate_message_with_cbt_and_key, create_authenticate_message_with_key_and_mic,
    create_negotiate_message, decode_challenge_header, encode_authorization,
};
// `parse_challenge` is only reached from outside `ntlm::messages` by the
// CredSSP path; `crate::__fuzz` calls it through its full path. Tests inside
// the module reach it through `super::`, so the reexport is feature-gated.
#[cfg(feature = "credssp")]
#[allow(unreachable_pub)] // used in-crate by auth/credssp.rs
pub use messages::parse_challenge;
#[cfg(feature = "credssp")]
#[allow(unreachable_pub)] // used in-crate by auth/credssp.rs
pub use messages::{create_authenticate_message_credssp, create_negotiate_message_credssp};

// NtlmSession uses crypto internals
use crate::error::NtlmError;
use crypto::{Rc4State, hmac_md5};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// NTLM session state for message encryption/decryption after authentication.
///
/// Derived from the NTLMv2 authentication exchange per MS-NLMP section 3.4.4.
/// Provides seal (encrypt+sign) and unseal (decrypt+verify) for WinRM
/// message-level encryption over HTTP.
///
/// # Usage
///
/// After completing the NTLM handshake with
/// `create_authenticate_message_with_key`, use the returned exported
/// session key to create an `NtlmSession`:
///
/// ```ignore
/// let (type3_msg, session_key) = create_authenticate_message_with_key(...);
/// let mut session = NtlmSession::from_auth(&session_key);
/// let sealed = session.seal(b"plaintext payload");
/// ```
///
/// The actual integration into the HTTP transport (MIME multipart framing for
/// encrypted payloads) is deferred to a future release.
///
/// # Memory hygiene
///
/// All four derived session keys plus the two RC4 S-boxes are wiped from
/// memory when the session drops, via `ZeroizeOnDrop`. This is defence in
/// depth — once `from_auth` runs, the long-lived session is the only place
/// the sealing/signing key material lives, and its `Drop` ensures it does
/// not survive the session in the process heap.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct NtlmSession {
    client_sign_key: [u8; 16],
    server_sign_key: [u8; 16],
    /// Sealing keys are kept so the RC4 handles can be re-initialised after
    /// a SPNEGO mechListMIC — see [`Self::sign_mech_list_mic`].
    client_seal_key: [u8; 16],
    server_seal_key: [u8; 16],
    client_seq_num: u32,
    server_seq_num: u32,
    client_seal_handle: Rc4State,
    server_seal_handle: Rc4State,
}

impl NtlmSession {
    /// Derive a session from the exported session key produced during
    /// the NTLMv2 authentication exchange.
    ///
    /// Computes the four session keys (client/server seal/sign) per
    /// MS-NLMP section 3.4.4 and initializes the RC4 cipher handles.
    pub fn from_auth(exported_session_key: &[u8; 16]) -> Self {
        let client_seal_key = Self::derive_key(
            exported_session_key,
            b"session key to client-to-server sealing key magic constant\0",
        );
        let client_sign_key = Self::derive_key(
            exported_session_key,
            b"session key to client-to-server signing key magic constant\0",
        );
        let server_seal_key = Self::derive_key(
            exported_session_key,
            b"session key to server-to-client sealing key magic constant\0",
        );
        let server_sign_key = Self::derive_key(
            exported_session_key,
            b"session key to server-to-client signing key magic constant\0",
        );

        Self {
            client_sign_key,
            server_sign_key,
            client_seal_key,
            server_seal_key,
            client_seq_num: 0,
            server_seq_num: 0,
            client_seal_handle: Rc4State::new(&client_seal_key),
            server_seal_handle: Rc4State::new(&server_seal_key),
        }
    }

    fn derive_key(session_key: &[u8; 16], magic: &[u8]) -> [u8; 16] {
        use md5::Digest;
        let mut hasher = md5::Md5::new();
        hasher.update(session_key);
        hasher.update(magic);
        let result = hasher.finalize();
        let mut key = [0u8; 16];
        key.copy_from_slice(&result);
        key
    }

    /// Seal (encrypt + sign) a message for sending to the server.
    ///
    /// Returns `signature (16 bytes) || ciphertext`. The signature contains:
    /// - Version (4 bytes, always 1)
    /// - Encrypted HMAC-MD5 checksum (8 bytes)
    /// - Sequence number (4 bytes, little-endian)
    pub fn seal(&mut self, plaintext: &[u8]) -> Vec<u8> {
        // 1. Compute signature: HMAC_MD5(sign_key, seq_num + plaintext)[0..8]
        let mut sig_input = Vec::with_capacity(4 + plaintext.len());
        sig_input.extend_from_slice(&self.client_seq_num.to_le_bytes());
        sig_input.extend_from_slice(plaintext);
        let checksum = hmac_md5(&self.client_sign_key, &sig_input);
        let mut checksum_8 = [0u8; 8];
        checksum_8.copy_from_slice(&checksum[..8]);

        // 2. Encrypt the plaintext with RC4 FIRST (MS-NLMP 3.4.3 / _mac_with_ess
        //    in pyspnego: seal() does rc4(plaintext) then sign() does rc4(checksum)).
        let mut ciphertext = plaintext.to_vec();
        self.client_seal_handle.process(&mut ciphertext);

        // 3. Then encrypt the checksum with RC4 (consumes next bytes of keystream).
        self.client_seal_handle.process(&mut checksum_8);

        // 4. Build signature: Version(4) + Checksum(8) + SeqNum(4) = 16 bytes
        let mut result = Vec::with_capacity(16 + ciphertext.len());
        result.extend_from_slice(&1u32.to_le_bytes()); // version
        result.extend_from_slice(&checksum_8);
        result.extend_from_slice(&self.client_seq_num.to_le_bytes());

        self.client_seq_num += 1;

        result.extend_from_slice(&ciphertext);
        result
    }

    /// Compute an NTLM signature over `data` (no encryption of payload).
    /// Returns the 16-byte NTLMSSP_MESSAGE_SIGNATURE per MS-NLMP 3.4.4.1
    /// (with extended session security + key exchange). Consumes 8 bytes of
    /// the client RC4 keystream and increments the client sequence number.
    pub fn sign(&mut self, data: &[u8]) -> [u8; 16] {
        let mut sig_input = Vec::with_capacity(4 + data.len());
        sig_input.extend_from_slice(&self.client_seq_num.to_le_bytes());
        sig_input.extend_from_slice(data);
        let checksum = hmac_md5(&self.client_sign_key, &sig_input);
        let mut checksum_8 = [0u8; 8];
        checksum_8.copy_from_slice(&checksum[..8]);
        // KEY_EXCH path: encrypt the checksum with the client RC4 stream.
        self.client_seal_handle.process(&mut checksum_8);

        let mut sig = [0u8; 16];
        sig[0..4].copy_from_slice(&1u32.to_le_bytes());
        sig[4..12].copy_from_slice(&checksum_8);
        sig[12..16].copy_from_slice(&self.client_seq_num.to_le_bytes());
        self.client_seq_num += 1;
        sig
    }

    /// Sign the SPNEGO mech_type_list for the `mechListMIC` of the final
    /// NegTokenResp, then re-initialise the client RC4 sealing handle.
    ///
    /// Windows SPNEGO computes the mechListMIC with GSS_GetMIC — which
    /// consumes 8 bytes of RC4 keystream and one sequence number — and then
    /// resets the NTLM RC4 sealing state while keeping the sequence number.
    /// pyspnego mirrors this (`NegotiateProxy._step_spnego_mic` →
    /// `_reset_ntlm_crypto_state`) and notes that SSPI cannot be used for the
    /// inner NTLM precisely because it does not expose that reset. The next
    /// [`Self::seal`] therefore runs at keystream offset 0 with seq 1.
    ///
    /// CredSSP depends on this: a pubKeyAuth sealed at keystream offset 8
    /// decrypts to garbage on the server, which drops the context and
    /// answers a bare 401 without any TSRequest.
    pub fn sign_mech_list_mic(&mut self, mech_type_list: &[u8]) -> [u8; 16] {
        let sig = self.sign(mech_type_list);
        self.client_seal_handle = Rc4State::new(&self.client_seal_key);
        sig
    }

    /// Verify the server's SPNEGO `mechListMIC` over `mech_type_list`, then
    /// re-initialise the server RC4 sealing handle.
    ///
    /// Accept-direction twin of [`Self::sign_mech_list_mic`]: the server
    /// signs with its seq 0 and resets its sealing state, so its next sealed
    /// message (the CredSSP pubKeyAuth echo) is at seq 1, keystream offset 0.
    ///
    /// # Errors
    ///
    /// Returns [`NtlmError::InvalidMessage`] if the MIC is not 16 bytes, has
    /// a version other than 1, carries an unexpected sequence number, or its
    /// checksum does not match. The session must not be used after an error.
    pub fn verify_mech_list_mic(
        &mut self,
        mech_type_list: &[u8],
        mic: &[u8],
    ) -> Result<(), NtlmError> {
        if mic.len() != 16 {
            return Err(NtlmError::InvalidMessage(
                "mechListMIC must be 16 bytes".into(),
            ));
        }
        let version = u32::from_le_bytes([mic[0], mic[1], mic[2], mic[3]]);
        if version != 1 {
            return Err(NtlmError::InvalidMessage(
                "mechListMIC bad signature version".into(),
            ));
        }
        let sig_seq = u32::from_le_bytes([mic[12], mic[13], mic[14], mic[15]]);
        if sig_seq != self.server_seq_num {
            return Err(NtlmError::InvalidMessage(
                "mechListMIC sequence number mismatch".into(),
            ));
        }

        // Expected checksum: RC4(server handle, HMAC_MD5(server sign key,
        // seq || data)[0..8]). RC4 is symmetric, so encrypting our expected
        // value and comparing against the received (encrypted) checksum is
        // equivalent to decrypting theirs.
        let mut sig_input = Vec::with_capacity(4 + mech_type_list.len());
        sig_input.extend_from_slice(&self.server_seq_num.to_le_bytes());
        sig_input.extend_from_slice(mech_type_list);
        let checksum = hmac_md5(&self.server_sign_key, &sig_input);
        let mut expected = [0u8; 8];
        expected.copy_from_slice(&checksum[..8]);
        self.server_seal_handle.process(&mut expected);

        use subtle::ConstantTimeEq;
        if expected.ct_eq(&mic[4..12]).unwrap_u8() == 0 {
            return Err(NtlmError::InvalidMessage(
                "mechListMIC checksum mismatch".into(),
            ));
        }

        self.server_seq_num += 1;
        self.server_seal_handle = Rc4State::new(&self.server_seal_key);
        Ok(())
    }

    /// Unseal (decrypt + verify) a message received from the server.
    ///
    /// Expects `sealed` to be `signature (16 bytes) || ciphertext`.
    /// Verifies the signature version and sequence number. Returns the
    /// decrypted plaintext.
    ///
    /// # Errors
    ///
    /// Returns [`NtlmError::InvalidMessage`] if:
    /// - The message is shorter than 16 bytes
    /// - The signature version is not 1
    /// - The sequence number does not match the expected value
    /// - The HMAC-MD5 checksum does not match the expected value
    pub fn unseal(&mut self, sealed: &[u8]) -> Result<Vec<u8>, NtlmError> {
        if sealed.len() < 16 {
            return Err(NtlmError::InvalidMessage("sealed message too short".into()));
        }

        let signature = &sealed[..16];
        let ciphertext = &sealed[16..];

        // Verify signature version (unencrypted field)
        let version = u32::from_le_bytes([signature[0], signature[1], signature[2], signature[3]]);
        if version != 1 {
            return Err(NtlmError::InvalidMessage("bad signature version".into()));
        }

        // Verify sequence number (unencrypted field)
        let sig_seq =
            u32::from_le_bytes([signature[12], signature[13], signature[14], signature[15]]);
        if sig_seq != self.server_seq_num {
            return Err(NtlmError::InvalidMessage("sequence number mismatch".into()));
        }

        // Decrypt payload first (matches seal order: rc4(plaintext) then rc4(checksum)).
        let mut plaintext = ciphertext.to_vec();
        self.server_seal_handle.process(&mut plaintext);

        // Then decrypt the checksum.
        let mut sig_checksum = [0u8; 8];
        sig_checksum.copy_from_slice(&signature[4..12]);
        self.server_seal_handle.process(&mut sig_checksum);

        // Verify HMAC-MD5 checksum against decrypted plaintext.
        //
        // Use a constant-time comparison so the time taken to detect a
        // mismatch does not leak how many leading bytes of the checksum
        // are correct. Defence-in-depth against timing oracles.
        use subtle::ConstantTimeEq;
        let mut expected_sig_input = Vec::with_capacity(4 + plaintext.len());
        expected_sig_input.extend_from_slice(&self.server_seq_num.to_le_bytes());
        expected_sig_input.extend_from_slice(&plaintext);
        let expected_checksum = hmac_md5(&self.server_sign_key, &expected_sig_input);
        if sig_checksum.ct_eq(&expected_checksum[..8]).unwrap_u8() == 0 {
            return Err(NtlmError::InvalidMessage("checksum mismatch".into()));
        }

        self.server_seq_num += 1;
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn mic_hmac_md5_matches_pywinrm_vector() {
        // Vector captured from pywinrm oracle:
        let session_key = unhex("101112131415161718191a1b1c1d1e1f");
        let neg = unhex(
            "4e544c4d5353500001000000378208e200000000280000000000000028000000000c01000000000f",
        );
        let chal = unhex(
            "4e544c4d53535000020000001e001e003800000035828ae28dc091106adfffd0000000000000000098009800560000000a00f4650000000f570049004e002d00540054005300540041004e005500510030003800530002001e00570049004e002d00540054005300540041004e005500510030003800530001001e00570049004e002d00540054005300540041004e005500510030003800530004001e00570049004e002d00540054005300540041004e005500510030003800530003001e00570049004e002d00540054005300540041004e00550051003000380053000700080000f8c4ba9dc7dc0100000000",
        );
        let auth = unhex(
            "4e544c4d53535000030000001800180058000000f600f6007000000000000000660100000e000e00660100001e001e0074010000100010009201000035828ae2000c01000000000f000000000000000000000000000000000000000000000000000000000000000000000000000000008d3613113b1608b1afb92a5f0eb02477010100000000000000f8c4ba9dc7dc0120212223242526270000000002001e00570049004e002d00540054005300540041004e005500510030003800530001001e00570049004e002d00540054005300540041004e005500510030003800530004001e00570049004e002d00540054005300540041004e005500510030003800530003001e00570049004e002d00540054005300540041004e00550051003000380053000700080000f8c4ba9dc7dc010900220048005400540050002f003100390032002e003100360038002e00390036002e00310006000400020000000000000000000000760061006700720061006e00740050004f005300540045002d0046004900580045002d004c004f004900430017dc1c37061dbbea1b965421d8311908",
        );
        let expected = unhex("a235369e56d2a0fad48a755b6b4c63e6");
        let mut input = Vec::new();
        input.extend_from_slice(&neg);
        input.extend_from_slice(&chal);
        input.extend_from_slice(&auth);
        let key: [u8; 16] = session_key.try_into().unwrap();
        let mic = crypto::hmac_md5(&key, &input);
        assert_eq!(mic.to_vec(), expected, "MIC mismatch");
    }

    #[test]
    fn ntlm_session_keys_match_pywinrm_vector() {
        // Vector captured from pywinrm/spnego with exported_session_key = 0x10..0x1f
        let key: [u8; 16] = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f,
        ];
        let cli_seal = NtlmSession::derive_key(
            &key,
            b"session key to client-to-server sealing key magic constant\0",
        );
        let srv_seal = NtlmSession::derive_key(
            &key,
            b"session key to server-to-client sealing key magic constant\0",
        );
        let cli_sign = NtlmSession::derive_key(
            &key,
            b"session key to client-to-server signing key magic constant\0",
        );
        let srv_sign = NtlmSession::derive_key(
            &key,
            b"session key to server-to-client signing key magic constant\0",
        );
        let h = |b: &[u8]| b.iter().map(|x| format!("{:02x}", x)).collect::<String>();
        assert_eq!(
            h(&cli_seal),
            "af22a2127a4b090cccdfa26c427969c7",
            "client seal key"
        );
        assert_eq!(
            h(&srv_seal),
            "b9e4af6ccd5f5edeb067d13815036db5",
            "server seal key"
        );
        assert_eq!(
            h(&cli_sign),
            "a14c3d1e1b365279873f7dcf51aed29d",
            "client sign key"
        );
        assert_eq!(
            h(&srv_sign),
            "dbfeaa5883b889757ff1d849f31d6d53",
            "server sign key"
        );
    }

    #[test]
    fn sign_matches_pyspnego_mech_list_mic() {
        let key: [u8; 16] = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f,
        ];
        let mut s = NtlmSession::from_auth(&key);
        let mech = unhex("300c060a2b06010401823702020a");
        let sig = s.sign(&mech);
        assert_eq!(
            sig.to_vec(),
            unhex("0100000002f81117bb3953f700000000"),
            "mechListMIC mismatch"
        );
    }

    // Vectors generated with pyspnego 0.12.1 (`_ntlm_raw.security.sign/seal`
    // + `RC4Handle.reset`), session key 0x10..0x1f, flags 0xe28a8235.
    //
    // Windows SPNEGO re-initialises the NTLM RC4 sealing handle right after
    // the mechListMIC is produced (client side) or verified (server side),
    // keeping only the sequence-number increment. Without the reset the
    // CredSSP pubKeyAuth is sealed at keystream offset 8 instead of 0 and the
    // server answers a bare 401 (no TSRequest, no errorCode).
    const MECH_LIST_NTLM: &[u8] = &[
        0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a,
    ];
    const VECTOR_KEY: [u8; 16] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];
    const SERVER_MIC: &str = "01000000a7a9da7e0ff3680100000000";

    #[test]
    fn sign_mech_list_mic_then_seal_matches_pyspnego() {
        let mut s = NtlmSession::from_auth(&VECTOR_KEY);
        let mic = s.sign_mech_list_mic(MECH_LIST_NTLM);
        assert_eq!(mic.to_vec(), unhex("0100000002f81117bb3953f700000000"));
        let client_hash = unhex("f976d979417938eaa4cf8078ddda0e268deed123e5bf944763a0a2202dad3952");
        let sealed = s.seal(&client_hash);
        assert_eq!(
            sealed,
            unhex(
                "010000000886090156bfb29c01000000e254cc4a746ca019864ec451e5c0c3509405197402b28218d0de6416555abb0c"
            ),
            "pubKeyAuth must be sealed at keystream offset 0, seq 1"
        );
    }

    #[test]
    fn verify_mech_list_mic_then_unseal_matches_pyspnego() {
        let mut s = NtlmSession::from_auth(&VECTOR_KEY);
        s.verify_mech_list_mic(MECH_LIST_NTLM, &unhex(SERVER_MIC))
            .expect("server mechListMIC");
        let sealed = unhex(
            "01000000948f7ee5690a514c010000000ebbb2c034dbd4482fbfdaf5b510049cd5abff77739580bae87d74f82794ab93",
        );
        let pt = s.unseal(&sealed).expect("unseal seq 1 after reset");
        assert_eq!(pt, (0u8..32).collect::<Vec<u8>>());
    }

    #[test]
    fn unseal_after_verify_rejects_non_reset_peer() {
        // Same server sealing but WITHOUT the RC4 reset — what a peer that
        // keeps the keystream running would produce. Must fail the checksum.
        let mut s = NtlmSession::from_auth(&VECTOR_KEY);
        s.verify_mech_list_mic(MECH_LIST_NTLM, &unhex(SERVER_MIC))
            .unwrap();
        let noreset = unhex(
            "010000001405fcb64049e5040100000027b7d2fdbd180c94cdb3e76f6b8d98a2e0757cf02f9ca39b0c0d98f2a6c84d05",
        );
        assert!(s.unseal(&noreset).is_err());
    }

    #[test]
    fn verify_mech_list_mic_rejects_tampered_checksum() {
        let mut s = NtlmSession::from_auth(&VECTOR_KEY);
        let mut mic = unhex(SERVER_MIC);
        mic[5] ^= 0x01;
        assert!(s.verify_mech_list_mic(MECH_LIST_NTLM, &mic).is_err());
    }

    #[test]
    fn verify_mech_list_mic_rejects_wrong_seq() {
        let mut s = NtlmSession::from_auth(&VECTOR_KEY);
        let mut mic = unhex(SERVER_MIC);
        mic[12] = 1; // seq 1, expected 0
        assert!(s.verify_mech_list_mic(MECH_LIST_NTLM, &mic).is_err());
    }

    #[test]
    fn verify_mech_list_mic_rejects_bad_version_and_length() {
        let mut s = NtlmSession::from_auth(&VECTOR_KEY);
        let mut mic = unhex(SERVER_MIC);
        mic[0] = 2;
        assert!(s.verify_mech_list_mic(MECH_LIST_NTLM, &mic).is_err());
        let mut s = NtlmSession::from_auth(&VECTOR_KEY);
        assert!(
            s.verify_mech_list_mic(MECH_LIST_NTLM, &unhex(SERVER_MIC)[..15])
                .is_err()
        );
    }

    #[test]
    fn seal_matches_pywinrm_vector() {
        let key: [u8; 16] = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f,
        ];
        let mut session = NtlmSession::from_auth(&key);
        let plaintext: Vec<u8> = (0u8..32).collect();
        let sealed = session.seal(&plaintext);
        let expected = unhex(
            "010000000f62d40713d158d4000000001b23173031109ef42a884e223417c37909fada44f3180048ab67dc2d64ea9c41",
        );
        assert_eq!(sealed, expected, "seal output mismatch");
    }

    #[test]
    fn ntlm_session_seal_unseal_roundtrip() {
        let session_key: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];

        let mut session = NtlmSession::from_auth(&session_key);
        let plaintext = b"Hello, WinRM! This is a test SOAP message.";
        let sealed = session.seal(plaintext);

        assert_eq!(sealed.len(), 16 + plaintext.len());

        let version = u32::from_le_bytes(sealed[0..4].try_into().unwrap());
        assert_eq!(version, 1);

        let seq_num = u32::from_le_bytes(sealed[12..16].try_into().unwrap());
        assert_eq!(seq_num, 0);

        assert_ne!(&sealed[16..], &plaintext[..]);
    }

    #[test]
    fn ntlm_session_seal_increments_sequence() {
        let session_key: [u8; 16] = [0xAA; 16];
        let mut session = NtlmSession::from_auth(&session_key);

        let sealed1 = session.seal(b"message 1");
        let sealed2 = session.seal(b"message 2");

        let seq1 = u32::from_le_bytes(sealed1[12..16].try_into().unwrap());
        let seq2 = u32::from_le_bytes(sealed2[12..16].try_into().unwrap());
        assert_eq!(seq1, 0);
        assert_eq!(seq2, 1);
    }

    #[test]
    fn ntlm_session_unseal_too_short() {
        let session_key: [u8; 16] = [0xBB; 16];
        let mut session = NtlmSession::from_auth(&session_key);
        let result = session.unseal(&[0u8; 10]);
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("too short"));
    }

    #[test]
    fn ntlm_session_unseal_bad_version() {
        let session_key: [u8; 16] = [0xCC; 16];
        let mut session = NtlmSession::from_auth(&session_key);
        let mut fake = vec![0u8; 32];
        fake[0..4].copy_from_slice(&2u32.to_le_bytes());
        fake[12..16].copy_from_slice(&0u32.to_le_bytes());
        let result = session.unseal(&fake);
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("bad signature version"));
    }

    #[test]
    fn ntlm_session_unseal_bad_sequence() {
        let session_key: [u8; 16] = [0xDD; 16];
        let mut session = NtlmSession::from_auth(&session_key);
        let mut fake = vec![0u8; 32];
        fake[0..4].copy_from_slice(&1u32.to_le_bytes());
        fake[12..16].copy_from_slice(&99u32.to_le_bytes());
        let result = session.unseal(&fake);
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("sequence number mismatch"));
    }

    #[test]
    fn ntlm_session_seal_unseal_symmetric() {
        let session_key: [u8; 16] = [
            0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0,
            0xF0, 0x00,
        ];

        let mut client = NtlmSession::from_auth(&session_key);
        let plaintext = b"SOAP envelope data for WinRM";
        let sealed = client.seal(plaintext);

        assert!(sealed.len() > 16);
        let version = u32::from_le_bytes(sealed[0..4].try_into().unwrap());
        assert_eq!(version, 1);

        let mut client2 = NtlmSession::from_auth(&session_key);
        let sealed2 = client2.seal(plaintext);
        assert_eq!(sealed, sealed2);
    }

    #[test]
    fn ntlm_session_unseal_exact_16_bytes() {
        // Build a properly sealed empty message using client keys, then unseal
        // by constructing the "server side" manually. Since seal uses client
        // keys and unseal uses server keys, we simulate by sealing with
        // a session where client keys match the other session's server keys.
        // For simplicity, test that an invalid checksum on a 16-byte message
        // is now correctly rejected.
        let session_key: [u8; 16] = [0xEE; 16];
        let mut session = NtlmSession::from_auth(&session_key);
        let mut msg = vec![0u8; 16];
        msg[0..4].copy_from_slice(&1u32.to_le_bytes());
        msg[12..16].copy_from_slice(&0u32.to_le_bytes());
        let result = session.unseal(&msg);
        assert!(result.is_err(), "fake checksum should be rejected");
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("checksum mismatch"));
    }

    #[test]
    fn ntlm_session_derive_key_is_deterministic() {
        let key1 = [0x42u8; 16];
        let key2 = [0x42u8; 16];
        let mut s1 = NtlmSession::from_auth(&key1);
        let mut s2 = NtlmSession::from_auth(&key2);

        let sealed1 = s1.seal(b"test");
        let sealed2 = s2.seal(b"test");
        assert_eq!(
            sealed1, sealed2,
            "same key must produce identical sealed output"
        );

        let mut s3 = NtlmSession::from_auth(&[0u8; 16]);
        let sealed3 = s3.seal(b"test");
        assert_ne!(
            sealed1, sealed3,
            "different keys must produce different sealed output"
        );

        let mut s4 = NtlmSession::from_auth(&[1u8; 16]);
        let sealed4 = s4.seal(b"test");
        assert_ne!(
            sealed1, sealed4,
            "different keys must produce different sealed output"
        );
    }

    #[test]
    fn ntlm_session_multiple_seal_sequence_numbers() {
        let key = [0xAA; 16];
        let mut sealer = NtlmSession::from_auth(&key);

        let msg1 = sealer.seal(b"first");
        let msg2 = sealer.seal(b"second");

        let seq1 = u32::from_le_bytes(msg1[12..16].try_into().unwrap());
        let seq2 = u32::from_le_bytes(msg2[12..16].try_into().unwrap());
        assert_eq!(seq1, 0);
        assert_eq!(seq2, 1);
    }

    #[test]
    fn ntlm_session_unseal_rejects_stale_sequence() {
        let key = [0xAA; 16];
        let mut session = NtlmSession::from_auth(&key);
        // Fake message with seq_num=99 (expected 0)
        let mut fake = vec![0u8; 20];
        fake[0..4].copy_from_slice(&1u32.to_le_bytes());
        fake[12..16].copy_from_slice(&99u32.to_le_bytes());
        let result = session.unseal(&fake);
        assert!(result.is_err(), "stale seq_num should be rejected");
    }

    #[test]
    fn ntlm_session_unseal_rejects_tampered_checksum() {
        let key = [0xBB; 16];
        let mut session = NtlmSession::from_auth(&key);
        // Fake message with valid version and seq_num but wrong checksum
        let mut fake = vec![0u8; 32];
        fake[0..4].copy_from_slice(&1u32.to_le_bytes());
        fake[4..12].copy_from_slice(&[0xFF; 8]); // garbage checksum
        fake[12..16].copy_from_slice(&0u32.to_le_bytes());
        let result = session.unseal(&fake);
        assert!(result.is_err(), "tampered checksum should be rejected");
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("checksum mismatch"));
    }

    // Kills ntlm/mod.rs:159 — sign: replace += with *= on client_seq_num
    // *= 1 keeps seq at 0 forever; += 1 increments. After two signs,
    // the sequence numbers embedded in the signatures must differ.
    #[test]
    fn sign_increments_sequence_number() {
        let key = [0xDD; 16];
        let mut session = NtlmSession::from_auth(&key);
        let sig1 = session.sign(b"msg1");
        let sig2 = session.sign(b"msg1"); // same data, different seq
        let seq1 = u32::from_le_bytes(sig1[12..16].try_into().unwrap());
        let seq2 = u32::from_le_bytes(sig2[12..16].try_into().unwrap());
        assert_eq!(seq1, 0);
        assert_eq!(seq2, 1);
    }

    // Note: unseal's server_seq_num += 1 mutant (line 215) survives because
    // unseal uses server-side keys that differ from seal's client-side keys.
    // Killing it requires a real WinRM server or a hand-crafted server-keyed message.
}
