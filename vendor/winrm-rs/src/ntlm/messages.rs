// NTLM Type 1/2/3 message construction and parsing.
//
// Implements the negotiate, challenge, and authenticate messages per MS-NLMP.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use zeroize::Zeroizing;

use super::crypto::*;
use crate::error::NtlmError;

/// Parsed NTLM Type 2 (Challenge) message (MS-NLMP 2.2.1.2).
///
/// Produced by `parse_challenge` from the raw bytes of a server challenge.
/// Contains the fields needed to compute the Type 3 (Authenticate) response.
#[derive(Debug)]
#[allow(unreachable_pub)] // exposed under the `__internal` feature for fuzz targets
pub struct ChallengeMessage {
    /// 8-byte nonce from the server, used as input to NTProofStr (MS-NLMP 3.3.2).
    pub server_challenge: [u8; 8],
    /// Negotiated capability flags (MS-NLMP 2.2.2.5).
    #[allow(dead_code)]
    pub negotiate_flags: u32,
    /// Raw `AV_PAIR` list from the `TargetInfo` field, included verbatim in the
    /// NTLMv2 client blob.
    pub target_info: Vec<u8>,
    /// NetBIOS domain name extracted from `AV_NB_DOMAIN_NAME` in the target info.
    /// Retained for diagnostics; not consumed by the authenticate-message builders.
    #[allow(dead_code)]
    pub target_domain: String,
    /// Server timestamp from `AV_TIMESTAMP` (Windows FILETIME, 100 ns since
    /// 1601-01-01), if present. Used in the client blob when available.
    pub timestamp: Option<[u8; 8]>,
}

/// Create an NTLM Type 1 (Negotiate) message (MS-NLMP 2.2.1.1).
///
/// Returns a 32-byte message with the `NTLMSSP` signature, message type 1,
/// and negotiate flags requesting Unicode, NTLM, extended session security,
/// and target name. Domain and workstation security buffers are empty.
pub(crate) fn create_negotiate_message() -> Vec<u8> {
    create_negotiate_message_with_flags(TYPE1_FLAGS, true)
}

/// Create a Type 1 message for use inside CredSSP.
///
/// CredSSP requires NEGOTIATE_KEY_EXCH, NEGOTIATE_SEAL, NEGOTIATE_SIGN,
/// NEGOTIATE_128, NEGOTIATE_56 to enable the sealing of pubKeyAuth and
/// TSCredentials. Also includes NEGOTIATE_VERSION which adds the 8-byte
/// OS version field at the end of the message (40 bytes total).
#[cfg(feature = "credssp")]
#[allow(unreachable_pub)] // re-exported under the `credssp` feature for the CredSSP path
pub fn create_negotiate_message_credssp() -> Vec<u8> {
    create_negotiate_message_with_flags(TYPE1_FLAGS_CREDSSP, true)
}

fn create_negotiate_message_with_flags(flags: u32, include_version: bool) -> Vec<u8> {
    let mut msg = Vec::with_capacity(if include_version { 40 } else { 32 });
    msg.extend_from_slice(SIGNATURE); // 0-7: signature
    msg.extend_from_slice(&1u32.to_le_bytes()); // 8-11: type
    msg.extend_from_slice(&flags.to_le_bytes()); // 12-15: flags
    // Domain/workstation SBs: empty (len=0) but offset = end-of-header (matches pywinrm).
    let sb_offset: u32 = if include_version { 40 } else { 32 };
    msg.extend_from_slice(&0u16.to_le_bytes()); // domain len
    msg.extend_from_slice(&0u16.to_le_bytes()); // domain max
    msg.extend_from_slice(&sb_offset.to_le_bytes()); // domain offset
    msg.extend_from_slice(&0u16.to_le_bytes()); // ws len
    msg.extend_from_slice(&0u16.to_le_bytes()); // ws max
    msg.extend_from_slice(&sb_offset.to_le_bytes()); // ws offset
    if include_version {
        // Version (MS-NLMP 2.2.2.10): MajorVer=10, MinorVer=0, BuildNumber=0, NTLMRevision=15
        msg.extend_from_slice(&[0, 12, 1, 0, 0, 0, 0, 15]); // 32-39
    }
    msg
}

/// Parse an NTLM Type 2 (Challenge) message from raw bytes (MS-NLMP 2.2.1.2).
///
/// Extracts the server challenge, negotiate flags, target info AV_PAIRs,
/// NetBIOS domain name, and optional server timestamp. Returns
/// [`NtlmError::InvalidMessage`] if the message is too short, has an invalid
/// signature, or is not message type 2.
#[allow(unreachable_pub)] // re-exported `pub` under the `__internal` feature for fuzz targets
pub fn parse_challenge(data: &[u8]) -> Result<ChallengeMessage, NtlmError> {
    if data.len() < 32 {
        return Err(NtlmError::InvalidMessage("Type 2 message too short".into()));
    }
    if &data[0..8] != SIGNATURE {
        return Err(NtlmError::InvalidMessage("bad NTLMSSP signature".into()));
    }
    let msg_type = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    if msg_type != 2 {
        return Err(NtlmError::InvalidMessage(format!(
            "expected type 2, got {msg_type}"
        )));
    }

    let negotiate_flags = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);

    let mut server_challenge = [0u8; 8];
    server_challenge.copy_from_slice(&data[24..32]);

    // Target info security buffer at offset 40.
    //
    // ti_offset comes from a u32 cast to usize; on 32-bit targets the
    // raw `ti_offset + ti_len` could wrap. checked_add keeps us honest
    // regardless of pointer width.
    let (target_info, target_domain, timestamp) = if data.len() >= 48 {
        let ti_len = u16::from_le_bytes([data[40], data[41]]) as usize;
        let ti_offset = u32::from_le_bytes([data[44], data[45], data[46], data[47]]) as usize;
        match ti_offset.checked_add(ti_len) {
            Some(end) if end <= data.len() => {
                let ti = data[ti_offset..end].to_vec();
                let (domain, ts) = parse_av_pairs(&ti);
                (ti, domain, ts)
            }
            _ => (Vec::new(), String::new(), None),
        }
    } else {
        (Vec::new(), String::new(), None)
    };

    Ok(ChallengeMessage {
        server_challenge,
        negotiate_flags,
        target_info,
        target_domain,
        timestamp,
    })
}

/// Internal implementation -- returns both the Type 3 message and the exported session key.
///
/// The session key is wrapped in `Zeroizing` so it is wiped from the caller's
/// stack when dropped — closes the gap that compiler optimisation otherwise
/// leaves at -O2 (no automatic wipe for plain `[u8; 16]` returns).
fn create_authenticate_message_internal(
    challenge: &ChallengeMessage,
    username: &str,
    password: &str,
    domain: &str,
    channel_bindings: Option<[u8; 16]>,
    mic_input: Option<(&[u8], &[u8])>,
    target_name: Option<&str>,
) -> (Vec<u8>, Zeroizing<[u8; 16]>) {
    // Use the server's negotiated flags (from Type 2) for the Type 3 response,
    // augmented with KEY_EXCH and VERSION to enable message sealing.
    let flags = challenge.negotiate_flags | NEGOTIATE_KEY_EXCH | NEGOTIATE_VERSION;
    let with_key_exch = flags & NEGOTIATE_KEY_EXCH != 0;
    create_authenticate_message_full(
        challenge,
        username,
        password,
        domain,
        channel_bindings,
        flags,
        with_key_exch,
        mic_input,
        target_name,
        None,
    )
}

/// Build NTLM Type 3 with full control over flags, key exchange, and MIC.
///
/// `domain` is used for the NTOWFv2 hash computation. `display_domain` (if Some)
/// is used in the Domain security buffer of Type 3 (often empty for local
/// accounts even when the hash uses the server's target domain).
#[allow(clippy::too_many_arguments)]
pub(crate) fn create_authenticate_message_full(
    challenge: &ChallengeMessage,
    username: &str,
    password: &str,
    domain: &str,
    channel_bindings: Option<[u8; 16]>,
    flags: u32,
    with_key_exch: bool,
    mic_input: Option<(&[u8], &[u8])>,
    target_name: Option<&str>,
    display_domain: Option<&str>,
) -> (Vec<u8>, Zeroizing<[u8; 16]>) {
    let nt_hash = compute_nt_hash(password);
    let ntlmv2_hash = compute_ntlmv2_hash(&nt_hash, username, domain);

    // CREDSSP_FIXED_CC is a deterministic-test backdoor — only honoured in
    // debug builds. Production binaries always use the CSPRNG.
    let client_challenge: [u8; 8] = {
        #[cfg(debug_assertions)]
        let from_env = std::env::var("CREDSSP_FIXED_CC").ok().and_then(|s| {
            let bytes = (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
                .collect::<Option<Vec<_>>>()?;
            bytes.try_into().ok()
        });
        #[cfg(not(debug_assertions))]
        let from_env: Option<[u8; 8]> = None;
        from_env.unwrap_or_else(rand::random)
    };
    let timestamp = challenge.timestamp.unwrap_or_else(current_windows_filetime);

    // Build target_info: start from server's, optionally inject CBT,
    // TARGET_NAME and AV_FLAGS, end with AV_EOL.
    //
    // Wrapped in `Zeroizing` because the bytes (server-supplied, plus the
    // CBT and SPN we append) feed straight into the HMAC over the NTLMv2
    // blob and so are part of the cryptographic transcript.
    let mut target_info = Zeroizing::new(challenge.target_info.clone());
    // Strip trailing AV_EOL (4 bytes) so we can append more AV_PAIRs
    if target_info.len() >= 4 {
        let new_len = target_info.len() - 4;
        target_info.truncate(new_len);
    }

    if let Some(cb) = channel_bindings {
        target_info.extend_from_slice(&AV_CHANNEL_BINDINGS.to_le_bytes());
        target_info.extend_from_slice(&16u16.to_le_bytes());
        target_info.extend_from_slice(&cb);
    }

    if mic_input.is_some() {
        // AV_TARGET_NAME (0x0009): SPN of the target server (UTF-16LE)
        if let Some(spn) = target_name {
            let spn_utf16 = to_utf16le(spn);
            target_info.extend_from_slice(&AV_TARGET_NAME.to_le_bytes());
            target_info.extend_from_slice(&(spn_utf16.len() as u16).to_le_bytes());
            target_info.extend_from_slice(&spn_utf16);
        }
        // AV_FLAGS (0x0006): 4 bytes, bit 2 = MIC present
        target_info.extend_from_slice(&AV_FLAGS_ID.to_le_bytes());
        target_info.extend_from_slice(&4u16.to_le_bytes());
        target_info.extend_from_slice(&AV_FLAG_MIC.to_le_bytes());
    }

    // Re-add AV_EOL
    target_info.extend_from_slice(&AV_EOL.to_le_bytes());
    target_info.extend_from_slice(&0u16.to_le_bytes());

    let blob = build_ntlmv2_blob(&timestamp, &client_challenge, &target_info);

    let mut proof_input = Vec::with_capacity(8 + blob.len());
    proof_input.extend_from_slice(&challenge.server_challenge);
    proof_input.extend_from_slice(&blob);
    let nt_proof_str = hmac_md5(&ntlmv2_hash, &proof_input);

    // SessionBaseKey = HMAC-MD5(NTLMv2_Hash, NTProofStr)  (MS-NLMP 3.3.2)
    let session_base_key = hmac_md5(&ntlmv2_hash, &nt_proof_str);

    // For NTLMv2 with EXTENDED_SESSIONSECURITY, KeyExchangeKey == SessionBaseKey
    let key_exchange_key = session_base_key;

    // If NEGOTIATE_KEY_EXCH: generate random ExportedSessionKey, encrypt with RC4
    // Otherwise: ExportedSessionKey = KeyExchangeKey
    let (exported_session_key, encrypted_random_session_key) = if with_key_exch {
        // CREDSSP_FIXED_RSK is a deterministic-test backdoor — only honoured
        // in debug builds. Production binaries always use the CSPRNG.
        let random_key: [u8; 16] = {
            #[cfg(debug_assertions)]
            let from_env = std::env::var("CREDSSP_FIXED_RSK").ok().and_then(|s| {
                let bytes = (0..s.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
                    .collect::<Option<Vec<_>>>()?;
                bytes.try_into().ok()
            });
            #[cfg(not(debug_assertions))]
            let from_env: Option<[u8; 16]> = None;
            from_env.unwrap_or_else(rand::random)
        };
        let mut encrypted = random_key;
        let mut rc4 = Rc4State::new(&key_exchange_key);
        rc4.process(&mut encrypted);
        (random_key, encrypted.to_vec())
    } else {
        (key_exchange_key, Vec::new())
    };

    // NT response = NTProofStr + blob
    let mut nt_response = Vec::with_capacity(16 + blob.len());
    nt_response.extend_from_slice(&nt_proof_str);
    nt_response.extend_from_slice(&blob);

    // LM response
    // When a MIC is required (CredSSP / NTLMv2 with timestamp present in target_info)
    // the LM response MUST be 24 zero bytes to prevent replay attacks (MS-NLMP 3.1.5.1.2,
    // and matches pyspnego._ntlm._compute_response).
    let lm_response: Vec<u8> = if mic_input.is_some() {
        vec![0u8; 24]
    } else {
        let mut lm_input = Vec::with_capacity(16);
        lm_input.extend_from_slice(&challenge.server_challenge);
        lm_input.extend_from_slice(&client_challenge);
        let lm_hash = hmac_md5(&ntlmv2_hash, &lm_input);
        let mut v = Vec::with_capacity(24);
        v.extend_from_slice(&lm_hash);
        v.extend_from_slice(&client_challenge);
        v
    };

    // Domain shown in the Type 3 SB (may differ from `domain` used for the hash)
    let domain_for_sb = display_domain.unwrap_or(domain);
    let domain_bytes = to_utf16le(domain_for_sb);
    let user_bytes = to_utf16le(username);
    // Workstation: client hostname (uppercase). Empty if hostname unavailable.
    let workstation_bytes: Vec<u8> = if mic_input.is_some() {
        // Try to get hostname for CredSSP / modern Type 3 messages
        std::env::var("HOSTNAME")
            .ok()
            .or_else(|| {
                std::process::Command::new("hostname")
                    .output()
                    .ok()
                    .and_then(|o| String::from_utf8(o.stdout).ok())
                    .map(|s| s.trim().to_string())
            })
            .map(|h| to_utf16le(&h.to_uppercase()))
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    // Build Type 3 message
    // Header layout depends on NEGOTIATE_VERSION and MIC presence:
    //   - 64 bytes base (fields up to flags)
    //   - +8 bytes for OS version if NEGOTIATE_VERSION is set
    //   - +16 bytes for MIC if mic_input is provided
    let include_version = flags & NEGOTIATE_VERSION != 0;
    let include_mic = mic_input.is_some();
    let header_size: u32 =
        64 + (if include_version { 8 } else { 0 }) + (if include_mic { 16 } else { 0 });

    let mut offset = header_size;
    let lm_offset = offset;
    offset += lm_response.len() as u32;
    let nt_offset = offset;
    offset += nt_response.len() as u32;
    let domain_offset = offset;
    offset += domain_bytes.len() as u32;
    let user_offset = offset;
    offset += user_bytes.len() as u32;
    let ws_offset = offset;
    offset += workstation_bytes.len() as u32;
    let session_offset = offset;
    offset += encrypted_random_session_key.len() as u32;

    let mut msg = Vec::with_capacity(offset as usize);

    // Header
    msg.extend_from_slice(SIGNATURE);
    msg.extend_from_slice(&3u32.to_le_bytes());
    write_security_buffer(&mut msg, lm_response.len() as u16, lm_offset);
    write_security_buffer(&mut msg, nt_response.len() as u16, nt_offset);
    write_security_buffer(&mut msg, domain_bytes.len() as u16, domain_offset);
    write_security_buffer(&mut msg, user_bytes.len() as u16, user_offset);
    write_security_buffer(&mut msg, workstation_bytes.len() as u16, ws_offset);
    write_security_buffer(
        &mut msg,
        encrypted_random_session_key.len() as u16,
        session_offset,
    );
    msg.extend_from_slice(&flags.to_le_bytes());
    if include_version {
        msg.extend_from_slice(&[0, 12, 1, 0, 0, 0, 0, 15]);
    }
    let mic_pos = msg.len();
    if include_mic {
        msg.extend_from_slice(&[0u8; 16]); // placeholder
    }

    // Payload
    msg.extend_from_slice(&lm_response);
    msg.extend_from_slice(&nt_response);
    msg.extend_from_slice(&domain_bytes);
    msg.extend_from_slice(&user_bytes);
    msg.extend_from_slice(&workstation_bytes);
    msg.extend_from_slice(&encrypted_random_session_key);

    // Compute and patch MIC if requested
    if let Some((type1, type2)) = mic_input {
        let mut input = Vec::with_capacity(type1.len() + type2.len() + msg.len());
        input.extend_from_slice(type1);
        input.extend_from_slice(type2);
        input.extend_from_slice(&msg);
        let mic = hmac_md5(&exported_session_key, &input);
        msg[mic_pos..mic_pos + 16].copy_from_slice(&mic);

        // CREDSSP_DEBUG dumps every secret in the handshake to stderr —
        // strictly a debug-build aid. Compiled out of release binaries
        // entirely so a hostile env var cannot enable it in production.
        #[cfg(debug_assertions)]
        if std::env::var("CREDSSP_DEBUG").is_ok() {
            eprintln!("[CREDSSP_DEBUG] type1 ({}B): {}", type1.len(), hex(type1));
            eprintln!("[CREDSSP_DEBUG] type2 ({}B): {}", type2.len(), hex(type2));
            eprintln!("[CREDSSP_DEBUG] type3 ({}B): {}", msg.len(), hex(&msg));
            eprintln!("[CREDSSP_DEBUG] nt_proof: {}", hex(&nt_proof_str));
            eprintln!(
                "[CREDSSP_DEBUG] session_base_key: {}",
                hex(&session_base_key)
            );
            eprintln!(
                "[CREDSSP_DEBUG] exported_session_key: {}",
                hex(&exported_session_key)
            );
            eprintln!(
                "[CREDSSP_DEBUG] enc_random_sk: {}",
                hex(&encrypted_random_session_key)
            );
            eprintln!("[CREDSSP_DEBUG] mic: {}", hex(&mic));
            eprintln!(
                "[CREDSSP_DEBUG] client_challenge: {}",
                hex(&client_challenge)
            );
            eprintln!("[CREDSSP_DEBUG] timestamp: {}", hex(&timestamp));
        }
    }

    (msg, Zeroizing::new(exported_session_key))
}

// Only used inside the CREDSSP_DEBUG block, which is debug-only.
#[cfg(debug_assertions)]
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// Create an NTLM Type 3 (Authenticate) message (MS-NLMP 2.2.1.3).
///
/// Computes the NTLMv2 response using:
/// - NT Hash: `MD4(UTF-16LE(password))` (MS-NLMP 3.3.1)
/// - NTLMv2 Hash: `HMAC-MD5(NT_Hash, UTF-16LE(UPPER(username) + domain))` (MS-NLMP 3.3.2)
/// - NTProofStr: `HMAC-MD5(NTLMv2Hash, ServerChallenge + ClientBlob)` (MS-NLMP 3.3.2)
///
/// The client challenge is 8 random bytes. If the server provided a timestamp
/// in its Type 2 message, that timestamp is reused; otherwise the current
/// system time is converted to Windows FILETIME format.
#[cfg(any(test, feature = "__internal"))]
pub(crate) fn create_authenticate_message(
    challenge: &ChallengeMessage,
    username: &str,
    password: &str,
    domain: &str,
) -> Vec<u8> {
    create_authenticate_message_internal(challenge, username, password, domain, None, None, None).0
}

/// Like [`create_authenticate_message`] but with TLS Channel Binding Token,
/// also returns the 16-byte exported session key needed for NTLM message
/// sealing/signing.
pub(crate) fn create_authenticate_message_with_cbt_and_key(
    challenge: &ChallengeMessage,
    username: &str,
    password: &str,
    domain: &str,
    channel_bindings: [u8; 16],
) -> (Vec<u8>, Zeroizing<[u8; 16]>) {
    create_authenticate_message_internal(
        challenge,
        username,
        password,
        domain,
        Some(channel_bindings),
        None,
        None,
    )
}

/// Create a Type 3 with MIC (Message Integrity Check) and return the session key.
///
/// The MIC = HMAC-MD5(ExportedSessionKey, Type1 || Type2 || Type3) ensures
/// the handshake hasn't been tampered with. Required for NTLM message sealing.
pub(crate) fn create_authenticate_message_with_key_and_mic(
    challenge: &ChallengeMessage,
    username: &str,
    password: &str,
    domain: &str,
    type1: &[u8],
    type2: &[u8],
    target_name: &str,
) -> (Vec<u8>, Zeroizing<[u8; 16]>) {
    create_authenticate_message_internal(
        challenge,
        username,
        password,
        domain,
        None,
        Some((type1, type2)),
        Some(target_name),
    )
}

/// Create an NTLM Type 3 message for use inside CredSSP.
///
/// Mirrors the flags the server returned in the Type 2 challenge.
/// Generates EncryptedRandomSessionKey (NEGOTIATE_KEY_EXCH) and a MIC
/// computed over Type1 || Type2 || Type3.
///
/// `type1_bytes` and `type2_bytes` are the raw NTLMSSP messages exchanged
/// previously, used as input for the MIC HMAC.
#[cfg(feature = "credssp")]
#[allow(unreachable_pub)] // re-exported under the `credssp` feature for the CredSSP path
pub fn create_authenticate_message_credssp(
    challenge: &ChallengeMessage,
    username: &str,
    password: &str,
    domain: &str,
    spn: &str,
    type1_bytes: &[u8],
    type2_bytes: &[u8],
) -> (Vec<u8>, Zeroizing<[u8; 16]>) {
    let flags = challenge.negotiate_flags
        | NEGOTIATE_KEY_EXCH
        | NEGOTIATE_SEAL
        | NEGOTIATE_SIGN
        | NEGOTIATE_VERSION;
    create_authenticate_message_full(
        challenge,
        username,
        password,
        domain,
        None,
        flags,
        true,
        Some((type1_bytes, type2_bytes)),
        Some(spn),
        Some(""), // empty domain in Type 3 SB for local accounts
    )
}

/// Encode an NTLM message (Type 1 or Type 3) for the HTTP `Authorization` header.
///
/// Returns the string `"Negotiate <base64>"` suitable for direct use as the
/// `Authorization` header value in the NTLM/SPNEGO HTTP handshake.
pub(crate) fn encode_authorization(msg: &[u8]) -> String {
    format!("Negotiate {}", B64.encode(msg))
}

/// Decode an NTLM Type 2 (Challenge) message from an HTTP `WWW-Authenticate` header.
///
/// Expects the header value to start with `"Negotiate "` followed by a
/// base64-encoded Type 2 message. Returns [`NtlmError::InvalidMessage`] if
/// the prefix is missing, the base64 is invalid, or the decoded bytes fail
/// `parse_challenge` validation.
pub(crate) fn decode_challenge_header(header: &str) -> Result<ChallengeMessage, NtlmError> {
    let token = header
        .strip_prefix("Negotiate ")
        .ok_or_else(|| NtlmError::InvalidMessage("missing Negotiate prefix".into()))?;
    let bytes = B64
        .decode(token.trim_ascii())
        .map_err(|e| NtlmError::InvalidMessage(format!("base64 decode: {e}")))?;
    parse_challenge(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiate_message_has_correct_signature() {
        let msg = create_negotiate_message();
        assert_eq!(&msg[0..8], SIGNATURE);
        assert_eq!(u32::from_le_bytes(msg[8..12].try_into().unwrap()), 1);
        assert_eq!(msg.len(), 40); // 32 base + 8 version field
    }

    #[test]
    fn negotiate_message_has_correct_flags() {
        let msg = create_negotiate_message();
        let flags = u32::from_le_bytes(msg[12..16].try_into().unwrap());
        assert_ne!(flags & NEGOTIATE_UNICODE, 0);
        assert_ne!(flags & NEGOTIATE_NTLM, 0);
        assert_ne!(flags & REQUEST_TARGET, 0);
    }

    #[test]
    fn negotiate_message_flags_exact_value() {
        let msg = create_negotiate_message();
        let flags = u32::from_le_bytes(msg[12..16].try_into().unwrap());
        assert_eq!(flags, TYPE1_FLAGS);
        assert_ne!(flags & NEGOTIATE_SEAL, 0);
        assert_ne!(flags & NEGOTIATE_SIGN, 0);
        assert_ne!(flags & NEGOTIATE_KEY_EXCH, 0);
        assert_ne!(flags & NEGOTIATE_VERSION, 0);
    }

    #[test]
    fn parse_challenge_rejects_short_message() {
        let result = parse_challenge(&[0u8; 16]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_challenge_rejects_bad_signature() {
        let mut msg = vec![0u8; 48];
        msg[0..8].copy_from_slice(b"BADSGN\0\0");
        msg[8..12].copy_from_slice(&2u32.to_le_bytes());
        let result = parse_challenge(&msg);
        assert!(result.is_err());
    }

    #[test]
    fn parse_challenge_valid_minimal() {
        let mut msg = vec![0u8; 32];
        msg[0..8].copy_from_slice(b"NTLMSSP\0");
        msg[8..12].copy_from_slice(&2u32.to_le_bytes());
        msg[12..14].copy_from_slice(&0u16.to_le_bytes());
        msg[14..16].copy_from_slice(&0u16.to_le_bytes());
        msg[16..20].copy_from_slice(&0u32.to_le_bytes());
        msg[20..24].copy_from_slice(&TYPE1_FLAGS.to_le_bytes());
        msg[24..32].copy_from_slice(&[0xAA; 8]);

        let challenge = parse_challenge(&msg).unwrap();
        assert_eq!(challenge.server_challenge, [0xAA; 8]);
        assert_eq!(challenge.negotiate_flags, TYPE1_FLAGS);
        assert!(challenge.target_info.is_empty());
        assert!(challenge.target_domain.is_empty());
        assert!(challenge.timestamp.is_none());
    }

    #[test]
    fn parse_challenge_with_target_info() {
        let domain_utf16 = to_utf16le("CORP");
        let mut target_info = Vec::new();
        target_info.extend_from_slice(&AV_NB_DOMAIN_NAME.to_le_bytes());
        target_info.extend_from_slice(&(domain_utf16.len() as u16).to_le_bytes());
        target_info.extend_from_slice(&domain_utf16);
        target_info.extend_from_slice(&AV_TIMESTAMP.to_le_bytes());
        target_info.extend_from_slice(&8u16.to_le_bytes());
        target_info.extend_from_slice(&[0x11; 8]);
        target_info.extend_from_slice(&AV_EOL.to_le_bytes());
        target_info.extend_from_slice(&0u16.to_le_bytes());

        let ti_offset = 48u32;
        let ti_len = target_info.len() as u16;

        let mut msg = vec![0u8; ti_offset as usize + target_info.len()];
        msg[0..8].copy_from_slice(b"NTLMSSP\0");
        msg[8..12].copy_from_slice(&2u32.to_le_bytes());
        msg[20..24].copy_from_slice(&TYPE1_FLAGS.to_le_bytes());
        msg[24..32].copy_from_slice(&[0xBB; 8]);
        msg[40..42].copy_from_slice(&ti_len.to_le_bytes());
        msg[42..44].copy_from_slice(&ti_len.to_le_bytes());
        msg[44..48].copy_from_slice(&ti_offset.to_le_bytes());
        msg[ti_offset as usize..ti_offset as usize + target_info.len()]
            .copy_from_slice(&target_info);

        let challenge = parse_challenge(&msg).unwrap();
        assert_eq!(challenge.server_challenge, [0xBB; 8]);
        assert_eq!(challenge.target_domain, "CORP");
        assert_eq!(challenge.timestamp, Some([0x11; 8]));
        assert!(!challenge.target_info.is_empty());
    }

    #[test]
    fn parse_challenge_wrong_type() {
        let mut msg = vec![0u8; 32];
        msg[0..8].copy_from_slice(b"NTLMSSP\0");
        msg[8..12].copy_from_slice(&1u32.to_le_bytes());
        let result = parse_challenge(&msg);
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("expected type 2"));
    }

    #[test]
    fn parse_challenge_target_info_out_of_bounds() {
        let mut msg = vec![0u8; 48];
        msg[0..8].copy_from_slice(b"NTLMSSP\0");
        msg[8..12].copy_from_slice(&2u32.to_le_bytes());
        msg[20..24].copy_from_slice(&TYPE1_FLAGS.to_le_bytes());
        msg[24..32].copy_from_slice(&[0xCC; 8]);
        msg[40..42].copy_from_slice(&100u16.to_le_bytes());
        msg[44..48].copy_from_slice(&48u32.to_le_bytes());

        let challenge = parse_challenge(&msg).unwrap();
        assert!(challenge.target_info.is_empty());
    }

    #[test]
    fn create_authenticate_message_produces_valid_type3() {
        let challenge = ChallengeMessage {
            server_challenge: [0x01; 8],
            negotiate_flags: TYPE1_FLAGS,
            target_info: vec![0, 0, 0, 0],
            target_domain: "DOMAIN".to_string(),
            timestamp: Some([0x42; 8]),
        };

        let msg = create_authenticate_message(&challenge, "user", "password", "DOMAIN");

        assert_eq!(&msg[0..8], b"NTLMSSP\0");
        assert_eq!(u32::from_le_bytes(msg[8..12].try_into().unwrap()), 3);
        assert!(msg.len() > 64);
    }

    #[test]
    fn create_authenticate_message_without_timestamp() {
        let challenge = ChallengeMessage {
            server_challenge: [0x01; 8],
            negotiate_flags: TYPE1_FLAGS,
            target_info: vec![0, 0, 0, 0],
            target_domain: "DOM".to_string(),
            timestamp: None,
        };

        let msg = create_authenticate_message(&challenge, "admin", "pass", "DOM");
        assert_eq!(&msg[0..8], b"NTLMSSP\0");
        assert!(msg.len() > 64);
    }

    #[test]
    fn authenticate_message_security_buffer_offsets() {
        let challenge = ChallengeMessage {
            server_challenge: [0x01; 8],
            negotiate_flags: 0x0008_8205,
            target_info: vec![0, 0, 0, 0],
            target_domain: "DOM".to_string(),
            timestamp: Some([0x42; 8]),
        };
        let msg = create_authenticate_message(&challenge, "user", "pass", "DOM");

        let lm_len = u16::from_le_bytes(msg[12..14].try_into().unwrap()) as usize;
        let lm_offset = u32::from_le_bytes(msg[16..20].try_into().unwrap()) as usize;
        let nt_len = u16::from_le_bytes(msg[20..22].try_into().unwrap()) as usize;
        let nt_offset = u32::from_le_bytes(msg[24..28].try_into().unwrap()) as usize;
        let dom_len = u16::from_le_bytes(msg[28..30].try_into().unwrap()) as usize;
        let dom_offset = u32::from_le_bytes(msg[32..36].try_into().unwrap()) as usize;
        let user_len = u16::from_le_bytes(msg[36..38].try_into().unwrap()) as usize;
        let user_offset = u32::from_le_bytes(msg[40..44].try_into().unwrap()) as usize;
        let ws_len = u16::from_le_bytes(msg[44..46].try_into().unwrap()) as usize;
        let ws_offset = u32::from_le_bytes(msg[48..52].try_into().unwrap()) as usize;

        // Header is 72 bytes (64 base + 8 version field)
        assert_eq!(lm_offset, 72, "LM starts after header + version");
        assert_eq!(nt_offset, lm_offset + lm_len, "NT follows LM");
        assert_eq!(dom_offset, nt_offset + nt_len, "Domain follows NT");
        assert_eq!(user_offset, dom_offset + dom_len, "User follows Domain");
        assert_eq!(
            ws_offset,
            user_offset + user_len,
            "Workstation follows User"
        );

        assert_eq!(lm_len, 24);
        assert_eq!(dom_len, 6);
        assert_eq!(user_len, 8);
        assert_eq!(ws_len, 0);

        // EncryptedRandomSessionKey (16 bytes) follows workstation when KEY_EXCH
        let sk_len = u16::from_le_bytes(msg[52..54].try_into().unwrap()) as usize;
        let sk_offset = u32::from_le_bytes(msg[56..60].try_into().unwrap()) as usize;
        assert_eq!(sk_offset, ws_offset + ws_len);
        assert_eq!(sk_len, 16);
        assert_eq!(msg.len(), sk_offset + sk_len);
    }

    #[test]
    fn encode_authorization_has_negotiate_prefix() {
        let msg = create_negotiate_message();
        let header = encode_authorization(&msg);
        assert!(header.starts_with("Negotiate "));
    }

    #[test]
    fn decode_challenge_header_valid() {
        let mut type2 = vec![0u8; 32];
        type2[0..8].copy_from_slice(b"NTLMSSP\0");
        type2[8..12].copy_from_slice(&2u32.to_le_bytes());
        type2[20..24].copy_from_slice(&TYPE1_FLAGS.to_le_bytes());
        type2[24..32].copy_from_slice(&[0xDD; 8]);

        let header = format!("Negotiate {}", B64.encode(&type2));
        let challenge = decode_challenge_header(&header).unwrap();
        assert_eq!(challenge.server_challenge, [0xDD; 8]);
    }

    #[test]
    fn decode_challenge_header_missing_prefix() {
        let result = decode_challenge_header("Basic abc123");
        assert!(result.is_err());
    }

    #[test]
    fn decode_challenge_header_bad_base64() {
        let result = decode_challenge_header("Negotiate not-valid-base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn ntlm_error_display() {
        let err = NtlmError::InvalidMessage("test error".into());
        assert_eq!(format!("{err}"), "NTLM error: test error");
    }

    #[test]
    fn create_authenticate_message_with_key_returns_valid_type3() {
        let challenge = ChallengeMessage {
            server_challenge: [0x01; 8],
            negotiate_flags: TYPE1_FLAGS,
            target_info: vec![0, 0, 0, 0],
            target_domain: "DOMAIN".to_string(),
            timestamp: Some([0x42; 8]),
        };

        let (msg, session_key) = create_authenticate_message_internal(
            &challenge, "user", "password", "DOMAIN", None, None, None,
        );

        assert_eq!(&msg[0..8], b"NTLMSSP\0");
        assert_eq!(u32::from_le_bytes(msg[8..12].try_into().unwrap()), 3);
        assert!(msg.len() > 64);

        assert_ne!(*session_key, [0u8; 16]);
    }

    #[test]
    fn create_authenticate_message_with_key_deterministic_session_key() {
        let challenge = ChallengeMessage {
            server_challenge: [0xFF; 8],
            negotiate_flags: TYPE1_FLAGS,
            target_info: vec![0, 0, 0, 0],
            target_domain: "DOM".to_string(),
            timestamp: Some([0x11; 8]),
        };

        let (_, key1) = create_authenticate_message_internal(
            &challenge, "admin", "pass", "DOM", None, None, None,
        );
        let (_, key2) = create_authenticate_message_internal(
            &challenge, "admin", "pass", "DOM", None, None, None,
        );

        assert_ne!(*key1, [0u8; 16]);
        assert_ne!(*key2, [0u8; 16]);
    }

    #[test]
    fn authenticate_message_with_key_security_buffer_offsets() {
        let challenge = ChallengeMessage {
            server_challenge: [0x01; 8],
            negotiate_flags: 0x0008_8205,
            target_info: vec![0, 0, 0, 0],
            target_domain: "DOM".to_string(),
            timestamp: Some([0x42; 8]),
        };
        let (msg, key) = create_authenticate_message_internal(
            &challenge, "user", "pass", "DOM", None, None, None,
        );

        let lm_len = u16::from_le_bytes(msg[12..14].try_into().unwrap()) as usize;
        let lm_offset = u32::from_le_bytes(msg[16..20].try_into().unwrap()) as usize;
        let nt_len = u16::from_le_bytes(msg[20..22].try_into().unwrap()) as usize;
        let nt_offset = u32::from_le_bytes(msg[24..28].try_into().unwrap()) as usize;
        let dom_len = u16::from_le_bytes(msg[28..30].try_into().unwrap()) as usize;
        let dom_offset = u32::from_le_bytes(msg[32..36].try_into().unwrap()) as usize;
        let user_len = u16::from_le_bytes(msg[36..38].try_into().unwrap()) as usize;
        let user_offset = u32::from_le_bytes(msg[40..44].try_into().unwrap()) as usize;
        let ws_len = u16::from_le_bytes(msg[44..46].try_into().unwrap()) as usize;
        let ws_offset = u32::from_le_bytes(msg[48..52].try_into().unwrap()) as usize;

        // Header is 72 bytes (64 base + 8 version field)
        assert_eq!(lm_offset, 72, "LM starts after header + version");
        assert_eq!(nt_offset, lm_offset + lm_len, "NT follows LM");
        assert_eq!(dom_offset, nt_offset + nt_len, "Domain follows NT");
        assert_eq!(user_offset, dom_offset + dom_len, "User follows Domain");
        assert_eq!(
            ws_offset,
            user_offset + user_len,
            "Workstation follows User"
        );

        assert_eq!(lm_len, 24);
        assert_eq!(dom_len, 6);
        assert_eq!(user_len, 8);
        assert_eq!(ws_len, 0);

        // EncryptedRandomSessionKey (16 bytes) follows workstation when KEY_EXCH
        let sk_len = u16::from_le_bytes(msg[52..54].try_into().unwrap()) as usize;
        let sk_offset = u32::from_le_bytes(msg[56..60].try_into().unwrap()) as usize;
        assert_eq!(sk_offset, ws_offset + ws_len);
        assert_eq!(sk_len, 16);
        assert_eq!(msg.len(), sk_offset + sk_len);

        assert_ne!(*key, [0u8; 16]);
        assert_ne!(*key, [1u8; 16]);
    }

    #[test]
    fn create_authenticate_message_with_cbt_produces_valid_type3() {
        let challenge = {
            let mut msg = vec![0u8; 32];
            msg[0..8].copy_from_slice(b"NTLMSSP\0");
            msg[8..12].copy_from_slice(&2u32.to_le_bytes());
            msg[20..24].copy_from_slice(&TYPE1_FLAGS.to_le_bytes());
            msg[24..32].copy_from_slice(&[0xCC; 8]);
            parse_challenge(&msg).unwrap()
        };
        let cbt = [0xAA; 16];
        let (msg, _) =
            create_authenticate_message_with_cbt_and_key(&challenge, "user", "pass", "DOMAIN", cbt);
        // Should be a valid NTLM Type 3 message
        assert_eq!(&msg[0..8], SIGNATURE);
        let msg_type = u32::from_le_bytes([msg[8], msg[9], msg[10], msg[11]]);
        assert_eq!(msg_type, 3);
    }

    #[test]
    fn create_authenticate_message_with_cbt_differs_from_without() {
        let challenge = {
            let mut msg = vec![0u8; 32];
            msg[0..8].copy_from_slice(b"NTLMSSP\0");
            msg[8..12].copy_from_slice(&2u32.to_le_bytes());
            msg[20..24].copy_from_slice(&TYPE1_FLAGS.to_le_bytes());
            msg[24..32].copy_from_slice(&[0xCC; 8]);
            parse_challenge(&msg).unwrap()
        };
        let without = create_authenticate_message(&challenge, "user", "pass", "DOMAIN");
        let (with_cbt, _) = create_authenticate_message_with_cbt_and_key(
            &challenge, "user", "pass", "DOMAIN", [0xBB; 16],
        );
        // Messages should differ because target_info is modified
        assert_ne!(without, with_cbt);
        // Both should be valid Type 3
        assert_eq!(&without[0..8], SIGNATURE);
        assert_eq!(&with_cbt[0..8], SIGNATURE);
    }

    #[cfg(feature = "credssp")]
    fn build_test_challenge_for_credssp() -> ChallengeMessage {
        // Build a Type 2 with target_info containing standard AV pairs
        let mut target_info = Vec::new();
        // AV_NB_DOMAIN_NAME (2)
        target_info.extend_from_slice(&2u16.to_le_bytes());
        target_info.extend_from_slice(&30u16.to_le_bytes());
        target_info.extend_from_slice(&to_utf16le("WIN-TTSTANUQ08S"));
        // AV_TIMESTAMP (7)
        target_info.extend_from_slice(&7u16.to_le_bytes());
        target_info.extend_from_slice(&8u16.to_le_bytes());
        target_info.extend_from_slice(&[0xAA; 8]);
        // AV_EOL
        target_info.extend_from_slice(&[0u8; 4]);

        let mut msg = vec![0u8; 32];
        msg[0..8].copy_from_slice(b"NTLMSSP\0");
        msg[8..12].copy_from_slice(&2u32.to_le_bytes());
        // negotiate flags include CredSSP-required bits
        msg[20..24].copy_from_slice(&0xe28a_8235_u32.to_le_bytes());
        msg[24..32].copy_from_slice(&[0xCC; 8]);
        // Append target_info at offset 32
        let ti_off = msg.len() as u32;
        let ti_len = target_info.len() as u16;
        msg.extend_from_slice(&target_info);
        // Set target_info SB (offset 40-47)
        msg[40..42].copy_from_slice(&ti_len.to_le_bytes());
        msg[42..44].copy_from_slice(&ti_len.to_le_bytes());
        msg[44..48].copy_from_slice(&ti_off.to_le_bytes());

        parse_challenge(&msg).unwrap()
    }

    #[cfg(feature = "credssp")]
    #[test]
    fn create_negotiate_message_credssp_has_credssp_flags() {
        let msg = create_negotiate_message_credssp();
        assert_eq!(msg.len(), 40, "should be 40 bytes (32 base + 8 version)");
        assert_eq!(&msg[0..8], SIGNATURE);
        let flags = u32::from_le_bytes([msg[12], msg[13], msg[14], msg[15]]);
        // Must include KEY_EXCH, SEAL, SIGN, 128, 56, VERSION
        assert_ne!(flags & 0x4000_0000, 0, "NEGOTIATE_KEY_EXCH");
        assert_ne!(flags & 0x0000_0020, 0, "NEGOTIATE_SEAL");
        assert_ne!(flags & 0x0000_0010, 0, "NEGOTIATE_SIGN");
        assert_ne!(flags & 0x2000_0000, 0, "NEGOTIATE_128");
        assert_ne!(flags & 0x8000_0000, 0, "NEGOTIATE_56");
        assert_ne!(flags & 0x0200_0000, 0, "NEGOTIATE_VERSION");
    }

    #[cfg(feature = "credssp")]
    #[test]
    fn create_authenticate_message_credssp_has_random_session_key() {
        let challenge = build_test_challenge_for_credssp();
        let type1 = create_negotiate_message_credssp();
        let type2_bytes = vec![0u8; 32]; // dummy

        let (msg1, key1) = create_authenticate_message_credssp(
            &challenge,
            "vagrant",
            "vagrant",
            "",
            "HTTP/host",
            &type1,
            &type2_bytes,
        );
        let (msg2, key2) = create_authenticate_message_credssp(
            &challenge,
            "vagrant",
            "vagrant",
            "",
            "HTTP/host",
            &type1,
            &type2_bytes,
        );
        // Random session keys must differ between calls
        assert_ne!(key1, key2, "session keys should be random");
        // But messages should have same structure (different content)
        assert_eq!(msg1.len(), msg2.len());
    }

    #[cfg(feature = "credssp")]
    #[test]
    fn create_authenticate_message_credssp_includes_session_key_sb() {
        let challenge = build_test_challenge_for_credssp();
        let type1 = create_negotiate_message_credssp();
        let type2_bytes = vec![0u8; 32];

        let (msg, _) = create_authenticate_message_credssp(
            &challenge,
            "vagrant",
            "vagrant",
            "",
            "HTTP/host",
            &type1,
            &type2_bytes,
        );
        // Session SB at offset 52: should have len=16
        let sk_len = u16::from_le_bytes([msg[52], msg[53]]);
        assert_eq!(sk_len, 16, "EncryptedRandomSessionKey is 16 bytes");
    }

    #[cfg(feature = "credssp")]
    #[test]
    fn create_authenticate_message_credssp_uses_server_flags() {
        let challenge = build_test_challenge_for_credssp();
        let type1 = create_negotiate_message_credssp();
        let type2_bytes = vec![0u8; 32];

        let (msg, _) = create_authenticate_message_credssp(
            &challenge,
            "vagrant",
            "vagrant",
            "",
            "HTTP/host",
            &type1,
            &type2_bytes,
        );
        // Type 3 flags at offset 60
        let flags = u32::from_le_bytes([msg[60], msg[61], msg[62], msg[63]]);
        // Should include the server's flags + required CredSSP bits
        assert_ne!(flags & 0x4000_0000, 0, "NEGOTIATE_KEY_EXCH");
        assert_ne!(flags & 0x0000_0020, 0, "NEGOTIATE_SEAL");
    }

    #[cfg(feature = "credssp")]
    #[test]
    fn create_authenticate_message_credssp_has_version_field() {
        let challenge = build_test_challenge_for_credssp();
        let type1 = create_negotiate_message_credssp();
        let type2_bytes = vec![0u8; 32];

        let (msg, _) = create_authenticate_message_credssp(
            &challenge,
            "vagrant",
            "vagrant",
            "",
            "HTTP/host",
            &type1,
            &type2_bytes,
        );
        // Version field at offset 64-71
        // NTLMRevision = 15 (0x0f) at byte 71
        assert_eq!(msg[71], 0x0f, "NTLMRevision should be 15");
    }

    #[cfg(feature = "credssp")]
    #[test]
    fn create_authenticate_message_credssp_has_mic() {
        let challenge = build_test_challenge_for_credssp();
        let type1 = create_negotiate_message_credssp();
        let type2_bytes = vec![0u8; 32];

        let (msg, _) = create_authenticate_message_credssp(
            &challenge,
            "vagrant",
            "vagrant",
            "",
            "HTTP/host",
            &type1,
            &type2_bytes,
        );
        // MIC at offset 72-87 (after version field)
        let mic = &msg[72..88];
        // MIC should not be all zeros (it was computed)
        assert!(mic.iter().any(|&b| b != 0), "MIC should be non-zero");
    }

    #[cfg(feature = "credssp")]
    #[test]
    fn create_authenticate_message_credssp_target_info_has_av_target_name() {
        let challenge = build_test_challenge_for_credssp();
        let type1 = create_negotiate_message_credssp();
        let type2_bytes = vec![0u8; 32];

        let (msg, _) = create_authenticate_message_credssp(
            &challenge,
            "vagrant",
            "vagrant",
            "",
            "HTTP/somehost",
            &type1,
            &type2_bytes,
        );
        // The NT response contains the blob with AV pairs including AV_TARGET_NAME
        // Just check that "somehost" UTF-16LE bytes appear somewhere in the message
        let target_utf16 = to_utf16le("somehost");
        let found = msg.windows(target_utf16.len()).any(|w| w == target_utf16);
        assert!(found, "AV_TARGET_NAME should contain 'somehost'");
    }

    #[cfg(feature = "credssp")]
    #[test]
    fn create_authenticate_message_credssp_domain_sb_uses_display_domain() {
        let challenge = build_test_challenge_for_credssp();
        let type1 = create_negotiate_message_credssp();
        let type2_bytes = vec![0u8; 32];

        // pass non-empty domain to hash
        let (msg, _) = create_authenticate_message_credssp(
            &challenge,
            "vagrant",
            "vagrant",
            "DOMAIN",
            "HTTP/host",
            &type1,
            &type2_bytes,
        );
        // Domain SB at offset 28: should be 0 because display_domain is empty
        let dom_len = u16::from_le_bytes([msg[28], msg[29]]);
        assert_eq!(dom_len, 0, "Type 3 Domain SB should be empty for CredSSP");
    }

    #[test]
    fn create_negotiate_message_includes_version() {
        let msg = create_negotiate_message();
        assert_eq!(msg.len(), 40, "Type 1 is 40 bytes (32 base + 8 version)");
        // Version field at bytes 32-39
        assert_eq!(msg[39], 15, "NTLMRevision = 15");
    }

    // Kills hex() returning "" or "xyzzy"
    #[test]
    fn hex_encodes_bytes() {
        assert_eq!(hex(&[0xDE, 0xAD]), "dead");
        assert_eq!(hex(&[]), "");
        assert_eq!(hex(&[0x00, 0xFF]), "00ff");
    }

    // Kills create_authenticate_message_with_key_and_mic returning replacement values
    #[test]
    fn create_authenticate_message_with_key_and_mic_produces_valid_type3() {
        let challenge = ChallengeMessage {
            server_challenge: [0x01; 8],
            negotiate_flags: TYPE1_FLAGS,
            target_info: vec![0, 0, 0, 0],
            target_domain: "DOMAIN".to_string(),
            timestamp: Some([0x42; 8]),
        };
        let type1 = create_negotiate_message();
        let (msg, key) = create_authenticate_message_with_key_and_mic(
            &challenge,
            "user",
            "pass",
            "DOMAIN",
            &type1,
            &[0u8; 32], // fake type2
            "HTTP/host.domain.com",
        );
        assert_eq!(&msg[0..8], b"NTLMSSP\0");
        assert_eq!(u32::from_le_bytes(msg[8..12].try_into().unwrap()), 3);
        assert!(msg.len() > 64);
        assert_ne!(*key, [0u8; 16]);
    }

    // Kills create_negotiate_message_credssp returning vec![] / vec![0] / vec![1]
    #[cfg(feature = "credssp")]
    #[test]
    fn create_negotiate_message_credssp_is_valid_type1() {
        let msg = create_negotiate_message_credssp();
        assert_eq!(&msg[0..8], b"NTLMSSP\0");
        assert_eq!(u32::from_le_bytes(msg[8..12].try_into().unwrap()), 1);
        let flags = u32::from_le_bytes(msg[12..16].try_into().unwrap());
        // Should have NEGOTIATE_OEM which TYPE1_FLAGS doesn't
        assert_ne!(flags & NEGOTIATE_OEM, 0, "CredSSP flags should include OEM");
    }
}
