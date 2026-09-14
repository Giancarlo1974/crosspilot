// Minimal ASN.1 DER encoder/decoder for CredSSP (MS-CSSP).
//
// Handles only the structures needed by CredSSP: TSRequest, TSCredentials,
// TSPasswordCreds, SPNEGO NegTokenInit/NegTokenResp. Not a general-purpose
// ASN.1 library.
//
// CredSSP is still WIP — some encoder/decoder helpers here are not yet
// wired into a happy path. Silence dead_code at module level.
#![allow(dead_code)]

use crate::error::CredSspError;

// ASN.1 tag constants
const TAG_SEQUENCE: u8 = 0x30;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_INTEGER: u8 = 0x02;
const TAG_ENUM: u8 = 0x0A;
const TAG_OID: u8 = 0x06;
const TAG_BIT_STRING: u8 = 0x03;

// SPNEGO OID: 1.3.6.1.5.5.2
const SPNEGO_OID: &[u8] = &[0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
// NTLM mechanism OID: 1.3.6.1.4.1.311.2.2.10
const NTLM_OID: &[u8] = &[
    0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a,
];

/// Parsed TSRequest structure.
#[derive(Debug, Clone)]
#[allow(unreachable_pub)] // re-exported by `crate::__fuzz` under the `__internal` feature
pub struct TsRequest {
    pub version: u32,
    pub nego_token: Option<Vec<u8>>,
    pub auth_info: Option<Vec<u8>>,
    pub pub_key_auth: Option<Vec<u8>>,
    pub error_code: Option<u32>,
    pub client_nonce: Option<Vec<u8>>,
}

// --- DER Encoding Primitives ---

fn encode_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else if len < 0x10000 {
        vec![0x82, (len >> 8) as u8, len as u8]
    } else if len < 0x100_0000 {
        vec![0x83, (len >> 16) as u8, (len >> 8) as u8, len as u8]
    } else {
        // Without this arm the 3-byte form silently dropped the top bits and
        // emitted a TLV whose declared length was wrong. We never build a
        // message this large, and `decode_length` deliberately still refuses
        // to read one (its 3-byte cap bounds what a hostile server can
        // declare); this arm exists so the encoder cannot lie about a length.
        vec![
            0x84,
            (len >> 24) as u8,
            (len >> 16) as u8,
            (len >> 8) as u8,
            len as u8,
        ]
    }
}

fn encode_tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&encode_length(contents.len()));
    out.extend_from_slice(contents);
    out
}

fn encode_sequence(contents: &[u8]) -> Vec<u8> {
    encode_tlv(TAG_SEQUENCE, contents)
}

fn encode_context_tag(tag: u8, contents: &[u8]) -> Vec<u8> {
    encode_tlv(0xA0 | tag, contents)
}

fn encode_octet_string(data: &[u8]) -> Vec<u8> {
    encode_tlv(TAG_OCTET_STRING, data)
}

fn encode_integer_value(value: u32) -> Vec<u8> {
    // Encode as minimal positive integer (no leading zeros except for sign bit)
    if value == 0 {
        return encode_tlv(TAG_INTEGER, &[0]);
    }
    let bytes = value.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(3);
    // If high bit is set, prepend 0x00 to keep it positive
    if bytes[start] & 0x80 != 0 {
        let mut content = vec![0x00];
        content.extend_from_slice(&bytes[start..]);
        encode_tlv(TAG_INTEGER, &content)
    } else {
        encode_tlv(TAG_INTEGER, &bytes[start..])
    }
}

// --- CredSSP Structure Encoding ---

/// Encode a TSRequest message (MS-CSSP 2.2.1).
pub(crate) fn encode_ts_request(
    version: u32,
    nego_token: Option<&[u8]>,
    pub_key_auth: Option<&[u8]>,
    auth_info: Option<&[u8]>,
    client_nonce: Option<&[u8]>,
) -> Vec<u8> {
    let mut contents = Vec::new();

    // [0] version INTEGER
    contents.extend_from_slice(&encode_context_tag(0, &encode_integer_value(version)));

    // [1] negoTokens NegoData OPTIONAL
    if let Some(token) = nego_token {
        // NegoData ::= SEQUENCE OF SEQUENCE { negoToken [0] OCTET STRING }
        let inner = encode_context_tag(0, &encode_octet_string(token));
        let nego_seq = encode_sequence(&inner);
        let nego_data = encode_sequence(&nego_seq);
        contents.extend_from_slice(&encode_context_tag(1, &nego_data));
    }

    // [2] authInfo OCTET STRING OPTIONAL
    if let Some(info) = auth_info {
        contents.extend_from_slice(&encode_context_tag(2, &encode_octet_string(info)));
    }

    // [3] pubKeyAuth OCTET STRING OPTIONAL
    if let Some(auth) = pub_key_auth {
        contents.extend_from_slice(&encode_context_tag(3, &encode_octet_string(auth)));
    }

    // [5] clientNonce OCTET STRING OPTIONAL
    if let Some(nonce) = client_nonce {
        contents.extend_from_slice(&encode_context_tag(5, &encode_octet_string(nonce)));
    }

    encode_sequence(&contents)
}

/// Encode TSCredentials (MS-CSSP 2.2.1.2).
///
/// Returns a [`Zeroizing`] buffer so the cleartext-credentials DER blob is
/// wiped from memory once the caller drops it (typically right after the
/// blob is sealed by NTLM).
pub(crate) fn encode_ts_credentials(
    domain: &str,
    username: &str,
    password: &str,
) -> zeroize::Zeroizing<Vec<u8>> {
    use zeroize::Zeroizing;

    let domain_bytes = Zeroizing::new(crate::ntlm::crypto::to_utf16le(domain));
    let user_bytes = Zeroizing::new(crate::ntlm::crypto::to_utf16le(username));
    let pass_bytes = Zeroizing::new(crate::ntlm::crypto::to_utf16le(password));

    // TSPasswordCreds
    let mut pwd_contents = Zeroizing::new(Vec::new());
    pwd_contents.extend_from_slice(&encode_context_tag(0, &encode_octet_string(&domain_bytes)));
    pwd_contents.extend_from_slice(&encode_context_tag(1, &encode_octet_string(&user_bytes)));
    pwd_contents.extend_from_slice(&encode_context_tag(2, &encode_octet_string(&pass_bytes)));
    let ts_password_creds = Zeroizing::new(encode_sequence(&pwd_contents));

    // TSCredentials { credType: 1, credentials: DER(TSPasswordCreds) }
    let mut cred_contents = Zeroizing::new(Vec::new());
    cred_contents.extend_from_slice(&encode_context_tag(0, &encode_integer_value(1)));
    cred_contents.extend_from_slice(&encode_context_tag(
        1,
        &encode_octet_string(&ts_password_creds),
    ));
    Zeroizing::new(encode_sequence(&cred_contents))
}

/// Wrap an NTLM Type 1 message in SPNEGO NegTokenInit (RFC 4178).
///
/// Produces: APPLICATION[0] { OID(SPNEGO), NegTokenInit{mechTypes: [NTLM], mechToken: ntlm_type1} }
pub(crate) fn encode_spnego_init(ntlm_token: &[u8]) -> Vec<u8> {
    // mechTypes: SEQUENCE OF OID = { NTLM_OID }
    let mech_types = encode_context_tag(0, &encode_sequence(NTLM_OID));
    // mechToken: [2] OCTET STRING
    let mech_token = encode_context_tag(2, &encode_octet_string(ntlm_token));

    // NegTokenInit ::= SEQUENCE { mechTypes, mechToken }
    let mut neg_init_contents = Vec::new();
    neg_init_contents.extend_from_slice(&mech_types);
    neg_init_contents.extend_from_slice(&mech_token);
    let neg_token_init = encode_context_tag(0, &encode_sequence(&neg_init_contents));

    // GSS-API wrapper: APPLICATION[0] { OID(SPNEGO), NegTokenInit }
    let mut gss_contents = Vec::new();
    gss_contents.extend_from_slice(SPNEGO_OID);
    gss_contents.extend_from_slice(&neg_token_init);
    encode_tlv(0x60, &gss_contents)
}

/// Wrap an NTLM Type 3 message in SPNEGO NegTokenResp (RFC 4178).
///
/// `mech_list_mic` if Some is the 16-byte NTLMSSP signature computed over
/// the encoded mech_type_list (DER SEQUENCE OF OID containing NTLM). It is
/// REQUIRED by Windows CredSSP servers — without it the server returns
/// STATUS_LOGON_FAILURE / SubStatus 0xC000006A.
pub(crate) fn encode_spnego_response(ntlm_token: &[u8], mech_list_mic: Option<&[u8]>) -> Vec<u8> {
    // negState: [0] ENUMERATED (1 = accept-incomplete)
    let neg_state = encode_context_tag(0, &[0x0a, 0x01, 0x01]);
    // responseToken: [2] OCTET STRING
    let resp_token = encode_context_tag(2, &encode_octet_string(ntlm_token));
    let mut contents = Vec::new();
    contents.extend_from_slice(&neg_state);
    contents.extend_from_slice(&resp_token);
    if let Some(mic) = mech_list_mic {
        // mechListMIC: [3] OCTET STRING
        contents.extend_from_slice(&encode_context_tag(3, &encode_octet_string(mic)));
    }
    encode_context_tag(1, &encode_sequence(&contents))
}

/// DER-encoded mech_type_list containing only NTLM OID — used as input to
/// the SPNEGO mechListMIC HMAC. Matches `pack_mech_type_list([NTLM])` in pyspnego.
pub(crate) const MECH_TYPE_LIST_NTLM: &[u8] = &[
    0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a,
];

// --- DER Decoding Primitives ---

/// Decode a DER length field. Returns (length, bytes_consumed).
fn decode_length(data: &[u8]) -> Result<(usize, usize), CredSspError> {
    if data.is_empty() {
        return Err(CredSspError::Asn1Decode("empty length".into()));
    }
    if data[0] < 0x80 {
        Ok((data[0] as usize, 1))
    } else {
        let num_bytes = (data[0] & 0x7F) as usize;
        if num_bytes == 0 || num_bytes > 3 || data.len() < 1 + num_bytes {
            return Err(CredSspError::Asn1Decode("invalid length encoding".into()));
        }
        let mut len = 0usize;
        for i in 0..num_bytes {
            len = (len << 8) | data[1 + i] as usize;
        }
        Ok((len, 1 + num_bytes))
    }
}

/// Read a TLV (tag-length-value) at the start of data. Returns (tag, value_bytes, total_consumed).
fn read_tlv(data: &[u8]) -> Result<(u8, &[u8], usize), CredSspError> {
    if data.is_empty() {
        return Err(CredSspError::Asn1Decode("unexpected end of data".into()));
    }
    let tag = data[0];
    let (len, len_bytes) = decode_length(&data[1..])?;
    let start = 1 + len_bytes;
    let end = start + len;
    if end > data.len() {
        return Err(CredSspError::Asn1Decode(format!(
            "TLV length {len} exceeds data ({})",
            data.len() - start
        )));
    }
    Ok((tag, &data[start..end], end))
}

/// Find a context-tagged field [tag] within a SEQUENCE's contents.
fn find_context_tag(data: &[u8], tag: u8) -> Option<&[u8]> {
    let target = 0xA0 | tag;
    let mut pos = 0;
    while pos < data.len() {
        if let Ok((t, val, consumed)) = read_tlv(&data[pos..]) {
            if t == target {
                return Some(val);
            }
            pos += consumed;
        } else {
            break;
        }
    }
    None
}

/// Extract the value from an OCTET STRING TLV.
fn decode_octet_string(data: &[u8]) -> Result<&[u8], CredSspError> {
    let (tag, val, _) = read_tlv(data)?;
    if tag != TAG_OCTET_STRING {
        return Err(CredSspError::Asn1Decode(format!(
            "expected OCTET STRING (0x04), got 0x{tag:02x}"
        )));
    }
    Ok(val)
}

/// Extract an INTEGER value from a TLV.
///
/// Restricts the decoded magnitude to 4 bytes so the accumulator never
/// overflows `u32`. A hostile CredSSP server could otherwise send a 5-byte
/// or larger DER INTEGER and silently wrap our result, leading to version
/// or error-code confusion.
///
/// The one 5-byte form accepted is DER sign padding: a leading `0x00` in
/// front of a value whose high bit is set. That is exactly what
/// `encode_integer_value` emits for `value >= 0x8000_0000`, so rejecting it
/// would leave the codec unable to read back its own output.
fn decode_integer(data: &[u8]) -> Result<u32, CredSspError> {
    let (tag, val, _) = read_tlv(data)?;
    if tag != TAG_INTEGER {
        return Err(CredSspError::Asn1Decode(format!(
            "expected INTEGER (0x02), got 0x{tag:02x}"
        )));
    }
    // Strip a single leading sign-padding byte before applying the width cap.
    let magnitude = match val {
        [0x00, rest @ ..] if !rest.is_empty() => rest,
        other => other,
    };
    if magnitude.is_empty() || magnitude.len() > 4 {
        return Err(CredSspError::Asn1Decode(format!(
            "INTEGER length {} unsupported (expected 1..=4)",
            val.len()
        )));
    }
    let mut result = 0u32;
    for &b in magnitude {
        result = (result << 8) | b as u32;
    }
    Ok(result)
}

/// Decode a TSRequest from DER bytes (MS-CSSP 2.2.1).
pub(crate) fn decode_ts_request(data: &[u8]) -> Result<TsRequest, CredSspError> {
    let (tag, seq_data, _) = read_tlv(data)?;
    if tag != TAG_SEQUENCE {
        return Err(CredSspError::Asn1Decode(
            "TSRequest: expected SEQUENCE".into(),
        ));
    }

    let version = find_context_tag(seq_data, 0)
        .map(decode_integer)
        .transpose()?
        .unwrap_or(2);

    let nego_token = find_context_tag(seq_data, 1).and_then(|nego_data| {
        // NegoData → SEQUENCE OF SEQUENCE { [0] OCTET STRING }
        let (_, seq_of, _) = read_tlv(nego_data).ok()?;
        let (_, inner_seq, _) = read_tlv(seq_of).ok()?;
        let token_data = find_context_tag(inner_seq, 0)?;
        Some(decode_octet_string(token_data).ok()?.to_vec())
    });

    let auth_info = find_context_tag(seq_data, 2)
        .map(|d| decode_octet_string(d).map(|v| v.to_vec()))
        .transpose()?;

    let pub_key_auth = find_context_tag(seq_data, 3)
        .map(|d| decode_octet_string(d).map(|v| v.to_vec()))
        .transpose()?;

    let error_code = find_context_tag(seq_data, 4)
        .map(decode_integer)
        .transpose()?;

    let client_nonce = find_context_tag(seq_data, 5)
        .map(|d| decode_octet_string(d).map(|v| v.to_vec()))
        .transpose()?;

    Ok(TsRequest {
        version,
        nego_token,
        auth_info,
        pub_key_auth,
        error_code,
        client_nonce,
    })
}

/// Extract the inner NTLM token from a SPNEGO message (NegTokenInit or NegTokenResp).
pub(crate) fn decode_spnego_token(data: &[u8]) -> Result<Vec<u8>, CredSspError> {
    let (tag, contents, _) = read_tlv(data)?;

    if tag == 0x60 {
        // GSS-API APPLICATION[0] wrapper — skip OID, parse NegTokenInit inside [0]
        // Find the [0] context tag after the OID
        let oid_tlv =
            read_tlv(contents).map_err(|_| CredSspError::Asn1Decode("bad OID in SPNEGO".into()))?;
        let after_oid = &contents[oid_tlv.2..];
        // [0] NegTokenInit → mechToken [2]
        if let Some(init_data) = find_context_tag(after_oid, 0) {
            let (_, seq_data, _) = read_tlv(init_data)?;
            if let Some(token_data) = find_context_tag(seq_data, 2) {
                return Ok(decode_octet_string(token_data)?.to_vec());
            }
        }
        Err(CredSspError::Asn1Decode(
            "no mechToken in NegTokenInit".into(),
        ))
    } else if tag == 0xA1 {
        // NegTokenResp [1]
        let (_, seq_data, _) = read_tlv(contents)?;
        // responseToken is [2]
        if let Some(token_data) = find_context_tag(seq_data, 2) {
            return Ok(decode_octet_string(token_data)?.to_vec());
        }
        Err(CredSspError::Asn1Decode(
            "no responseToken in NegTokenResp".into(),
        ))
    } else {
        Err(CredSspError::Asn1Decode(format!(
            "unexpected SPNEGO tag: 0x{tag:02x}"
        )))
    }
}

/// Extract the `mechListMIC` (`[3] OCTET STRING`) from a SPNEGO NegTokenResp,
/// if present.
///
/// The server's final CredSSP token (in the pubKeyAuth TSRequest) is a
/// NegTokenResp with negState accept-completed and a mechListMIC but no
/// responseToken, so [`decode_spnego_token`] cannot be used for it.
pub(crate) fn decode_spnego_mech_list_mic(data: &[u8]) -> Result<Option<Vec<u8>>, CredSspError> {
    let (tag, contents, _) = read_tlv(data)?;
    if tag != 0xA1 {
        return Err(CredSspError::Asn1Decode(format!(
            "expected NegTokenResp (0xa1), got tag 0x{tag:02x}"
        )));
    }
    let (_, seq_data, _) = read_tlv(contents)?;
    match find_context_tag(seq_data, 3) {
        Some(mic) => Ok(Some(decode_octet_string(mic)?.to_vec())),
        None => Ok(None),
    }
}

/// Extract SubjectPublicKey from a DER-encoded X.509 certificate.
///
/// Navigates: Certificate → TBSCertificate → SubjectPublicKeyInfo → SubjectPublicKey (BIT STRING).
/// Returns the raw public key bytes (without the BIT STRING unused-bits prefix byte).
pub(crate) fn extract_subject_public_key(cert_der: &[u8]) -> Result<Vec<u8>, CredSspError> {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    let (_, cert_seq, _) = read_tlv(cert_der)?;
    // TBSCertificate ::= SEQUENCE { version, serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo, ... }
    let (_, tbs_seq, _) = read_tlv(cert_seq)?;

    // Skip fields until we reach subjectPublicKeyInfo (7th field, index 6)
    // But field count varies due to optional version. Let's find SubjectPublicKeyInfo
    // by looking for the SEQUENCE that contains a SEQUENCE (algorithm) + BIT STRING (key).
    // Simpler approach: iterate through TBS fields and find one that is a SEQUENCE
    // containing a BIT STRING.
    let mut pos = 0;
    let mut field_idx = 0;
    while pos < tbs_seq.len() {
        let (tag, val, consumed) = read_tlv(&tbs_seq[pos..])?;
        // SubjectPublicKeyInfo is typically field index 6 (0-based) when version is present
        // (version is context-tagged [0], which shifts indices)
        if tag == TAG_SEQUENCE && field_idx >= 5 {
            // Check if this SEQUENCE contains a BIT STRING (subjectPublicKey)
            let mut inner_pos = 0;
            while inner_pos < val.len() {
                let (inner_tag, inner_val, inner_consumed) = read_tlv(&val[inner_pos..])?;
                if inner_tag == TAG_BIT_STRING && inner_val.len() > 1 {
                    // Skip the "unused bits" byte (first byte of BIT STRING value)
                    return Ok(inner_val[1..].to_vec());
                }
                inner_pos += inner_consumed;
            }
        }
        pos += consumed;
        field_idx += 1;
    }

    Err(CredSspError::Asn1Decode(
        "SubjectPublicKey not found in certificate".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ts_request_encode_decode_roundtrip() {
        let encoded = encode_ts_request(6, Some(b"ntlm_token"), None, None, Some(&[0xAA; 32]));
        let decoded = decode_ts_request(&encoded).unwrap();
        assert_eq!(decoded.version, 6);
        assert_eq!(decoded.nego_token, Some(b"ntlm_token".to_vec()));
        assert!(decoded.auth_info.is_none());
        assert!(decoded.pub_key_auth.is_none());
        assert_eq!(decoded.client_nonce, Some(vec![0xAA; 32]));
    }

    #[test]
    fn ts_request_with_pub_key_auth() {
        let encoded = encode_ts_request(6, None, Some(b"encrypted_hash"), None, None);
        let decoded = decode_ts_request(&encoded).unwrap();
        assert_eq!(decoded.version, 6);
        assert!(decoded.nego_token.is_none());
        assert_eq!(decoded.pub_key_auth, Some(b"encrypted_hash".to_vec()));
    }

    #[test]
    fn ts_request_with_auth_info() {
        let encoded = encode_ts_request(6, None, None, Some(b"encrypted_creds"), None);
        let decoded = decode_ts_request(&encoded).unwrap();
        assert_eq!(decoded.auth_info, Some(b"encrypted_creds".to_vec()));
    }

    #[test]
    fn ts_credentials_encoding() {
        let creds = encode_ts_credentials("DOMAIN", "user", "pass");
        // Should be valid DER SEQUENCE
        assert_eq!(creds[0], TAG_SEQUENCE);
        // Should contain UTF-16LE encoded strings
        assert!(creds.len() > 20);
    }

    #[test]
    fn spnego_init_wraps_ntlm() {
        let type1 = b"NTLMSSP\x00\x01\x00\x00\x00";
        let wrapped = encode_spnego_init(type1);
        // Should be APPLICATION[0] (tag 0x60)
        assert_eq!(wrapped[0], 0x60);
        // Should contain SPNEGO OID
        assert!(wrapped.windows(SPNEGO_OID.len()).any(|w| w == SPNEGO_OID));
    }

    #[test]
    fn spnego_init_roundtrip() {
        let ntlm_token = b"test_ntlm_type1_token";
        let wrapped = encode_spnego_init(ntlm_token);
        let unwrapped = decode_spnego_token(&wrapped).unwrap();
        assert_eq!(unwrapped, ntlm_token);
    }

    #[test]
    fn spnego_response_roundtrip() {
        let ntlm_token = b"test_ntlm_type3_token";
        let wrapped = encode_spnego_response(ntlm_token, None);
        let unwrapped = decode_spnego_token(&wrapped).unwrap();
        assert_eq!(unwrapped, ntlm_token);
    }

    #[test]
    fn encode_length_short() {
        assert_eq!(encode_length(0), vec![0]);
        assert_eq!(encode_length(127), vec![127]);
    }

    #[test]
    fn encode_length_medium() {
        assert_eq!(encode_length(128), vec![0x81, 128]);
        assert_eq!(encode_length(255), vec![0x81, 255]);
    }

    #[test]
    fn encode_length_long() {
        assert_eq!(encode_length(256), vec![0x82, 1, 0]);
        assert_eq!(encode_length(65535), vec![0x82, 255, 255]);
    }

    #[test]
    fn integer_encoding() {
        let zero = encode_integer_value(0);
        assert_eq!(zero, vec![TAG_INTEGER, 1, 0]);

        let six = encode_integer_value(6);
        assert_eq!(six, vec![TAG_INTEGER, 1, 6]);

        let big = encode_integer_value(256);
        assert_eq!(big, vec![TAG_INTEGER, 2, 1, 0]);
    }

    #[test]
    fn encode_length_very_long() {
        // > 65535 → 3-byte length
        let l = encode_length(70000);
        assert_eq!(l[0], 0x83);
        assert_eq!(l.len(), 4);
    }

    // The 3-byte arm used to be the fallback for every larger length, which
    // truncated silently: a 16 MiB body was framed as a 0-byte one.
    #[test]
    fn encode_length_beyond_three_bytes_does_not_truncate() {
        assert_eq!(encode_length(0xFF_FFFF), vec![0x83, 0xFF, 0xFF, 0xFF]);
        assert_eq!(
            encode_length(0x100_0000),
            vec![0x84, 0x01, 0x00, 0x00, 0x00]
        );
        assert_eq!(
            encode_length(0x1234_5678),
            vec![0x84, 0x12, 0x34, 0x56, 0x78]
        );
    }

    // `encode_integer_value` prepends a 0x00 sign pad once the high bit is
    // set, producing a 5-byte INTEGER. The decoder has to read that back.
    #[test]
    fn integer_roundtrip_across_the_sign_boundary() {
        for value in [0u32, 1, 127, 128, 255, 0x7FFF_FFFF, 0x8000_0000, u32::MAX] {
            let encoded = encode_integer_value(value);
            assert_eq!(
                decode_integer(&encoded).unwrap(),
                value,
                "INTEGER {value:#x} did not roundtrip"
            );
        }
    }

    #[test]
    fn integer_rejects_oversized_magnitude() {
        // Five significant bytes: does not fit in a u32, must be refused
        // rather than silently wrapped.
        let too_big = vec![TAG_INTEGER, 5, 0x01, 0x02, 0x03, 0x04, 0x05];
        assert!(decode_integer(&too_big).is_err());
        // ...and a sign pad does not buy an extra byte of magnitude either.
        let padded_too_big = vec![TAG_INTEGER, 6, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
        assert!(decode_integer(&padded_too_big).is_err());
    }

    // NTSTATUS error codes have the high bit set, so a compliant CredSSP
    // server DER-encodes errorCode with a leading 0x00 sign pad. Before the
    // decode_integer fix the whole TSRequest failed to parse.
    #[test]
    fn ts_request_with_ntstatus_error_code_decodes() {
        // STATUS_LOGON_FAILURE, as a Windows CredSSP server sends it.
        let error_code: u32 = 0xC000_006A;
        let encoded_int = encode_integer_value(error_code);
        assert_eq!(
            encoded_int,
            vec![TAG_INTEGER, 5, 0x00, 0xC0, 0x00, 0x00, 0x6A],
            "sign-padded 5-byte INTEGER is the on-the-wire form"
        );
        // Hand-build the TSRequest a server would send: version + [4] errorCode.
        let mut contents = encode_context_tag(0, &encode_integer_value(6));
        contents.extend_from_slice(&encode_context_tag(4, &encoded_int));
        let wire = encode_sequence(&contents);

        let decoded = decode_ts_request(&wire).expect("server TSRequest must decode");
        assert_eq!(decoded.version, 6);
        assert_eq!(decoded.error_code, Some(error_code));
    }

    #[test]
    fn ts_request_version_roundtrips_with_high_bit_set() {
        let encoded = encode_ts_request(0x8000_0001, None, None, None, None);
        let decoded = decode_ts_request(&encoded).unwrap();
        assert_eq!(decoded.version, 0x8000_0001);
    }

    #[test]
    fn integer_encoding_high_bit() {
        // 128 has high bit set → needs leading 0x00
        let enc = encode_integer_value(128);
        assert_eq!(enc, vec![TAG_INTEGER, 2, 0x00, 0x80]);
    }

    #[test]
    fn decode_length_error_empty() {
        assert!(decode_length(&[]).is_err());
    }

    #[test]
    fn decode_length_error_truncated() {
        // Claims 2-byte length but only 1 byte follows
        assert!(decode_length(&[0x82, 0x01]).is_err());
    }

    #[test]
    fn decode_length_error_zero_num_bytes() {
        // 0x80 = indefinite form, not supported
        assert!(decode_length(&[0x80]).is_err());
    }

    #[test]
    fn read_tlv_error_empty() {
        assert!(read_tlv(&[]).is_err());
    }

    #[test]
    fn read_tlv_error_truncated_value() {
        // TAG=0x30, LEN=10, but only 2 bytes of data
        assert!(read_tlv(&[0x30, 10, 0x00, 0x00]).is_err());
    }

    #[test]
    fn decode_octet_string_wrong_tag() {
        // INTEGER instead of OCTET STRING
        let data = encode_integer_value(42);
        assert!(decode_octet_string(&data).is_err());
    }

    #[test]
    fn decode_integer_wrong_tag() {
        let data = encode_octet_string(b"nope");
        assert!(decode_integer(&data).is_err());
    }

    #[test]
    fn decode_integer_rejects_oversized_payload() {
        // 5-byte INTEGER would silently overflow our u32 accumulator.
        let data = [TAG_INTEGER, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
        let err = decode_integer(&data).unwrap_err();
        assert!(matches!(err, CredSspError::Asn1Decode(_)));
    }

    #[test]
    fn decode_integer_rejects_empty_payload() {
        let data = [TAG_INTEGER, 0x00];
        let err = decode_integer(&data).unwrap_err();
        assert!(matches!(err, CredSspError::Asn1Decode(_)));
    }

    #[test]
    fn decode_spnego_mech_list_mic_from_server_final_token() {
        // Captured from Server 2025 in the pubKeyAuth TSRequest: NegTokenResp
        // { negState accept-completed, mechListMIC } — no responseToken.
        let tok: &[u8] = &[
            0xa1, 0x1b, 0x30, 0x19, 0xa0, 0x03, 0x0a, 0x01, 0x00, 0xa3, 0x12, 0x04, 0x10, 0x01,
            0x00, 0x00, 0x00, 0x7c, 0x04, 0x2c, 0xe7, 0x3e, 0x8f, 0x62, 0x15, 0x00, 0x00, 0x00,
            0x00,
        ];
        let mic = decode_spnego_mech_list_mic(tok).unwrap();
        assert_eq!(
            mic,
            Some(vec![
                0x01, 0x00, 0x00, 0x00, 0x7c, 0x04, 0x2c, 0xe7, 0x3e, 0x8f, 0x62, 0x15, 0x00, 0x00,
                0x00, 0x00
            ])
        );
    }

    #[test]
    fn decode_spnego_mech_list_mic_absent_or_present_in_client_shape() {
        let tok = encode_spnego_response(b"NTLMSSP\0", None);
        assert_eq!(decode_spnego_mech_list_mic(&tok).unwrap(), None);
        let tok = encode_spnego_response(b"NTLMSSP\0", Some(&[0xAB; 16]));
        assert_eq!(
            decode_spnego_mech_list_mic(&tok).unwrap(),
            Some(vec![0xAB; 16])
        );
    }

    #[test]
    fn decode_spnego_mech_list_mic_rejects_non_neg_token_resp() {
        assert!(decode_spnego_mech_list_mic(&[0x60, 0x00]).is_err());
        assert!(decode_spnego_mech_list_mic(&[]).is_err());
    }

    #[test]
    fn decode_spnego_token_neg_token_init_missing_mech_token() {
        // APPLICATION[0] wrapper, OID, then [0] SEQUENCE without [2] mechToken
        let oid = encode_tlv(TAG_OID, &[0x2a, 0x86, 0x48]);
        let neg_token_init = encode_context_tag(0, &encode_sequence(&[]));
        let mut contents = Vec::new();
        contents.extend_from_slice(&oid);
        contents.extend_from_slice(&neg_token_init);
        let app0 = encode_tlv(0x60, &contents);
        let err = decode_spnego_token(&app0).unwrap_err();
        assert!(matches!(err, CredSspError::Asn1Decode(_)));
    }

    #[test]
    fn decode_spnego_token_neg_token_resp_missing_response_token() {
        // [1] NegTokenResp with empty SEQUENCE
        let resp = encode_context_tag(1, &encode_sequence(&[]));
        let err = decode_spnego_token(&resp).unwrap_err();
        assert!(matches!(err, CredSspError::Asn1Decode(_)));
    }

    #[test]
    fn decode_spnego_token_unknown_outer_tag() {
        // Random tag (not 0x60 or 0xA1)
        let data = encode_tlv(0x42, &[0x00]);
        let err = decode_spnego_token(&data).unwrap_err();
        assert!(matches!(err, CredSspError::Asn1Decode(_)));
    }

    #[test]
    fn encode_spnego_response_with_mech_list_mic() {
        // Drives the line `if let Some(mic) = mech_list_mic` branch.
        let mic = vec![0u8; 16];
        let resp = encode_spnego_response(b"ntlm-token", Some(&mic));
        // Decode back and ensure NegTokenResp wraps something and MIC bytes
        // appear in the encoded form.
        assert!(!resp.is_empty());
        assert!(resp.windows(16).any(|w| w == mic.as_slice()));
    }

    #[test]
    fn decode_length_rejects_long_form_with_zero_num_bytes() {
        // 0x80 = long-form prefix with num_bytes=0 (forbidden in DER).
        let err = decode_length(&[0x80]).unwrap_err();
        assert!(matches!(err, CredSspError::Asn1Decode(_)));
    }

    #[test]
    fn decode_length_rejects_long_form_truncated() {
        // 0x82 announces 2 bytes follow, but only 1 byte available.
        let err = decode_length(&[0x82, 0x01]).unwrap_err();
        assert!(matches!(err, CredSspError::Asn1Decode(_)));
    }

    #[test]
    fn read_tlv_rejects_length_exceeding_data() {
        // tag 0x04 (OCTET STRING), len=10, but only 2 bytes follow.
        let err = read_tlv(&[0x04, 0x0a, 0x00, 0x00]).unwrap_err();
        assert!(matches!(err, CredSspError::Asn1Decode(_)));
    }

    #[test]
    fn decode_ts_request_returns_default_version_when_absent() {
        // SEQUENCE with [1] nego_token only — version defaults to 2.
        let octet = encode_octet_string(b"NTLM");
        let inner = encode_sequence(&encode_context_tag(0, &octet));
        let nego_data = encode_sequence(&inner);
        let body = encode_context_tag(1, &nego_data);
        let req = encode_sequence(&body);
        let parsed = decode_ts_request(&req).unwrap();
        assert_eq!(parsed.version, 2);
        assert!(parsed.nego_token.is_some());
    }

    #[test]
    fn decode_ts_request_not_sequence() {
        // OCTET STRING instead of SEQUENCE
        let data = encode_octet_string(b"bad");
        assert!(decode_ts_request(&data).is_err());
    }

    #[test]
    fn decode_spnego_token_bad_tag() {
        // Random tag that's neither 0x60 nor 0xA1
        let data = encode_octet_string(b"not spnego");
        assert!(decode_spnego_token(&data).is_err());
    }

    #[test]
    fn extract_subject_public_key_from_self_signed_cert() {
        // Minimal self-signed DER certificate structure:
        // SEQUENCE { SEQUENCE { ... BIT STRING(public_key) ... }, ... }
        // We'll build a minimal fake certificate with a BIT STRING in the right place.
        let pub_key_bytes = vec![0x00, 0x30, 0x0d]; // BIT STRING: 0x00 unused bits prefix + key
        let bit_string = encode_tlv(TAG_BIT_STRING, &pub_key_bytes);
        let algo = encode_sequence(&[TAG_OID, 3, 0x2a, 0x86, 0x48]); // fake algo OID
        let mut spki_contents = Vec::new();
        spki_contents.extend_from_slice(&algo);
        spki_contents.extend_from_slice(&bit_string);
        let spki = encode_sequence(&spki_contents);

        // Build TBS with enough fields before SPKI (need field_idx >= 5)
        let version = encode_context_tag(0, &encode_integer_value(2));
        let serial = encode_integer_value(1);
        let sig_algo = encode_sequence(&[TAG_OID, 3, 0x2a, 0x86, 0x48]);
        let issuer = encode_sequence(&[]);
        let validity = encode_sequence(&[]);
        let subject = encode_sequence(&[]);

        let mut tbs = Vec::new();
        tbs.extend_from_slice(&version);
        tbs.extend_from_slice(&serial);
        tbs.extend_from_slice(&sig_algo);
        tbs.extend_from_slice(&issuer);
        tbs.extend_from_slice(&validity);
        tbs.extend_from_slice(&subject);
        tbs.extend_from_slice(&spki);
        let tbs_seq = encode_sequence(&tbs);

        let sig_algo2 = encode_sequence(&[TAG_OID, 3, 0x2a, 0x86, 0x48]);
        let sig_val = encode_tlv(TAG_BIT_STRING, &[0x00, 0xFF]);

        let mut cert_contents = Vec::new();
        cert_contents.extend_from_slice(&tbs_seq);
        cert_contents.extend_from_slice(&sig_algo2);
        cert_contents.extend_from_slice(&sig_val);
        let cert = encode_sequence(&cert_contents);

        let result = extract_subject_public_key(&cert).unwrap();
        assert_eq!(result, vec![0x30, 0x0d]); // key bytes without unused-bits prefix
    }

    #[test]
    fn extract_subject_public_key_bad_cert() {
        assert!(extract_subject_public_key(&[0x30, 0x00]).is_err());
    }

    #[test]
    fn find_context_tag_not_found() {
        let data = encode_context_tag(0, &encode_integer_value(1));
        assert!(find_context_tag(&data, 5).is_none());
    }

    #[test]
    fn ts_request_all_fields() {
        let encoded = encode_ts_request(
            6,
            Some(b"nego"),
            Some(b"pubkey"),
            Some(b"creds"),
            Some(&[0xBB; 32]),
        );
        let decoded = decode_ts_request(&encoded).unwrap();
        assert_eq!(decoded.version, 6);
        assert_eq!(decoded.nego_token, Some(b"nego".to_vec()));
        assert_eq!(decoded.pub_key_auth, Some(b"pubkey".to_vec()));
        assert_eq!(decoded.auth_info, Some(b"creds".to_vec()));
        assert_eq!(decoded.client_nonce, Some(vec![0xBB; 32]));
    }

    #[test]
    fn encode_length_boundary_255_uses_one_byte_form() {
        // 255 must use 0x81 form (not 0x82), kills mutant: < 0x100 → <= 0x100
        let l = encode_length(255);
        assert_eq!(l, vec![0x81, 255]);
        // 256 must use 0x82 form
        let l = encode_length(256);
        assert_eq!(l, vec![0x82, 1, 0]);
    }

    #[test]
    fn encode_context_tag_uses_or_not_xor() {
        // Tag 3 with OR: 0xA0 | 3 = 0xA3
        // Tag 3 with XOR: 0xA0 ^ 3 = 0xA3 (same! bits don't overlap)
        // Tag 5 with OR: 0xA0 | 5 = 0xA5
        // Tag 5 with XOR: 0xA0 ^ 5 = 0xA5 (same again)
        // We need a tag where OR != XOR → only if tag has bit 5,6,7 set
        // Actually for tags 0-15, OR and XOR give the same result since
        // 0xA0 = 1010_0000 and tags are 0000_xxxx — no bit overlap.
        // The mutation is semantically equivalent for our use case.
        // But let's verify the output bytes are correct for roundtrip.
        let encoded = encode_context_tag(3, &[0x42]);
        assert_eq!(encoded[0], 0xA3); // 0xA0 | 3
        assert_eq!(encoded[1], 1); // length
        assert_eq!(encoded[2], 0x42); // content
    }
}
