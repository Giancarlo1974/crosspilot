// Cryptographic primitives for NTLMv2 authentication.
//
// Hash functions, RC4 cipher, AV_PAIR parsing, and encoding helpers.
//
// NOTE: Several constants and helpers here are only referenced from the
// `credssp`-gated code path. Rather than scatter `#[cfg(feature = "credssp")]`
// across every individual item, we silence `dead_code` for the whole file —
// this is a low-level primitives module, not public API.
#![allow(dead_code)]

use hmac::{Hmac, KeyInit, Mac};
use md4::{Digest, Md4};
use md5::Md5;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub(crate) type HmacMd5 = Hmac<Md5>;

pub(crate) const SIGNATURE: &[u8; 8] = b"NTLMSSP\0";

// Negotiate flags (MS-NLMP 2.2.2.5)
pub(crate) const NEGOTIATE_UNICODE: u32 = 0x0000_0001;
pub(crate) const NEGOTIATE_OEM: u32 = 0x0000_0002;
pub(crate) const REQUEST_TARGET: u32 = 0x0000_0004;
pub(crate) const NEGOTIATE_SIGN: u32 = 0x0000_0010;
pub(crate) const NEGOTIATE_SEAL: u32 = 0x0000_0020;
pub(crate) const NEGOTIATE_NTLM: u32 = 0x0000_0200;
pub(crate) const NEGOTIATE_ALWAYS_SIGN: u32 = 0x0000_8000;
pub(crate) const NEGOTIATE_EXTENDED_SESSIONSECURITY: u32 = 0x0008_0000;
pub(crate) const NEGOTIATE_VERSION: u32 = 0x0200_0000;
pub(crate) const NEGOTIATE_128: u32 = 0x2000_0000;
pub(crate) const NEGOTIATE_KEY_EXCH: u32 = 0x4000_0000;
pub(crate) const NEGOTIATE_56: u32 = 0x8000_0000;

pub(crate) const TYPE1_FLAGS: u32 = NEGOTIATE_UNICODE
    | REQUEST_TARGET
    | NEGOTIATE_SIGN
    | NEGOTIATE_SEAL
    | NEGOTIATE_NTLM
    | NEGOTIATE_ALWAYS_SIGN
    | NEGOTIATE_EXTENDED_SESSIONSECURITY
    | NEGOTIATE_VERSION
    | NEGOTIATE_128
    | NEGOTIATE_KEY_EXCH
    | NEGOTIATE_56;

/// Flags required for NTLM inside CredSSP — needs sealing/key exchange.
/// Matches what pyspnego/Windows SSPI sends: 0xe2088237
pub(crate) const TYPE1_FLAGS_CREDSSP: u32 = NEGOTIATE_UNICODE
    | NEGOTIATE_OEM
    | REQUEST_TARGET
    | NEGOTIATE_SIGN
    | NEGOTIATE_SEAL
    | NEGOTIATE_NTLM
    | NEGOTIATE_ALWAYS_SIGN
    | NEGOTIATE_EXTENDED_SESSIONSECURITY
    | NEGOTIATE_VERSION
    | NEGOTIATE_128
    | NEGOTIATE_KEY_EXCH
    | NEGOTIATE_56;

// AV_PAIR IDs (MS-NLMP 2.2.2.1)
pub(crate) const AV_EOL: u16 = 0x0000;
pub(crate) const AV_NB_DOMAIN_NAME: u16 = 0x0002;
pub(crate) const AV_FLAGS_ID: u16 = 0x0006;
pub(crate) const AV_TIMESTAMP: u16 = 0x0007;
pub(crate) const AV_TARGET_NAME: u16 = 0x0009;
pub(crate) const AV_CHANNEL_BINDINGS: u16 = 0x000A;

/// Bit in AV_FLAGS indicating that a MIC is present in the AUTHENTICATE_MESSAGE.
pub(crate) const AV_FLAG_MIC: u32 = 0x0000_0002;

/// NT Hash = MD4(UTF-16LE(password)) (MS-NLMP 3.3.1, NTOWFv1).
pub(crate) fn compute_nt_hash(password: &str) -> [u8; 16] {
    let utf16 = to_utf16le(password);
    let mut hasher = Md4::new();
    hasher.update(&utf16);
    let result = hasher.finalize();
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&result);
    hash
}

/// NTLMv2 Hash = HMAC-MD5(NT_Hash, UTF-16LE(UPPER(username) + domain)) (MS-NLMP 3.3.2, NTOWFv2).
pub(crate) fn compute_ntlmv2_hash(nt_hash: &[u8; 16], username: &str, domain: &str) -> [u8; 16] {
    let identity = Zeroizing::new(format!("{}{}", username.to_uppercase(), domain));
    let identity_bytes = Zeroizing::new(to_utf16le(&identity));
    hmac_md5(nt_hash, &identity_bytes)
}

pub(crate) fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut mac = HmacMd5::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(data);
    let result = mac.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&result.into_bytes());
    out
}

/// Build the NTLMv2 client blob (MS-NLMP 3.3.2).
pub(crate) fn build_ntlmv2_blob(
    timestamp: &[u8; 8],
    client_challenge: &[u8; 8],
    target_info: &[u8],
) -> Vec<u8> {
    let mut blob = Vec::with_capacity(28 + target_info.len() + 4);
    blob.push(0x01); // RespType
    blob.push(0x01); // HiRespType
    blob.extend_from_slice(&[0u8; 6]); // Reserved
    blob.extend_from_slice(timestamp); // TimeStamp (8 bytes)
    blob.extend_from_slice(client_challenge); // ChallengeFromClient (8 bytes)
    blob.extend_from_slice(&[0u8; 4]); // Reserved
    blob.extend_from_slice(target_info); // AvPairs
    blob.extend_from_slice(&[0u8; 4]); // Reserved (terminator)
    blob
}

/// Parse AV_PAIRs from target info, extracting domain name and timestamp.
pub(crate) fn parse_av_pairs(data: &[u8]) -> (String, Option<[u8; 8]>) {
    let mut domain = String::new();
    let mut timestamp: Option<[u8; 8]> = None;
    let mut offset = 0;

    while offset + 4 <= data.len() {
        let av_id = u16::from_le_bytes([data[offset], data[offset + 1]]);
        let av_len = u16::from_le_bytes([data[offset + 2], data[offset + 3]]) as usize;
        offset += 4;

        if av_id == AV_EOL {
            break;
        }
        if offset + av_len > data.len() {
            break;
        }

        match av_id {
            AV_NB_DOMAIN_NAME => {
                domain = from_utf16le(&data[offset..offset + av_len]);
            }
            AV_TIMESTAMP if av_len == 8 => {
                let mut ts = [0u8; 8];
                ts.copy_from_slice(&data[offset..offset + 8]);
                timestamp = Some(ts);
            }
            _ => {}
        }

        offset += av_len;
    }

    (domain, timestamp)
}

pub(crate) fn write_security_buffer(buf: &mut Vec<u8>, len: u16, offset: u32) {
    buf.extend_from_slice(&len.to_le_bytes()); // Length
    buf.extend_from_slice(&len.to_le_bytes()); // MaxLength
    buf.extend_from_slice(&offset.to_le_bytes()); // Offset
}

pub(crate) fn to_utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
}

pub(crate) fn from_utf16le(data: &[u8]) -> String {
    let u16s: Vec<u16> = data
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    String::from_utf16_lossy(&u16s)
}

/// Current time as Windows FILETIME (100ns intervals since 1601-01-01).
pub(crate) fn current_windows_filetime() -> [u8; 8] {
    let unix_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // FILETIME epoch offset: seconds between 1601-01-01 and 1970-01-01
    let filetime = (unix_secs + 11_644_473_600) * 10_000_000;
    filetime.to_le_bytes()
}

/// Compute the 16-byte NTLM Channel Binding Token (CBT) from a DER-encoded
/// server certificate.
///
/// Per RFC 5929 (`tls-server-end-point`) and MS-NLMP 2.2.2.2:
/// 1. SHA-256 hash of the DER-encoded end-entity certificate
/// 2. Prepend `tls-server-end-point:` prefix to get the application data
/// 3. Build `SEC_CHANNEL_BINDINGS` structure with the application data
/// 4. MD5 hash of the entire structure → 16 bytes for `AV_CHANNEL_BINDINGS`
pub(crate) fn compute_channel_bindings(cert_der: &[u8]) -> [u8; 16] {
    use sha2::{Digest as Sha2Digest, Sha256};

    // Step 1: SHA-256 hash of the DER-encoded server certificate
    let cert_hash = Sha256::digest(cert_der);

    // Step 2: Build channel binding application data per RFC 5929 §4
    let mut app_data = b"tls-server-end-point:".to_vec();
    app_data.extend_from_slice(&cert_hash);

    // Step 3: Build gss_channel_bindings_struct per RFC 2744 §3.11
    // Format (as used by SSPI/pyspnego, NOT the Windows SEC_CHANNEL_BINDINGS struct):
    //   [initiator_addrtype:u32 LE][initiator_len:u32 LE][initiator_data]
    //   [acceptor_addrtype:u32 LE][acceptor_len:u32 LE][acceptor_data]
    //   [application_data_len:u32 LE][application_data]
    // For TLS-only CBT, initiator and acceptor are empty (length 0).
    let mut bindings = Vec::with_capacity(20 + app_data.len());
    bindings.extend_from_slice(&0u32.to_le_bytes()); // initiator addrtype = 0
    bindings.extend_from_slice(&0u32.to_le_bytes()); // initiator length = 0
    bindings.extend_from_slice(&0u32.to_le_bytes()); // acceptor addrtype = 0
    bindings.extend_from_slice(&0u32.to_le_bytes()); // acceptor length = 0
    bindings.extend_from_slice(&(app_data.len() as u32).to_le_bytes()); // app_data length
    bindings.extend_from_slice(&app_data);

    // Step 4: MD5 of the entire gss_channel_bindings_struct
    let md5_result = Md5::digest(&bindings);
    let mut output = [0u8; 16];
    output.copy_from_slice(&md5_result);
    output
}

/// RC4 (arcfour) cipher state for NTLM message sealing.
///
/// Minimal inline implementation per the RC4 algorithm. Used by [`super::NtlmSession`]
/// for encrypting/decrypting NTLM message signatures and payloads.
///
/// The S-box (256 B) is derived from a sealing key and so is itself secret —
/// `Zeroize` + `ZeroizeOnDrop` ensure the bytes are wiped when the session
/// drops, even after caller-side spills (compiler-confirmed at -O2 the
/// previous version retained S-box bytes through callee-saved registers).
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct Rc4State {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4State {
    pub(crate) fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for (i, v) in s.iter_mut().enumerate() {
            *v = i as u8;
        }
        let mut j: u8 = 0;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }
        Rc4State { s, i: 0, j: 0 }
    }

    pub(crate) fn process(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let k =
                self.s[(self.s[self.i as usize].wrapping_add(self.s[self.j as usize])) as usize];
            *byte ^= k;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Kills | → ^ and | → & mutants on TYPE1_FLAGS and TYPE1_FLAGS_CREDSSP.
    // Assert against hardcoded hex values so the constant itself is tested.
    #[test]
    fn type1_flags_exact_hex_value() {
        assert_eq!(TYPE1_FLAGS, 0xe208_8235);
    }

    #[test]
    fn type1_flags_credssp_exact_hex_value() {
        assert_eq!(TYPE1_FLAGS_CREDSSP, 0xe208_8237);
    }

    #[test]
    fn nt_hash_known_value() {
        // Known test vector: password "Password" -> MD4 of UTF-16LE
        let hash = compute_nt_hash("Password");
        assert_eq!(hash.len(), 16);
        // Verify it's not all zeros (actual computation happened)
        assert_ne!(hash, [0u8; 16]);
    }

    #[test]
    fn nt_hash_known_test_vector() {
        // NT Hash of "Password" = MD4(UTF-16LE("Password"))
        // Known value: A4F49C406510BDCAB6824EE7C30FD852
        let hash = compute_nt_hash("Password");
        assert_eq!(
            hash,
            [
                0xA4, 0xF4, 0x9C, 0x40, 0x65, 0x10, 0xBD, 0xCA, 0xB6, 0x82, 0x4E, 0xE7, 0xC3, 0x0F,
                0xD8, 0x52
            ]
        );
    }

    #[test]
    fn nt_hash_different_passwords_differ() {
        let h1 = compute_nt_hash("password1");
        let h2 = compute_nt_hash("password2");
        assert_ne!(h1, h2);
        // Verify it's not the [1; 16] mutation replacement
        assert_ne!(h1, [1u8; 16]);
        assert_ne!(h2, [1u8; 16]);
    }

    #[test]
    fn utf16le_roundtrip() {
        let input = "Hello";
        let encoded = to_utf16le(input);
        let decoded = from_utf16le(&encoded);
        assert_eq!(decoded, input);
    }

    #[test]
    fn from_utf16le_empty() {
        assert_eq!(from_utf16le(&[]), "");
    }

    #[test]
    fn to_utf16le_empty() {
        assert!(to_utf16le("").is_empty());
    }

    #[test]
    fn build_blob_correct_structure() {
        let ts = [0u8; 8];
        let cc = [1u8; 8];
        let ti = vec![0, 0, 0, 0]; // MsvAvEOL
        let blob = build_ntlmv2_blob(&ts, &cc, &ti);
        assert_eq!(blob[0], 0x01); // RespType
        assert_eq!(blob[1], 0x01); // HiRespType
        assert_eq!(&blob[2..8], &[0u8; 6]); // Reserved
    }

    #[test]
    fn windows_filetime_is_reasonable() {
        let ft_bytes = current_windows_filetime();
        let ft = u64::from_le_bytes(ft_bytes);
        // Should be after year 2020 (~132500000000000000)
        assert!(ft > 132_000_000_000_000_000);
    }

    #[test]
    fn write_security_buffer_format() {
        let mut buf = Vec::new();
        write_security_buffer(&mut buf, 10, 64);
        assert_eq!(buf.len(), 8);
        assert_eq!(u16::from_le_bytes(buf[0..2].try_into().unwrap()), 10); // len
        assert_eq!(u16::from_le_bytes(buf[2..4].try_into().unwrap()), 10); // max
        assert_eq!(u32::from_le_bytes(buf[4..8].try_into().unwrap()), 64); // offset
    }

    #[test]
    fn parse_av_pairs_with_unknown_ids() {
        // Build target info with an unknown AV_PAIR (id=0x0005)
        let mut ti = Vec::new();
        ti.extend_from_slice(&5u16.to_le_bytes()); // unknown id
        ti.extend_from_slice(&4u16.to_le_bytes()); // len 4
        ti.extend_from_slice(&[0xFF; 4]); // data
        ti.extend_from_slice(&AV_EOL.to_le_bytes());
        ti.extend_from_slice(&0u16.to_le_bytes());

        let (domain, timestamp) = parse_av_pairs(&ti);
        assert!(domain.is_empty());
        assert!(timestamp.is_none());
    }

    #[test]
    fn parse_av_pairs_truncated_data() {
        // AV_PAIR with len extending past buffer
        let mut ti = Vec::new();
        ti.extend_from_slice(&AV_NB_DOMAIN_NAME.to_le_bytes());
        ti.extend_from_slice(&100u16.to_le_bytes()); // len = 100 but buffer is tiny
        ti.extend_from_slice(&[0x41; 4]); // only 4 bytes of data

        let (domain, _) = parse_av_pairs(&ti);
        assert!(domain.is_empty()); // should bail out gracefully
    }

    #[test]
    fn parse_av_pairs_timestamp_wrong_len() {
        // AV_TIMESTAMP with wrong length (not 8)
        let mut ti = Vec::new();
        ti.extend_from_slice(&AV_TIMESTAMP.to_le_bytes());
        ti.extend_from_slice(&4u16.to_le_bytes()); // len 4, not 8
        ti.extend_from_slice(&[0xFF; 4]);
        ti.extend_from_slice(&AV_EOL.to_le_bytes());
        ti.extend_from_slice(&0u16.to_le_bytes());

        let (_, timestamp) = parse_av_pairs(&ti);
        assert!(timestamp.is_none()); // should NOT parse as timestamp
    }

    #[test]
    fn parse_av_pairs_empty() {
        let ti = vec![0, 0, 0, 0]; // just AV_EOL
        let (domain, timestamp) = parse_av_pairs(&ti);
        assert!(domain.is_empty());
        assert!(timestamp.is_none());
    }

    #[test]
    fn parse_av_pairs_exact_boundary() {
        // Build target info where data ends exactly at offset + av_len
        let domain = to_utf16le("AB"); // 4 bytes
        let mut ti = Vec::new();
        ti.extend_from_slice(&AV_NB_DOMAIN_NAME.to_le_bytes());
        ti.extend_from_slice(&(domain.len() as u16).to_le_bytes());
        ti.extend_from_slice(&domain);

        let (parsed_domain, _) = parse_av_pairs(&ti);
        assert_eq!(parsed_domain, "AB");
    }

    #[test]
    fn compute_ntlmv2_hash_deterministic() {
        let nt_hash = compute_nt_hash("Password");
        let hash1 = compute_ntlmv2_hash(&nt_hash, "user", "DOMAIN");
        let hash2 = compute_ntlmv2_hash(&nt_hash, "user", "DOMAIN");
        assert_eq!(hash1, hash2);
        // Different user should produce different hash
        let hash3 = compute_ntlmv2_hash(&nt_hash, "other", "DOMAIN");
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn compute_ntlmv2_hash_case_insensitive_username() {
        let nt_hash = compute_nt_hash("Password");
        let hash_lower = compute_ntlmv2_hash(&nt_hash, "user", "DOM");
        let hash_upper = compute_ntlmv2_hash(&nt_hash, "USER", "DOM");
        assert_eq!(hash_lower, hash_upper);
    }

    #[test]
    fn rc4_known_test_vector() {
        // RFC 6229 / Wikipedia RC4 test vector: Key = "Key", plaintext = "Plaintext"
        let mut state = Rc4State::new(b"Key");
        let mut data = b"Plaintext".to_vec();
        state.process(&mut data);
        assert_eq!(data, [0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3]);
    }

    #[test]
    fn rc4_roundtrip() {
        let key = b"test-key-12345";
        let plaintext = b"Hello, World! This is a test message for RC4.";
        let mut encrypted = plaintext.to_vec();
        Rc4State::new(key).process(&mut encrypted);
        assert_ne!(&encrypted[..], &plaintext[..]);
        let mut decrypted = encrypted.clone();
        Rc4State::new(key).process(&mut decrypted);
        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn rc4_empty_input() {
        let mut data = Vec::new();
        Rc4State::new(b"key").process(&mut data);
        assert!(data.is_empty());
    }

    #[test]
    fn compute_channel_bindings_produces_16_bytes() {
        let fake_cert = vec![0x30, 0x82, 0x01, 0x00]; // minimal DER
        let result = compute_channel_bindings(&fake_cert);
        assert_eq!(result.len(), 16);
    }

    #[test]
    fn compute_channel_bindings_deterministic() {
        let cert = b"test certificate DER bytes";
        let a = compute_channel_bindings(cert);
        let b = compute_channel_bindings(cert);
        assert_eq!(a, b);
    }

    #[test]
    fn compute_channel_bindings_different_certs_differ() {
        let a = compute_channel_bindings(b"cert A");
        let b = compute_channel_bindings(b"cert B");
        assert_ne!(a, b);
    }
}
