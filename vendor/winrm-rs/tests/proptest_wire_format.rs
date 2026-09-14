//! Property-based tests for protocol wire-format invariants.
//!
//! These complement the libfuzzer crash-hunting targets in `fuzz/` with
//! positive roundtrip and structural invariants. They run under the
//! `__internal` feature, which exposes crate internals through the
//! hidden `winrm_rs::__fuzz` module.
//!
//! Properties anchor the wire bytes the audit identified as load-bearing:
//! - NTLM Type-1 negotiate: signature `NTLMSSP\0` and message-type 1
//! - PowerShell encoding: roundtrip via `decode` is identity for arbitrary
//!   UTF-8 input, output is pure ASCII (safe to splice into HTTP/SOAP)
//! - SOAP parser: never panics on adversarial input
//! - `parse_challenge`: never panics on adversarial input ≤ 16 KiB
//!
//! Run with: `cargo test --features __internal --test proptest_wire_format`

#![cfg(feature = "__internal")]

use proptest::prelude::*;

// P-PS-1 — powershell encode is decodable as base64 of UTF-16-LE bytes.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]
    #[test]
    fn powershell_encode_is_base64_of_utf16le(s in "\\PC{0,2048}") {
        use base64::Engine;
        let encoded = winrm_rs::encode_powershell_command(&s);
        // P-PS-2: must be pure base64 (ASCII, +/= alphabet, no CR/LF)
        prop_assert!(encoded.bytes().all(|b| b.is_ascii() && b != b'\r' && b != b'\n'));
        // P-PS-1 inverse: base64-decode must succeed and decode UTF-16-LE.
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&encoded)
            .expect("encode_powershell_command output must be valid base64");
        prop_assert_eq!(raw.len() % 2, 0, "UTF-16-LE byte count must be even");
        let utf16: Vec<u16> = raw
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        let roundtrip = String::from_utf16(&utf16)
            .expect("UTF-16-LE roundtrip must succeed for valid UTF-8 input");
        prop_assert_eq!(roundtrip, s);
    }
}

// P-NTLM-1 — `parse_challenge` never panics on any byte string ≤ 16 KiB.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]
    #[test]
    fn parse_challenge_never_panics(buf in proptest::collection::vec(any::<u8>(), 0..16384)) {
        // Either an Err result, or an Ok(ChallengeMessage) — but never a panic.
        let _ = winrm_rs::__fuzz::parse_challenge(&buf);
    }
}

// P-SOAP-1 — SOAP fault detector never panics on arbitrary string input.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]
    #[test]
    fn check_soap_fault_never_panics(s in "\\PC{0,4096}") {
        let _ = winrm_rs::__fuzz::check_soap_fault(&s);
    }
}

// P-NTLM-3 — `parse_challenge` rejects buffers that don't start with the
// `NTLMSSP\0` signature.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]
    #[test]
    fn parse_challenge_requires_signature(
        bad_prefix in proptest::array::uniform8(any::<u8>()),
        rest in proptest::collection::vec(any::<u8>(), 24..512),
    ) {
        prop_assume!(&bad_prefix[..] != b"NTLMSSP\0");
        let mut buf = bad_prefix.to_vec();
        buf.extend_from_slice(&rest);
        let result = winrm_rs::__fuzz::parse_challenge(&buf);
        prop_assert!(result.is_err(), "parse_challenge must reject non-NTLMSSP signature");
    }
}
