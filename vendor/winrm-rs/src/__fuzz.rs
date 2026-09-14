//! Internal, unstable surface consumed only by the in-tree `fuzz/` targets.
//!
//! Every item here is a thin wrapper over a crate internal. The module is
//! gated behind the `__internal` feature, hidden from rustdoc, and exempt
//! from SemVer: anything in it may change or disappear in a patch release.
//! Downstream code must not enable `__internal` or reference this module.
//!
//! Wrappers (rather than `pub use`) keep the visibility of the wrapped items
//! unchanged, so enabling the feature cannot widen the real API surface.

#![allow(missing_docs)]

use crate::error::{NtlmError, SoapError, WinrmError};

// ---------------------------------------------------------------------------
// NTLM — wire format (`src/ntlm/messages.rs`)
// ---------------------------------------------------------------------------

pub use crate::ntlm::messages::ChallengeMessage;

/// Parse a raw NTLM Type 2 (Challenge) message.
pub fn parse_challenge(data: &[u8]) -> Result<ChallengeMessage, NtlmError> {
    crate::ntlm::messages::parse_challenge(data)
}

/// Parse an HTTP `WWW-Authenticate: Negotiate <base64>` challenge header.
pub fn decode_challenge_header(header: &str) -> Result<ChallengeMessage, NtlmError> {
    crate::ntlm::messages::decode_challenge_header(header)
}

/// Build an NTLM Type 1 (Negotiate) message.
pub fn create_negotiate_message() -> Vec<u8> {
    crate::ntlm::messages::create_negotiate_message()
}

/// Format an NTLM message as an `Authorization` header value.
pub fn encode_authorization(msg: &[u8]) -> String {
    crate::ntlm::messages::encode_authorization(msg)
}

/// Build an NTLM Type 3 (Authenticate) message.
pub fn create_authenticate_message(
    challenge: &ChallengeMessage,
    username: &str,
    password: &str,
    domain: &str,
) -> Vec<u8> {
    crate::ntlm::messages::create_authenticate_message(challenge, username, password, domain)
}

/// Build a Type 3 with a channel binding token; also returns the session key.
pub fn create_authenticate_message_with_cbt_and_key(
    challenge: &ChallengeMessage,
    username: &str,
    password: &str,
    domain: &str,
    channel_bindings: [u8; 16],
) -> (Vec<u8>, [u8; 16]) {
    let (msg, key) = crate::ntlm::messages::create_authenticate_message_with_cbt_and_key(
        challenge,
        username,
        password,
        domain,
        channel_bindings,
    );
    (msg, *key)
}

/// Build a Type 3 with a MIC over Type1 || Type2 || Type3.
pub fn create_authenticate_message_with_key_and_mic(
    challenge: &ChallengeMessage,
    username: &str,
    password: &str,
    domain: &str,
    type1: &[u8],
    type2: &[u8],
    target_name: &str,
) -> (Vec<u8>, [u8; 16]) {
    let (msg, key) = crate::ntlm::messages::create_authenticate_message_with_key_and_mic(
        challenge,
        username,
        password,
        domain,
        type1,
        type2,
        target_name,
    );
    (msg, *key)
}

// ---------------------------------------------------------------------------
// NTLM — crypto primitives (`src/ntlm/crypto.rs`)
// ---------------------------------------------------------------------------

/// Parse the `AV_PAIR` list carried in a Type 2 `TargetInfo` field.
pub fn parse_av_pairs(data: &[u8]) -> (String, Option<[u8; 8]>) {
    crate::ntlm::crypto::parse_av_pairs(data)
}

/// Decode UTF-16-LE bytes, replacing unpaired surrogates.
pub fn from_utf16le(data: &[u8]) -> String {
    crate::ntlm::crypto::from_utf16le(data)
}

/// Encode a `str` as UTF-16-LE bytes.
pub fn to_utf16le(s: &str) -> Vec<u8> {
    crate::ntlm::crypto::to_utf16le(s)
}

/// NTOWFv1: MD4 of the UTF-16-LE password.
pub fn compute_nt_hash(password: &str) -> [u8; 16] {
    crate::ntlm::crypto::compute_nt_hash(password)
}

/// NTOWFv2: HMAC-MD5 over uppercased user + domain.
pub fn compute_ntlmv2_hash(nt_hash: &[u8; 16], username: &str, domain: &str) -> [u8; 16] {
    crate::ntlm::crypto::compute_ntlmv2_hash(nt_hash, username, domain)
}

/// Build the NTLMv2 client blob (MS-NLMP 3.3.2).
pub fn build_ntlmv2_blob(
    timestamp: &[u8; 8],
    client_challenge: &[u8; 8],
    target_info: &[u8],
) -> Vec<u8> {
    crate::ntlm::crypto::build_ntlmv2_blob(timestamp, client_challenge, target_info)
}

/// Compute the `tls-server-end-point` channel binding token from a DER cert.
pub fn compute_channel_bindings(cert_der: &[u8]) -> [u8; 16] {
    crate::ntlm::crypto::compute_channel_bindings(cert_der)
}

pub fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    crate::ntlm::crypto::hmac_md5(key, data)
}

/// Run RC4 over `data` in place with `key`.
///
/// # Panics
///
/// Panics if `key` is empty — the in-crate callers always pass a 16-byte
/// derived sealing key, so the fuzz harness must uphold the same invariant.
pub fn rc4_process(key: &[u8], data: &mut [u8]) {
    crate::ntlm::crypto::Rc4State::new(key).process(data);
}

// ---------------------------------------------------------------------------
// SOAP — response parsing (`src/soap/parser.rs`)
// ---------------------------------------------------------------------------

pub use crate::soap::ReceiveOutput;

pub fn parse_shell_id(xml: &str) -> Result<String, SoapError> {
    crate::soap::parser::parse_shell_id(xml)
}

pub fn parse_command_id(xml: &str) -> Result<String, SoapError> {
    crate::soap::parser::parse_command_id(xml)
}

pub fn parse_receive_output(xml: &str) -> Result<ReceiveOutput, SoapError> {
    crate::soap::parser::parse_receive_output(xml)
}

pub fn check_soap_fault(xml: &str) -> Result<(), SoapError> {
    crate::soap::parser::check_soap_fault(xml)
}

/// Parse a WS-Enumeration `Enumerate`/`Pull` response.
pub fn parse_enumerate_response(xml: &str) -> Result<(String, Option<String>), SoapError> {
    crate::soap::parser::parse_enumerate_response(xml)
}

// ---------------------------------------------------------------------------
// SOAP — envelope construction (`src/soap/envelope.rs`)
// ---------------------------------------------------------------------------

/// Escape the five XML predefined entities.
pub fn xml_escape(s: &str) -> String {
    crate::soap::envelope::xml_escape(s)
}

pub fn create_shell_request(endpoint: &str, config: &crate::config::WinrmConfig) -> String {
    crate::soap::envelope::create_shell_request(endpoint, config)
}

pub fn execute_command_request(
    endpoint: &str,
    shell_id: &str,
    command: &str,
    args: &[&str],
    timeout_secs: u64,
    max_envelope_size: u32,
) -> String {
    crate::soap::envelope::execute_command_request(
        endpoint,
        shell_id,
        command,
        args,
        timeout_secs,
        max_envelope_size,
    )
}

pub fn receive_output_request(
    endpoint: &str,
    shell_id: &str,
    command_id: &str,
    timeout_secs: u64,
    max_envelope_size: u32,
) -> String {
    crate::soap::envelope::receive_output_request(
        endpoint,
        shell_id,
        command_id,
        timeout_secs,
        max_envelope_size,
    )
}

pub fn signal_terminate_request(
    endpoint: &str,
    shell_id: &str,
    command_id: &str,
    timeout_secs: u64,
    max_envelope_size: u32,
) -> String {
    crate::soap::envelope::signal_terminate_request(
        endpoint,
        shell_id,
        command_id,
        timeout_secs,
        max_envelope_size,
    )
}

/// Delete carries the shell's own ResourceURI since 1.2.1 — a caller-supplied
/// string spliced into the header, so it is part of the injection surface.
pub fn delete_shell_request(
    endpoint: &str,
    shell_id: &str,
    resource_uri: &str,
    timeout_secs: u64,
    max_envelope_size: u32,
) -> String {
    crate::soap::envelope::delete_shell_request_for(
        endpoint,
        shell_id,
        resource_uri,
        timeout_secs,
        max_envelope_size,
    )
}

pub fn send_input_request(
    endpoint: &str,
    shell_id: &str,
    command_id: &str,
    data: &[u8],
    end_of_stream: bool,
    timeout_secs: u64,
    max_envelope_size: u32,
) -> String {
    crate::soap::envelope::send_input_request(
        endpoint,
        shell_id,
        command_id,
        data,
        end_of_stream,
        timeout_secs,
        max_envelope_size,
    )
}

pub fn enumerate_wql_request(
    endpoint: &str,
    wql_query: &str,
    wql_namespace: Option<&str>,
    timeout_secs: u64,
    max_envelope_size: u32,
) -> String {
    crate::soap::envelope::enumerate_wql_request(
        endpoint,
        wql_query,
        wql_namespace,
        timeout_secs,
        max_envelope_size,
    )
}

pub fn pull_request(
    endpoint: &str,
    enumeration_context: &str,
    timeout_secs: u64,
    max_envelope_size: u32,
) -> String {
    crate::soap::envelope::pull_request(
        endpoint,
        enumeration_context,
        timeout_secs,
        max_envelope_size,
    )
}

// ---------------------------------------------------------------------------
// Transport / transfer input validation
// ---------------------------------------------------------------------------

/// Strip scheme, userinfo, path and port from a caller-supplied host string.
pub fn sanitize_host(input: &str) -> String {
    crate::transport::sanitize_host(input)
}

/// Reject remote paths that are over-long or contain control characters.
pub fn validate_remote_path(path: &str) -> Result<(), WinrmError> {
    crate::transfer::validate_remote_path(path)
}

/// Escape a value for a PowerShell single-quoted string literal.
pub fn escape_ps_single_quoted(s: &str) -> String {
    crate::transfer::escape_ps_single_quoted(s)
}

// ---------------------------------------------------------------------------
// CredSSP ASN.1 / DER (`src/asn1.rs`)
// ---------------------------------------------------------------------------

#[cfg(feature = "credssp")]
pub use crate::asn1::TsRequest;

/// Decode a CredSSP `TSRequest` (MS-CSSP 2.2.1) from DER.
#[cfg(feature = "credssp")]
pub fn decode_ts_request(data: &[u8]) -> Result<TsRequest, crate::error::CredSspError> {
    crate::asn1::decode_ts_request(data)
}

/// Encode a CredSSP `TSRequest`.
#[cfg(feature = "credssp")]
pub fn encode_ts_request(
    version: u32,
    nego_token: Option<&[u8]>,
    pub_key_auth: Option<&[u8]>,
    auth_info: Option<&[u8]>,
    client_nonce: Option<&[u8]>,
) -> Vec<u8> {
    crate::asn1::encode_ts_request(version, nego_token, pub_key_auth, auth_info, client_nonce)
}

/// Encode `TSCredentials` (MS-CSSP 2.2.1.2).
#[cfg(feature = "credssp")]
pub fn encode_ts_credentials(domain: &str, username: &str, password: &str) -> Vec<u8> {
    crate::asn1::encode_ts_credentials(domain, username, password).to_vec()
}

/// Unwrap an SPNEGO token and return the inner NTLM message.
#[cfg(feature = "credssp")]
pub fn decode_spnego_token(data: &[u8]) -> Result<Vec<u8>, crate::error::CredSspError> {
    crate::asn1::decode_spnego_token(data)
}

/// Extract the `mechListMIC` from a SPNEGO `NegTokenResp`, if present.
#[cfg(feature = "credssp")]
pub fn decode_spnego_mech_list_mic(
    data: &[u8],
) -> Result<Option<Vec<u8>>, crate::error::CredSspError> {
    crate::asn1::decode_spnego_mech_list_mic(data)
}

/// Wrap an NTLM Type 1 in a SPNEGO `NegTokenInit`.
#[cfg(feature = "credssp")]
pub fn encode_spnego_init(ntlm_token: &[u8]) -> Vec<u8> {
    crate::asn1::encode_spnego_init(ntlm_token)
}

/// Wrap an NTLM Type 3 in a SPNEGO `NegTokenResp`.
#[cfg(feature = "credssp")]
pub fn encode_spnego_response(ntlm_token: &[u8], mech_list_mic: Option<&[u8]>) -> Vec<u8> {
    crate::asn1::encode_spnego_response(ntlm_token, mech_list_mic)
}

/// Pull the raw `subjectPublicKey` bit-string out of a DER certificate.
#[cfg(feature = "credssp")]
pub fn extract_subject_public_key(cert_der: &[u8]) -> Result<Vec<u8>, crate::error::CredSspError> {
    crate::asn1::extract_subject_public_key(cert_der)
}
