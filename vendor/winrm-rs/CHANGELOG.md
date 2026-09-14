# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.2.2] - 2026-09-04

CredSSP shipped in 1.2.1; this one makes PSRP shells disconnectable. Found by
driving `psrp-rs` disconnect/reconnect against a live Server 2025 and diffing
the WS-Management traffic against pypsrp on the same host.

### Fixed

- **Shells were created without a `wsmv:SessionId`, so Windows refused to
  disconnect them.** Server 2025 answered every Disconnect with
  `InternalError: This WinRS shell instance does not support disconnect and
  reconnect operations because it was created by an older WinRS client`.
  Windows binds a shell to the session that created it: strip the SessionId
  from the Create alone (measured against a pypsrp reference on the same host)
  and Disconnect is refused exactly this way; keep it on the Create but drop
  it from the follow-ups and every follow-up is refused with 0x8033810F
  (`does not contain a valid SessionID element`). The transport now stamps one
  `wsmv:SessionId` per client on **every** request, injected at the send
  chokepoint rather than threaded through the 19 envelope builders. Verified
  live: all 51 integration tests still pass with the header on every request.
  (`src/transport.rs`, `src/soap/envelope.rs`)

- **Disconnect recycled the operation timeout as the shell idle timeout, which
  Windows rejects.** The body sent `<rsp:IdleTimeOut>PT20S</rsp:IdleTimeOut>`,
  and the server answered `The requested IdleTimeout of 20000 is outside the
  allowed range. Specify an IdleTimeout value between 60000 and 2147483647`.
  The Disconnect body is now the bare `<rsp:Disconnect/>` — the shell keeps the
  idle timeout it was created with, matching pypsrp. (`src/soap/envelope.rs`)

## [1.2.1] - 2026-09-04

Three fixes, all found by running the crate against live Windows hosts —
Server 2012 R2 and Server 2025 — rather than by reading it. Two are
shell-lifecycle leaks: each one leaks a server-side shell per occurrence, and
they accumulate silently against `MaxShellsPerUser` (30 by default). Past that
ceiling every `Create` fails with `InternalError`, which reads like a broken
host: the symptom appears long after the cause, on an operation that is not at
fault. The third is the bug that kept CredSSP from ever completing.

### Fixed

- **Delete addressed a shell under the wrong ResourceURI, so PSRP shells were
  never released.** `soap::envelope::delete_shell_request` built its header
  with `build_header`, which hardcodes `RESOURCE_URI_CMD`. Create, Receive,
  Send and Signal all carry the shell's own ResourceURI; Delete was the one
  operation that did not. A PSRP shell deleted under the `cmd` URI makes the
  server answer `InvalidSelectors: the shell was not found on the server` —
  and leave the PowerShell shell running. Measured on a live host: 28 orphans
  after one test campaign, at which point the server refused every new shell.
  `Shell::close` now passes the URI the shell was created with, through the
  new `WinrmClient::delete_shell_with_resource_uri`. (`src/soap/envelope.rs`,
  `src/client.rs`, `src/shell.rs`)

- **A failed `Shell::disconnect` abandoned the shell.** `disconnect` takes
  `self` and set `closed = true` before sending the request, so an error
  destroyed the only handle to a shell that was still running — and `Drop`
  cannot delete it, being synchronous. The WinRS PowerShell plugin rejects
  Disconnect on both Server 2012 R2 and Server 2025, so this leaked on every
  attempt. The shell is now deleted before the original error is surfaced.
  (`src/shell.rs`)

- **CredSSP: `pubKeyAuth` was sealed at the wrong RC4 keystream position, so
  every handshake died at step 6 with a bare 401.** Windows SPNEGO computes
  the NTLM `mechListMIC` with GSS_GetMIC — 8 bytes of keystream, one sequence
  number — and then re-initialises the RC4 sealing handle, keeping only the
  sequence number; pyspnego mirrors this (`_reset_ntlm_crypto_state`). Our
  `NtlmSession` kept the keystream running, so `pubKeyAuth` went out at
  offset 8 with seq 1: the server decrypted garbage, dropped the context and
  answered `401` with a token-less `WWW-Authenticate: CredSSP`. Found with a
  byte-for-byte differential against pyspnego 0.12.1 on identical inputs
  (fixed client challenge, session key and nonce): Type 1/2/3, mechListMIC,
  SubjectPublicKey and the client hash all matched; only the sealed
  `pubKeyAuth` differed. `NtlmSession::sign_mech_list_mic` now resets the
  client handle after signing; `verify_mech_list_mic` checks the server's
  mechListMIC (previously ignored) and resets the server handle, so the
  `pubKeyAuth` echo unseals at server seq 1. The plain NTLM-over-HTTP sealing
  path is untouched. `credssp_run_command_whoami` passes against Server 2025
  and no longer needs `WINRM_TEST_CREDSSP=1`.
  (`src/ntlm/mod.rs`, `src/asn1.rs`, `src/auth/credssp.rs`)

- **`__internal` builds (fuzz targets, `tests/proptest_wire_format.rs`) did not
  compile.** The `delete_shell_request` rename above left the `__fuzz` wrapper
  behind. It now forwards to `delete_shell_request_for`, and the fuzzed
  ResourceURI is part of `fuzz_soap_envelope`'s injection invariant, since it
  is caller-supplied from this release on. (`src/__fuzz.rs`,
  `fuzz/fuzz_targets/fuzz_soap_envelope.rs`)

### Testing

- The live suite now runs against a Windows Server 2025 bench as well as the
  2012 R2 one. That second bench is what the HTTPS and CBT tests need:
  Server 2012 R2 pairs GCM only with static-RSA key exchange and offers CBC
  with ECDHE, so rustls has no cipher suite in common with a default 2012 R2
  listener and the handshake ends in EOF there. (The `Vagrantfile`s and
  `vm-*.sh` helpers stay untracked, as they have been since `b342a7c`.)
- Four tests in `tests/integration_real.rs` now skip with an explicit reason
  rather than failing: three HTTPS ones and `run_powershell_unicode` on
  Server 2012 R2 (PowerShell 4.0 ignores `[Console]::OutputEncoding` under
  `-EncodedCommand`, so non-ASCII returns in the OEM code page).
- `credssp_run_command_whoami` runs unconditionally against Server 2025 and
  passes; `fuzz_asn1_spnego` also covers `decode_spnego_mech_list_mic`.

## [1.2.0] - 2026-09-03

### Security

- **XML injection via `ResourceURI`** — `soap::envelope::build_header_for`
  interpolated the resource URI into `<wsman:ResourceURI>` without escaping.
  The URI is caller-influenced: `run_wql` splices the WMI namespace into it
  and the PSRP builders take a configuration name, so a namespace containing
  markup could add elements to the outgoing SOAP header. Now escaped like
  every other interpolated value. Found while auditing the interpolation
  sites to write the `fuzz_soap_envelope` invariant, which now guards it.
  (`src/soap/envelope.rs`)

### Fixed

- **DER length truncation** — `asn1::encode_length` fell back to the 3-byte
  form for any length, silently dropping the high bits above 16 MiB and
  emitting a TLV whose declared length was wrong. It now emits the 4-byte
  form. `decode_length` deliberately keeps its 3-byte cap, which bounds what
  a hostile CredSSP server can declare. (`src/asn1.rs`)
- **CredSSP `TSRequest` carrying an NTSTATUS error code failed to decode** —
  `asn1::decode_integer` rejected any DER INTEGER longer than 4 bytes,
  including the 5-byte sign-padded form a value with the high bit set must
  use. NTSTATUS codes are exactly that shape, so a `TSRequest` whose
  `errorCode` was, say, `0xC000006A` (`STATUS_LOGON_FAILURE`) — the response
  a Windows CredSSP server sends on a rejected logon — failed to parse
  outright, and the real failure reason surfaced as an ASN.1 decode error
  instead. The same asymmetry meant the codec could not read back its own
  output for any `version` or `errorCode` at or above `0x8000_0000`. A single
  leading `0x00` sign pad is now stripped before the 4-byte magnitude cap is
  applied; the `u32` overflow guard is unchanged. (`src/asn1.rs`)

### Changed

- **MSRV raised to 1.98.0** (from 1.94.0). CI toolchain pins, the MSRV job and
  `clippy.toml` follow.
- Dependencies refreshed: `base64` 0.22 → 0.23, `x509-cert` 0.2 → 0.3
  (`der` 0.7 → 0.8, `spki` 0.7 → 0.8), plus `tokio` 1.53.1, `hyper` 1.11.1,
  `rustls` 0.23.43, `uuid` 1.26, `http` 1.5, `thiserror` 2.0.20 and the rest
  of the lockfile.
- **Fuzzing expanded from 5 to 18 libFuzzer targets**, now covering the
  CredSSP DER decoder, SPNEGO token unwrapping, X.509 public-key extraction,
  `AV_PAIR` parsing, the `WWW-Authenticate` header path, Type 3 construction,
  multi-message sealing, envelope construction, `xml_escape`, host
  sanitisation and remote-path quoting. Targets assert protocol invariants
  rather than only absence of panics. Adds per-surface dictionaries, a
  committed seed corpus, `scripts/fuzz.sh`, and a nightly campaign workflow.
  See [`fuzz/README.md`](fuzz/README.md).
- Crate internals reach the fuzz targets through a new `#[doc(hidden)]`
  `winrm_rs::__fuzz` module behind the existing `__internal` feature, instead
  of ad-hoc re-exports at the crate root. Not part of the public API.

## [1.1.2] - 2026-05-10

### Fixed

- **macOS test flake** — `run_command_with_cancel` /
  `run_powershell_with_cancel` on both `WinrmClient` and `Shell` now
  short-circuit with `WinrmError::Cancelled` when entered with a
  pre-cancelled token. Previously the `tokio::select!` arm order was
  non-deterministic across platforms; on macOS the inner request
  future could surface a transport error before the cancel arm ran.
  Wire semantics unchanged. (`src/client.rs`, `src/shell.rs`)

## [1.1.1] - 2026-05-10

### Security

- **CRITICAL** — Three NTLM/CredSSP RNG-override env-var test backdoors
  (`CREDSSP_FIXED_CC`, `CREDSSP_FIXED_RSK`, `CREDSSP_FIXED_NONCE`) are
  now gated behind `cfg(debug_assertions)`. Release binaries always use
  the CSPRNG, so a hostile environment can no longer collapse the NTLMv2
  client challenge, the random session key, or the CredSSP-v6 pubKeyAuth
  nonce to deterministic values. (`src/ntlm/messages.rs`,
  `src/auth/credssp.rs`)
- **CRITICAL** — Three secret-dumping env-var debug backdoors
  (`CREDSSP_DEBUG`, `CREDSSP_DUMP`, `SSLKEYLOGFILE`) are now gated
  behind `cfg(debug_assertions)`. Release binaries strip the
  `eprintln!` / `KeyLogFile` paths entirely, so support tickets and
  rogue env vars can no longer exfiltrate `nt_proof_str`,
  `session_base_key`, `exported_session_key`, MIC, or the outer-TLS
  master secret. (`src/ntlm/messages.rs`, `src/auth/credssp.rs`)
- **CRITICAL** — `NtlmSession` and `Rc4State` now derive
  `Zeroize + ZeroizeOnDrop`. Sealing/signing keys and the 256-byte RC4
  S-box are wiped from memory when the session drops, closing the
  compiler-confirmed gap (5 OPTIMIZED_AWAY_ZEROIZE / 1 STACK_RETENTION /
  9 REGISTER_SPILL findings at -O2). (`src/ntlm/mod.rs`,
  `src/ntlm/crypto.rs`)
- **HIGH** — `create_authenticate_message_*` now return
  `Zeroizing<[u8; 16]>` for the exported session key, so the caller's
  stack slot is wiped on drop instead of surviving compiler
  optimisation. Wire bytes unchanged; only the Rust return type
  changes. (`src/ntlm/messages.rs`, `src/auth/ntlm.rs`,
  `src/auth/credssp.rs`)
- **MEDIUM** — `compute_ntlmv2_hash` wraps the `format!`-built identity
  string and its UTF-16-LE encoding in `Zeroizing`, removing two
  un-zeroed heap allocations of (uppercase) username + domain.
  (`src/ntlm/crypto.rs`)
- **MEDIUM** — Type-3 `target_info` clone is now `Zeroizing<Vec<u8>>`;
  the buffer feeds into the NTLMv2 transcript HMAC and so is part of
  the cryptographic state. (`src/ntlm/messages.rs`)
- **LOW** — Unconditional `eprintln!` of the negotiated CredSSP
  version replaced with `tracing::debug!`. (`src/auth/credssp.rs`)
- **LOW** — `parse_receive_response` now emits `tracing::warn` when
  the server returns an `<ExitCode>` element with unparseable text,
  surfacing a previously silent fail-soft branch that callers gating
  on exit code could not distinguish from "command still running".
  (`src/soap/parser.rs`)
- **CRITICAL** — CredSSP outer TLS now validates the server certificate
  chain by default. Previously the outer HTTPS leg used a hardcoded
  `NoVerifier`, making the channel that carries CredSSP TSRequests
  vulnerable to MITM. The inner CredSSP TLS continues to use
  `SslVerifyMode::NONE` because authentication is provided by
  `pubKeyAuth` (MS-CSSP §3.1.5.1), which the client now also documents
  inline. (`src/auth/credssp.rs`)
- **HIGH** — Kerberos mutual authentication failures are now propagated.
  Previously `ctx.step(server_token)` was assigned to `_`, so a forged
  or missing server token silently passed. (`src/auth/kerberos.rs`)
- **HIGH** — Basic auth credentials are now stored in `SecretString` and
  built inside a `Zeroizing` buffer, ensuring the cleartext is wiped
  from heap memory immediately after base64-encoding. (`src/auth/basic.rs`)
- **HIGH** — NTLM CBT fallback (cert capture None while TLS active) now
  emits a `tracing::warn` so operators can detect silent regression to
  non-CBT auth. (`src/auth/ntlm.rs`)
- **MEDIUM** — `WinrmConfig.max_output_bytes` (new field, default 64
  MiB) caps cumulative stdout+stderr per command, preventing OOM via a
  malicious server streaming an unbounded base64 chunk sequence. Set to
  `None` to restore unbounded behaviour. (`src/config.rs`, `src/shell.rs`,
  `src/client.rs`)
- **MEDIUM** — NTLM unseal HMAC-MD5 comparison switched to
  `subtle::ConstantTimeEq`. (`src/ntlm/mod.rs`)
- **MEDIUM** — ASN.1 `decode_integer` rejects DER INTEGER payloads of
  length 0 or > 4 bytes, preventing silent u32 overflow on hostile
  TSRequests. (`src/asn1.rs`)
- **MEDIUM** — Type 2 NTLM challenge `target_info` parse now uses
  `checked_add` for offset+length bounds (32-bit safety).
  (`src/ntlm/messages.rs`)
- **MEDIUM** — HTTP redirects are no longer followed
  (`Policy::none()`); a 30x from the WinRM endpoint surfaces as an
  error rather than risking Authorization-header forwarding.
  Construction also emits `tracing::warn` when
  `accept_invalid_certs=true`. (`src/transport.rs`)
- **MEDIUM** — `encode_ts_credentials` returns `Zeroizing<Vec<u8>>`;
  intermediate plaintext credential buffers are wiped after CredSSP
  seal. (`src/asn1.rs`)
- **MEDIUM** — `endpoint()` sanitises the host argument (strips
  scheme / userinfo / path / port; preserves IPv6 literals) and logs a
  WARN when it had to clean anything. (`src/transport.rs`)
- **LOW** — PSRP Create envelope now `xml_escape`s the ShellId
  defensively. (`src/soap/envelope.rs`)
- **LOW** — `CertCapturingVerifier` logs an error when the mutex is
  poisoned, instead of silently dropping the captured cert.
  (`src/tls.rs`)
- **DEPS** — `cargo update -p rustls-webpki` (0.103.10 → 0.103.13)
  closes RUSTSEC-2026-0098, -0099, -0104.

### Added

- New dev-test `tests/security_regression.rs` pins HTTP redirect
  refusal as a public-API behaviour.
- New dev-test `tests/proptest_wire_format.rs` (gated on the
  `__internal` feature) anchors NTLM signature, base64 PowerShell
  encoding, and SOAP-fault detector invariants with `proptest`.
- `subtle 2.6` dependency (already present transitively through
  rustls/ring; promoted to a direct dep for the constant-time HMAC
  compare).
- `proptest 1` dev-dependency.
- `zeroize` direct dep now uses the `derive` feature for
  `#[derive(ZeroizeOnDrop)]` on `NtlmSession` and `Rc4State`.

### Changed

- `WinrmConfig.accept_invalid_certs` doc comment now includes a
  `# Security` section explicitly stating the flag also disables CredSSP
  outer-TLS verification.

## [1.0.0] - 2026-04-12

### Highlights

First stable release. The public API (`WinrmClient`, `WinrmConfig`,
`WinrmCredentials`, `Shell`, `CommandOutput`, `WinrmError`) is now
considered stable and covered by SemVer guarantees.

### Breaking (relative to 0.5.0)

- Public surface reduced. The following items are no longer re-exported
  from the crate root and are now crate-internal:
  `create_authenticate_message_with_key`, `parse_challenge`,
  `parse_shell_id`, `parse_command_id`, `parse_receive_output`,
  `check_soap_fault`. They remain accessible to fuzz targets via the
  internal-only `__internal` feature (not part of the SemVer contract).

### Changed

- CredSSP (`--features credssp`) is now explicitly marked **experimental**
  in the crate docs and README. The handshake is not yet validated
  end-to-end; do not rely on it in production.

### Documentation

- `lib.rs` now documents the purpose of the `secrecy::SecretString` /
  `ExposeSecret` and `tokio_util::sync::CancellationToken` re-exports.
- README documents integration-test environment variables
  (`WINRM_TEST_HOST`, `WINRM_TEST_USER`, `WINRM_TEST_PASS`,
  `WINRM_TEST_PORT`) and how to invoke them.
- `Cargo.toml` now explains why `credssp` needs `openssl` (Microsoft
  CredSSP server incompatibility with `rustls` in-memory TLS).

## [0.5.0] - 2026-03-29

### Added

- File transfer: upload/download via PowerShell base64 chunking
- Streaming output: `start_command` + `receive_next` for incremental polling
- HTTP proxy support for all WinRM requests
- CI pipeline with fmt, clippy, test (Linux/macOS/Windows), coverage, doc, MSRV, audit, deny, fuzz, semver checks
- Integration tests for real WinRM endpoints
- Fuzz targets for NTLM, SOAP, and PowerShell encoding
- Release automation via GitHub Actions

## [0.4.0]

### Added

- Kerberos authentication via `cross-krb5` (feature-gated with `--features kerberos`)
- Certificate authentication (TLS client certificate)

## [0.3.0]

### Added

- NTLM sealing (message encryption)
- Credential security with `secrecy` and `zeroize`
- Retry with exponential backoff for transient HTTP errors

## [0.2.0]

### Added

- Shell reuse across multiple commands
- Stdin piping support

## [0.1.0]

### Added

- NTLMv2 authentication (pure Rust, no OpenSSL)
- Basic authentication
- PowerShell command execution (UTF-16LE Base64 encoded)
- Raw command execution (`cmd.exe` or any executable)
- Full shell lifecycle: create, execute, receive, signal, delete

[Unreleased]: https://github.com/muchiny/winrm-rs/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/muchiny/winrm-rs/compare/v1.1.2...v1.2.0
[1.1.2]: https://github.com/muchiny/winrm-rs/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/muchiny/winrm-rs/compare/v1.0.0...v1.1.1
[1.0.0]: https://github.com/muchiny/winrm-rs/compare/v0.5.0...v1.0.0
[0.5.0]: https://github.com/muchiny/winrm-rs/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/muchiny/winrm-rs/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/muchiny/winrm-rs/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/muchiny/winrm-rs/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/muchiny/winrm-rs/releases/tag/v0.1.0
