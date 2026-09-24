# Changelog

All notable changes to `smb2-client` will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
project adheres to [SemVer](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.5] — 2026-09-06

### Documentation

- Correct the Features section: the client offers SMB 2.0.2 + 2.1.0
  only (not "2.0.2 → 3.x"). SMB 3.x is not offered yet — the source
  comment in `msg::negotiate` already said so; the README overclaimed.
- Correct the signing claim: HMAC-SHA256 is exercised over the offered
  2.x dialects (live-validated). AES-CMAC / SP800-108 KDF code exists
  in `header.rs` (`sign_v3` / `kdf_signing_key`) but is not validated —
  the client never reaches that branch today because 3.x isn't offered.

No code changes.

## [0.2.4] — 2026-09-04

Convergence release: incorporates improvements from
[PR #1](https://github.com/icedracon/smb2-client/pull/1) by
[@g0h4n](https://github.com/g0h4n) (Quentin Texier) which was opened
2026-09-03 independently — the same weekend 0.2.3 was being finalized,
and covering the same feature (non-destructive `read_file` +
directory listing for read-only share walks such as SYSVOL). 0.2.3
shipped first; this 0.2.4 patch adopts the API-surface improvements
from that PR while preserving 0.2.3's hostile-input parser guards +
empty-name CREATE fix.

### Added
- **`pub const msg::FILE_DIRECTORY_INFORMATION: u8 = 0x01`** — the
  QUERY_DIRECTORY info-class byte is now discoverable at the module
  level for downstream callers building custom requests.
- **`pub fn msg::query_directory_output(msg) -> Result<Vec<u8>>`** —
  raw output-buffer extractor separate from the higher-level
  `parse_directory_info` decoder, useful when a caller wants to walk
  a non-FileDirectoryInformation info-class from the same wire
  framing. Bounds-checked; truncated response returns
  `SmbError::Truncated`, never panics.
- **`pub const status::OBJECT_PATH_NOT_FOUND: u32 = 0xC000_003A`** —
  distinct from `OBJECT_NAME_NOT_FOUND`; a CREATE against a nested
  share path returns this when a directory component of the prefix
  does not exist.

### Changed
- **`SmbClient::read_file` ACCESS mask broadened** from
  `0x0010_0081` (READ_DATA + READ_ATTRS + SYNCHRONIZE) to
  `0x0012_0089` (adds READ_EA + READ_CONTROL). Matches what the
  Windows SMB client canonically requests for a plain-file open;
  avoids servers that reject the narrower mask.
- **`SmbClient::read_file` SHARE mask broadened** from `0x0000_0001`
  (R) to `0x0000_0007` (R+W+D). Allows concurrent writers, matching
  `smbclient` / other well-known clients. Downstream callers that
  need stricter deny-on-write semantics can open the file with the
  lower-level primitives directly.

### Credit
Thanks to [@g0h4n](https://github.com/g0h4n) for the parallel PR #1
which motivated these API improvements. The PR is closed as
superseded by 0.2.3 + this 0.2.4 convergence patch; future
contributions welcome.

## [0.2.3] — 2026-09-04

### Added
- **`SmbClient::list_directory(path) -> Vec<msg::DirEntry>`** — SMB2
  QUERY_DIRECTORY (FileDirectoryInformation class 1); drains entries
  until STATUS_NO_MORE_FILES; filters `.` and `..`. Bounds- and
  loop-bounded parser: attacker-controlled `NextEntryOffset` that
  fails to strictly advance ends the walk (0-cycle guard); a
  `FileNameLength` overrunning its record skips the entry; a
  truncated response fixed part returns empty rather than panicking
  through the direct-indexing helpers.
- **`SmbClient::read_file(path) -> Vec<u8>`** — non-destructive
  companion to the existing `read_file_delete`. Opens read-only
  (no DELETE_ON_CLOSE), reads to EOF in 64 KiB chunks. Fails
  immediately if the file is absent.
- **`msg::DirEntry { name, is_dir, size }`** — decoded entry type.
- **`cmd::QUERY_DIRECTORY = 0x000E`** + **`status::NO_MORE_FILES`** +
  **`msg::query_directory_req`** + **`msg::parse_directory_info`**.

### Fixed
- **`msg::create_file` empty-name (share-root) open.** Server 2025
  returned STATUS_INVALID_PARAMETER on a 57-byte CREATE whose name
  buffer was absent. Fix: `NameOffset` still points at the buffer
  position, and the variable buffer is always present (≥1 byte)
  even when the name is empty. `list_directory("")` (open share
  root) now works against modern Windows.

## [0.2.2] — 2026-09-03

### Added
- **`SmbClient::login_null(host)`** — anonymous IPC$ session
  (`""` / `""` / `""` NTLMv2 null bind). On DCs that still permit
  anonymous IPC$ (`RestrictAnonymous=0`) yields a session usable
  for SAMR / LSAT enum + share listing; on hardened DCs (2019+
  default) the server returns `STATUS_ACCESS_DENIED` /
  `STATUS_LOGON_FAILURE` and the caller reports the box as
  hardened. No signing key results from an anonymous logon.

## [0.2.1] — 2026-08-06

### Added
- `TCP_NODELAY` on the SMB2 transport socket — reduces round-trip
  latency for the many-small-PDU workloads dcerpc drives.

### Changed
- Trimmed the `reg save` polling timeout to 3 s (was longer) — SMB
  `C$` hive-file read polls fail faster on hardened DCs where the
  save silently never completes.

## [0.2.0] — 2026-08-02

### Added
- **Optional SOCKS5 egress** for all SMB dials. `SmbClient::connect`
  routes through an upstream proxy when the `SOCKS5_PROXY` env is
  set, so downstream `dcerpc` clients (RPC over TCP + SMB named
  pipes) pivot cleanly through a compromised jump host.

## [0.1.0] — 2026-07-28

Initial release: minimal async SMB2 client (dialect 2.1.0) in pure Rust.

### Added
- SMB2 negotiate + NTLMv2 (SPNEGO / GSSAPI) session setup.
- Tree connect to `IPC$`.
- Named-pipe open / read / write / close on IPC$ pipes (`\lsarpc`,
  `\samr`, `\srvsvc`, `\wkssvc`, `\atsvc`, `\winreg`, ...).
- rustls default (no OpenSSL dependency) for fully-static musl builds.
- Live-validated against Server 2016 / 2019 / 2022 / 2025.
