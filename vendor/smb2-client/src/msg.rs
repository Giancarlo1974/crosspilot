//! SMB2 request bodies and response parsers (MS-SMB2 §2.2). Offsets in the on-wire
//! `*Offset` fields are measured from the start of the SMB2 header (i.e. `64 + body_off`).

use crate::{Result, SmbError};

fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}
fn u16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn u32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

// ---- NEGOTIATE (§2.2.3) ---------------------------------------------------

/// Offer dialect 2.1.0 with a random client GUID.
pub fn negotiate(client_guid: &[u8; 16]) -> Vec<u8> {
    // Offer SMB 2.0.2 (Server 2008/R2) and 2.1.0. The server picks the highest it supports and
    // negotiates *down*, so this reaches 2008 through 2025 (2012/2016/2019/2022/2025 all accept
    // 2.1.0 — validated live against Server 2025). Both sign with HMAC-SHA256.
    //
    // SMB 3.0.x (AES-CMAC) support exists in header.rs (sign_v3 / kdf_signing_key) and the
    // client branches on the negotiated dialect, but 3.x is not offered yet — it's only needed
    // for servers hardened to refuse SMB2 entirely, and the CMAC path isn't validated.
    let dialects: [u16; 2] = [0x0202, 0x0210];
    let mut b = Vec::new();
    b.extend_from_slice(&36u16.to_le_bytes()); // StructureSize
    b.extend_from_slice(&(dialects.len() as u16).to_le_bytes()); // DialectCount
    b.extend_from_slice(&0x0001u16.to_le_bytes()); // SecurityMode = SIGNING_ENABLED
    b.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    b.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
    b.extend_from_slice(client_guid);
    b.extend_from_slice(&0u64.to_le_bytes()); // ClientStartTime
    for dialect in dialects {
        b.extend_from_slice(&dialect.to_le_bytes());
    }
    b
}

// ---- SESSION_SETUP (§2.2.5 / §2.2.6) --------------------------------------

/// The security buffer holds a raw NTLMSSP token.
pub fn session_setup(token: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&25u16.to_le_bytes()); // StructureSize
    b.push(0); // Flags
    b.push(0x01); // SecurityMode = SIGNING_ENABLED
    b.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
    b.extend_from_slice(&0u32.to_le_bytes()); // Channel
    let sec_off = 64u16 + 24; // header + fixed part
    b.extend_from_slice(&sec_off.to_le_bytes()); // SecurityBufferOffset
    b.extend_from_slice(&(token.len() as u16).to_le_bytes()); // SecurityBufferLength
    b.extend_from_slice(&0u64.to_le_bytes()); // PreviousSessionId
    b.extend_from_slice(token);
    b
}

/// Extract the security buffer (server NTLM token) from a SESSION_SETUP response.
pub fn session_setup_token(msg: &[u8]) -> Result<Vec<u8>> {
    // body starts at 64; StructureSize(2), SessionFlags(2), SecBufOffset(2), SecBufLength(2)
    let body = msg.get(64..).ok_or(SmbError::Truncated)?;
    let off = u16(body, 4) as usize; // from SMB header start
    let len = u16(body, 6) as usize;
    msg.get(off..off + len)
        .map(|s| s.to_vec())
        .ok_or(SmbError::Truncated)
}

// ---- TREE_CONNECT (§2.2.9) ------------------------------------------------

pub fn tree_connect(path: &str) -> Vec<u8> {
    let name = utf16le(path);
    let mut b = Vec::new();
    b.extend_from_slice(&9u16.to_le_bytes()); // StructureSize
    b.extend_from_slice(&0u16.to_le_bytes()); // Reserved/Flags
    let path_off = 64u16 + 8;
    b.extend_from_slice(&path_off.to_le_bytes()); // PathOffset
    b.extend_from_slice(&(name.len() as u16).to_le_bytes()); // PathLength
    b.extend_from_slice(&name);
    b
}

// ---- CREATE (§2.2.13 / §2.2.14) -------------------------------------------

/// Open a named pipe (e.g. "samr") on the IPC$ tree.
pub fn create_pipe(name: &str) -> Vec<u8> {
    let n = utf16le(name);
    let mut b = Vec::new();
    b.extend_from_slice(&57u16.to_le_bytes()); // StructureSize
    b.push(0); // SecurityFlags
    b.push(0); // RequestedOplockLevel
    b.extend_from_slice(&2u32.to_le_bytes()); // ImpersonationLevel = Impersonation
    b.extend_from_slice(&0u64.to_le_bytes()); // SmbCreateFlags
    b.extend_from_slice(&0u64.to_le_bytes()); // Reserved
    b.extend_from_slice(&0x0012_019Fu32.to_le_bytes()); // DesiredAccess: read+write data/EA/attrs (WRITE needs FILE_WRITE_DATA for a fire-and-forget AUTH3)
    b.extend_from_slice(&0u32.to_le_bytes()); // FileAttributes
    b.extend_from_slice(&0x0000_0007u32.to_le_bytes()); // ShareAccess = R|W|D
    b.extend_from_slice(&0x0000_0001u32.to_le_bytes()); // CreateDisposition = OPEN
    b.extend_from_slice(&0u32.to_le_bytes()); // CreateOptions
    let name_off = 64u16 + 56;
    b.extend_from_slice(&name_off.to_le_bytes()); // NameOffset
    b.extend_from_slice(&(n.len() as u16).to_le_bytes()); // NameLength
    b.extend_from_slice(&0u32.to_le_bytes()); // CreateContextsOffset
    b.extend_from_slice(&0u32.to_le_bytes()); // CreateContextsLength
    b.extend_from_slice(&n);
    b
}

/// Generic disk-file CREATE (§2.2.13). `path` is relative to the connected share root (no
/// leading backslash). Callers pass the access mask, share mode, disposition, and options.
pub fn create_file(path: &str, access: u32, share: u32, disposition: u32, options: u32) -> Vec<u8> {
    let n = utf16le(path);
    let mut b = Vec::new();
    b.extend_from_slice(&57u16.to_le_bytes()); // StructureSize
    b.push(0); // SecurityFlags
    b.push(0); // RequestedOplockLevel
    b.extend_from_slice(&2u32.to_le_bytes()); // ImpersonationLevel = Impersonation
    b.extend_from_slice(&0u64.to_le_bytes()); // SmbCreateFlags
    b.extend_from_slice(&0u64.to_le_bytes()); // Reserved
    b.extend_from_slice(&access.to_le_bytes()); // DesiredAccess
    b.extend_from_slice(&0u32.to_le_bytes()); // FileAttributes (ignored on OPEN)
    b.extend_from_slice(&share.to_le_bytes()); // ShareAccess
    b.extend_from_slice(&disposition.to_le_bytes()); // CreateDisposition
    b.extend_from_slice(&options.to_le_bytes()); // CreateOptions

    // NameOffset always points at the buffer position, and the variable buffer
    // is always present (≥1 byte). Opening the share root (empty name) needs
    // NameLength=0 but a NameOffset that still addresses a real byte in the
    // message plus that mandatory padding byte — Windows returns
    // STATUS_INVALID_PARAMETER for a 57-byte body whose name buffer is absent.
    let name_off = 64u16 + 56;
    b.extend_from_slice(&name_off.to_le_bytes()); // NameOffset
    b.extend_from_slice(&(n.len() as u16).to_le_bytes()); // NameLength
    b.extend_from_slice(&0u32.to_le_bytes()); // CreateContextsOffset
    b.extend_from_slice(&0u32.to_le_bytes()); // CreateContextsLength
    if n.is_empty() {
        b.push(0); // mandatory 1-byte Buffer when there is no name
    } else {
        b.extend_from_slice(&n);
    }
    b
}

/// SMB2 READ (§2.2.19): read `length` bytes at `offset` from the open file.
pub fn read_req(file_id: &[u8; 16], offset: u64, length: u32) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&49u16.to_le_bytes()); // StructureSize
    b.push(0); // Padding
    b.push(0); // Flags
    b.extend_from_slice(&length.to_le_bytes()); // Length
    b.extend_from_slice(&offset.to_le_bytes()); // Offset
    b.extend_from_slice(file_id);
    b.extend_from_slice(&0u32.to_le_bytes()); // MinimumCount
    b.extend_from_slice(&0u32.to_le_bytes()); // Channel
    b.extend_from_slice(&0u32.to_le_bytes()); // RemainingBytes
    b.extend_from_slice(&0u16.to_le_bytes()); // ReadChannelInfoOffset
    b.extend_from_slice(&0u16.to_le_bytes()); // ReadChannelInfoLength
    b.push(0); // Buffer (min 1 byte)
    b
}

/// Extract the data returned by a READ response (§2.2.20).
pub fn read_output(msg: &[u8]) -> Result<Vec<u8>> {
    let body = msg.get(64..).ok_or(SmbError::Truncated)?;
    let data_off = *body.get(2).ok_or(SmbError::Truncated)? as usize; // DataOffset, from header start
    let data_len = u32(body, 4) as usize;
    msg.get(data_off..data_off + data_len)
        .map(|s| s.to_vec())
        .ok_or(SmbError::Truncated)
}

/// SMB2 WRITE (§2.2.21): write `data` to the open handle at `offset`.
pub fn write_req(file_id: &[u8; 16], offset: u64, data: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&49u16.to_le_bytes()); // StructureSize
    b.extend_from_slice(&(64u16 + 48).to_le_bytes()); // DataOffset (header + 48-byte body)
    b.extend_from_slice(&(data.len() as u32).to_le_bytes()); // Length
    b.extend_from_slice(&offset.to_le_bytes()); // Offset
    b.extend_from_slice(file_id);
    b.extend_from_slice(&0u32.to_le_bytes()); // Channel
    b.extend_from_slice(&0u32.to_le_bytes()); // RemainingBytes
    b.extend_from_slice(&0u16.to_le_bytes()); // WriteChannelInfoOffset
    b.extend_from_slice(&0u16.to_le_bytes()); // WriteChannelInfoLength
    b.extend_from_slice(&0u32.to_le_bytes()); // Flags
    b.extend_from_slice(data);
    b
}

/// SMB2 CLOSE (§2.2.15).
pub fn close_req(file_id: &[u8; 16]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&24u16.to_le_bytes()); // StructureSize
    b.extend_from_slice(&0u16.to_le_bytes()); // Flags
    b.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    b.extend_from_slice(file_id);
    b
}

/// FileId (16 bytes) from a CREATE response.
pub fn create_file_id(msg: &[u8]) -> Result<[u8; 16]> {
    // FileId sits at body offset 64 → absolute 128.
    msg.get(128..144)
        .map(|s| s.try_into().unwrap())
        .ok_or(SmbError::Truncated)
}

/// One entry from a directory enumeration (FileDirectoryInformation, class 1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
}

/// FileDirectoryInformation class (§2.4.10) — the classic
/// name+attrs+size directory-enumeration info-class. Exposed publicly
/// in 0.2.4 (adopted from g0h4n's PR #1) so downstream callers building
/// custom `query_directory_req`-shaped requests do not have to remember
/// the magic byte. Additional info classes (FileFullDirectoryInformation
/// class 2, FileBothDirectoryInformation class 3, etc.) can be added
/// alongside if needed.
pub const FILE_DIRECTORY_INFORMATION: u8 = 0x01;

/// Raw output-buffer extractor for a QUERY_DIRECTORY response (§2.2.34).
/// Returns the whole info-class buffer as bytes; callers that want the
/// higher-level `Vec<DirEntry>` decoding call [`parse_directory_info`]
/// instead. Adopted from g0h4n's PR #1 for 0.2.4 — useful when a caller
/// wants to walk a non-FileDirectoryInformation info-class from the same
/// wire framing. Bounds-checked: a truncated response returns
/// `SmbError::Truncated`, never panics through the direct-indexing
/// helpers.
pub fn query_directory_output(msg: &[u8]) -> Result<Vec<u8>> {
    let body = msg.get(64..).ok_or(SmbError::Truncated)?;
    if body.len() < 8 {
        return Err(SmbError::Truncated);
    }
    let off = u16(body, 2) as usize; // OutputBufferOffset, from header start
    let len = u32(body, 4) as usize; // OutputBufferLength
    msg.get(off..off.checked_add(len).ok_or(SmbError::Truncated)?)
        .map(|s| s.to_vec())
        .ok_or(SmbError::Truncated)
}

/// SMB2 QUERY_DIRECTORY (§2.2.33): enumerate an open directory handle using
/// FileDirectoryInformation (class 1). `pattern` is the search wildcard
/// (typically `*`); on continuation calls the server ignores it and resumes
/// from where the handle left off, so passing `*` every time is correct.
pub fn query_directory_req(file_id: &[u8; 16], pattern: &str, output_len: u32) -> Vec<u8> {
    let n = utf16le(pattern);
    let mut b = Vec::new();
    b.extend_from_slice(&33u16.to_le_bytes()); // StructureSize (fixed 33)
    b.push(FILE_DIRECTORY_INFORMATION); // FileInformationClass
    b.push(0); // Flags (0: resume from handle position)
    b.extend_from_slice(&0u32.to_le_bytes()); // FileIndex
    b.extend_from_slice(file_id);
    let name_off = 64u16 + 32; // header + 32-byte fixed body
    b.extend_from_slice(&name_off.to_le_bytes()); // FileNameOffset
    b.extend_from_slice(&(n.len() as u16).to_le_bytes()); // FileNameLength
    b.extend_from_slice(&output_len.to_le_bytes()); // OutputBufferLength
    if n.is_empty() {
        b.push(0); // Buffer min 1 byte
    } else {
        b.extend_from_slice(&n);
    }
    b
}

/// Parse a QUERY_DIRECTORY response (§2.2.34) carrying FileDirectoryInformation
/// entries. Bounds-checked and loop-bounded: a hostile server cannot drive an
/// out-of-range read or a non-terminating walk (a NextEntryOffset that fails to
/// advance, or an entry claiming a name longer than the buffer, ends parsing).
pub fn parse_directory_info(msg: &[u8]) -> Result<Vec<DirEntry>> {
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
    let body = msg.get(64..).ok_or(SmbError::Truncated)?;
    // Response fixed part: StructureSize(2), OutputBufferOffset(2), OutputBufferLength(4).
    // Guard its 8 bytes before the direct-indexing u16/u32 helpers touch them —
    // a truncated response must return empty, not panic.
    if body.len() < 8 {
        return Ok(Vec::new());
    }
    let out_off = u16(body, 2) as usize; // from header start
    let out_len = u32(body, 4) as usize;
    let buf = msg
        .get(out_off..out_off.checked_add(out_len).ok_or(SmbError::Truncated)?)
        .ok_or(SmbError::Truncated)?;

    let mut entries = Vec::new();
    let mut pos = 0usize;
    // Cap iterations well above any real directory to bound a malformed chain.
    for _ in 0..100_000 {
        let rec = match buf.get(pos..) {
            Some(r) if r.len() >= 64 => r,
            _ => break,
        };
        let next = u32(rec, 0) as usize; // NextEntryOffset
        let attrs = u32(rec, 56); // FileAttributes
        let name_len = u32(rec, 60) as usize; // FileNameLength (bytes)
                                              // FileName starts at fixed offset 64 within the record.
        if let Some(name_bytes) = rec.get(64..64usize.saturating_add(name_len)) {
            let units: Vec<u16> = name_bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            let name = String::from_utf16_lossy(&units);
            if name != "." && name != ".." && !name.is_empty() {
                entries.push(DirEntry {
                    name,
                    is_dir: attrs & FILE_ATTRIBUTE_DIRECTORY != 0,
                    size: u64::from_le_bytes(
                        rec.get(40..48)
                            .and_then(|s| s.try_into().ok())
                            .unwrap_or([0; 8]),
                    ),
                });
            }
        } else {
            break; // name overruns the record → stop, don't read OOB
        }
        if next == 0 {
            break; // last entry
        }
        // NextEntryOffset must strictly advance, else a hostile 0-cycle loops forever.
        pos = match pos.checked_add(next) {
            Some(p) if p > pos => p,
            _ => break,
        };
    }
    Ok(entries)
}

// ---- IOCTL (§2.2.31 / §2.2.32) --------------------------------------------

pub const FSCTL_PIPE_TRANSCEIVE: u32 = 0x0011_C017;

/// Send `input` through the pipe and read the response in one round trip.
pub fn ioctl_transceive(file_id: &[u8; 16], input: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&57u16.to_le_bytes()); // StructureSize
    b.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    b.extend_from_slice(&FSCTL_PIPE_TRANSCEIVE.to_le_bytes()); // CtlCode
    b.extend_from_slice(file_id);
    let input_off = 64u32 + 56;
    b.extend_from_slice(&input_off.to_le_bytes()); // InputOffset
    b.extend_from_slice(&(input.len() as u32).to_le_bytes()); // InputCount
    b.extend_from_slice(&0u32.to_le_bytes()); // MaxInputResponse
    b.extend_from_slice(&input_off.to_le_bytes()); // OutputOffset
    b.extend_from_slice(&0u32.to_le_bytes()); // OutputCount
    b.extend_from_slice(&0x0001_0000u32.to_le_bytes()); // MaxOutputResponse (64 KiB — SMB2.1 max transact)
    b.extend_from_slice(&0x0000_0001u32.to_le_bytes()); // Flags = IS_FSCTL
    b.extend_from_slice(&0u32.to_le_bytes()); // Reserved2
    b.extend_from_slice(input);
    b
}

/// Extract the pipe output (RPC response bytes) from an IOCTL response.
pub fn ioctl_output(msg: &[u8]) -> Result<Vec<u8>> {
    // response body: StructureSize(2) Reserved(2) CtlCode(4) FileId(16)
    // InputOffset(4) InputCount(4) OutputOffset(4) OutputCount(4) ...
    let body = msg.get(64..).ok_or(SmbError::Truncated)?;
    let out_off = u32(body, 32) as usize; // from SMB header start
    let out_len = u32(body, 36) as usize;
    msg.get(out_off..out_off + out_len)
        .map(|s| s.to_vec())
        .ok_or(SmbError::Truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiate_offers_dialect_210() {
        let b = negotiate(&[0; 16]);
        assert_eq!(u16(&b, 0), 36); // StructureSize
        assert_eq!(u16(&b, 2), 2); // DialectCount (2.0.2 + 2.1.0)
                                   // dialects at 36 (fixed part) — after 4+2+2+4+16+8 = 36
        assert_eq!(u16(&b, 36), 0x0202);
        assert_eq!(u16(&b, 38), 0x0210);
    }

    #[test]
    fn create_pipe_name_offset_correct() {
        let b = create_pipe("samr");
        assert_eq!(u16(&b, 0), 57);
        assert_eq!(u16(&b, 44), 64 + 56); // NameOffset field
        assert_eq!(u16(&b, 46), 8); // "samr" = 4 wchar * 2
    }

    #[test]
    fn ioctl_uses_transceive_ctlcode() {
        let b = ioctl_transceive(&[0; 16], &[1, 2, 3]);
        assert_eq!(u32(&b, 4), FSCTL_PIPE_TRANSCEIVE);
        assert_eq!(u32(&b, 28), 3); // InputCount
    }

    #[test]
    fn query_directory_req_shape() {
        let b = query_directory_req(&[0; 16], "*", 0x1_0000);
        assert_eq!(u16(&b, 0), 33); // StructureSize
        assert_eq!(b[2], 0x01); // FileInformationClass = FileDirectoryInformation
        assert_eq!(u16(&b, 24), 64 + 32); // FileNameOffset
        assert_eq!(u16(&b, 26), 2); // FileNameLength ("*" = 1 wchar × 2)
        assert_eq!(u32(&b, 28), 0x1_0000); // OutputBufferLength
    }

    // Hand-build a QUERY_DIRECTORY response with two FileDirectoryInformation
    // records (a directory "Policies" and a file "GptTmpl.inf") plus the "."/".."
    // entries that must be filtered. Validates the NDR-free info walk.
    #[test]
    fn parse_directory_info_reads_entries_and_filters_dot() {
        fn rec(out: &mut Vec<u8>, next: u32, attrs: u32, size: u64, name: &str) {
            let units: Vec<u16> = name.encode_utf16().collect();
            let name_bytes: Vec<u8> = units.iter().flat_map(|u| u.to_le_bytes()).collect();
            let start = out.len();
            out.extend_from_slice(&next.to_le_bytes()); // 0 NextEntryOffset
            out.extend_from_slice(&0u32.to_le_bytes()); // 4 FileIndex
            out.extend_from_slice(&[0u8; 32]); // 8..40 four FILETIMEs
            out.extend_from_slice(&size.to_le_bytes()); // 40 EndOfFile
            out.extend_from_slice(&0u64.to_le_bytes()); // 48 AllocationSize
            out.extend_from_slice(&attrs.to_le_bytes()); // 56 FileAttributes
            out.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes()); // 60 FileNameLength
            out.extend_from_slice(&name_bytes); // 64.. FileName
            if next != 0 {
                // pad this record out to exactly `next` bytes
                while out.len() - start < next as usize {
                    out.push(0);
                }
            }
        }
        let mut buf = Vec::new();
        rec(&mut buf, 72, 0x10, 0, "."); // filtered
        rec(&mut buf, 72, 0x10, 0, ".."); // filtered
        rec(&mut buf, 80, 0x10, 0, "Policies"); // dir
        rec(&mut buf, 0, 0x20, 1234, "GptTmpl.inf"); // file (last)

        // Wrap in an SMB2 response: 64-byte header + fixed part (StructureSize,
        // OutputBufferOffset, OutputBufferLength), then the buffer.
        let out_off = 64u16 + 8;
        let mut msg = vec![0u8; 64];
        msg.extend_from_slice(&9u16.to_le_bytes()); // StructureSize
        msg.extend_from_slice(&out_off.to_le_bytes()); // OutputBufferOffset
        msg.extend_from_slice(&(buf.len() as u32).to_le_bytes()); // OutputBufferLength
        msg.extend_from_slice(&buf);

        let entries = parse_directory_info(&msg).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "Policies");
        assert!(entries[0].is_dir);
        assert_eq!(entries[1].name, "GptTmpl.inf");
        assert!(!entries[1].is_dir);
        assert_eq!(entries[1].size, 1234);
    }

    #[test]
    fn parse_directory_info_survives_hostile_input() {
        // Truncated / zero buffers must not panic.
        for cut in 0..80 {
            let _ = parse_directory_info(&vec![0u8; cut]);
        }
        // A record whose NextEntryOffset does not advance (0-cycle guard) and a
        // name_len that overruns the record must terminate, not loop/OOB.
        let mut buf = vec![0u8; 64];
        buf[60..64].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // FileNameLength = u32::MAX
        let out_off = 64u16 + 8;
        let mut msg = vec![0u8; 64];
        msg.extend_from_slice(&9u16.to_le_bytes());
        msg.extend_from_slice(&out_off.to_le_bytes());
        msg.extend_from_slice(&(buf.len() as u32).to_le_bytes());
        msg.extend_from_slice(&buf);
        let entries = parse_directory_info(&msg).unwrap();
        assert!(entries.is_empty()); // name overrun → skipped, next=0 → stop
    }

    #[test]
    fn create_file_carries_access_and_options() {
        let b = create_file("Windows\\Temp\\x.out", 0x0013_0081, 0x7, 1, 0x1060);
        assert_eq!(u16(&b, 0), 57); // StructureSize
        assert_eq!(u32(&b, 24), 0x0013_0081); // DesiredAccess
        assert_eq!(u32(&b, 32), 0x7); // ShareAccess
        assert_eq!(u32(&b, 36), 1); // CreateDisposition = FILE_OPEN
        assert_eq!(u32(&b, 40), 0x1060); // CreateOptions (incl DELETE_ON_CLOSE)
        assert_eq!(u16(&b, 44), 64 + 56); // NameOffset
        assert_eq!(
            u16(&b, 46),
            "Windows\\Temp\\x.out".chars().count() as u16 * 2
        );
    }

    #[test]
    fn read_req_offset_and_length() {
        let b = read_req(&[0xAB; 16], 0x1_0000, 0x4000);
        assert_eq!(u16(&b, 0), 49); // StructureSize
        assert_eq!(u32(&b, 4), 0x4000); // Length
        assert_eq!(u32(&b, 8), 0x1_0000); // Offset (low dword)
        assert_eq!(&b[16..32], &[0xAB; 16]); // FileId
    }

    #[test]
    fn close_req_shape() {
        let b = close_req(&[0xCD; 16]);
        assert_eq!(u16(&b, 0), 24); // StructureSize
        assert_eq!(&b[8..24], &[0xCD; 16]); // FileId
    }
}
