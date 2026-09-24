//! A minimal SMB2 client — from-scratch pure Rust, scoped to what
//! named-pipe DCE/RPC needs: negotiate (dialect 2.1.0), NTLM session setup, tree-connect to
//! IPC$, create a pipe, and FSCTL_PIPE_TRANSCEIVE to carry RPC PDUs.
//!
//! Raw NTLMSSP is placed directly in the session-setup security buffer (Windows accepts it
//! without a SPNEGO wrapper). SMB 2.x message signing (HMAC-SHA256, truncated to 16 bytes)
//! is applied once a session key is established, since DCs require signing on IPC$.

pub mod client;
pub mod header;
pub mod msg;
pub mod server;
pub mod socks;
pub mod spnego;
pub mod transport;

pub use client::{Cred, SmbClient};
pub use msg::DirEntry;

#[derive(Debug, thiserror::Error)]
pub enum SmbError {
    #[error("truncated SMB2 message")]
    Truncated,
    #[error("bad protocol id")]
    BadProtocol,
    #[error("SMB2 status {0:#010x} for command {1:#06x}")]
    Status(u32, u16),
    #[error("unexpected security token")]
    BadToken,
    #[error("ntlm: {0}")]
    Ntlm(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, SmbError>;

/// SMB2 status codes we branch on.
pub mod status {
    pub const SUCCESS: u32 = 0x0000_0000;
    pub const PENDING: u32 = 0x0000_0103; // interim async response; the real one follows
    pub const MORE_PROCESSING_REQUIRED: u32 = 0xC000_0016;
    pub const END_OF_FILE: u32 = 0xC000_0011;
    pub const OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
    /// STATUS_OBJECT_PATH_NOT_FOUND — a component of the path prefix does
    /// not exist (distinct from `OBJECT_NAME_NOT_FOUND` where the final
    /// leaf is missing). Useful for CREATE against a nested share path.
    /// Adopted from g0h4n's PR #1 for 0.2.4.
    pub const OBJECT_PATH_NOT_FOUND: u32 = 0xC000_003A;
    pub const SHARING_VIOLATION: u32 = 0xC000_0043;
    /// STATUS_NO_MORE_FILES — QUERY_DIRECTORY has returned the last entry.
    pub const NO_MORE_FILES: u32 = 0x8000_0006;
}
