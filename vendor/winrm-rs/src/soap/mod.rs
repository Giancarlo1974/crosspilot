//! WS-Management SOAP protocol layer.
//!
//! - `namespaces` -- URI constants for WS-Man actions and resources
//! - `envelope` -- SOAP envelope builders for shell lifecycle operations
//! - `parser` -- response parsers for shell IDs, command IDs, and output streams

pub(crate) mod envelope;
pub(crate) mod namespaces;
pub(crate) mod parser;

// Re-export for internal use
pub(crate) use envelope::*;
pub(crate) use parser::parse_enumerate_response;
// `parser`'s response helpers are `pub` inside a private module (see the
// `unreachable_pub` allows there) so `crate::__fuzz` can wrap them; in-crate
// callers reach them through this crate-visible shim.
pub(crate) use parser::{check_soap_fault, parse_command_id, parse_receive_output, parse_shell_id};
// Re-export ReceiveOutput as fully public so lib.rs can `pub use` it.
pub use parser::ReceiveOutput;
