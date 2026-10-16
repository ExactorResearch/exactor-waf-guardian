//! SafeLine T1K binary protocol integration suite.

pub mod codec;
pub mod parser;
pub mod server;

pub use codec::{read_packet, write_packet, T1kPacket};
pub use parser::{parse_t1k_request, T1kExtraMetadata};
pub use server::{run_t1k_server, T1kServerState};
