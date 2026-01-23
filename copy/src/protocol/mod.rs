//! Protocol Messages
//!
//! This module contains protocol definitions for:
//! - Relay protocol: JSON-based messages for relay server communication
//! - Transfer protocol: Binary messages for efficient P2P file transfer

pub mod relay;
pub mod transfer;

// Re-export commonly used types
pub use relay::{
    RegisterMessage, AddPortsMessage,
    ProbeMessage, RelayMessage, NATAnalysis
};
