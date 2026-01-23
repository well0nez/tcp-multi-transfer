//! TCP Hole Punching Implementation
//!
//! TCP hole punching requires "simultaneous open" - both peers must try to 
//! connect at EXACTLY the same time.

mod helpers;
mod strategy;

// Re-export public API
pub use strategy::{punch_connection_with_strategy, PeerInfo};
pub use helpers::current_timestamp;

