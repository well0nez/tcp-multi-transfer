//! TCP Hole Punching Implementation
//!
//! TCP hole punching requires "simultaneous open" - both peers must try to
//! connect at EXACTLY the same time.

mod helpers;
mod strategy;

// Re-export public API
pub use strategy::{punch_connection, PeerInfo, PunchOptions};
pub use helpers::{current_timestamp, create_hole_punch_socket, bind_to_port};

