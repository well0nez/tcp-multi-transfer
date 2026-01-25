//! TCP File Transfer Implementation - Optimized HIGH-THROUGHPUT
//!
//! Optimizations:
//! - CHUNK_SIZE: 8MB (configurable via --chunk) - fewer syscalls
//! - BUFFER_SIZE: 16MB for efficient I/O
//! - TCP Socket buffers: 64MB send/recv (OS may cap lower)
//! - Pipeline Depth: 16 chunks (~128MB in flight)
//! - Periodic progress updates (200ms) with atomic byte counters
//! - SHA256 only at the end (from disk)
//! - CRC32 per chunk during transfer with ACK/NACK
//! - Pipelined I/O - Disk reads and network writes run in parallel!

use std::sync::atomic::{AtomicUsize, Ordering};

mod helpers;
mod sender;
mod receiver;

// Re-export public API
pub use helpers::{calculate_sha256, sha256_to_hex};
pub use sender::{TcpSender, run_multi_sender};
pub use receiver::{TcpReceiver, run_multi_receiver};

/// Default chunk size for reading/writing (8MB) - fewer syscalls
pub const DEFAULT_CHUNK_SIZE: usize = 8 * 1024 * 1024;

/// BUG-009 FIX: Use AtomicUsize instead of unsafe static mut
static CHUNK_SIZE: AtomicUsize = AtomicUsize::new(DEFAULT_CHUNK_SIZE);

/// Set the chunk size (called from main.rs)
pub fn set_chunk_size(size: usize) {
    CHUNK_SIZE.store(size, Ordering::Relaxed);
}

/// Get the current chunk size
pub(crate) fn get_chunk_size() -> usize {
    CHUNK_SIZE.load(Ordering::Relaxed)
}
