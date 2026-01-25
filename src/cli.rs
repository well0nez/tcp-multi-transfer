//! Command Line Interface
//!
//! CLI argument parsing and configuration

use anyhow::{anyhow, Result};
use clap::{Parser, ValueEnum};

pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const DEFAULT_NAT_PROBE_COUNT: u32 = 10;

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Mode {
    Send,
    Receive,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum PredictionMode {
    Delta,
    External,
}

impl PredictionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            PredictionMode::Delta => "delta",
            PredictionMode::External => "external",
        }
    }
}

#[derive(Parser, Debug)]
#[command(name = "tcp-multi-transfer")]
#[command(author = "TCP Transfer Team")]
#[command(version)]
#[command(about = "Multi-TCP file transfer with NAT traversal (hole punching)")]
pub struct Args {
    /// Relay server address (host:port)
    #[arg(short, long)]
    pub server: String,

    /// Session ID (both sender and receiver must use the same ID)
    #[arg(short = 'i', long)]
    pub session_id: String,

    /// Mode: send or receive
    #[arg(short, long, value_enum)]
    pub mode: Mode,

    /// File to send (sender mode only)
    #[arg(short, long)]
    pub file: Option<String>,

    /// Hole punch timeout in seconds
    #[arg(long, default_value = "15")]
    pub timeout: u64,

    /// Number of NAT probes to send
    #[arg(long, default_value_t = DEFAULT_NAT_PROBE_COUNT)]
    pub probe_count: u32,

    /// Run probe-only debug mode
    #[arg(long)]
    pub probe_debug: bool,

    /// NAT prediction mode
    #[arg(long, value_enum, default_value_t = PredictionMode::Delta)]
    pub prediction_mode: PredictionMode,

    /// Expand prediction scan range by percentage
    #[arg(long, default_value_t = 0.0)]
    pub prediction_range_extra_pct: f64,

    /// Number of parallel TCP connections (multi TCP)
    #[arg(long, default_value_t = 1, help_heading = "Multi-TCP")]
    pub tcp_connections: u8,

    /// Maximum number of sequential punch attempts
    #[arg(long, default_value_t = 20, help_heading = "Multi-TCP")]
    pub max_attempts: u32,

    /// Allow fallback to fewer connections if punch fails
    #[arg(long, default_value_t = false, help_heading = "Multi-TCP")]
    pub allow_fallback: bool,

    /// Minimum number of connections required (if fallback allowed)
    #[arg(long, default_value_t = 1, help_heading = "Multi-TCP")]
    pub min_connections: u32,

    /// Enable debug logging
    #[arg(long)]
    pub debug: bool,

    /// Chunk size for transfer (e.g., 512KB, 1MB, 2MB)
    #[arg(long, default_value = "8MB")]
    pub chunk: String,
}

pub fn parse_chunk_size(s: &str) -> Result<usize> {
    let s = s.trim().to_uppercase();
    if s.ends_with("MB") {
        let num: f64 = s
            .trim_end_matches("MB")
            .trim()
            .parse()
            .map_err(|_| anyhow!("Invalid chunk size"))?;
        Ok((num * 1024.0 * 1024.0) as usize)
    } else if s.ends_with("KB") {
        let num: f64 = s
            .trim_end_matches("KB")
            .trim()
            .parse()
            .map_err(|_| anyhow!("Invalid chunk size"))?;
        Ok((num * 1024.0) as usize)
    } else if s.ends_with("B") {
        let num: usize = s
            .trim_end_matches("B")
            .trim()
            .parse()
            .map_err(|_| anyhow!("Invalid chunk size"))?;
        Ok(num)
    } else {
        s.parse::<usize>()
            .map_err(|_| anyhow!("Invalid chunk size"))
    }
}
