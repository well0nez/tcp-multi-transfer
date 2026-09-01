//! Command Line Interface
//!
//! CLI argument parsing and configuration

use clap::{Parser, ValueEnum};
use anyhow::{Result, anyhow};

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
#[command(after_help = "Advanced switches for tuning and measurement: -X")]
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
    #[arg(long, default_value = "30")]
    pub timeout: u64,

    /// Number of NAT probes to send
    #[arg(long, default_value_t = DEFAULT_NAT_PROBE_COUNT, hide = true)]
    pub probe_count: u32,

    /// Run probe-only debug mode
    #[arg(long, hide = true)]
    pub probe_debug: bool,

    /// NAT prediction mode
    #[arg(long, value_enum, default_value_t = PredictionMode::Delta, hide = true)]
    pub prediction_mode: PredictionMode,

    /// Expand prediction scan range by percentage
    #[arg(long, default_value_t = 0.0, hide = true)]
    pub prediction_range_extra_pct: f64,
    
    /// Number of parallel TCP connections (multi TCP)
    #[arg(long, default_value_t = 1, help_heading = "Multi-TCP")]
    pub tcp_connections: u8,
    
    /// How many failures in a row before a connection is given up
    #[arg(long, default_value_t = 5, help_heading = "Multi-TCP", hide = true)]
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

    // Jeder zusaetzliche Port ist eine weitere Ziehung aus dem Portband der
    // eigenen NAT; vergibt sie vorhersagbar, wird der Wert automatisch auf 1
    // gesetzt. Vorgabe 16 aus zwei Messungen: bei 64 gedeckten Ports und
    // einem Band von 251 stieg die Erfolgsquote je Versuch von 23 % (m=1) auf
    // 80 % (m=8); mit m=16 genuegen dann 32 gedeckte Ports. Herleitung im
    // README, Abschnitt "Coverage times draws".
    /// Local ports held simultaneously while punching
    #[arg(long, alias = "parallel-ports", default_value_t = 16, help_heading = "Punch")]
    pub punch_ports: usize,

    /// Upper bound on targets x local ports
    #[arg(long, default_value_t = 512, help_heading = "Punch", hide = true)]
    pub socket_budget: usize,

    // Duennt gleichmaessig aus und bleibt im beobachteten Band der
    // Gegenstelle, statt hinten abzuschneiden. Dient dazu, die Abdeckung fuer
    // einen A/B-Vergleich im selben Binary zu variieren.
    /// Touch only N of the peer's candidates (0 = all)
    #[arg(long, default_value_t = 0, help_heading = "Punch", hide = true)]
    pub max_candidates: usize,

    /// Upper bound on the wait for a better candidate, in milliseconds
    #[arg(long, default_value_t = 300, help_heading = "Punch", hide = true)]
    pub grace_ms: u64,

    /// Derive the wait from the first candidate's own latency
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set,
          help_heading = "Punch", hide = true)]
    pub grace_adaptiv: bool,

    /// Pause after a refused attempt, in milliseconds
    #[arg(long, default_value_t = 100, help_heading = "Punch", hide = true)]
    pub retry_pause_ms: u64,

    // Notbehelf, wenn das Socket-Budget nicht fuer alle Ziele reicht.
    // Gemessen deutlich schlechter als genug Sockets, deshalb keine Vorgabe.
    /// Cycle time for serving targets in turn, in milliseconds (0 = 800)
    #[arg(long, default_value_t = 0, help_heading = "Punch", hide = true)]
    pub rotate_after_ms: u64,

    /// Drop to one punch port when our own NAT allocates predictably
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set,
          help_heading = "Punch", hide = true)]
    pub auto_parallel: bool,

    /// Prefer LAN candidates when both peers are behind the same NAT
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set, help_heading = "Punch")]
    pub prefer_lan: bool,

    /// Send NAT probes from the bound punch ports instead of ephemeral ports
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set,
          help_heading = "Punch", hide = true)]
    pub probe_from_bound: bool,

    /// Reference behaviour for before/after comparison
    #[arg(long, default_value_t = false, help_heading = "Punch", hide = true)]
    pub legacy: bool,

    /// Append one JSON line per punch attempt and transfer to this file
    #[arg(long, help_heading = "Measurement")]
    pub metrics_file: Option<String>,

    /// Free-text label written into every metrics line
    #[arg(long, help_heading = "Measurement")]
    pub metrics_label: Option<String>,

    // Roher Bytestrom ohne Chunk-Protokoll, Pruefsummen und Plattenzugriff —
    // die Referenz, gegen die der Transfercode gemessen wird.
    /// Measure the path with N MB of raw traffic instead of sending a file
    #[arg(long, help_heading = "Measurement")]
    pub bench: Option<u64>,

    /// Number of round-trip probes before the path measurement
    #[arg(long, default_value_t = 20, help_heading = "Measurement", hide = true)]
    pub bench_rtt: u32,

    /// Sampling interval of the time series, in milliseconds
    #[arg(long, default_value_t = 250, help_heading = "Measurement", hide = true)]
    pub bench_sample_ms: u64,

    // Nur so liegen Referenz und Messwert dicht genug beieinander, um bei
    // schwankendem Uplink vergleichbar zu sein.
    /// Follow the path measurement with a file transfer over the same connection
    #[arg(long, alias = "bench-und-transfer", default_value_t = false,
          help_heading = "Measurement")]
    pub bench_then_transfer: bool,
}

impl Args {
    /// Baut die Punch-Optionen. `--legacy` gewinnt gegen die Einzelschalter,
    /// damit ein Referenzlauf nicht versehentlich halb neu ist.
    pub fn punch_options(&self) -> crate::punch::PunchOptions {
        if self.legacy {
            return crate::punch::PunchOptions::legacy();
        }
        crate::punch::PunchOptions {
            prefer_lan: self.prefer_lan,
            parallel_ports: self.punch_ports.max(1),
            socket_budget: self.socket_budget.max(1),
            max_candidates: if self.max_candidates == 0 { None } else { Some(self.max_candidates) },
            retry_pause: std::time::Duration::from_millis(self.retry_pause_ms),
            grace: std::time::Duration::from_millis(self.grace_ms),
            grace_adaptiv: self.grace_adaptiv,
            rotate_after: if self.rotate_after_ms == 0 {
                None
            } else {
                Some(std::time::Duration::from_millis(self.rotate_after_ms))
            },
        }
    }

    /// Probes von den gebundenen Ports? `--legacy` erzwingt das alte Verhalten.
    pub fn probe_from_bound_ports(&self) -> bool {
        !self.legacy && self.probe_from_bound
    }
}

/// Kleinste zulaessige Blockgroesse. Ohne Untergrenze ergibt `--chunk 0` einen
/// Lesepuffer der Laenge null (SHA256 der leeren Eingabe fuer jede Datei) und
/// im Mehrstrombetrieb eine Division durch null.
const MIN_CHUNK_ARG: usize = 64 * 1024;

pub fn parse_chunk_size(s: &str) -> Result<usize> {
    let s = s.trim().to_uppercase();
    if s.ends_with("MB") {
        let num: f64 = s.trim_end_matches("MB").trim().parse().map_err(|_| anyhow!("Invalid chunk size"))?;
        Ok((num * 1024.0 * 1024.0) as usize)
    } else if s.ends_with("KB") {
        let num: f64 = s.trim_end_matches("KB").trim().parse().map_err(|_| anyhow!("Invalid chunk size"))?;
        Ok((num * 1024.0) as usize)
    } else if s.ends_with("B") {
        let num: usize = s.trim_end_matches("B").trim().parse().map_err(|_| anyhow!("Invalid chunk size"))?;
        Ok(num)
    } else {
        s.parse::<usize>().map_err(|_| anyhow!("Invalid chunk size"))
    }
    .and_then(|n| {
        // Obergrenze, weil `--chunk 1e12MB` ueber den Float-Zwischenwert
        // saettigt und danach beim Puffer-Anlegen den Speicher sprengt.
        const MAX_CHUNK_ARG: usize = 256 * 1024 * 1024;
        if n > MAX_CHUNK_ARG {
            return Err(anyhow!("Chunk size must be at most {} MB", MAX_CHUNK_ARG / 1048576));
        }
        if n < MIN_CHUNK_ARG {
            Err(anyhow!("Chunk size must be at least {} KB", MIN_CHUNK_ARG / 1024))
        } else {
            Ok(n)
        }
    })
}
