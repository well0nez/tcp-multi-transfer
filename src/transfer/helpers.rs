//! Transfer Helper Functions
//!
//! Utility functions for file transfer including SHA256 hashing,
//! progress tracking, socket configuration, and timeout helpers.

use std::path::Path;
use std::time::Duration;
use std::time::Instant;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::fmt::Write as FmtWrite;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use anyhow::{Result, anyhow};
use sha2::{Sha256, Digest};
use indicatif::{ProgressBar, ProgressStyle, ProgressState};
use socket2::Socket;

/// Progress update interval
const PROGRESS_TICK: Duration = Duration::from_millis(500);

/// Speed smoothing factor (EMA)
const SPEED_EMA_ALPHA: f64 = 0.1;

/// TCP socket buffer size (64MB each for send/recv)
const TCP_BUFFER_SIZE: usize = 64 * 1024 * 1024;

/// Progress tracker with atomic byte counter and periodic UI updates
pub struct ProgressTracker {
    bar: ProgressBar,
    stop: Arc<AtomicBool>,
    task: tokio::task::JoinHandle<()>,
}

impl ProgressTracker {
    pub fn with_bytes(total_bytes: u64, filename: &str, bytes: Arc<AtomicU64>) -> Self {
        Self::with_bytes_and_speed(total_bytes, filename, bytes.clone(), bytes)
    }

    pub fn with_bytes_and_speed(
        total_bytes: u64,
        filename: &str,
        position_bytes: Arc<AtomicU64>,
        speed_bytes: Arc<AtomicU64>,
    ) -> Self {
        let speed_x100 = Arc::new(AtomicU64::new(0));
        let bar = create_progress_bar(total_bytes, filename, speed_x100.clone());
        let stop = Arc::new(AtomicBool::new(false));
        let task = spawn_progress_task(
            bar.clone(),
            position_bytes.clone(),
            speed_bytes.clone(),
            speed_x100.clone(),
            stop.clone(),
            total_bytes,
        );

        let _ = position_bytes;
        Self { bar, stop, task }
    }

    pub fn set_position(&self, pos: u64) {
        self.bar.set_position(pos);
    }
    
    pub fn finish_with_message(&self, msg: String) {
        self.stop.store(true, Ordering::Relaxed);
        self.task.abort();
        self.bar.finish_with_message(msg);
    }
    
    pub fn set_message(&self, msg: &str) {
        self.bar.set_message(msg.to_string());
    }
}

impl Drop for ProgressTracker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.task.abort();
    }
}

fn create_progress_bar(
    total_bytes: u64,
    filename: &str,
    speed_x100: Arc<AtomicU64>,
) -> ProgressBar {
    let pb = ProgressBar::new(total_bytes);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({mbits_per_sec}) {msg}")
        .unwrap()
        .with_key("mbits_per_sec", move |_state: &ProgressState, w: &mut dyn FmtWrite| {
            let mbits_per_sec = speed_x100.load(Ordering::Relaxed) as f64 / 100.0;
            let _ = write!(w, "{:.2} Mbit/s", mbits_per_sec);
        })
        .progress_chars("=>-"));
    pb.set_message(filename.to_string());
    pb
}

fn spawn_progress_task(
    bar: ProgressBar,
    position_bytes: Arc<AtomicU64>,
    speed_bytes: Arc<AtomicU64>,
    speed_x100: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    total_bytes: u64,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(PROGRESS_TICK);
        let mut last_speed_bytes = 0_u64;
        let mut last_tick = Instant::now();
        let mut ema_mbit = 0.0_f64;

        loop {
            interval.tick().await;
            if stop.load(Ordering::Relaxed) {
                break;
            }
            let now_pos_raw = position_bytes.load(Ordering::Relaxed);
            let now_speed_raw = speed_bytes.load(Ordering::Relaxed);
            let now = Instant::now();
            let elapsed = now.duration_since(last_tick).as_secs_f64().max(0.000_001);
            let now_pos = std::cmp::min(now_pos_raw, total_bytes);
            let delta_bytes = now_speed_raw.saturating_sub(last_speed_bytes) as f64;
            let inst_mbit = delta_bytes * 8.0 / 1_000_000.0 / elapsed;
            ema_mbit = if ema_mbit == 0.0 {
                inst_mbit
            } else {
                (1.0 - SPEED_EMA_ALPHA) * ema_mbit + SPEED_EMA_ALPHA * inst_mbit
            };
            speed_x100.store((ema_mbit * 100.0) as u64, Ordering::Relaxed);

            bar.set_position(now_pos);

            last_speed_bytes = now_speed_raw;
            last_tick = now;
        }
    })
}

/// Calculate SHA256 hash of a file
pub async fn calculate_sha256(file_path: &str) -> Result<([u8; 32], u64)> {
    let path = Path::new(file_path);
    let file_size = tokio::fs::metadata(path).await?.len();
    let hash = sha256_file(path).await?;
    Ok((hash, file_size))
}

pub(crate) async fn sha256_file(path: &Path) -> Result<[u8; 32]> {
    let mut file = File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; super::get_chunk_size()];
    
    loop {
        let n = file.read(&mut buffer).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    Ok(hash)
}

/// Convert SHA256 hash to hex string
pub fn sha256_to_hex(hash: &[u8; 32]) -> String {
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Configure TCP socket for optimal performance
pub fn configure_tcp_socket(stream: &TcpStream) -> Result<()> {
    let std_stream = stream.as_ref();
    std_stream.set_nodelay(true)?;
    
    #[cfg(unix)]
    {
        use std::os::unix::io::{AsRawFd, FromRawFd};
        let fd = std_stream.as_raw_fd();
        let socket = unsafe { Socket::from_raw_fd(fd) };
        let _ = socket.set_send_buffer_size(TCP_BUFFER_SIZE);
        let _ = socket.set_recv_buffer_size(TCP_BUFFER_SIZE);
        let actual_send = socket.send_buffer_size().unwrap_or(0);
        let actual_recv = socket.recv_buffer_size().unwrap_or(0);
        tracing::info!("TCP buffers: send={}MB recv={}MB (requested {}MB)", 
            actual_send / (1024 * 1024),
            actual_recv / (1024 * 1024),
            TCP_BUFFER_SIZE / (1024 * 1024));
        std::mem::forget(socket);
    }
    
    #[cfg(windows)]
    {
        use std::os::windows::io::{AsRawSocket, FromRawSocket};
        let raw = std_stream.as_raw_socket();
        let socket = unsafe { Socket::from_raw_socket(raw) };
        let _ = socket.set_send_buffer_size(TCP_BUFFER_SIZE);
        let _ = socket.set_recv_buffer_size(TCP_BUFFER_SIZE);
        let actual_send = socket.send_buffer_size().unwrap_or(0);
        let actual_recv = socket.recv_buffer_size().unwrap_or(0);
        tracing::info!("TCP buffers: send={}MB recv={}MB (requested {}MB)", 
            actual_send / (1024 * 1024),
            actual_recv / (1024 * 1024),
            TCP_BUFFER_SIZE / (1024 * 1024));
        std::mem::forget(socket);
    }
    
    tracing::debug!("TCP_NODELAY enabled");
    Ok(())
}

/// Read exact amount of bytes with timeout
pub async fn read_exact_timeout(stream: &mut TcpStream, buf: &mut [u8], timeout: Duration) -> Result<()> {
    match tokio::time::timeout(timeout, stream.read_exact(buf)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(anyhow!("Read error: {}", e)),
        Err(_) => Err(anyhow!("Read timeout")),
    }
}

/// Write all bytes with timeout
pub async fn write_all_timeout(stream: &mut TcpStream, buf: &[u8], timeout: Duration) -> Result<()> {
    match tokio::time::timeout(timeout, stream.write_all(buf)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(anyhow!("Write error: {}", e)),
        Err(_) => Err(anyhow!("Write timeout")),
    }
}
