//! Transfer Helper Functions
//!
//! Utility functions for file transfer including SHA256 hashing,
//! progress tracking, socket configuration, and timeout helpers.

use std::path::Path;
use std::time::Duration;
use std::fmt::Write as FmtWrite;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use anyhow::{Result, anyhow};
use sha2::{Sha256, Digest};
use indicatif::{ProgressBar, ProgressStyle, ProgressState};
use socket2::Socket;

/// Progress update interval in bytes (10MB)
const PROGRESS_BYTE_INTERVAL: u64 = 10 * 1024 * 1024;

/// Progress update interval in time (2 seconds)
const PROGRESS_TIME_INTERVAL: Duration = Duration::from_secs(2);

/// TCP socket buffer size (64MB each for send/recv)
const TCP_BUFFER_SIZE: usize = 64 * 1024 * 1024;

/// Progress tracker with hybrid update strategy
pub struct ProgressTracker {
    bar: ProgressBar,
    last_update_bytes: u64,
    last_update_time: std::time::Instant,
}

impl ProgressTracker {
    pub fn new(total_bytes: u64, filename: &str) -> Self {
        Self {
            bar: create_progress_bar(total_bytes, filename),
            last_update_bytes: 0,
            last_update_time: std::time::Instant::now(),
        }
    }
    
    pub fn update(&mut self, current_bytes: u64) {
        let bytes_since_update = current_bytes.saturating_sub(self.last_update_bytes);
        let time_since_update = self.last_update_time.elapsed();
        
        if bytes_since_update >= PROGRESS_BYTE_INTERVAL || time_since_update >= PROGRESS_TIME_INTERVAL {
            self.bar.set_position(current_bytes);
            self.last_update_bytes = current_bytes;
            self.last_update_time = std::time::Instant::now();
        }
    }
    
    pub fn set_position(&self, pos: u64) {
        self.bar.set_position(pos);
    }
    
    pub fn finish_with_message(&self, msg: String) {
        self.bar.finish_with_message(msg);
    }
    
    pub fn set_message(&self, msg: &str) {
        self.bar.set_message(msg.to_string());
    }
}

fn create_progress_bar(total_bytes: u64, filename: &str) -> ProgressBar {
    let pb = ProgressBar::new(total_bytes);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({mbits_per_sec}) {msg}")
        .unwrap()
        .with_key("mbits_per_sec", |state: &ProgressState, w: &mut dyn FmtWrite| {
            let mbits_per_sec = state.per_sec() * 8.0 / 1_000_000.0;
            let _ = write!(w, "{:.2} Mbit/s", mbits_per_sec);
        })
        .progress_chars("=>-"));
    pb.set_message(filename.to_string());
    pb
}

/// Calculate SHA256 hash of a file
pub async fn calculate_sha256(file_path: &str) -> Result<([u8; 32], u64)> {
    let path = Path::new(file_path);
    let file_size = tokio::fs::metadata(path).await?.len();
    let hash = sha256_file(path).await?;
    Ok((hash, file_size))
}

async fn sha256_file(path: &Path) -> Result<[u8; 32]> {
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
