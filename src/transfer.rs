//! TCP File Transfer Implementation - Optimized HIGH-THROUGHPUT
//!
//! Optimizations:
//! - CHUNK_SIZE: 4MB (configurable via --chunk) - fewer syscalls
//! - BUFFER_SIZE: 16MB for efficient I/O
//! - TCP Socket buffers: 64MB send/recv (OS may cap lower)
//! - Pipeline Depth: 16 chunks (~64MB in flight at 4MB chunks)
//! - Hybrid progress: every 10MB OR every 2 seconds
//! - SHA256 only at the end (from disk) - TCP handles in-flight integrity
//! - No checksum during transfer - TCP already guarantees delivery
//! - Pipelined I/O - Disk reads and network writes run in parallel!

use std::collections::VecDeque;
use std::io::SeekFrom;
use std::path::Path;
use std::sync::{Arc, atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering}};
use std::time::{Duration, Instant};
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt, AsyncSeekExt, BufReader, BufWriter};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Notify};
use bytes::{Buf, BufMut};
use sha2::{Sha256, Digest};
use indicatif::{ProgressBar, ProgressStyle};
use anyhow::{Result, anyhow};
use tracing::{info, warn, error, debug};
use socket2::Socket;

use crate::protocol::transfer::*;

/// Default chunk size for reading/writing (4MB) - fewer syscalls
/// Can be overridden via --chunk flag
pub const DEFAULT_CHUNK_SIZE: usize = 4 * 1024 * 1024;

/// Buffer size for file I/O (16MB)  
const BUFFER_SIZE: usize = 16 * 1024 * 1024;

/// TCP socket buffer size (64MB each for send/recv)
/// Note: OS may cap this lower - we'll log actual values
const TCP_BUFFER_SIZE: usize = 64 * 1024 * 1024;

/// Pipeline depth for async I/O (16 chunks = ~32MB in flight at 2MB chunks)
const PIPELINE_DEPTH: usize = 16;

/// Progress update interval in bytes (10MB)
const PROGRESS_BYTE_INTERVAL: u64 = 10 * 1024 * 1024;

/// Progress update interval in time (2 seconds)
const PROGRESS_TIME_INTERVAL: Duration = Duration::from_secs(2);

/// Timeout for individual read/write operations
/// Note: For multi-stream transfers with many connections, individual streams
/// may be idle for extended periods while other streams handle chunks.
const IO_TIMEOUT: Duration = Duration::from_secs(120);

/// Protocol timeout for handshake
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Global chunk size (set from main.rs)
static mut CHUNK_SIZE: usize = DEFAULT_CHUNK_SIZE;

/// Set the chunk size (called from main.rs)
pub fn set_chunk_size(size: usize) {
    unsafe {
        CHUNK_SIZE = size;
    }
}

/// Get the current chunk size
fn get_chunk_size() -> usize {
    unsafe { CHUNK_SIZE }
}

/// Configure TCP socket for optimal performance
fn configure_tcp_socket(stream: &TcpStream) -> Result<()> {
    let std_stream = stream.as_ref();
    std_stream.set_nodelay(true)?;
    
    // Set large TCP buffers for high throughput
    #[cfg(unix)]
    {
        use std::os::unix::io::{AsRawFd, FromRawFd};
        let fd = std_stream.as_raw_fd();
        let socket = unsafe { Socket::from_raw_fd(fd) };
        
        // Request large buffers
        let _ = socket.set_send_buffer_size(TCP_BUFFER_SIZE);
        let _ = socket.set_recv_buffer_size(TCP_BUFFER_SIZE);
        
        // Log actual buffer sizes (OS may cap lower)
        let actual_send = socket.send_buffer_size().unwrap_or(0);
        let actual_recv = socket.recv_buffer_size().unwrap_or(0);
        info!("TCP buffers: send={}MB recv={}MB (requested {}MB)", 
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
        
        // Request large buffers
        let _ = socket.set_send_buffer_size(TCP_BUFFER_SIZE);
        let _ = socket.set_recv_buffer_size(TCP_BUFFER_SIZE);
        
        // Log actual buffer sizes (OS may cap lower)
        let actual_send = socket.send_buffer_size().unwrap_or(0);
        let actual_recv = socket.recv_buffer_size().unwrap_or(0);
        info!("TCP buffers: send={}MB recv={}MB (requested {}MB)", 
            actual_send / (1024 * 1024),
            actual_recv / (1024 * 1024),
            TCP_BUFFER_SIZE / (1024 * 1024));
        
        std::mem::forget(socket);
    }
    
    debug!("TCP_NODELAY enabled");
    Ok(())
}

/// Create a progress bar for file transfer
fn create_progress_bar(total_bytes: u64, filename: &str) -> ProgressBar {
    let pb = ProgressBar::new(total_bytes);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}) {msg}")
        .unwrap()
        .progress_chars("=>-"));
    pb.set_message(filename.to_string());
    pb
}

/// Progress tracker with hybrid (bytes OR time) updates
struct ProgressTracker {
    bar: ProgressBar,
    last_update_bytes: u64,
    last_update_time: Instant,
}

impl ProgressTracker {
    fn new(total_bytes: u64, filename: &str) -> Self {
        Self {
            bar: create_progress_bar(total_bytes, filename),
            last_update_bytes: 0,
            last_update_time: Instant::now(),
        }
    }
    
    fn update(&mut self, current_bytes: u64) {
        let bytes_since_update = current_bytes - self.last_update_bytes;
        let time_since_update = self.last_update_time.elapsed();
        
        if bytes_since_update >= PROGRESS_BYTE_INTERVAL || time_since_update >= PROGRESS_TIME_INTERVAL {
            self.bar.set_position(current_bytes);
            self.last_update_bytes = current_bytes;
            self.last_update_time = Instant::now();
        }
    }
    
    fn set_position(&self, pos: u64) {
        self.bar.set_position(pos);
    }
    
    fn finish_with_message(&self, msg: String) {
        self.bar.finish_with_message(msg);
    }
    
    fn set_message(&self, msg: &str) {
        self.bar.set_message(msg.to_string());
    }
}

/// Calculate SHA256 hash of a file
pub async fn calculate_sha256(file_path: &str) -> Result<([u8; 32], u64)> {
    let path = Path::new(file_path);
    let file_size = tokio::fs::metadata(path).await?.len();
    let hash = sha256_file(path).await?;
    Ok((hash, file_size))
}

/// Calculate SHA256 hash of a file (internal)
async fn sha256_file(path: &Path) -> Result<[u8; 32]> {
    let mut file = File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; get_chunk_size()];
    
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

/// Format hash as hex string
pub fn sha256_to_hex(hash: &[u8; 32]) -> String {
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Read exactly n bytes with timeout
async fn read_exact_timeout(stream: &mut TcpStream, buf: &mut [u8], timeout: Duration) -> Result<()> {
    match tokio::time::timeout(timeout, stream.read_exact(buf)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(anyhow!("Read error: {}", e)),
        Err(_) => Err(anyhow!("Read timeout")),
    }
}

/// Write all bytes with timeout
async fn write_all_timeout(stream: &mut TcpStream, buf: &[u8], timeout: Duration) -> Result<()> {
    match tokio::time::timeout(timeout, stream.write_all(buf)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(anyhow!("Write error: {}", e)),
        Err(_) => Err(anyhow!("Write timeout")),
    }
}

async fn handshake_sender(stream: &mut TcpStream) -> Result<()> {
    info!("Performing sender handshake...");
    configure_tcp_socket(stream)?;

    let hello = HelloMessage { role: "sender".to_string() };
    write_all_timeout(stream, &hello.encode(), HANDSHAKE_TIMEOUT).await?;
    debug!("Sent HELLO");

    let mut buf = [0u8; 256];
    read_exact_timeout(stream, &mut buf[..5], HANDSHAKE_TIMEOUT).await?;

    if buf[0] != MessageType::Hello as u8 {
        return Err(anyhow!("Expected HELLO, got type {}", buf[0]));
    }

    let len = (&buf[1..5]).get_u32() as usize;
    read_exact_timeout(stream, &mut buf[5..5 + len], HANDSHAKE_TIMEOUT).await?;

    if let Some(hello) = HelloMessage::decode(&buf[..5 + len]) {
        if hello.role != "receiver" {
            return Err(anyhow!("Expected receiver, got {}", hello.role));
        }
        info!("Received HELLO from receiver");
    } else {
        return Err(anyhow!("Failed to parse HELLO"));
    }

    Ok(())
}

async fn handshake_receiver(stream: &mut TcpStream) -> Result<()> {
    info!("Performing receiver handshake...");
    configure_tcp_socket(stream)?;

    let mut buf = [0u8; 256];
    read_exact_timeout(stream, &mut buf[..5], HANDSHAKE_TIMEOUT).await?;

    if buf[0] != MessageType::Hello as u8 {
        return Err(anyhow!("Expected HELLO, got type {}", buf[0]));
    }

    let len = (&buf[1..5]).get_u32() as usize;
    read_exact_timeout(stream, &mut buf[5..5 + len], HANDSHAKE_TIMEOUT).await?;

    if let Some(hello) = HelloMessage::decode(&buf[..5 + len]) {
        if hello.role != "sender" {
            return Err(anyhow!("Expected sender, got {}", hello.role));
        }
        info!("Received HELLO from sender");
    } else {
        return Err(anyhow!("Failed to parse HELLO"));
    }

    let hello = HelloMessage { role: "receiver".to_string() };
    write_all_timeout(stream, &hello.encode(), HANDSHAKE_TIMEOUT).await?;
    debug!("Sent HELLO");

    Ok(())
}

async fn send_stream_info(stream: &mut TcpStream, stream_index: u32, total_streams: u32) -> Result<()> {
    let info = StreamInfoMessage { stream_index, total_streams };
    write_all_timeout(stream, &info.encode(), HANDSHAKE_TIMEOUT).await?;

    let mut buf = [0u8; 1];
    read_exact_timeout(stream, &mut buf, HANDSHAKE_TIMEOUT).await?;
    if buf[0] != MessageType::StreamInfoAck as u8 {
        return Err(anyhow!("Expected STREAM_INFO_ACK, got type {}", buf[0]));
    }
    Ok(())
}

async fn recv_stream_info(stream: &mut TcpStream) -> Result<StreamInfoMessage> {
    let mut buf = [0u8; 9];
    read_exact_timeout(stream, &mut buf, HANDSHAKE_TIMEOUT).await?;
    if buf[0] != MessageType::StreamInfo as u8 {
        return Err(anyhow!("Expected STREAM_INFO, got type {}", buf[0]));
    }
    let info = StreamInfoMessage::decode(&buf)
        .ok_or_else(|| anyhow!("Failed to parse STREAM_INFO"))?;

    let ack = encode_simple(MessageType::StreamInfoAck);
    write_all_timeout(stream, &ack, HANDSHAKE_TIMEOUT).await?;
    Ok(info)
}

async fn send_file_info_on_stream(
    stream: &mut TcpStream,
    file_path: &str,
    file_size: u64,
    sha256: [u8; 32],
) -> Result<()> {
    let filename = Path::new(file_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    let file_info = FileInfoMessage {
        filename: filename.clone(),
        file_size,
        sha256,
    };

    info!("Sending file info: {} ({:.2} MB)", filename, file_size as f64 / (1024.0 * 1024.0));
    info!("Chunk size: {} KB", get_chunk_size() / 1024);

    write_all_timeout(stream, &file_info.encode(), HANDSHAKE_TIMEOUT).await?;

    let mut buf = [0u8; 1];
    read_exact_timeout(stream, &mut buf, HANDSHAKE_TIMEOUT).await?;

    if buf[0] != MessageType::FileInfoAck as u8 {
        return Err(anyhow!("Expected FILE_INFO_ACK, got type {}", buf[0]));
    }

    info!("File info acknowledged");
    Ok(())
}

async fn receive_file_info_from_stream(stream: &mut TcpStream) -> Result<FileInfoMessage> {
    let mut header = [0u8; 13];
    read_exact_timeout(stream, &mut header, HANDSHAKE_TIMEOUT).await?;

    if header[0] != MessageType::FileInfo as u8 {
        return Err(anyhow!("Expected FILE_INFO, got type {}", header[0]));
    }

    let name_len = (&header[1..5]).get_u32() as usize;
    let file_size = (&header[5..13]).get_u64();

    let mut name_and_hash = vec![0u8; name_len + 32];
    read_exact_timeout(stream, &mut name_and_hash, HANDSHAKE_TIMEOUT).await?;

    let filename = String::from_utf8(name_and_hash[..name_len].to_vec())
        .map_err(|_| anyhow!("Invalid filename encoding"))?;

    let mut sha256 = [0u8; 32];
    sha256.copy_from_slice(&name_and_hash[name_len..]);

    let info = FileInfoMessage { filename, file_size, sha256 };

    info!("Receiving: {} ({:.2} MB)", info.filename, info.file_size as f64 / (1024.0 * 1024.0));
    info!("Expected SHA256: {}", sha256_to_hex(&info.sha256));

    let ack = encode_simple(MessageType::FileInfoAck);
    write_all_timeout(stream, &ack, HANDSHAKE_TIMEOUT).await?;
    info!("File info acknowledged");

    Ok(info)
}

/// File sender over TCP
pub struct TcpSender {
    stream: TcpStream,
    file_path: String,
    file_size: u64,
    sha256: [u8; 32],
}

impl TcpSender {
    /// Create a sender with pre-calculated hash
    pub fn new_with_hash(stream: TcpStream, file_path: &str, file_size: u64, sha256: [u8; 32]) -> Self {
        Self {
            stream,
            file_path: file_path.to_string(),
            file_size,
            sha256,
        }
    }

    async fn handshake(&mut self) -> Result<()> {
        handshake_sender(&mut self.stream).await
    }

    async fn send_file_info(&mut self) -> Result<()> {
        send_file_info_on_stream(&mut self.stream, &self.file_path, self.file_size, self.sha256).await
    }

    pub async fn run(&mut self) -> Result<()> {
        let start = Instant::now();
        
        self.handshake().await?;
        self.send_file_info().await?;
        
        let filename = Path::new(&self.file_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        
        let mut progress = ProgressTracker::new(self.file_size, filename);
        
        // ============================================================
        // PIPELINED I/O: Read and Write run in parallel!
        // ============================================================
        // Channel allows disk reads to run ahead while network writes are in progress
        let (tx, mut rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(PIPELINE_DEPTH);
        
        let chunk_size = get_chunk_size();
        let file_path = self.file_path.clone();
        
        info!("Starting PIPELINED file transfer (depth={})...", PIPELINE_DEPTH);
        
        // READER TASK: Reads from disk into channel (runs ahead!)
        let reader_handle = tokio::spawn(async move {
            let file = File::open(&file_path).await?;
            let mut reader = BufReader::with_capacity(BUFFER_SIZE, file);
            let mut buffer = vec![0u8; chunk_size];
            
            loop {
                let n = reader.read(&mut buffer).await?;
                if n == 0 {
                    break; // EOF
                }
                // Send chunk to writer (blocks if channel full - backpressure!)
                if tx.send(bytes::Bytes::copy_from_slice(&buffer[..n])).await.is_err() {
                    // Writer dropped - transfer aborted
                    break;
                }
            }
            Ok::<_, anyhow::Error>(())
        });
        
        // WRITER: Consumes from channel and sends over TCP
        let mut total_sent: u64 = 0;
        while let Some(data) = rx.recv().await {
            write_all_timeout(&mut self.stream, &data, IO_TIMEOUT).await?;
            total_sent += data.len() as u64;
            progress.update(total_sent);
        }
        
        // Wait for reader to complete and check for errors
        reader_handle.await
            .map_err(|e| anyhow!("Reader task panicked: {}", e))?
            .map_err(|e| anyhow!("Reader error: {}", e))?;
        
        self.stream.flush().await?;
        progress.set_position(total_sent);
        
        let done = encode_simple(MessageType::Done);
        write_all_timeout(&mut self.stream, &done, HANDSHAKE_TIMEOUT).await?;
        info!("Sent DONE, waiting for final ACK...");
        
        let mut buf = [0u8; 1];
        read_exact_timeout(&mut self.stream, &mut buf, Duration::from_secs(120)).await?;
        
        if buf[0] != MessageType::Ack as u8 {
            return Err(anyhow!("Expected final ACK, got type {}", buf[0]));
        }
        
        let elapsed = start.elapsed();
        let speed_mbps = (self.file_size as f64 / (1024.0 * 1024.0)) / elapsed.as_secs_f64();
        
        progress.finish_with_message(format!("✅ Transfer complete! ({:.1} MB/s)", speed_mbps));
        info!("Transfer complete: {:.2} MB in {:.1}s ({:.1} MB/s) [PIPELINED]", 
            self.file_size as f64 / (1024.0 * 1024.0),
            elapsed.as_secs_f64(),
            speed_mbps);
        
        Ok(())
    }
}

/// File receiver over TCP
pub struct TcpReceiver {
    stream: Option<TcpStream>,
}

impl TcpReceiver {
    pub fn new(stream: TcpStream) -> Self {
        Self { stream: Some(stream) }
    }

    async fn handshake(&mut self) -> Result<()> {
        let stream = self.stream.as_mut().ok_or_else(|| anyhow!("Stream not available"))?;
        handshake_receiver(stream).await
    }

    async fn receive_file_info(&mut self) -> Result<FileInfoMessage> {
        let stream = self.stream.as_mut().ok_or_else(|| anyhow!("Stream not available"))?;
        receive_file_info_from_stream(stream).await
    }

    pub async fn run(&mut self) -> Result<()> {
        let start = Instant::now();
        
        self.handshake().await?;
        let file_info = self.receive_file_info().await?;
        
        let temp_path = format!("{}.tmp", file_info.filename);
        let progress = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let progress_clone = progress.clone();
        
        // ============================================================
        // PIPELINED I/O: Network reads and Disk writes run in parallel!
        // ============================================================
        let (tx, mut rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(PIPELINE_DEPTH);
        
        let file_size = file_info.file_size;
        let chunk_size = get_chunk_size();
        
        info!("Starting PIPELINED file transfer (depth={})...", PIPELINE_DEPTH);
        
        // Take ownership of stream for the reader task (safe with Option::take)
        let mut stream = self.stream.take()
            .ok_or_else(|| anyhow!("Stream not available"))?;
        
        // READER TASK: Reads from network into channel (runs ahead!)
        let reader_handle = tokio::spawn(async move {
            let mut total_received: u64 = 0;
            let mut buffer = vec![0u8; chunk_size];
            
            while total_received < file_size {
                let remaining = file_size - total_received;
                let to_read = std::cmp::min(remaining as usize, chunk_size);
                
                let n = match tokio::time::timeout(IO_TIMEOUT, stream.read(&mut buffer[..to_read])).await {
                    Ok(Ok(0)) => return Err(anyhow!("Connection closed unexpectedly")),
                    Ok(Ok(n)) => n,
                    Ok(Err(e)) => return Err(anyhow!("Read error: {}", e)),
                    Err(_) => return Err(anyhow!("Read timeout")),
                };
                
                // Send chunk to writer (blocks if channel full - backpressure!)
                if tx.send(bytes::Bytes::copy_from_slice(&buffer[..n])).await.is_err() {
                    break; // Writer dropped - transfer aborted
                }
                
                total_received += n as u64;
                progress_clone.store(total_received, std::sync::atomic::Ordering::Relaxed);
            }
            
            // Wait for DONE message
            let mut done_buf = [0u8; 1];
            match read_exact_timeout(&mut stream, &mut done_buf, HANDSHAKE_TIMEOUT).await {
                Ok(_) if done_buf[0] == MessageType::Done as u8 => {},
                Ok(_) => warn!("Expected DONE, got type {}", done_buf[0]),
                Err(e) => warn!("Error reading DONE: {}", e),
            }
            
            Ok::<_, anyhow::Error>(stream)
        });
        
        // WRITER TASK: Writes to disk (runs in parallel!)
        let temp_path_clone = temp_path.clone();
        let writer_handle = tokio::spawn(async move {
            let file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&temp_path_clone)
                .await?;
            
            file.set_len(file_size).await?;
            let mut writer = BufWriter::with_capacity(BUFFER_SIZE, file);
            
            while let Some(data) = rx.recv().await {
                writer.write_all(&data).await?;
            }
            
            writer.flush().await?;
            Ok::<_, anyhow::Error>(())
        });
        
        // Progress display in main thread
        let mut progress_bar = ProgressTracker::new(file_info.file_size, &file_info.filename);
        let check_interval = Duration::from_millis(100);
        
        loop {
            tokio::time::sleep(check_interval).await;
            let current = progress.load(std::sync::atomic::Ordering::Relaxed);
            progress_bar.update(current);
            
            if current >= file_size {
                break;
            }
            
            // Check if tasks are still running
            if reader_handle.is_finished() || writer_handle.is_finished() {
                break;
            }
        }
        
        // Wait for both tasks to complete
        let stream = reader_handle.await
            .map_err(|e| anyhow!("Reader task panicked: {}", e))?
            .map_err(|e| anyhow!("Reader error: {}", e))?;
        
        writer_handle.await
            .map_err(|e| anyhow!("Writer task panicked: {}", e))?
            .map_err(|e| anyhow!("Writer error: {}", e))?;
        
        // Restore stream for final ACK
        self.stream = Some(stream);
        
        let transfer_time = start.elapsed();
        let transfer_speed = (file_info.file_size as f64 / (1024.0 * 1024.0)) / transfer_time.as_secs_f64();
        info!("Transfer complete: {:.1} MB/s [PIPELINED]", transfer_speed);
        
        progress_bar.set_position(file_size);
        
        // Verify SHA256 from disk (end-to-end verification)
        progress_bar.set_message("Verifying SHA256...");
        info!("Calculating SHA256 from disk...");
        let verify_start = Instant::now();
        let calculated_hash = sha256_file(Path::new(&temp_path)).await?;
        let verify_time = verify_start.elapsed();
        info!("SHA256 verification took {:.1}s", verify_time.as_secs_f64());
        
        if calculated_hash == file_info.sha256 {
            tokio::fs::rename(&temp_path, &file_info.filename).await?;
            
            let ack = encode_simple(MessageType::Ack);
            let stream = self.stream.as_mut().ok_or_else(|| anyhow!("Stream not available"))?;
            write_all_timeout(stream, &ack, HANDSHAKE_TIMEOUT).await?;
            
            let elapsed = start.elapsed();
            let speed_mbps = (file_info.file_size as f64 / (1024.0 * 1024.0)) / elapsed.as_secs_f64();
            
            progress_bar.finish_with_message(format!("✅ Complete! SHA256 verified ({:.1} MB/s)", speed_mbps));
            info!("✅ Transfer complete! SHA256 verified.");
            info!("File saved: {}", file_info.filename);
            info!("Speed: {:.1} MB/s (incl. verification)", speed_mbps);
            
            Ok(())
        } else {
            tokio::fs::remove_file(&temp_path).await.ok();
            
            error!("SHA256 mismatch!");
            error!("Expected: {}", sha256_to_hex(&file_info.sha256));
            error!("Got:      {}", sha256_to_hex(&calculated_hash));
            
            progress_bar.finish_with_message("❌ SHA256 verification failed!".to_string());
            Err(anyhow!("SHA256 verification failed"))
        }
    }
}

#[derive(Clone, Debug)]
struct Chunk {
    id: u32,
    offset: u64,
    len: u32,
}

struct WriteChunk {
    offset: u64,
    data: Vec<u8>,
}

fn build_chunks(file_size: u64, chunk_size: usize) -> VecDeque<Chunk> {
    let mut chunks = VecDeque::new();
    if file_size == 0 {
        return chunks;
    }
    let mut offset: u64 = 0;
    let mut id: u32 = 0;
    let chunk_size = chunk_size as u64;
    while offset < file_size {
        let remaining = file_size - offset;
        let len = std::cmp::min(remaining, chunk_size) as u32;
        chunks.push_back(Chunk { id, offset, len });
        offset += len as u64;
        id = id.wrapping_add(1);
    }
    chunks
}

async fn send_chunk_ack(stream: &mut TcpStream, chunk_id: u32) -> Result<()> {
    let msg = ChunkAckMessage { chunk_id };
    write_all_timeout(stream, &msg.encode(), IO_TIMEOUT).await
}

async fn read_chunk_ack(stream: &mut TcpStream) -> Result<u32> {
    let mut buf = [0u8; 5];
    read_exact_timeout(stream, &mut buf, IO_TIMEOUT).await?;
    if buf[0] != MessageType::ChunkAck as u8 {
        return Err(anyhow!("Expected CHUNK_ACK, got type {}", buf[0]));
    }
    let mut cursor = &buf[1..];
    Ok(cursor.get_u32())
}

async fn sender_worker_loop(
    stream: &mut TcpStream,
    file_path: &str,
    queue: Arc<Mutex<VecDeque<Chunk>>>,
    remaining: Arc<AtomicUsize>,
    notify: Arc<Notify>,
    progress: Arc<AtomicU64>,
) -> Result<()> {
    let mut file = File::open(file_path).await?;
    // Reserve space for header (17 bytes) + data
    const HEADER_SIZE: usize = 17;
    let mut buffer = vec![0u8; HEADER_SIZE + get_chunk_size()];

    loop {
        if remaining.load(Ordering::Relaxed) == 0 {
            break;
        }

        let chunk_opt = {
            let mut q = queue.lock().await;
            q.pop_front()
        };

        let chunk = match chunk_opt {
            Some(c) => c,
            None => {
                if remaining.load(Ordering::Relaxed) == 0 {
                    break;
                }
                notify.notified().await;
                continue;
            }
        };

        file.seek(SeekFrom::Start(chunk.offset)).await?;
        let len = chunk.len as usize;
        
        // Read data into buffer after header space
        if let Err(e) = file.read_exact(&mut buffer[HEADER_SIZE..HEADER_SIZE+len]).await {
             let mut q = queue.lock().await;
             q.push_front(chunk);
             notify.notify_one();
             return Err(anyhow!("Read error: {}", e));
        }

        // Serialize header into the beginning
        let mut header_cursor = &mut buffer[0..HEADER_SIZE];
        header_cursor.put_u8(MessageType::Data as u8);
        header_cursor.put_u32(chunk.id);
        header_cursor.put_u64(chunk.offset);
        header_cursor.put_u32(chunk.len);

        // Send header + data in one go
        if let Err(e) = write_all_timeout(stream, &buffer[..HEADER_SIZE+len], IO_TIMEOUT).await {
            let mut q = queue.lock().await;
            q.push_front(chunk);
            notify.notify_one();
            return Err(e);
        }

        let ack_res = read_chunk_ack(stream).await;
        match ack_res {
            Ok(ack_id) => {
                if ack_id != chunk.id {
                    let id = chunk.id;
                    let mut q = queue.lock().await;
                    q.push_front(chunk);
                    notify.notify_one();
                    return Err(anyhow!("Chunk ACK mismatch: expected {}, got {}", id, ack_id));
                }
            }
            Err(e) => {
                let mut q = queue.lock().await;
                q.push_front(chunk);
                notify.notify_one();
                return Err(e);
            }
        }

        progress.fetch_add(chunk.len as u64, Ordering::Relaxed);
        let left = remaining.fetch_sub(1, Ordering::SeqCst).saturating_sub(1);
        if left == 0 {
            notify.notify_waiters();
            break;
        }
    }

    Ok(())
}

async fn read_data_header(stream: &mut TcpStream) -> Result<Chunk> {
    let mut header = [0u8; 16];
    read_exact_timeout(stream, &mut header, IO_TIMEOUT).await?;
    let mut cursor = &header[..];
    let chunk_id = cursor.get_u32();
    let offset = cursor.get_u64();
    let len = cursor.get_u32();
    Ok(Chunk { id: chunk_id, offset, len })
}

type BufferPool = Arc<Mutex<Vec<Vec<u8>>>>;

async fn disk_writer_loop(
    file_path: String,
    mut rx: tokio::sync::mpsc::Receiver<WriteChunk>,
    progress: Arc<AtomicU64>,
    pool: BufferPool,
) -> Result<()> {
    let mut file = OpenOptions::new().write(true).open(file_path).await?;
    
    while let Some(chunk) = rx.recv().await {
        file.seek(SeekFrom::Start(chunk.offset)).await?;
        file.write_all(&chunk.data).await?;
        progress.fetch_add(chunk.data.len() as u64, Ordering::Relaxed);
        
        // Recycle buffer
        let data = chunk.data;
        // Keep capacity, clear content (though next user will overwrite or resize)
        // No need to clear if we overwrite, but let's just push it back.
        // Important: check if pool is not excessively large? (optional)
        pool.lock().await.push(data);
    }
    
    file.flush().await?;
    Ok(())
}

async fn receiver_worker_loop(
    stream: &mut TcpStream,
    remaining: Arc<AtomicUsize>,
    done_flags: Arc<Vec<std::sync::atomic::AtomicBool>>,
    notify: Arc<Notify>,
    write_tx: tokio::sync::mpsc::Sender<WriteChunk>,
    expect_done: bool,
    pool: BufferPool,
) -> Result<bool> {
    // We don't allocate a persistent buffer here. We fetch one per chunk.
    let chunk_size = get_chunk_size();

    loop {
        if remaining.load(Ordering::Relaxed) == 0 && !expect_done {
            break;
        }

        let mut type_buf = [0u8; 1];
        let read_type = read_exact_timeout(stream, &mut type_buf, IO_TIMEOUT).await;
        let msg_type = match read_type {
            Ok(_) => type_buf[0],
            Err(e) => {
                if expect_done {
                    return Err(e);
                }
                break;
            }
        };

        if msg_type == MessageType::Data as u8 {
            let chunk = read_data_header(stream).await?;
            if (chunk.id as usize) >= done_flags.len() {
                return Err(anyhow!("Invalid chunk id {}", chunk.id));
            }
            let len = chunk.len as usize;
            
            // Get buffer from pool or allocate
            let mut buffer = {
                let mut p = pool.lock().await;
                p.pop().unwrap_or_else(|| Vec::with_capacity(chunk_size))
            };
            // Resize to exact len needed for read, but keep capacity if possible
            if buffer.len() < len {
                buffer.resize(len, 0u8);
            } else {
                buffer.truncate(len);
            }

            read_exact_timeout(stream, &mut buffer[..len], IO_TIMEOUT).await?;

            let already_done = done_flags[chunk.id as usize]
                .swap(true, Ordering::SeqCst);
            if !already_done {
                let write_chunk = WriteChunk {
                    offset: chunk.offset,
                    data: buffer, // Move ownership
                };
                if write_tx.send(write_chunk).await.is_err() {
                    return Err(anyhow!("Write channel closed"));
                }
                
                let left = remaining.fetch_sub(1, Ordering::SeqCst).saturating_sub(1);
                if left == 0 {
                    notify.notify_waiters();
                }
            } else {
                // Return unused buffer to pool
                pool.lock().await.push(buffer);
            }

            send_chunk_ack(stream, chunk.id).await?;
        } else if msg_type == MessageType::Done as u8 {
            return Ok(true);
        } else {
            return Err(anyhow!("Unexpected frame type {}", msg_type));
        }
    }

    Ok(false)
}

pub async fn run_multi_sender(
    mut streams: Vec<TcpStream>,
    file_path: &str,
    file_size: u64,
    sha256: [u8; 32],
) -> Result<()> {
    if streams.is_empty() {
        return Err(anyhow!("No streams available for multi-send"));
    }

    // Sort streams by remote port to ensure both sides agree on ordering
    streams.sort_by_key(|s| s.peer_addr().map(|a| a.port()).unwrap_or(0));
    info!("Sorted {} streams by remote port for deterministic ordering", streams.len());

    let total_streams = streams.len();
    for (i, stream) in streams.iter_mut().enumerate() {
        handshake_sender(stream).await?;
        send_stream_info(stream, i as u32, total_streams as u32).await?;
    }

    let mut control_stream = streams.remove(0);
    send_file_info_on_stream(&mut control_stream, file_path, file_size, sha256).await?;

    let chunk_size = get_chunk_size();
    let queue = Arc::new(Mutex::new(build_chunks(file_size, chunk_size)));
    let total_chunks = queue.lock().await.len();
    let remaining = Arc::new(AtomicUsize::new(total_chunks));
    let notify = Arc::new(Notify::new());
    let progress = Arc::new(AtomicU64::new(0));

    let filename = Path::new(file_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");
    let progress_bar = create_progress_bar(file_size, filename);
    let progress_bar_clone = progress_bar.clone();
    let progress_clone = progress.clone();
    let progress_handle = tokio::spawn(async move {
        let check_interval = Duration::from_millis(100);
        loop {
            tokio::time::sleep(check_interval).await;
            let current = progress_clone.load(Ordering::Relaxed);
            progress_bar_clone.set_position(current);
            if current >= file_size {
                break;
            }
        }
    });

    let mut handles = Vec::new();
    for stream in streams.into_iter() {
        let queue = queue.clone();
        let remaining = remaining.clone();
        let notify = notify.clone();
        let progress = progress.clone();
        let path = file_path.to_string();
        handles.push(tokio::spawn(async move {
            let mut s = stream;
            if let Err(e) = sender_worker_loop(&mut s, &path, queue, remaining, notify, progress).await {
                warn!("Sender stream error: {}", e);
            }
        }));
    }

    if let Err(e) = sender_worker_loop(
        &mut control_stream,
        file_path,
        queue.clone(),
        remaining.clone(),
        notify.clone(),
        progress.clone(),
    ).await {
        progress_handle.abort();
        return Err(e);
    }

    for handle in handles {
        let _ = handle.await;
    }

    if remaining.load(Ordering::Relaxed) > 0 {
        progress_handle.abort();
        return Err(anyhow!("Transfer incomplete: {} chunks remaining", remaining.load(Ordering::Relaxed)));
    }

    control_stream.flush().await?;

    let done = encode_simple(MessageType::Done);
    write_all_timeout(&mut control_stream, &done, HANDSHAKE_TIMEOUT).await?;
    info!("Sent DONE, waiting for final ACK...");

    let mut buf = [0u8; 1];
    read_exact_timeout(&mut control_stream, &mut buf, Duration::from_secs(120)).await?;
    if buf[0] != MessageType::Ack as u8 {
        return Err(anyhow!("Expected final ACK, got type {}", buf[0]));
    }

    progress_bar.set_position(file_size);
    progress_bar.finish_with_message("✅ Transfer complete".to_string());
    let _ = progress_handle.await;
    Ok(())
}

pub async fn run_multi_receiver(mut streams: Vec<TcpStream>) -> Result<()> {
    let start = Instant::now();
    if streams.is_empty() {
        return Err(anyhow!("No streams available for multi-receive"));
    }

    // Sort streams by remote port to ensure both sides agree on ordering
    streams.sort_by_key(|s| s.peer_addr().map(|a| a.port()).unwrap_or(0));
    info!("Sorted {} streams by remote port for deterministic ordering", streams.len());

    let mut total_streams: Option<usize> = None;
    let mut by_index: Vec<Option<TcpStream>> = Vec::new();

    for mut stream in streams.into_iter() {
        handshake_receiver(&mut stream).await?;
        let info = recv_stream_info(&mut stream).await?;
        let total = info.total_streams as usize;
        if total == 0 {
            return Err(anyhow!("Invalid total_streams=0"));
        }
        if total_streams.is_none() {
            total_streams = Some(total);
            by_index.resize_with(total, || None);
        } else if total_streams != Some(total) {
            return Err(anyhow!("Mismatched total_streams across connections"));
        }
        let idx = info.stream_index as usize;
        if idx >= total {
            return Err(anyhow!("Invalid stream_index {}", idx));
        }
        if by_index[idx].is_some() {
            return Err(anyhow!("Duplicate stream_index {}", idx));
        }
        by_index[idx] = Some(stream);
    }

    let total_streams = total_streams.unwrap_or(0);
    if by_index.iter().any(|s| s.is_none()) {
        return Err(anyhow!("Missing stream(s) for multi-transfer"));
    }

    let mut streams_by_index: Vec<TcpStream> = by_index.into_iter().map(|s| s.unwrap()).collect();
    if total_streams != streams_by_index.len() {
        return Err(anyhow!("Stream count mismatch"));
    }

    let mut control_stream = streams_by_index.remove(0);
    let file_info = receive_file_info_from_stream(&mut control_stream).await?;

    let temp_path = format!("{}.tmp", file_info.filename);
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&temp_path)
        .await?;
    file.set_len(file_info.file_size).await?;
    drop(file);

    let chunk_size = get_chunk_size() as u64;
    let total_chunks = if file_info.file_size == 0 {
        0
    } else {
        ((file_info.file_size + chunk_size - 1) / chunk_size) as usize
    };
    let remaining = Arc::new(AtomicUsize::new(total_chunks));
    let done_flags = Arc::new((0..total_chunks).map(|_| AtomicBool::new(false)).collect::<Vec<_>>());
    let notify = Arc::new(Notify::new());
    let progress = Arc::new(AtomicU64::new(0));
    let buffer_pool: BufferPool = Arc::new(Mutex::new(Vec::new()));

    let (write_tx, write_rx) = tokio::sync::mpsc::channel::<WriteChunk>(32);
    let writer_progress = progress.clone();
    let temp_path_clone = temp_path.clone();
    let writer_pool = buffer_pool.clone();
    
    let writer_handle = tokio::spawn(async move {
        disk_writer_loop(temp_path_clone, write_rx, writer_progress, writer_pool).await
    });

    let progress_bar = create_progress_bar(file_info.file_size, &file_info.filename);
    let progress_bar_clone = progress_bar.clone();
    let progress_clone = progress.clone();
    let progress_handle = tokio::spawn(async move {
        let check_interval = Duration::from_millis(100);
        loop {
            tokio::time::sleep(check_interval).await;
            let current = progress_clone.load(Ordering::Relaxed);
            progress_bar_clone.set_position(current);
            if current >= file_info.file_size {
                break;
            }
        }
    });

    let mut handles = Vec::new();
    for stream in streams_by_index.into_iter() {
        let remaining = remaining.clone();
        let done_flags = done_flags.clone();
        let notify = notify.clone();
        let write_tx = write_tx.clone();
        let pool = buffer_pool.clone();
        handles.push(tokio::spawn(async move {
            let mut s = stream;
            if let Err(e) = receiver_worker_loop(&mut s, remaining, done_flags, notify, write_tx, false, pool).await {
                warn!("Receiver stream error: {}", e);
            }
        }));
    }

    let done_seen = match receiver_worker_loop(
        &mut control_stream,
        remaining.clone(),
        done_flags.clone(),
        notify.clone(),
        write_tx,
        true,
        buffer_pool.clone(),
    ).await {
        Ok(v) => v,
        Err(e) => {
            progress_handle.abort();
            return Err(e);
        }
    };

    for handle in handles {
        let _ = handle.await;
    }

    if !done_seen {
        progress_handle.abort();
        return Err(anyhow!("Did not receive DONE on control stream"));
    }

    while remaining.load(Ordering::Relaxed) > 0 {
        notify.notified().await;
    }
    
    // Wait for writer to finish flushing
    writer_handle.await.map_err(|e| anyhow!("Writer task panicked: {}", e))??;

    progress_bar.set_position(file_info.file_size);
    progress_bar.set_message("Verifying SHA256...");
    info!("Calculating SHA256 from disk...");
    let verify_start = Instant::now();
    let calculated_hash = sha256_file(Path::new(&temp_path)).await?;
    let verify_time = verify_start.elapsed();
    info!("SHA256 verification took {:.1}s", verify_time.as_secs_f64());

    if calculated_hash == file_info.sha256 {
        tokio::fs::rename(&temp_path, &file_info.filename).await?;

        let ack = encode_simple(MessageType::Ack);
        write_all_timeout(&mut control_stream, &ack, HANDSHAKE_TIMEOUT).await?;

        let elapsed = start.elapsed();
        let speed_mbps = (file_info.file_size as f64 / (1024.0 * 1024.0)) / elapsed.as_secs_f64();
        progress_bar.finish_with_message(format!("✅ Complete! SHA256 verified"));
        info!("✅ Transfer complete! SHA256 verified.");
        info!("File saved: {}", file_info.filename);
        info!("Speed: {:.1} MB/s (incl. verification)", speed_mbps);
        let _ = progress_handle.await;
        Ok(())
    } else {
        tokio::fs::remove_file(&temp_path).await.ok();

        error!("SHA256 mismatch!");
        error!("Expected: {}", sha256_to_hex(&file_info.sha256));
        error!("Got:      {}", sha256_to_hex(&calculated_hash));

        progress_bar.finish_with_message("❌ SHA256 verification failed!".to_string());
        let _ = progress_handle.await;
        Err(anyhow!("SHA256 verification failed"))
    }
}
