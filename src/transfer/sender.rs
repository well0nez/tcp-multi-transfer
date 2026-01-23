//! TCP File Transfer Sender Implementation

use std::collections::VecDeque;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Notify};
use bytes::Buf;
use crc32fast::Hasher;
use anyhow::{Result, anyhow};
use tracing::{info, debug};

use crate::protocol::transfer::*;
use super::helpers::*;

/// Buffer size for file I/O (16MB)
const BUFFER_SIZE: usize = 16 * 1024 * 1024;

/// Pipeline depth for async I/O (16 chunks = ~128MB in flight at 8MB chunks)
const PIPELINE_DEPTH: usize = 16;

/// Timeout for individual read/write operations
const IO_TIMEOUT: Duration = Duration::from_secs(120);

/// Protocol timeout for handshake
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);

/// Sender handshake
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
    info!("Chunk size: {} KB", super::get_chunk_size() / 1024);

    write_all_timeout(stream, &file_info.encode(), HANDSHAKE_TIMEOUT).await?;

    let mut buf = [0u8; 1];
    read_exact_timeout(stream, &mut buf, HANDSHAKE_TIMEOUT).await?;

    if buf[0] != MessageType::FileInfoAck as u8 {
        return Err(anyhow!("Expected FILE_INFO_ACK, got type {}", buf[0]));
    }

    info!("File info acknowledged");
    Ok(())
}

async fn read_chunk_ack_message(stream: &mut TcpStream) -> Result<ChunkAckMessage> {
    let mut buf = [0u8; 5];
    read_exact_timeout(stream, &mut buf, IO_TIMEOUT).await?;
    ChunkAckMessage::decode(&buf).ok_or_else(|| anyhow!("Failed to parse CHUNK_ACK"))
}

pub struct TcpSender {
    stream: TcpStream,
    file_path: String,
    file_size: u64,
    sha256: [u8; 32],
}

impl TcpSender {
    pub fn new_with_hash(stream: TcpStream, file_path: &str, file_size: u64, sha256: [u8; 32]) -> Self {
        Self { stream, file_path: file_path.to_string(), file_size, sha256 }
    }

    pub async fn run(&mut self) -> Result<()> {
        let start = Instant::now();
        handshake_sender(&mut self.stream).await?;
        send_file_info_on_stream(&mut self.stream, &self.file_path, self.file_size, self.sha256).await?;
        
        let filename = Path::new(&self.file_path).file_name().and_then(|n| n.to_str()).unwrap_or("unknown");
        let mut progress = ProgressTracker::new(self.file_size, filename);
        let (tx, mut rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(PIPELINE_DEPTH);
        let chunk_size = super::get_chunk_size();
        let file_path = self.file_path.clone();
        
        info!("Starting PIPELINED file transfer (depth={})...", PIPELINE_DEPTH);
        
        let reader_handle = tokio::spawn(async move {
            let file = File::open(&file_path).await?;
            let mut reader = BufReader::with_capacity(BUFFER_SIZE, file);
            let mut buffer = vec![0u8; chunk_size];
            loop {
                let n = reader.read(&mut buffer).await?;
                if n == 0 { break; }
                if tx.send(bytes::Bytes::copy_from_slice(&buffer[..n])).await.is_err() { break; }
            }
            Ok::<_, anyhow::Error>(())
        });
        
        let mut total_sent: u64 = 0;
        while let Some(data) = rx.recv().await {
            write_all_timeout(&mut self.stream, &data, IO_TIMEOUT).await?;
            total_sent += data.len() as u64;
            progress.update(total_sent);
        }
        
        reader_handle.await.map_err(|e| anyhow!("Reader task panicked: {}", e))??;
        self.stream.flush().await?;
        progress.set_position(total_sent);
        
        let done = encode_simple(MessageType::Done);
        write_all_timeout(&mut self.stream, &done, HANDSHAKE_TIMEOUT).await?;
        info!("Sent DONE, waiting for final ACK...");
        
        let mut buf = [0u8; 1];
        read_exact_timeout(&mut self.stream, &mut buf, Duration::from_secs(120)).await?;
        if buf[0] != MessageType::Ack as u8 { return Err(anyhow!("Expected final ACK, got type {}", buf[0])); }
        
        let elapsed = start.elapsed();
        let speed_mbps = (self.file_size as f64 / (1024.0 * 1024.0)) / elapsed.as_secs_f64();
        progress.finish_with_message(format!("Transfer complete! ({:.1} MB/s)", speed_mbps));
        info!("Transfer complete: {:.2} MB in {:.1}s ({:.1} MB/s)", self.file_size as f64 / 1048576.0, elapsed.as_secs_f64(), speed_mbps);
        Ok(())
    }
}

pub async fn run_multi_sender(
    mut streams: Vec<TcpStream>,
    file_path: &str,
    file_size: u64,
    sha256: [u8; 32],
) -> Result<()> {
    if streams.is_empty() { return Err(anyhow!("No streams")); }
    
    // Sort streams deterministically
    streams.sort_by_key(|s| s.peer_addr().map(|a| a.port()).unwrap_or(0));
    info!("Sorted {} streams by remote port", streams.len());
    
    let total_streams = streams.len();
    for (i, stream) in streams.iter_mut().enumerate() {
        // Handshake + FileInfo only on first stream (heavy protocol setup)
        if i == 0 {
            handshake_sender(stream).await?;
            send_file_info_on_stream(stream, file_path, file_size, sha256).await?;
        }
        
        // StreamInfo on ALL streams (lightweight stream validation)
        send_stream_info(stream, i as u32, total_streams as u32).await?;
    }
    
    let chunk_size = super::get_chunk_size();
    let total_chunks = ((file_size + chunk_size as u64 - 1) / chunk_size as u64) as u32;
    let pending = Arc::new(Mutex::new((0..total_chunks).collect::<VecDeque<_>>()));
    let notify = Arc::new(Notify::new());
    let completed_chunks = Arc::new(AtomicUsize::new(0));
    let completed_bytes = Arc::new(AtomicU64::new(0));
    
    let filename = Path::new(file_path).file_name().and_then(|n| n.to_str()).unwrap_or("unknown");
    let mut progress = ProgressTracker::new(file_size, filename);
    
    let mut handles = Vec::new();
    for stream in streams {
        let file_path = file_path.to_string();
        let pending = pending.clone();
        let notify = notify.clone();
        let completed_chunks = completed_chunks.clone();
        let completed_bytes = completed_bytes.clone();
        handles.push(tokio::spawn(async move {
            sender_worker(stream, file_path, file_size, pending, notify, completed_chunks, completed_bytes, total_chunks, chunk_size).await
        }));
    }
    
    loop {
        let done_bytes = completed_bytes.load(Ordering::Relaxed);
        progress.update(done_bytes);
        if completed_chunks.load(Ordering::Relaxed) as u32 >= total_chunks { break; }
        if handles.iter().all(|h| h.is_finished()) { break; }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    
    let mut returned_streams = Vec::new();
    for handle in handles {
        if let Ok(Ok(stream)) = handle.await {
            returned_streams.push(stream);
        }
    }
    
    if completed_chunks.load(Ordering::Relaxed) as u32 != total_chunks {
        return Err(anyhow!("Transfer incomplete"));
    }
    
    let mut done_stream = returned_streams.into_iter().next().ok_or_else(|| anyhow!("No stream for Done"))?;
    
    let done = encode_simple(MessageType::Done);
    write_all_timeout(&mut done_stream, &done, HANDSHAKE_TIMEOUT).await?;
    let mut ack_buf = [0u8; 1];
    read_exact_timeout(&mut done_stream, &mut ack_buf, Duration::from_secs(120)).await?;
    if ack_buf[0] != MessageType::Ack as u8 { return Err(anyhow!("Expected final ACK")); }
    
    progress.finish_with_message("Transfer complete!".to_string());
    Ok(())
}

async fn sender_worker(
    mut stream: TcpStream,
    file_path: String,
    file_size: u64,
    pending: Arc<Mutex<VecDeque<u32>>>,
    notify: Arc<Notify>,
    completed_chunks: Arc<AtomicUsize>,
    completed_bytes: Arc<AtomicU64>,
    total_chunks: u32,
    chunk_size: usize,
) -> Result<TcpStream> {
    let mut file = File::open(&file_path).await?;
    let mut buffer = vec![0u8; chunk_size];
    
    loop {
        let chunk_id = {
            let mut queue = pending.lock().await;
            queue.pop_front()
        };
        
        let chunk_id = match chunk_id {
            Some(id) => id,
            None => {
                if completed_chunks.load(Ordering::Relaxed) as u32 >= total_chunks { break; }
                notify.notified().await;
                continue;
            }
        };
        
        let offset = chunk_id as u64 * chunk_size as u64;
        let remaining = file_size.saturating_sub(offset);
        let len = std::cmp::min(remaining, chunk_size as u64) as usize;
        
        file.seek(std::io::SeekFrom::Start(offset)).await?;
        file.read_exact(&mut buffer[..len]).await?;
        
        let mut hasher = Hasher::new();
        hasher.update(&buffer[..len]);
        let hash32 = hasher.finalize();
        
        let header = ChunkHeaderMessage { chunk_id, offset, len: len as u32, hash32 };
        
        write_all_timeout(&mut stream, &header.encode(), IO_TIMEOUT).await?;
        write_all_timeout(&mut stream, &buffer[..len], IO_TIMEOUT).await?;
        
        match read_chunk_ack_message(&mut stream).await {
            Ok(ack) if ack.is_nack => {
                pending.lock().await.push_back(chunk_id);
                notify.notify_one();
            }
            Ok(_) => {
                completed_chunks.fetch_add(1, Ordering::Relaxed);
                completed_bytes.fetch_add(len as u64, Ordering::Relaxed);
                if completed_chunks.load(Ordering::Relaxed) as u32 >= total_chunks {
                    notify.notify_waiters();
                }
            }
            Err(_) => {
                pending.lock().await.push_back(chunk_id);
                notify.notify_one();
                return Err(anyhow!("Ack error"));
            }
        }
    }
    Ok(stream)
}