//! TCP File Transfer Receiver Implementation

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::fs::OpenOptions;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufWriter};
use tokio::net::TcpStream;
use tokio::sync::Notify;
use bytes::Buf;
use crc32fast::Hasher;
use anyhow::{Result, anyhow};
use tracing::{info, warn, debug};
use sha2::Digest;

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

/// Receiver handshake
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

async fn receive_file_info_on_stream(stream: &mut TcpStream) -> Result<FileInfoMessage> {
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

pub struct TcpReceiver {
    stream: Option<TcpStream>,
}

impl TcpReceiver {
    pub fn new(stream: TcpStream) -> Self { Self { stream: Some(stream) } }

    pub async fn run(&mut self) -> Result<()> {
        let start = std::time::Instant::now();
        let mut stream = self.stream.take().ok_or_else(|| anyhow!("Stream not available"))?;
        handshake_receiver(&mut stream).await?;
        let file_info = receive_file_info_on_stream(&mut stream).await?;
        
        let temp_path = format!("{}.tmp", file_info.filename);
        let progress = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let progress_clone = progress.clone();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(PIPELINE_DEPTH);
        let file_size = file_info.file_size;
        let chunk_size = super::get_chunk_size();
        
        info!("Starting PIPELINED file transfer (depth={})...", PIPELINE_DEPTH);
        
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
                if tx.send(bytes::Bytes::copy_from_slice(&buffer[..n])).await.is_err() { break; }
                total_received += n as u64;
                progress_clone.store(total_received, std::sync::atomic::Ordering::Relaxed);
            }
            let mut done_buf = [0u8; 1];
            match read_exact_timeout(&mut stream, &mut done_buf, HANDSHAKE_TIMEOUT).await {
                Ok(_) if done_buf[0] == MessageType::Done as u8 => {},
                Ok(_) => warn!("Expected DONE, got type {}", done_buf[0]),
                Err(e) => warn!("Error reading DONE: {}", e),
            }
            Ok::<_, anyhow::Error>(stream)
        });
        
        let temp_path_clone = temp_path.clone();
        let writer_handle = tokio::spawn(async move {
            let file = OpenOptions::new().create(true).write(true).truncate(true).open(&temp_path_clone).await?;
            file.set_len(file_size).await?;
            let mut writer = BufWriter::with_capacity(BUFFER_SIZE, file);
            while let Some(data) = rx.recv().await { writer.write_all(&data).await?; }
            writer.flush().await?;
            Ok::<_, anyhow::Error>(())
        });
        
        let mut progress_bar = ProgressTracker::new(file_info.file_size, &file_info.filename);
        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let current = progress.load(std::sync::atomic::Ordering::Relaxed);
            progress_bar.update(current);
            if current >= file_size { break; }
            if reader_handle.is_finished() || writer_handle.is_finished() { break; }
        }
        
        let stream = reader_handle.await.map_err(|e| anyhow!("Reader panicked: {}", e))??;
        writer_handle.await.map_err(|e| anyhow!("Writer panicked: {}", e))??;
        self.stream = Some(stream);
        
        let transfer_time = start.elapsed();
        let transfer_speed = (file_info.file_size as f64 / 1048576.0) / transfer_time.as_secs_f64();
        info!("Transfer complete: {:.1} MB/s [PIPELINED]", transfer_speed);
        
        progress_bar.set_position(file_size);
        progress_bar.set_message("Verifying SHA256...");
        info!("Calculating SHA256 from disk...");
        let calculated_hash = sha256_file(Path::new(&temp_path)).await?;
        
        if calculated_hash == file_info.sha256 {
            tokio::fs::rename(&temp_path, &file_info.filename).await?;
            let ack = encode_simple(MessageType::Ack);
            let stream = self.stream.as_mut().unwrap();
            write_all_timeout(stream, &ack, HANDSHAKE_TIMEOUT).await?;
            let speed_mbps = (file_info.file_size as f64 / 1048576.0) / start.elapsed().as_secs_f64();
            progress_bar.finish_with_message(format!("Complete! ({:.1} MB/s)", speed_mbps));
            info!("File saved: {}", file_info.filename);
            Ok(())
        } else {
            tokio::fs::remove_file(&temp_path).await.ok();
            tracing::error!("SHA256 mismatch!");
            progress_bar.finish_with_message("SHA256 verification failed!".to_string());
            Err(anyhow!("SHA256 verification failed"))
        }
    }
}

async fn sha256_file(path: &Path) -> Result<[u8; 32]> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = sha2::Sha256::new();
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

pub async fn run_multi_receiver(mut streams: Vec<TcpStream>) -> Result<()> {
    if streams.is_empty() { return Err(anyhow!("No streams")); }
    
    streams.sort_by_key(|s| s.peer_addr().map(|a| a.port()).unwrap_or(0));
    info!("Sorted {} streams by remote port", streams.len());
    
    // Handshake + FileInfo only on first stream (heavy protocol setup)
    let mut file_info: Option<FileInfoMessage> = None;
    for (i, stream) in streams.iter_mut().enumerate() {
        if i == 0 {
            handshake_receiver(stream).await?;
            file_info = Some(receive_file_info_on_stream(stream).await?);
        }
        
        // StreamInfo on ALL streams (lightweight stream validation)
        recv_stream_info(stream).await?;
    }
    
    let file_info = file_info.ok_or_else(|| anyhow!("No file info received"))?;
    
    let temp_path = format!("{}.tmp", file_info.filename);
    let file = OpenOptions::new().create(true).write(true).truncate(true).open(&temp_path).await?;
    file.set_len(file_info.file_size).await?;
    drop(file);
    
    let chunk_size = super::get_chunk_size();
    let total_chunks = ((file_info.file_size + chunk_size as u64 - 1) / chunk_size as u64) as u32;
    
    let received_flags = Arc::new((0..total_chunks).map(|_| AtomicBool::new(false)).collect::<Vec<_>>());
    let received_count = Arc::new(AtomicUsize::new(0));
    let received_bytes = Arc::new(AtomicU64::new(0));
    let done_received = Arc::new(AtomicBool::new(false));
    let done_notify = Arc::new(Notify::new());
    
    let mut handles = Vec::new();
    for (i, stream) in streams.into_iter().enumerate() {
        let temp = temp_path.clone();
        let flags = received_flags.clone();
        let count = received_count.clone();
        let bytes = received_bytes.clone();
        let done = done_received.clone();
        let notify = done_notify.clone();
        handles.push(tokio::spawn(async move {
            receiver_worker(i as u8, stream, temp, file_info.file_size, flags, count, bytes, done, notify).await
        }));
    }
    
    let mut progress_bar = ProgressTracker::new(file_info.file_size, &file_info.filename);
    loop {
        let current = received_bytes.load(Ordering::Relaxed);
        progress_bar.update(current);
        if done_received.load(Ordering::Relaxed) { break; }
        if handles.iter().all(|h| h.is_finished()) { break; }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    
    for handle in handles { let _ = handle.await; }
    
    if received_count.load(Ordering::Relaxed) as u32 != total_chunks {
        return Err(anyhow!("Transfer incomplete"));
    }
    
    progress_bar.set_message("Verifying SHA256...");
    let calculated_hash = sha256_file(Path::new(&temp_path)).await?;
    if calculated_hash == file_info.sha256 {
        tokio::fs::rename(&temp_path, &file_info.filename).await?;
        progress_bar.finish_with_message("Complete!".to_string());
        Ok(())
    } else {
        Err(anyhow!("SHA256 mismatch"))
    }
}

async fn receiver_worker(
    _conn_id: u8,
    mut stream: TcpStream,
    temp_path: String,
    _file_size: u64,
    received_flags: Arc<Vec<AtomicBool>>,
    received_count: Arc<AtomicUsize>,
    received_bytes: Arc<AtomicU64>,
    done_received: Arc<AtomicBool>,
    done_notify: Arc<Notify>,
) -> Result<TcpStream> {
    let mut file = OpenOptions::new().write(true).open(&temp_path).await?;
    let _chunk_size = super::get_chunk_size();
    let _total_chunks = received_flags.len() as u32;
    
    loop {
        if done_received.load(Ordering::Relaxed) { break; }
        
        let mut type_buf = [0u8; 1];
        let read_res = tokio::select! {
            _ = done_notify.notified() => { return Ok(stream); }
            res = read_exact_timeout(&mut stream, &mut type_buf, IO_TIMEOUT) => res,
        };
        
        if let Err(_) = read_res { if done_received.load(Ordering::Relaxed) { break; } else { return Err(anyhow!("Read error")); } }
        
        let msg_type = MessageType::from_u8(type_buf[0]).ok_or_else(|| anyhow!("Unknown msg"))?;
        
        match msg_type {
            MessageType::ChunkHeader => {
                let mut header_rest = [0u8; 20];
                read_exact_timeout(&mut stream, &mut header_rest, IO_TIMEOUT).await?;
                let mut header_buf = [0u8; 21];
                header_buf[0] = type_buf[0];
                header_buf[1..].copy_from_slice(&header_rest);
                let header = ChunkHeaderMessage::decode(&header_buf).unwrap();
                
                let mut data = vec![0u8; header.len as usize];
                read_exact_timeout(&mut stream, &mut data, IO_TIMEOUT).await?;
                
                let mut hasher = Hasher::new();
                hasher.update(&data);
                if hasher.finalize() != header.hash32 {
                    let nack = ChunkAckMessage { chunk_id: header.chunk_id, is_nack: true };
                    write_all_timeout(&mut stream, &nack.encode(), IO_TIMEOUT).await?;
                    continue;
                }
                
                file.seek(std::io::SeekFrom::Start(header.offset)).await?;
                file.write_all(&data).await?;
                
                if !received_flags[header.chunk_id as usize].swap(true, Ordering::AcqRel) {
                    received_count.fetch_add(1, Ordering::Relaxed);
                    received_bytes.fetch_add(header.len as u64, Ordering::Relaxed);
                }
                
                let ack = ChunkAckMessage { chunk_id: header.chunk_id, is_nack: false };
                write_all_timeout(&mut stream, &ack.encode(), IO_TIMEOUT).await?;
            }
            MessageType::Done => {
                done_received.store(true, Ordering::Relaxed);
                done_notify.notify_waiters();
                let ack = encode_simple(MessageType::Ack);
                write_all_timeout(&mut stream, &ack, HANDSHAKE_TIMEOUT).await?;
                break;
            }
            _ => return Err(anyhow!("Unexpected msg")),
        }
    }
    Ok(stream)
}