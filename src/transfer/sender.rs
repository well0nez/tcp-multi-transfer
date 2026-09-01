//! TCP File Transfer Sender Implementation

use std::collections::VecDeque;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Notify};
use bytes::Buf;
use crc32fast::Hasher;
use anyhow::{Result, anyhow};
use tracing::{info, debug, warn};

use crate::protocol::transfer::*;
use super::helpers::*;

/// Progress update chunk size for socket writes (256KB)
const PROGRESS_IO_CHUNK: usize = 256 * 1024;

use super::{IO_TIMEOUT, HANDSHAKE_TIMEOUT};

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

async fn send_stream_info(
    stream: &mut TcpStream,
    stream_index: u32,
    total_streams: u32,
    chunk_size: u32,
) -> Result<()> {
    let info = StreamInfoMessage { stream_index, total_streams, chunk_size };
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

async fn write_payload_with_progress(
    stream: &mut TcpStream,
    buf: &[u8],
    timeout: Duration,
    counter: &Arc<AtomicU64>,
) -> Result<()> {
    let mut offset = 0;
    while offset < buf.len() {
        let end = std::cmp::min(offset + PROGRESS_IO_CHUNK, buf.len());
        write_all_timeout(stream, &buf[offset..end], timeout).await?;
        counter.fetch_add((end - offset) as u64, Ordering::Relaxed);
        offset = end;
    }
    Ok(())
}

pub async fn run_multi_sender(
    mut streams: Vec<TcpStream>,
    file_path: &str,
    file_size: u64,
    sha256: [u8; 32],
) -> Result<super::TransferReport> {
    if streams.is_empty() { return Err(anyhow!("No streams")); }
    let start = Instant::now();
    let stream_count = streams.len();
    info!("Using {} streams in connection order", streams.len());
    
    for (i, stream) in streams.iter().enumerate() {
        if i != 0 {
            configure_tcp_socket(stream)?;
        }
    }
    
    let total_streams = streams.len();
    // Der Sender legt die Blockgroesse fest und teilt sie mit; sie darf nicht
    // auf beiden Seiten unabhaengig geraten werden.
    let chunk_size = super::chunk_size_fuer(file_size, total_streams);
    info!("Block size {} KB for {:.2} MB across {} streams",
          chunk_size / 1024, file_size as f64 / 1048576.0, total_streams);

    // Der erste Strom traegt den Handschlag; faellt der aus, geht gar nichts.
    handshake_sender(&mut streams[0]).await?;
    send_file_info_on_stream(&mut streams[0], file_path, file_size, sha256).await?;

    // Die uebrigen duerfen einzeln ausfallen. Enden die Seiten mit
    // unterschiedlich vielen Verbindungen — eine Seite meldet established, die
    // andere gibt nach Wiederholungen auf —, ist die Gegenstelle eines Stroms
    // zu. Frueher riss das den ganzen Transfer mit; jetzt faellt nur dieser
    // Strom weg.
    let mut brauchbar = Vec::with_capacity(streams.len());
    for (i, mut stream) in streams.into_iter().enumerate() {
        match send_stream_info(&mut stream, i as u32, total_streams as u32, chunk_size as u32).await {
            Ok(()) => brauchbar.push(stream),
            Err(e) if i == 0 => return Err(e),
            Err(e) => warn!("Stream {} dropped during setup: {}", i, e),
        }
    }
    let streams = brauchbar;
    if streams.is_empty() { return Err(anyhow!("No usable stream left")); }
    let nach_setup = Instant::now();
    let total_chunks = ((file_size + chunk_size as u64 - 1) / chunk_size as u64) as u32;
    let pending = Arc::new(Mutex::new((0..total_chunks).collect::<VecDeque<_>>()));
    let notify = Arc::new(Notify::new());
    let completed_chunks = Arc::new(AtomicUsize::new(0));
    let completed_bytes = Arc::new(AtomicU64::new(0));
    let sent_bytes = Arc::new(AtomicU64::new(0));
    
    let filename = Path::new(file_path).file_name().and_then(|n| n.to_str()).unwrap_or("unknown");
    let progress = ProgressTracker::with_bytes_and_speed(file_size, filename, sent_bytes.clone(), completed_bytes.clone());
    
    let mut handles = Vec::new();
    for stream in streams {
        let file_path = file_path.to_string();
        let pending = pending.clone();
        let notify = notify.clone();
        let completed_chunks = completed_chunks.clone();
        let completed_bytes = completed_bytes.clone();
        let sent_bytes = sent_bytes.clone();
        handles.push(tokio::spawn(async move {
            sender_worker(stream, file_path, file_size, pending, notify, completed_chunks, completed_bytes, sent_bytes, total_chunks, chunk_size).await
        }));
    }
    
    loop {
        if completed_chunks.load(Ordering::Relaxed) as u32 >= total_chunks { break; }
        if handles.iter().all(|h| h.is_finished()) { break; }
        tokio::time::sleep(Duration::from_millis(200)).await;
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
    let nach_nutzlast = Instant::now();
    
    let mut done_stream = returned_streams.into_iter().next().ok_or_else(|| anyhow!("No stream for Done"))?;
    
    let done = encode_simple(MessageType::Done);
    write_all_timeout(&mut done_stream, &done, HANDSHAKE_TIMEOUT).await?;
    let mut ack_buf = [0u8; 1];
    read_exact_timeout(&mut done_stream, &mut ack_buf, Duration::from_secs(120)).await?;
    if ack_buf[0] != MessageType::Ack as u8 { return Err(anyhow!("Expected final ACK")); }
    
    progress.set_position(file_size);
    progress.finish_with_message("Transfer complete!".to_string());
    Ok(super::TransferReport {
        bytes: file_size,
        streams: stream_count,
        setup_ms: (nach_setup - start).as_secs_f64() * 1000.0,
        payload_ms: (nach_nutzlast - nach_setup).as_secs_f64() * 1000.0,
        finish_ms: nach_nutzlast.elapsed().as_secs_f64() * 1000.0,
        total_ms: start.elapsed().as_secs_f64() * 1000.0,
        tcp_info: crate::netinfo::tcp_info(&done_stream),
    })
}

async fn sender_worker(
    mut stream: TcpStream,
    file_path: String,
    file_size: u64,
    pending: Arc<Mutex<VecDeque<u32>>>,
    notify: Arc<Notify>,
    completed_chunks: Arc<AtomicUsize>,
    completed_bytes: Arc<AtomicU64>,
    sent_bytes: Arc<AtomicU64>,
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
                // Mit Zeitgrenze warten. `notify_waiters()` weckt nur, wer
                // bereits registriert ist — zwischen der Pruefung oben und der
                // Registrierung hier kann das letzte Weckzeichen fallen, und
                // der Worker schliefe fuer immer, waehrend der Aufrufer auf ihn
                // wartet. Die Schleife prueft die Bedingung ohnehin erneut.
                let _ = tokio::time::timeout(
                    Duration::from_millis(200), notify.notified()
                ).await;
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
        write_payload_with_progress(&mut stream, &buffer[..len], IO_TIMEOUT, &sent_bytes).await?;
        
        match read_chunk_ack_message(&mut stream).await {
            Ok(ack) if ack.is_nack => {
                // Der Block kommt noch einmal — die schon gezaehlten Bytes
                // wieder abziehen, sonst laeuft die Anzeige ueber 100 %.
                sent_bytes.fetch_sub(len as u64, Ordering::Relaxed);
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
