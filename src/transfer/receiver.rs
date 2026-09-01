//! TCP File Transfer Receiver Implementation

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::fs::OpenOptions;
use tokio::io::{AsyncSeekExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Notify;
use bytes::Buf;
use crc32fast::Hasher;
use anyhow::{Result, anyhow};
use tracing::{info, warn, debug};

use crate::protocol::transfer::*;
use super::helpers::*;
use super::helpers::sha256_file;

/// Progress update chunk size for socket reads (256KB)
const PROGRESS_IO_CHUNK: usize = 256 * 1024;

use super::{IO_TIMEOUT, HANDSHAKE_TIMEOUT};

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
    let mut buf = [0u8; 13];
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

    // Der Name kommt von der Gegenstelle und wird als Pfad benutzt. Ohne
    // Pruefung schriebe ein Absender mit "../../..." ausserhalb des
    // Arbeitsverzeichnisses — die Pruefsumme passte dabei, sie wird ja ueber
    // seine eigenen Daten gebildet. Es bleibt nur der letzte Pfadbestandteil.
    let filename = Path::new(&filename)
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| !n.is_empty() && *n != "." && *n != "..")
        .ok_or_else(|| anyhow!("Unusable file name: {:?}", filename))?
        .to_string();

    let info = FileInfoMessage { filename, file_size, sha256 };

    info!("Receiving: {} ({:.2} MB)", info.filename, info.file_size as f64 / (1024.0 * 1024.0));
    info!("Expected SHA256: {}", sha256_to_hex(&info.sha256));

    let ack = encode_simple(MessageType::FileInfoAck);
    write_all_timeout(stream, &ack, HANDSHAKE_TIMEOUT).await?;
    info!("File info acknowledged");

    Ok(info)
}

async fn read_exact_with_progress(
    stream: &mut TcpStream,
    buf: &mut [u8],
    timeout: Duration,
    counter: &Arc<AtomicU64>,
) -> Result<()> {
    let mut offset = 0;
    while offset < buf.len() {
        let end = std::cmp::min(offset + PROGRESS_IO_CHUNK, buf.len());
        read_exact_timeout(stream, &mut buf[offset..end], timeout).await?;
        counter.fetch_add((end - offset) as u64, Ordering::Relaxed);
        offset = end;
    }
    Ok(())
}

pub async fn run_multi_receiver(mut streams: Vec<TcpStream>) -> Result<super::TransferReport> {
    if streams.is_empty() { return Err(anyhow!("No streams")); }
    let start = std::time::Instant::now();
    info!("Using {} streams in connection order", streams.len());
    
    for (i, stream) in streams.iter().enumerate() {
        if i != 0 {
            configure_tcp_socket(stream)?;
        }
    }
    
    // Handshake + FileInfo only on first stream (heavy protocol setup)
    let mut chunk_size_vom_sender: Option<usize> = None;
    handshake_receiver(&mut streams[0]).await?;
    let file_info = receive_file_info_on_stream(&mut streams[0]).await?;

    // Wie auf der Senderseite: einzelne Stroeme duerfen beim Setup wegfallen.
    let mut brauchbar = Vec::with_capacity(streams.len());
    for (i, mut stream) in streams.into_iter().enumerate() {
        match recv_stream_info(&mut stream).await {
            Ok(info) => {
                match chunk_size_vom_sender {
                    None => chunk_size_vom_sender = Some(info.chunk_size as usize),
                    Some(bisher) if bisher != info.chunk_size as usize => {
                        return Err(anyhow!(
                            "Sender announced different block sizes ({} and {})",
                            bisher, info.chunk_size
                        ));
                    }
                    _ => {}
                }
                brauchbar.push(stream);
            }
            Err(e) if i == 0 => return Err(e),
            Err(e) => warn!("Stream {} dropped during setup: {}", i, e),
        }
    }
    let streams = brauchbar;
    if streams.is_empty() { return Err(anyhow!("No usable stream left")); }
    let stream_count = streams.len();
    
    let nach_setup = std::time::Instant::now();
    
    let temp_path = format!("{}.tmp", file_info.filename);
    let file = OpenOptions::new().create(true).write(true).truncate(true).open(&temp_path).await?;
    file.set_len(file_info.file_size).await?;
    drop(file);
    
    // Der Sender bestimmt die Blockgroesse; wir rechnen sie nicht nach.
    let chunk_size = chunk_size_vom_sender
        .filter(|c| *c > 0)
        .ok_or_else(|| anyhow!("Sender announced no block size"))?;
    let total_chunks = ((file_info.file_size + chunk_size as u64 - 1) / chunk_size as u64) as u32;
    info!("Block size {} KB for {:.2} MB across {} streams (announced by sender)",
          chunk_size / 1024, file_info.file_size as f64 / 1048576.0, stream_count);
    
    let received_flags = Arc::new((0..total_chunks).map(|_| AtomicBool::new(false)).collect::<Vec<_>>());
    let received_count = Arc::new(AtomicUsize::new(0));
    let io_bytes = Arc::new(AtomicU64::new(0));
    let done_received = Arc::new(AtomicBool::new(false));
    let done_notify = Arc::new(Notify::new());
    
    let mut handles = Vec::new();
    for (i, stream) in streams.into_iter().enumerate() {
        let temp = temp_path.clone();
        let flags = received_flags.clone();
        let count = received_count.clone();
        let io_bytes = io_bytes.clone();
        let done = done_received.clone();
        let notify = done_notify.clone();
        handles.push(tokio::spawn(async move {
            receiver_worker(i as u8, stream, temp, file_info.file_size, flags, count, io_bytes, done, notify).await
        }));
    }
    
    let progress_bar = ProgressTracker::with_bytes(file_info.file_size, &file_info.filename, io_bytes.clone());
    loop {
        if done_received.load(Ordering::Relaxed) { break; }
        if handles.iter().all(|h| h.is_finished()) { break; }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    
    // Den Strom, auf dem DONE ankam, brauchen wir noch fuer die Quittung.
    let mut offene: Vec<TcpStream> = Vec::new();
    for handle in handles {
        match handle.await {
            Ok(Ok(stream)) => offene.push(stream),
            Ok(Err(e)) => warn!("Receiving stream ended with an error: {}", e),
            Err(e) => warn!("Receiving task aborted: {}", e),
        }
    }
    
    if received_count.load(Ordering::Relaxed) as u32 != total_chunks {
        return Err(anyhow!("Transfer incomplete"));
    }
    let nach_nutzlast = std::time::Instant::now();
    
    progress_bar.set_position(file_info.file_size);
    progress_bar.set_message("Verifying SHA256...");
    let calculated_hash = sha256_file(Path::new(&temp_path)).await?;
    if calculated_hash == file_info.sha256 {
        tokio::fs::rename(&temp_path, &file_info.filename).await?;
        // Erst jetzt quittieren: die Quittung bedeutet "Pruefsumme stimmt".
        if let Some(stream) = offene.first_mut() {
            let ack = encode_simple(MessageType::Ack);
            write_all_timeout(stream, &ack, HANDSHAKE_TIMEOUT).await?;
        } else {
            return Err(anyhow!("No stream left to acknowledge on"));
        }
        progress_bar.finish_with_message("Complete!".to_string());
        Ok(super::TransferReport {
            bytes: file_info.file_size,
            streams: stream_count,
            setup_ms: (nach_setup - start).as_secs_f64() * 1000.0,
            payload_ms: (nach_nutzlast - nach_setup).as_secs_f64() * 1000.0,
            finish_ms: nach_nutzlast.elapsed().as_secs_f64() * 1000.0,
            total_ms: start.elapsed().as_secs_f64() * 1000.0,
            tcp_info: None,
        })
    } else {
        Err(anyhow!("SHA256 mismatch"))
    }
}

async fn receiver_worker(
    _conn_id: u8,
    mut stream: TcpStream,
    temp_path: String,
    file_size: u64,
    received_flags: Arc<Vec<AtomicBool>>,
    received_count: Arc<AtomicUsize>,
    io_bytes: Arc<AtomicU64>,
    done_received: Arc<AtomicBool>,
    done_notify: Arc<Notify>,
) -> Result<TcpStream> {
    let mut file = OpenOptions::new().write(true).open(&temp_path).await?;
    let mut data = Vec::new();
    
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
                let header = ChunkHeaderMessage::decode(&header_buf)
                    .ok_or_else(|| anyhow!("Malformed chunk header"))?;

                // Kopfangaben stammen von der Gegenstelle und werden nicht
                // blind geglaubt: eine Blocknummer ausserhalb des Bereichs
                // wuerde beim Indizieren abstuerzen.
                if header.chunk_id as usize >= received_flags.len() {
                    return Err(anyhow!(
                        "Chunk number {} outside the expected range (0..{})",
                        header.chunk_id, received_flags.len()
                    ));
                }
                // Laenge und Versatz ebenso: sonst reserviert ein
                // Kopfeintrag bis zu vier Gigabyte oder schreibt hinter das
                // Dateiende.
                if header.offset >= file_size
                    || header.len as u64 > file_size - header.offset
                {
                    return Err(anyhow!(
                        "Chunk {} claims {} bytes at offset {}, file is {} bytes",
                        header.chunk_id, header.len, header.offset, file_size
                    ));
                }
                
                let data_len = header.len as usize;
                if data.len() < data_len {
                    data.resize(data_len, 0u8);
                }
                read_exact_with_progress(&mut stream, &mut data[..data_len], IO_TIMEOUT, &io_bytes).await?;
                
                let mut hasher = Hasher::new();
                hasher.update(&data[..data_len]);
                if hasher.finalize() != header.hash32 {
                    let nack = ChunkAckMessage { chunk_id: header.chunk_id, is_nack: true };
                    write_all_timeout(&mut stream, &nack.encode(), IO_TIMEOUT).await?;
                    continue;
                }
                
                file.seek(std::io::SeekFrom::Start(header.offset)).await?;
                file.write_all(&data[..data_len]).await?;
                
                if !received_flags[header.chunk_id as usize].swap(true, Ordering::AcqRel) {
                    received_count.fetch_add(1, Ordering::Relaxed);
                }
                
                let ack = ChunkAckMessage { chunk_id: header.chunk_id, is_nack: false };
                write_all_timeout(&mut stream, &ack.encode(), IO_TIMEOUT).await?;
            }
            MessageType::Done => {
                // Hier wird **nicht** quittiert. Die Schlussquittung sagt laut
                // Protokoll aus, dass die SHA256 geprueft wurde — das kann
                // erst nach dem Zusammensetzen aller Bloecke geschehen. Der
                // Strom geht dafuer an den Aufrufer zurueck.
                done_received.store(true, Ordering::Relaxed);
                done_notify.notify_waiters();
                break;
            }
            _ => return Err(anyhow!("Unexpected msg")),
        }
    }
    Ok(stream)
}
