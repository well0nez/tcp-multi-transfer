//! Strategy-based Hole Punching
//!
//! Unterstützt verschiedene Punch-Strategien basierend auf NAT-Typen:
//! - listen: Wartet auf eingehende Verbindung (NAT-friendly)
//! - connect: Direkter Connect zum Peer (NAT-friendly)
//! - scan: Scannt Port-Range (Complex NAT)

use std::time::Duration;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use anyhow::{Result, anyhow};
use tracing::{info, debug, warn};

use super::helpers::*;
use crate::protocol::relay::PeerAddressInfo;

/// Haupt-Funktion für strategie-basiertes Hole Punching
pub async fn punch_connection_with_strategy(
    socket: socket2::Socket,
    peer_info: &PeerInfo,
    strategy: &str,
    start_at: f64,
    time_offset: f64,
    timeout: Duration,
) -> Result<TcpStream> {
    match strategy {
        "listen" => punch_listen(socket, start_at, time_offset, timeout).await,
        "connect" => punch_connect(socket, peer_info, start_at, time_offset, timeout).await,
        "scan" => punch_scan(socket, peer_info, start_at, time_offset, timeout).await,
        _ => {
            warn!("Unknown punch strategy '{}', falling back to 'scan'", strategy);
            punch_scan(socket, peer_info, start_at, time_offset, timeout).await
        }
    }
}

/// LISTEN-Modus: Wartet auf eingehende Verbindung
async fn punch_listen(
    socket: socket2::Socket,
    start_at: f64,
    time_offset: f64,
    timeout: Duration,
) -> Result<TcpStream> {
    // Warte bis synchronized start time
    let local_start_at = start_at - time_offset;
    let now = current_timestamp();
    let wait_time = (local_start_at - now).max(0.0);
    
    if wait_time > 0.0 {
        info!("⏱️ Waiting {:.3}s until synchronized start (LISTEN mode)", wait_time);
        tokio::time::sleep(Duration::from_secs_f64(wait_time)).await;
    }
    
    // Setup listener
    socket.listen(128)?;
    let std_listener: std::net::TcpListener = socket.into();
    std_listener.set_nonblocking(true)?;
    let listener = TcpListener::from_std(std_listener)?;
    
    let local_addr = listener.local_addr()?;
    info!("📡 LISTEN mode: Waiting for connection on {}", local_addr);
    
    // Accept mit Timeout
    match tokio::time::timeout(timeout, listener.accept()).await {
        Ok(Ok((mut stream, peer_addr))) => {
            info!("✅ LISTEN: Accepted connection from {}", peer_addr);
            stream.set_nodelay(true)?;
            
            // Pre-Handshake
            if pre_handshake(&mut stream).await.is_ok() {
                Ok(stream)
            } else {
                Err(anyhow!("Pre-handshake failed in LISTEN mode"))
            }
        }
        Ok(Err(e)) => Err(anyhow!("Accept failed: {}", e)),
        Err(_) => Err(anyhow!("LISTEN timeout after {:?}", timeout)),
    }
}

/// CONNECT-Modus: Direkter Connect zum Peer
async fn punch_connect(
    socket: socket2::Socket,
    peer_info: &PeerInfo,
    start_at: f64,
    time_offset: f64,
    timeout: Duration,
) -> Result<TcpStream> {
    // Warte bis synchronized start time
    let local_start_at = start_at - time_offset;
    let now = current_timestamp();
    let wait_time = (local_start_at - now).max(0.0);
    
    if wait_time > 0.0 {
        info!("⏱️ Waiting {:.3}s until synchronized start (CONNECT mode)", wait_time);
        tokio::time::sleep(Duration::from_secs_f64(wait_time)).await;
    }
    
    let peer_addr = peer_info.peer_addr;
    info!("🔌 CONNECT mode: Connecting to {}", peer_addr);
    
    // Direkter Connect
    socket.set_nonblocking(true)?;
    let _ = socket.connect(&socket2::SockAddr::from(peer_addr));
    
    let std_stream: std::net::TcpStream = socket.into();
    let mut stream = TcpStream::from_std(std_stream)?;
    
    // Warte auf Verbindung
    match tokio::time::timeout(timeout, stream.writable()).await {
        Ok(Ok(_)) => {
            if stream.peer_addr().is_err() {
                return Err(anyhow!("Connection failed - no peer address"));
            }
            
            stream.set_nodelay(true)?;
            info!("✅ CONNECT: Connected to {}", peer_addr);
            
            // Pre-Handshake
            if pre_handshake(&mut stream).await.is_ok() {
                Ok(stream)
            } else {
                Err(anyhow!("Pre-handshake failed in CONNECT mode"))
            }
        }
        Ok(Err(e)) => Err(anyhow!("Writable failed: {}", e)),
        Err(_) => Err(anyhow!("CONNECT timeout after {:?}", timeout)),
    }
}

/// SCAN-Modus: Scannt Peer-Adressen PARALLEL mit Listener
/// 
/// Basierend auf Original-Implementation: Ein Task PRO peer_address!
async fn punch_scan(
    socket: socket2::Socket,
    peer_info: &PeerInfo,
    start_at: f64,
    time_offset: f64,
    timeout: Duration,
) -> Result<TcpStream> {
    // Warte bis synchronized start time
    let local_start_at = start_at - time_offset;
    let now = current_timestamp();
    let wait_time = (local_start_at - now).max(0.0);
    
    if wait_time > 0.0 {
        info!("⏱️ Waiting {:.3}s until synchronized start (SCAN mode)", wait_time);
        tokio::time::sleep(Duration::from_secs_f64(wait_time)).await;
    }
    
    // Sammle alle Peer-Adressen (enthält PUBLIC Ports!)
    let mut peer_addresses: Vec<SocketAddr> = Vec::new();
    for addr_info in &peer_info.peer_addresses {
        if let Ok(addr) = format!("{}:{}", addr_info.ip, addr_info.port).parse::<SocketAddr>() {
            if !peer_addresses.contains(&addr) {
                peer_addresses.push(addr);
            }
        }
    }
    
    if peer_addresses.is_empty() {
        return Err(anyhow!("No peer addresses available"));
    }
    
    info!("🔍 SCAN mode: Trying {} unique addresses", peer_addresses.len());
    debug!("SCAN: peer_addresses = {:?}", peer_addresses);
    
    // Listener Setup
    let listener_socket = socket.try_clone()?;
    listener_socket.listen(128)?;
    let std_listener: std::net::TcpListener = listener_socket.into();
    std_listener.set_nonblocking(true)?;
    let listener = TcpListener::from_std(std_listener)?;
    let listener_local_port = listener.local_addr()?.port();
    info!("📡 Listener ready on port {}", listener_local_port);
    
    // Channel für Kandidaten
    let channel_capacity = peer_addresses.len().saturating_add(2).max(4);
    let (tx, mut rx) = tokio::sync::mpsc::channel::<TcpStream>(channel_capacity);
    
    // Listener Task
    let listener_tx = tx.clone();
    let listener_handle = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((mut stream, peer_addr)) => {
                    debug!("SCAN: Accepted from {}", peer_addr);
                    stream.set_nodelay(true).ok();
                    if pre_handshake(&mut stream).await.is_ok() {
                        let _ = listener_tx.send(stream).await;
                        break;
                    }
                }
                Err(e) => {
                    debug!("SCAN: Accept error: {}", e);
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
    });
    
    // Connector Tasks - EIN TASK PRO PEER_ADDRESS! (PARALLEL!)
    let local_port = listener_local_port;
    let total_addrs = peer_addresses.len();
    let connector_handles: Vec<_> = peer_addresses.into_iter().enumerate().map(|(idx, peer_addr)| {
        let connector_tx = tx.clone();
        let timeout = timeout;
        
        tokio::spawn(async move {
            let start = tokio::time::Instant::now();
            let mut attempt = 0;
            
            while start.elapsed() < timeout {
                attempt += 1;
                
                // Erstelle neuen Socket für diesen Versuch
                let socket = match create_hole_punch_socket() {
                    Ok(s) => s,
                    Err(e) => {
                        debug!("SCAN[{}]: Failed to create socket: {}", idx, e);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                
                // CRITICAL: Bind zu unserem local_port!
                if let Err(e) = bind_to_port(&socket, local_port) {
                    debug!("SCAN[{}]: Failed to bind: {}", idx, e);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
                
                socket.set_nonblocking(true).ok();
                
                // Versuche zu connecten
                let connect_result = socket.connect(&socket2::SockAddr::from(peer_addr));
                
                match connect_result {
                    Ok(()) => {
                        // Immediate success
                        let std_stream: std::net::TcpStream = socket.into();
                        if let Ok(mut stream) = TcpStream::from_std(std_stream) {
                            if pre_handshake(&mut stream).await.is_ok() {
                                info!("✅ SCAN: Connected to {} (addr {}/{})", peer_addr, idx + 1, total_addrs);
                                let _ = connector_tx.send(stream).await;
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        // Check if "in progress" (expected for non-blocking)
                        #[cfg(unix)]
                        let is_in_progress = e.raw_os_error() == Some(libc::EINPROGRESS)
                            || e.kind() == std::io::ErrorKind::WouldBlock;
                        #[cfg(not(unix))]
                        let is_in_progress = e.kind() == std::io::ErrorKind::WouldBlock;
                        
                        if is_in_progress {
                            let std_stream: std::net::TcpStream = socket.into();
                            if let Ok(mut stream) = wait_for_connect(std_stream, Duration::from_millis(500)).await {
                                if pre_handshake(&mut stream).await.is_ok() {
                                    info!("✅ SCAN: Connected to {} (addr {}/{})", peer_addr, idx + 1, total_addrs);
                                    let _ = connector_tx.send(stream).await;
                                    return;
                                }
                            }
                        } else if attempt % 20 == 0 {
                            debug!("SCAN[{}]: Attempt {} to {} failed: {}", idx, attempt, peer_addr, e);
                        }
                    }
                }
                
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            
            debug!("SCAN[{}]: Timed out after {} attempts to {}", idx, attempt, peer_addr);
        })
    }).collect();
    
    drop(tx);
    
    // Warte auf ersten erfolgreichen Stream
    let scan_start_time = tokio::time::Instant::now();
    let timeout_duration = timeout + Duration::from_secs(1);
    
    match tokio::time::timeout(timeout_duration, rx.recv()).await {
        Ok(Some(stream)) => {
            listener_handle.abort();
            for h in connector_handles {
                h.abort();
            }
            info!("✅ SCAN: Connection established after {:.3}s", scan_start_time.elapsed().as_secs_f64());
            Ok(stream)
        }
        _ => {
            listener_handle.abort();
            for h in connector_handles {
                h.abort();
            }
            let elapsed = scan_start_time.elapsed().as_secs_f64();
            Err(anyhow!("SCAN timeout after {:.1}s (configured: {:?})", elapsed, timeout))
        }
    }
}

/// Helper: Warte auf erfolgreichen Connect (für non-blocking sockets)
async fn wait_for_connect(stream: std::net::TcpStream, timeout: Duration) -> Result<TcpStream> {
    use tokio::io::Interest;
    
    let stream = TcpStream::from_std(stream)?;
    
    match tokio::time::timeout(timeout, stream.ready(Interest::WRITABLE)).await {
        Ok(Ok(_)) => {
            match stream.peer_addr() {
                Ok(_) => {
                    stream.set_nodelay(true)?;
                    Ok(stream)
                }
                Err(e) => Err(anyhow!("Connection failed: {}", e))
            }
        }
        Ok(Err(e)) => Err(anyhow!("Ready check failed: {}", e)),
        Err(_) => Err(anyhow!("Connection timeout")),
    }
}

/// Helper: Warte auf erfolgreichen Connect
async fn wait_for_connect_async(stream: &mut TcpStream, timeout: Duration) -> Result<()> {
    match tokio::time::timeout(timeout, stream.writable()).await {
        Ok(Ok(_)) => {
            if stream.peer_addr().is_err() {
                Err(anyhow!("Connection failed"))
            } else {
                Ok(())
            }
        }
        Ok(Err(e)) => Err(anyhow!("Writable error: {}", e)),
        Err(_) => Err(anyhow!("Timeout")),
    }
}

/// Peer-Info für Strategy-basiertes Punching
pub struct PeerInfo {
    pub peer_addr: SocketAddr,
    pub peer_addresses: Vec<PeerAddressInfo>,
    pub peer_nat_analysis: Option<crate::protocol::NATAnalysis>,
}
