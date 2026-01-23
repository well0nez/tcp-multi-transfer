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

/// SCAN-Modus: Scannt Port-Range parallel mit Listener
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
    
    // Nutze peer_addresses für Port-Range (enthält PUBLIC Ports!)
    // peer_nat_analysis enthält lokale Ports - NICHT für Scan nutzen!
    let ports: Vec<u16> = peer_info.peer_addresses.iter().map(|a| a.port).collect();
    if ports.is_empty() {
        return Err(anyhow!("No scan range available (peer_addresses empty)"));
    }
    let (scan_start, scan_end) = (*ports.iter().min().unwrap(), *ports.iter().max().unwrap());
    
    let peer_ip = peer_info.peer_addr.ip();
    let port_count = scan_end.saturating_sub(scan_start).saturating_add(1);
    info!("🔍 SCAN mode: Scanning {}:{}-{} ({} ports)", peer_ip, scan_start, scan_end, port_count);
    debug!("SCAN: peer_nat_analysis = {:?}", peer_info.peer_nat_analysis);
    
    // Simultaneous Scan: Listener + Connector
    let (tx, mut rx) = tokio::sync::mpsc::channel::<TcpStream>(1);
    
    // Listener Task
    let listener_socket = socket.try_clone()?;
    listener_socket.listen(128)?;
    let std_listener: std::net::TcpListener = listener_socket.into();
    std_listener.set_nonblocking(true)?;
    let listener = TcpListener::from_std(std_listener)?;
    
    let listener_tx = tx.clone();
    let listener_handle = tokio::spawn(async move {
        loop {
            match tokio::time::timeout(Duration::from_secs(5), listener.accept()).await {
                Ok(Ok((mut stream, peer_addr))) => {
                    debug!("SCAN: Accepted from {}", peer_addr);
                    stream.set_nodelay(true).ok();
                    if pre_handshake(&mut stream).await.is_ok() {
                        let _ = listener_tx.send(stream).await;
                        break;
                    }
                }
                Ok(Err(_)) => tokio::time::sleep(Duration::from_millis(10)).await,
                Err(_) => break,  // Timeout
            }
        }
    });
    
    // Scanner Task
    let connector_tx = tx.clone();
    let local_port = socket.local_addr().map(|a| a.as_socket().unwrap().port()).unwrap_or(0);
    let connector_handle = tokio::spawn(async move {
        let start = tokio::time::Instant::now();
        debug!("SCAN: Starting connector task for ports {}-{}", scan_start, scan_end);
        
        for port in scan_start..=scan_end {
            debug!("SCAN: Trying port {}", port);
            if start.elapsed() >= timeout {
                break;
            }
            
            let socket = match create_hole_punch_socket() {
                Ok(s) => s,
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };
            
            if bind_to_port(&socket, local_port).is_err() {
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
            
            socket.set_nonblocking(true).ok();
            
            let target_addr: SocketAddr = format!("{}:{}", peer_ip, port).parse().unwrap();
            debug!("SCAN: Connecting to {}", target_addr);
            
            match socket.connect(&socket2::SockAddr::from(target_addr)) {
                Ok(()) | Err(_) => {
                    let std_stream: std::net::TcpStream = socket.into();
                    if let Ok(mut stream) = TcpStream::from_std(std_stream) {
                        if wait_for_connect_async(&mut stream, Duration::from_millis(500)).await.is_ok() {
                            if pre_handshake(&mut stream).await.is_ok() {
                                info!("✅ SCAN: Connected to {}:{}", peer_ip, port);
                                let _ = connector_tx.send(stream).await;
                                return;
                            } else {
                                debug!("SCAN: Pre-handshake failed for {}:{}", peer_ip, port);
                            }
                        } else {
                            debug!("SCAN: Connect timeout for {}:{}", peer_ip, port);
                        }
                    } else {
                        debug!("SCAN: Failed to create TcpStream for {}:{}", peer_ip, port);
                    }
                }
            }
            
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        debug!("SCAN: Connector task finished after {:.3}s", start.elapsed().as_secs_f64());
    });
    
    drop(tx);
    
    // Warte auf ersten erfolgreichen Stream
    let scan_start_time = tokio::time::Instant::now();
    match tokio::time::timeout(timeout + Duration::from_secs(1), rx.recv()).await {
        Ok(Some(stream)) => {
            listener_handle.abort();
            connector_handle.abort();
            info!("✅ SCAN: Connection established after {:.3}s", scan_start_time.elapsed().as_secs_f64());
            Ok(stream)
        }
        _ => {
            listener_handle.abort();
            connector_handle.abort();
            let elapsed = scan_start_time.elapsed().as_secs_f64();
            Err(anyhow!("SCAN timeout after {:.1}s (configured: {:?})", elapsed, timeout))
        }
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
