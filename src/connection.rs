//! Multi-Connection Management Module
//!
//! Handles establishing multiple TCP connections through coordinated hole punching cycles.

use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use anyhow::{Result, anyhow};
use tracing::{info, error, warn, debug};

use crate::protocol::{RelayMessage, AddPortsMessage};
use crate::punch::{punch_connection_with_strategy, PeerInfo, current_timestamp};
use crate::relay::{Session, create_bound_socket};

/// GO Signal mit Zeitstempel
pub struct GoSignal {
    pub start_at: f64,
}

/// Wartet auf retry_granted vom Server
async fn wait_for_retry_granted(
    relay_reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    expected_conn_num: u32,
) -> Result<bool> {
    let timeout = Duration::from_secs(30);
    let start = std::time::Instant::now();
    
    loop {
        if start.elapsed() > timeout {
            return Err(anyhow!("Timeout waiting for retry_granted"));
        }
        
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(5), relay_reader.read_line(&mut line))
            .await
            .map_err(|_| anyhow!("Read timeout waiting for retry_granted"))??;
        
        if line.trim().is_empty() {
            return Err(anyhow!("Empty line from relay server"));
        }
        
        let msg: RelayMessage = serde_json::from_str(&line)
            .map_err(|e| anyhow!("Failed to parse relay message: {} - {}", e, line.trim()))?;
        
        match msg {
            RelayMessage::RetryGranted { connection_num } => {
                if connection_num == expected_conn_num {
                    info!("✓ Retry granted for connection {}", connection_num + 1);
                    return Ok(true);
                } else {
                    warn!("Received retry_granted for conn {} but expected {}, skipping", connection_num, expected_conn_num);
                }
            }
            RelayMessage::Error { message } => {
                return Err(anyhow!("Server error: {}", message));
            }
            _ => {
                debug!("Skipping message while waiting for retry_granted: {:?}", msg);
            }
        }
    }
}

/// Wartet auf ports_added_ack vom Server
async fn wait_for_ports_added_ack(
    relay_reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    expected_ports: &[u16],
) -> Result<()> {
    let timeout = Duration::from_secs(30);
    let start = std::time::Instant::now();
    
    loop {
        if start.elapsed() > timeout {
            return Err(anyhow!("Timeout waiting for ports_added_ack"));
        }
        
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(5), relay_reader.read_line(&mut line))
            .await
            .map_err(|_| anyhow!("Read timeout waiting for ports_added_ack"))??;
        
        if line.trim().is_empty() {
            return Err(anyhow!("Empty line from relay server"));
        }
        
        let msg: RelayMessage = serde_json::from_str(&line)
            .map_err(|e| anyhow!("Failed to parse relay message: {} - {}", e, line.trim()))?;
        
        match msg {
            RelayMessage::PortsAddedAck { ports } => {
                info!("✓ Received ports_added_ack for {} ports", ports.len());
                
                // Verify we got ACK for all expected ports
                let expected_set: std::collections::HashSet<_> = expected_ports.iter().copied().collect();
                let acked_set: std::collections::HashSet<_> = ports.iter().copied().collect();
                
                if expected_set == acked_set {
                    return Ok(());
                } else {
                    warn!("⚠️ ACK ports don't match expected: expected {:?}, got {:?}", expected_ports, ports);
                }
            }
            RelayMessage::Error { message } => {
                return Err(anyhow!("Server error: {}", message));
            }
            _ => {
                debug!("Skipping message while waiting for ports_added_ack: {:?}", msg);
            }
        }
    }
}

/// Wartet auf peer_info Message für eine bestimmte Connection
pub async fn receive_peer_info_for_connection(
    relay_reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    expected_conn_num: u32,
) -> Result<(PeerInfo, String, u32)> {
    loop {
        let mut line = String::new();
        let _ = tokio::time::timeout(Duration::from_secs(120), relay_reader.read_line(&mut line))
            .await
            .map_err(|_| anyhow!("Timeout waiting for peer_info (120s)"))?;
        
        if line.trim().is_empty() {
            return Err(anyhow!("Empty line from relay server"));
        }
        
        let msg: RelayMessage = serde_json::from_str(&line)
            .map_err(|e| anyhow!("Failed to parse relay message: {} - {}", e, line.trim()))?;
        
        match msg {
            RelayMessage::PeerInfo { connection_num, punch_strategy, peer_public_addr, peer_addresses, peer_nat_analysis, tcp_connections, .. } => {
                let conn = connection_num.unwrap_or(0);
                if conn != expected_conn_num {
                    warn!("Received peer_info for conn {} but expected {}, skipping", conn, expected_conn_num);
                    continue;
                }
                
                let strategy = punch_strategy.unwrap_or_else(|| "scan".to_string());
                let peer_tcp_connections = tcp_connections.unwrap_or(1);  // Default: 1 Connection
                
                // Baue PeerInfo-Struct
                let peer_addr = RelayMessage::parse_addr(&peer_public_addr)
                    .ok_or_else(|| anyhow!("Invalid peer address"))?;
                let peer_addr: SocketAddr = format!("{}:{}", peer_addr.0, peer_addr.1).parse()?;
                
                let peer_info = PeerInfo {
                    peer_addr,
                    peer_addresses,
                    peer_nat_analysis,
                };
                
                return Ok((peer_info, strategy, peer_tcp_connections));
            }
            RelayMessage::Error { message } => {
                return Err(anyhow!("Server error: {}", message));
            }
            _ => {
                // Andere Messages ignorieren oder verarbeiten
                debug!("Skipping message while waiting for peer_info: {:?}", msg);
            }
        }
    }
}

/// Wartet auf GO Message für eine bestimmte Connection
pub async fn receive_go_for_connection(
    relay_reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    expected_conn_num: u32,
) -> Result<GoSignal> {
    loop {
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(120), relay_reader.read_line(&mut line))
            .await
            .map_err(|_| anyhow!("Timeout waiting for GO (120s)"))??;
        
        if line.trim().is_empty() {
            return Err(anyhow!("Empty line from relay server"));
        }
        
        let msg: RelayMessage = serde_json::from_str(&line)
            .map_err(|e| anyhow!("Failed to parse relay message: {} - {}", e, line.trim()))?;
        
        match msg {
            RelayMessage::Go { start_at, connection_num, .. } => {
                let conn = connection_num.unwrap_or(0);
                if conn != expected_conn_num {
                    warn!("Received GO for conn {} but expected {}, skipping", conn, expected_conn_num);
                    continue;
                }
                
                return Ok(GoSignal { start_at });
            }
            RelayMessage::Error { message } => {
                return Err(anyhow!("Server error: {}", message));
            }
            _ => {
                debug!("Skipping message while waiting for GO: {:?}", msg);
            }
        }
    }
}

/// Etabliert mehrere Connections durch wiederholte Punch-Zyklen
pub async fn establish_multi_connections(
    mut relay_reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
    mut relay_writer: tokio::net::tcp::OwnedWriteHalf,
    session: &mut Session,
    tcp_connections: u32,
    role: &str,
    timeout: Duration,
    session_id: &str,
    server_addr: SocketAddr,
    probe_port: Option<u16>,
) -> Result<Vec<TcpStream>> {
    let mut streams = Vec::new();
    let mut failures_in_a_row = 0;
    const MAX_FAILURES: u32 = 5;
    
    // Für Receiver: Empfange ERSTE peer_info VOR der Schleife!
    let (actual_tcp_connections, start_conn) = if role == "receiver" {
        info!("📡 Receiver: Waiting for initial peer_info (connection 1/?)...");
        
        // 1. Warte auf peer_info für conn=0
        let (peer_info, punch_strategy, peer_tcp_connections) = receive_peer_info_for_connection(
            &mut relay_reader,
            0
        ).await?;
        
        info!("✓ Received initial peer_info: peer wants {} connections", peer_tcp_connections);
        
        // NEU: KEIN massives Binding/Probing mehr am Anfang!
        // Sockets werden on-demand gebunden (während der Connection-Schleife)
        
        info!("✓ Received peer_info for connection 1/{}: strategy={}", peer_tcp_connections, punch_strategy);
        
        // 3. Sende READY
        let ready_msg = format!(r#"{{"type":"ready","connection_num":0}}"#) + "\n";
        relay_writer.write_all(ready_msg.as_bytes()).await?;
        relay_writer.flush().await?;
        info!("✓ READY sent for connection 1/{}", peer_tcp_connections);
        
        // 4. Warte auf GO
        let go_signal = receive_go_for_connection(&mut relay_reader, 0).await?;
        let countdown = go_signal.start_at - current_timestamp();
        info!("✓ GO received for connection 1/{}! Start in {:.2}s", peer_tcp_connections, countdown);
        
        // 5. Punch erste Connection
        let socket_index = 0;
        if socket_index >= session.bound_sockets.len() {
            return Err(anyhow!("No socket available for connection 0"));
        }
        
        let stream = punch_connection_with_strategy(
            session.bound_sockets[socket_index].try_clone()?,
            &peer_info,
            &punch_strategy,
            go_signal.start_at,
            session.time_offset,
            timeout,
        ).await?;
        
        streams.push(stream);
        info!("✅ Connection 1/{} established!", peer_tcp_connections);
        
        // Schleife startet bei 1 (erste Connection bereits etabliert)
        (peer_tcp_connections, 1)
    } else {
        // Sender: Check if we need to bind more sockets
        let current_socket_count = session.bound_sockets.len() as u32;
        
        if tcp_connections > current_socket_count {
            let needed_more = (tcp_connections - current_socket_count) as usize;
            info!("🔄 Sender: Binding {} more sockets...", needed_more);
            
            let next_port = if let Some(last) = session.bound_sockets.last() {
                last.local_addr().map(|a| a.as_socket().map(|s| s.port()).unwrap_or(0)).unwrap_or(0).wrapping_add(1)
            } else {
                0
            };
            
            if next_port > 0 {
                let mut new_ports = Vec::new();
                let mut added_count = 0;
                let mut current_port = next_port;
                let mut attempt_counter = 0;
                
                while added_count < needed_more && attempt_counter < 100 {
                    match create_bound_socket(current_port) {
                        Ok(s) => {
                            session.bound_sockets.push(s);
                            new_ports.push(current_port);
                            added_count += 1;
                            debug!("Bound extra socket on port {}", current_port);
                        },
                        Err(_) => {}
                    }
                    current_port = current_port.wrapping_add(1);
                    attempt_counter += 1;
                }
                
                info!("✓ Bound {} additional sockets (total: {})", added_count, session.bound_sockets.len());
                
                // Sender: NO probing needed for Port-Preserved NATs!
                // Just send add_ports message so server knows the bound ports
                if !new_ports.is_empty() {
                    info!("📤 Sender: Sending add_ports for {} new ports (no probing needed for Port-Preserved NAT)", new_ports.len());
                    
                    let add_msg = AddPortsMessage::new(session_id, new_ports.clone());
                    let json = serde_json::to_string(&add_msg)? + "\n";
                    relay_writer.write_all(json.as_bytes()).await?;
                    relay_writer.flush().await?;
                    info!("✓ Sent add_ports message");
                    
                    // Wait for ACK
                    match wait_for_ports_added_ack(&mut relay_reader, &new_ports).await {
                        Ok(_) => info!("✓ New ports confirmed by server"),
                        Err(e) => warn!("⚠️ Failed to get ACK for new ports: {}", e),
                    }
                }
            }
        }
        
        // Sender weiß schon, wie viele er will - Schleife startet bei 0
        (tcp_connections, 0)
    };
    
    // Hauptschleife für verbleibende Connections
    for conn_num in start_conn..actual_tcp_connections {
        // 0. ON-DEMAND Socket Binding: VORHER binden, damit Server den richtigen Port kennt!
        let socket_index = conn_num as usize;
        if socket_index >= session.bound_sockets.len() {
            // Berechne nächsten Port (mit Retry für Windows Port-Konflikte)
            let base_port = if let Some(last) = session.bound_sockets.last() {
                last.local_addr().map(|a| a.as_socket().map(|s| s.port()).unwrap_or(0)).unwrap_or(0).wrapping_add(1)
            } else {
                return Err(anyhow!("No initial socket available"));
            };
            
            // Bind mit Port-Range-Retry (Windows: os error 10013 bei belegten Ports)
            let mut bound = false;
            for port_offset in 0u16..50 {
                let try_port = base_port.wrapping_add(port_offset);
                match create_bound_socket(try_port) {
                    Ok(new_socket) => {
                        let new_port = new_socket.local_addr()?.as_socket().map(|s| s.port()).unwrap_or(try_port);
                        session.bound_sockets.push(new_socket);
                        info!("🔧 On-demand: Bound new socket on port {} for connection {}", new_port, conn_num + 1);
                        
                        // Sende add_ports an Server (OHNE Probing!)
                        let add_msg = AddPortsMessage::new(session_id, vec![new_port]);
                        let json = serde_json::to_string(&add_msg)? + "\n";
                        relay_writer.write_all(json.as_bytes()).await?;
                        relay_writer.flush().await?;
                        info!("📤 Sent add_ports for new socket {}", new_port);
                        
                        // Warte auf ACK
                        match wait_for_ports_added_ack(&mut relay_reader, &[new_port]).await {
                            Ok(_) => info!("✓ New port {} confirmed by server", new_port),
                            Err(e) => warn!("⚠️ Failed to get ACK for new port {}: {}", new_port, e),
                        }
                        bound = true;
                        break;
                    }
                    Err(e) => {
                        if port_offset == 0 {
                            debug!("Port {} unavailable: {}, trying next...", try_port, e);
                        }
                    }
                }
            }
            if !bound {
                return Err(anyhow!("Failed to bind socket for connection {} (tried 50 ports from {})", conn_num + 1, base_port));
            }
        }
        
        info!("📡 Waiting for peer_info for connection {}/{}...", conn_num + 1, actual_tcp_connections);
        
        loop {  // Retry-Loop für diese Connection
            // 1. Warte auf peer_info für diese Connection
            let (peer_info, punch_strategy, _peer_tcp_connections) = match receive_peer_info_for_connection(
                &mut relay_reader,
                conn_num
            ).await {
                Ok(data) => data,
                Err(e) => {
                    error!("Failed to receive peer_info: {}", e);
                    failures_in_a_row += 1;
                    if failures_in_a_row >= MAX_FAILURES {
                        return Err(anyhow!("Max failures reached waiting for peer_info"));
                    }
                    continue;
                }
            };
            
            info!("✓ Received peer_info for connection {}/{}: strategy={}", conn_num + 1, actual_tcp_connections, punch_strategy);
            
            // 2. Sende READY mit connection_num
            let ready_msg = format!(r#"{{"type":"ready","connection_num":{}}}"#, conn_num) + "\n";
            relay_writer.write_all(ready_msg.as_bytes()).await?;
            relay_writer.flush().await?;
            info!("✓ READY sent for connection {}", conn_num + 1);
            
            // 3. Warte auf GO
            let go_signal = match receive_go_for_connection(&mut relay_reader, conn_num).await {
                Ok(signal) => signal,
                Err(e) => {
                    error!("Failed to receive GO: {}", e);
                    failures_in_a_row += 1;
                    if failures_in_a_row >= MAX_FAILURES {
                        return Err(anyhow!("Max failures reached waiting for GO"));
                    }
                    continue;
                }
            };
            
            let countdown = go_signal.start_at - current_timestamp();
            info!("✓ GO received for connection {}! Start in {:.2}s", conn_num + 1, countdown);
            
            // Socket ist bereits gebunden (am Anfang der Schleife)
            match punch_connection_with_strategy(
                session.bound_sockets[socket_index].try_clone()?,
                &peer_info,
                &punch_strategy,
                go_signal.start_at,
                session.time_offset,
                timeout,
            ).await {
                Ok(stream) => {
                    failures_in_a_row = 0;  // Reset bei Erfolg
                    streams.push(stream);
                    info!("✅ Connection {}/{} established!", conn_num + 1, actual_tcp_connections);
                    break;  // Nächste Connection
                }
                Err(e) => {
                    failures_in_a_row += 1;
                    error!("❌ Connection {} failed: {}", conn_num + 1, e);
                    
                    if failures_in_a_row >= MAX_FAILURES {
                        return Err(anyhow!("Max {} consecutive failures reached", MAX_FAILURES));
                    }
                    
                    warn!("🔄 Requesting retry for connection {} (failure {}/{})", 
                          conn_num + 1, failures_in_a_row, MAX_FAILURES);
                    
                    // 1. Sende retry_request an Server
                    let retry_msg = format!(r#"{{"type":"retry_request","connection_num":{}}}"#, conn_num) + "\n";
                    relay_writer.write_all(retry_msg.as_bytes()).await?;
                    relay_writer.flush().await?;
                    info!("📤 Sent retry_request for connection {}", conn_num + 1);
                    
                    // 2. Warte auf retry_granted vom Server
                    match wait_for_retry_granted(&mut relay_reader, conn_num).await {
                        Ok(true) => {
                            info!("✓ Retry granted by server for connection {}", conn_num + 1);
                            
                            // 3. Bind NEUEN Socket mit Port-Range-Retry (Windows: os error 10013)
                            let base_port = if let Some(last) = session.bound_sockets.last() {
                                last.local_addr().map(|a| a.as_socket().map(|s| s.port()).unwrap_or(0)).unwrap_or(0).wrapping_add(1)
                            } else {
                                return Err(anyhow!("No socket available for retry"));
                            };
                            
                            let mut retry_bound = false;
                            for port_offset in 0u16..50 {
                                let try_port = base_port.wrapping_add(port_offset);
                                match create_bound_socket(try_port) {
                                    Ok(new_socket) => {
                                        let new_port = new_socket.local_addr()?.as_socket().map(|s| s.port()).unwrap_or(try_port);
                                        
                                        // Ersetze alten Socket mit neuem
                                        if socket_index < session.bound_sockets.len() {
                                            session.bound_sockets[socket_index] = new_socket;
                                        } else {
                                            session.bound_sockets.push(new_socket);
                                        }
                                        
                                        info!("🔧 Retry: Bound new socket on port {} for connection {}", new_port, conn_num + 1);
                                        
                                        // 4. Sende add_ports mit neuem Port
                                        let add_msg = AddPortsMessage::new(session_id, vec![new_port]);
                                        let json = serde_json::to_string(&add_msg)? + "\n";
                                        relay_writer.write_all(json.as_bytes()).await?;
                                        relay_writer.flush().await?;
                                        info!("📤 Sent add_ports for retry socket {}", new_port);
                                        
                                        // Warte auf ACK
                                        match wait_for_ports_added_ack(&mut relay_reader, &[new_port]).await {
                                            Ok(_) => info!("✓ New port {} confirmed by server", new_port),
                                            Err(e) => warn!("⚠️ Failed to get ACK for new port {}: {}", new_port, e),
                                        }
                                        
                                        retry_bound = true;
                                        break;
                                    }
                                    Err(e) => {
                                        if port_offset == 0 {
                                            debug!("Retry: Port {} unavailable: {}, trying next...", try_port, e);
                                        }
                                    }
                                }
                            }
                            
                            if !retry_bound {
                                error!("Failed to bind new socket for retry (tried 50 ports from {})", base_port);
                                continue;
                            }
                            
                            // 5. Loop wiederholt → Warte auf neue peer_info (mit neuem Port!)
                        }
                        Ok(false) | Err(_) => {
                            warn!("Retry not granted for connection {}", conn_num + 1);
                            continue;
                        }
                    }
                }
            }
        }
    }
    
    Ok(streams)
}
