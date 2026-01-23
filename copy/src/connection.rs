//! Multi-Connection Management Module
//!
//! Handles establishing multiple TCP connections through coordinated hole punching cycles.

use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use anyhow::{Result, anyhow};
use tracing::{info, error, warn, debug};

use crate::protocol::RelayMessage;
use crate::punch::{punch_connection_with_strategy, PeerInfo, current_timestamp};
use crate::relay::{Session, create_bound_socket};

/// GO Signal mit Zeitstempel
pub struct GoSignal {
    pub start_at: f64,
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
    timeout: Duration,
) -> Result<Vec<TcpStream>> {
    let mut streams = Vec::new();
    let mut failures_in_a_row = 0;
    const MAX_FAILURES: u32 = 5;
    
    // CRITICAL: Für den Receiver - lese tcp_connections aus der ERSTEN peer_info!
    // Der Sender bestimmt, wie viele Connections genutzt werden.
    let mut actual_tcp_connections = tcp_connections;
    
    for conn_num in 0..actual_tcp_connections {
        info!("📡 Waiting for peer_info for connection {}/{}...", conn_num + 1, actual_tcp_connections);
        
        loop {  // Retry-Loop für diese Connection
            // 1. Warte auf peer_info für diese Connection
            let (peer_info, punch_strategy, peer_tcp_connections) = match receive_peer_info_for_connection(
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
            
            // CRITICAL: Bei der ERSTEN peer_info - übernehme tcp_connections vom Peer (Sender bestimmt!)
            if conn_num == 0 && peer_tcp_connections > actual_tcp_connections {
                info!("🔄 Peer wants {} connections, we only prepared {}. Binding more sockets...", 
                      peer_tcp_connections, actual_tcp_connections);
                
                let needed_more = (peer_tcp_connections - actual_tcp_connections) as usize;
                let next_port = if let Some(last) = session.bound_sockets.last() {
                    last.local_addr().map(|a| a.as_socket().map(|s| s.port()).unwrap_or(0)).unwrap_or(0).wrapping_add(1)
                } else {
                    0
                };
                
                if next_port > 0 {
                    let mut added_count = 0;
                    let mut attempt_counter = 0;
                    let mut current_port = next_port;
                    
                    while added_count < needed_more && attempt_counter < 100 {
                        match create_bound_socket(current_port) {
                            Ok(s) => {
                                session.bound_sockets.push(s);
                                added_count += 1;
                                debug!("Bound extra socket on port {}", current_port);
                            },
                            Err(_) => {}
                        }
                        current_port = current_port.wrapping_add(1);
                        attempt_counter += 1;
                    }
                    
                    info!("✓ Bound {} additional sockets (total: {})", added_count, session.bound_sockets.len());
                }
                
                // Update the actual connection count
                actual_tcp_connections = peer_tcp_connections;
                info!("✓ Adjusted to {} connections as requested by peer", actual_tcp_connections);
            }
            
            info!("✓ Received peer_info for connection {}: strategy={}", conn_num + 1, punch_strategy);
            
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
            
            // 4. Synchronized Punch mit Strategie
            let socket_index = conn_num as usize;
            if socket_index >= session.bound_sockets.len() {
                return Err(anyhow!("No socket available for connection {}", conn_num));
            }
            
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
                    info!("✅ Connection {}/{} established!", conn_num + 1, tcp_connections);
                    break;  // Nächste Connection
                }
                Err(e) => {
                    failures_in_a_row += 1;
                    error!("❌ Connection {} failed: {}", conn_num + 1, e);
                    
                    if failures_in_a_row >= MAX_FAILURES {
                        return Err(anyhow!("Max {} consecutive failures reached", MAX_FAILURES));
                    }
                    
                    warn!("🔄 Retrying connection {} (failure {}/{})", 
                          conn_num + 1, failures_in_a_row, MAX_FAILURES);
                    // Loop wiederholt → neuer Zyklus für diese Connection
                }
            }
        }
    }
    
    Ok(streams)
}
