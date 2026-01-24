//! Async task for receiving and routing relay messages

use std::time::Duration;
use std::net::SocketAddr;
use tokio::io::{AsyncBufReadExt, BufReader};
use anyhow::Result;
use tracing::{info, error, warn, debug};

use crate::protocol::RelayMessage;
use crate::punch::PeerInfo;
use super::message_queue::MessageQueues;
use super::types::GoSignal;

pub fn spawn_message_receiver(
    mut relay_reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
    queues: MessageQueues,
) -> tokio::task::JoinHandle<Result<()>> {
    tokio::spawn(async move {
        info!("Message receiver task started");
        
        loop {
            if queues.is_shutdown() {
                info!("Message receiver shutting down");
                break;
            }
            
            let mut line = String::new();
            
            match tokio::time::timeout(Duration::from_secs(5), relay_reader.read_line(&mut line)).await {
                Ok(Ok(0)) => {
                    error!("Connection closed by relay server");
                    queues.push_error("Connection lost".to_string());
                    break;
                }
                Ok(Err(e)) => {
                    error!("Read error from relay server: {}", e);
                    queues.push_error(format!("Read error: {}", e));
                    break;
                }
                Ok(Ok(_)) => {
                    if line.trim().is_empty() {
                        continue;
                    }
                    
                    match serde_json::from_str::<RelayMessage>(&line) {
                        Ok(msg) => {
                            match msg {
                                RelayMessage::PeerInfo { 
                                    connection_num, 
                                    punch_strategy, 
                                    peer_public_addr, 
                                    peer_addresses, 
                                    peer_nat_analysis, 
                                    tcp_connections, 
                                    .. 
                                } => {
                                    let conn = connection_num.unwrap_or(0);
                                    let strategy = punch_strategy.unwrap_or_else(|| "scan".to_string());
                                    let tcp_conns = tcp_connections.unwrap_or(1);
                                    
                                    if let Some((ip, port)) = RelayMessage::parse_addr(&peer_public_addr) {
                                        if let Ok(peer_addr) = format!("{}:{}", ip, port).parse::<SocketAddr>() {
                                            let peer_info = PeerInfo {
                                                peer_addr,
                                                peer_addresses,
                                                peer_nat_analysis,
                                            };
                                            
                                            queues.push_peer_info(conn, peer_info, strategy, tcp_conns);
                                            debug!("Queued PeerInfo for conn {}", conn);
                                        } else {
                                            warn!("Failed to parse peer address: {}:{}", ip, port);
                                        }
                                    } else {
                                        warn!("Invalid peer_public_addr format: {:?}", peer_public_addr);
                                    }
                                }
                                
                                RelayMessage::Go { start_at, connection_num, .. } => {
                                    let conn = connection_num.unwrap_or(0);
                                    queues.push_go(conn, GoSignal { start_at });
                                    debug!("Queued GO for conn {}", conn);
                                }
                                
                                RelayMessage::PortsAddedAck { ports } => {
                                    queues.push_ports_ack(ports.clone());
                                    debug!("Queued PortsAddedAck for {} ports", ports.len());
                                }
                                
                                RelayMessage::PeerAddedPorts { ports } => {
                                    queues.push_peer_added_ports(ports.clone());
                                    debug!("Queued PeerAddedPorts: {:?}", ports);
                                }
                                
                                RelayMessage::RetryGranted { connection_num } => {
                                    queues.push_retry_granted(connection_num);
                                    debug!("Queued RetryGranted for conn {}", connection_num);
                                }
                                
                                RelayMessage::RetryRejected { connection_num, reason } => {
                                    queues.push_retry_rejected(connection_num, reason.clone());
                                    debug!("Queued RetryRejected for conn {}: {}", connection_num, reason);
                                }
                                
                                RelayMessage::Error { message } => {
                                    queues.push_error(message.clone());
                                    error!("Server error: {}", message);
                                }
                                
                                _ => {
                                    debug!("Unhandled message type: {:?}", msg);
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Failed to parse message: {} - {}", e, line.trim());
                        }
                    }
                }
                Err(_) => {
                    debug!("Read timeout (keepalive)");
                }
            }
        }
        
        info!("Message receiver task stopped");
        Ok(())
    })
}