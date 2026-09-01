//! Async task for receiving and routing relay messages

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
            
            // Ohne Zeitgrenze lesen. `read_line` ist nicht abbruchsicher: wird
            // es mitten in einer Zeile abgebrochen, sind die bereits gelesenen
            // Bytes verloren und der Rest der Zeile landet als Bruchstueck im
            // Parser — die Nachricht (peer_info, GO) ist damit weg. Die
            // Zeitgrenze diente nur dazu, das Abschaltzeichen zu bemerken;
            // dafuer bricht der Aufrufer die Aufgabe jetzt gezielt ab.
            match relay_reader.read_line(&mut line).await {
                Ok(0) => {
                    if queues.is_shutdown() {
                        info!("Relay connection closed after shutdown");
                        break;
                    }
                    // Nach der letzten abgestimmten Verbindung legen beide
                    // Seiten die Steuerverbindung auf; der Relay schliesst
                    // daraufhin auch die des Nachzueglers. Wer als Zweiter
                    // fertig wird, sieht das immer — es ist der Normalfall.
                    if queues.ist_letzte_verbindung() {
                        info!("Relay connection closed - coordination finished");
                    } else {
                        error!("Connection closed by relay server");
                    }
                    queues.push_error("Transport lost: relay connection closed".to_string());
                    break;
                }
                Err(e) => {
                    if queues.is_shutdown() {
                        info!("Relay connection read error after shutdown: {}", e);
                        break;
                    }
                    error!("Read error from relay server: {}", e);
                    queues.push_error(format!("Transport lost: {}", e));
                    break;
                }
                Ok(_) => {
                    if line.trim().is_empty() {
                        continue;
                    }
                    
                    match serde_json::from_str::<RelayMessage>(&line) {
                        Ok(msg) => {
                            match msg {
                                RelayMessage::PeerInfo { 
                                    connection_num,
                                    peer_public_addr,
                                    peer_addresses,
                                    peer_nat_analysis,
                                    your_nat_analysis,
                                    tcp_connections,
                                    same_network,
                                    ..
                                } => {
                                    let conn = connection_num.unwrap_or(0);
                                    let tcp_conns = tcp_connections.unwrap_or(1);
                                    
                                    if let Some((ip, port)) = RelayMessage::parse_addr(&peer_public_addr) {
                                        if format!("{}:{}", ip, port).parse::<SocketAddr>().is_ok() {
                                            let peer_info = PeerInfo {
                                                peer_addresses,
                                                same_network,
                                                peer_nat_analysis,
                                                own_nat_analysis: your_nat_analysis,
                                            };
                                            
                                            queues.push_peer_info(conn, peer_info, tcp_conns);
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
                                
                                // Der Server meldet neue Ports der Gegenstelle;
                                // die Punch-Ziele kommen aber ausschliesslich aus
                                // peer_info. Die Nachricht wird deshalb nur
                                // quittiert, nicht ausgewertet.
                                RelayMessage::PeerAddedPorts { ports } => {
                                    debug!("peer_added_ports: {:?} (not used)", ports);
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
            }
        }
        
        info!("Message receiver task stopped");
        Ok(())
    })
}