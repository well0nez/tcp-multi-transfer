//! Multi-connection establishment through coordinated hole punching

use std::net::SocketAddr;
use std::time::Duration;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use anyhow::{Result, anyhow};
use tracing::{info, error, warn, debug};

use crate::protocol::AddPortsMessage;
use crate::punch::{punch_connection_with_strategy, current_timestamp};
use crate::relay::{Session, create_bound_socket};

mod types;
mod message_queue;
mod message_receiver;
mod state_machine;
mod notification_handler;
mod queue_readers;

pub use message_queue::MessageQueues;
pub use message_receiver::spawn_message_receiver;
pub use state_machine::{
    ConnectionState, 
    handle_peer_info_transition,
    handle_go_transition,
    handle_connection_success,
    handle_connection_failure,
    handle_retry_request,
    handle_retry_granted,
};
pub use notification_handler::spawn_notification_handler;
pub use queue_readers::{
    wait_for_peer_info_from_queue,
    wait_for_go_from_queue,
    wait_for_ports_ack_from_queue,
    wait_for_retry_granted_from_queue,
};

pub async fn establish_multi_connections(
    relay_reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
    mut relay_writer: tokio::net::tcp::OwnedWriteHalf,
    session: &mut Session,
    tcp_connections: u32,
    role: &str,
    timeout: Duration,
    session_id: &str,
    _server_addr: SocketAddr,
    _probe_port: Option<u16>,
) -> Result<Vec<TcpStream>> {
    info!("🚀 Starting queue-based connection establishment");
    
    let queues = MessageQueues::new();
    let _receiver_handle = spawn_message_receiver(relay_reader, queues.clone());
    info!("✅ Message receiver task spawned");
    
    let peer_extra_ports_shared = Arc::new(Mutex::new(Vec::new()));
    let _notification_handle = spawn_notification_handler(
        queues.clone(),
        peer_extra_ports_shared.clone(),
    );
    info!("✅ Notification handler task spawned");
    
    let mut streams = Vec::new();
    let mut failures_in_a_row = 0;
    const MAX_FAILURES: u32 = 5;
    
    let (actual_tcp_connections, start_conn) = if role == "receiver" {
        info!("Receiver: Waiting for initial peer_info (connection 1/?)...");
        
        let (peer_info, punch_strategy, peer_tcp_connections) = wait_for_peer_info_from_queue(
            &queues,
            0,
            Duration::from_secs(120)
        ).await?;
        
        info!("Received initial peer_info: peer wants {} connections", peer_tcp_connections);
        info!("Received peer_info for connection 1/{}: strategy={}", peer_tcp_connections, punch_strategy);
        
        let ready_msg = format!(r#"{{"type":"ready","connection_num":0}}"#) + "\n";
        relay_writer.write_all(ready_msg.as_bytes()).await?;
        relay_writer.flush().await?;
        info!("READY sent for connection 1/{}", peer_tcp_connections);
        
        let go_signal = wait_for_go_from_queue(&queues, 0, Duration::from_secs(120)).await?;
        let countdown = go_signal.start_at - current_timestamp();
        info!("GO received for connection 1/{}! Start in {:.2}s", peer_tcp_connections, countdown);
        
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
        info!("Connection 1/{} established!", peer_tcp_connections);
        
        (peer_tcp_connections, 1)
    } else {
        let current_socket_count = session.bound_sockets.len() as u32;
        
        if tcp_connections > current_socket_count {
            let needed_more = (tcp_connections - current_socket_count) as usize;
            info!("Sender: Binding {} more sockets...", needed_more);
            
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
                
                info!("Bound {} additional sockets (total: {})", added_count, session.bound_sockets.len());
                
                if !new_ports.is_empty() {
                    info!("Sender: Sending add_ports for {} new ports (Port-Preserved NAT)", new_ports.len());
                    
                    let add_msg = AddPortsMessage::new(session_id, new_ports.clone());
                    let json = serde_json::to_string(&add_msg)? + "\n";
                    relay_writer.write_all(json.as_bytes()).await?;
                    relay_writer.flush().await?;
                    info!("Sent add_ports message");
                    
                    match wait_for_ports_ack_from_queue(&queues, &new_ports, Duration::from_secs(30)).await {
                        Ok(_) => info!("New ports confirmed by server"),
                        Err(e) => warn!("Failed to get ACK for new ports: {}", e),
                    }
                }
            }
        }
        
        (tcp_connections, 0)
    };
    
    for conn_num in start_conn..actual_tcp_connections {
        let socket_index = conn_num as usize;
        
        if socket_index >= session.bound_sockets.len() {
            let base_port = if let Some(last) = session.bound_sockets.last() {
                last.local_addr().map(|a| a.as_socket().map(|s| s.port()).unwrap_or(0)).unwrap_or(0).wrapping_add(1)
            } else {
                return Err(anyhow!("No initial socket available"));
            };
            
            let mut bound = false;
            for port_offset in 0u16..50 {
                let try_port = base_port.wrapping_add(port_offset);
                match create_bound_socket(try_port) {
                    Ok(new_socket) => {
                        let new_port = new_socket.local_addr()?.as_socket().map(|s| s.port()).unwrap_or(try_port);
                        session.bound_sockets.push(new_socket);
                        info!("On-demand: Bound new socket on port {} for connection {}", new_port, conn_num + 1);
                        
                        let add_msg = AddPortsMessage::new(session_id, vec![new_port]);
                        let json = serde_json::to_string(&add_msg)? + "\n";
                        relay_writer.write_all(json.as_bytes()).await?;
                        relay_writer.flush().await?;
                        info!("Sent add_ports for new socket {}", new_port);
                        
                        match wait_for_ports_ack_from_queue(&queues, &[new_port], Duration::from_secs(30)).await {
                            Ok(_) => info!("New port {} confirmed by server", new_port),
                            Err(e) => warn!("Failed to get ACK for new port {}: {}", new_port, e),
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
        
        info!("Starting state machine for connection {}/{}...", conn_num + 1, actual_tcp_connections);
        
        let mut state = ConnectionState::WaitingForPeerInfo { conn_num };
        let mut connection_stream: Option<TcpStream> = None;
        
        loop {
            state = match state {
                ConnectionState::WaitingForPeerInfo { conn_num } => {
                    debug!("State: WaitingForPeerInfo (conn {})", conn_num);
                    
                    match wait_for_peer_info_from_queue(&queues, conn_num, Duration::from_secs(120)).await {
                        Ok((peer_info, strategy, _)) => {
                            info!("Received peer_info for connection {}/{}: strategy={}", conn_num + 1, actual_tcp_connections, strategy);
                            handle_peer_info_transition(state, peer_info, strategy)?
                        }
                        Err(e) => {
                            error!("Failed to receive peer_info: {}", e);
                            failures_in_a_row += 1;
                            if failures_in_a_row >= MAX_FAILURES {
                                return Err(anyhow!("Max failures reached waiting for peer_info"));
                            }
                            handle_connection_failure(state, e.to_string())?
                        }
                    }
                }
                
                ConnectionState::WaitingForGO { conn_num, peer_info: _, strategy: _ } => {
                    debug!("State: WaitingForGO (conn {})", conn_num);
                    
                    let ready_msg = format!(r#"{{"type":"ready","connection_num":{}}}"#, conn_num) + "\n";
                    relay_writer.write_all(ready_msg.as_bytes()).await?;
                    relay_writer.flush().await?;
                    info!("READY sent for connection {}", conn_num + 1);
                    
                    match wait_for_go_from_queue(&queues, conn_num, Duration::from_secs(120)).await {
                        Ok(go_signal) => {
                            let countdown = go_signal.start_at - current_timestamp();
                            info!("GO received for connection {}! Start in {:.2}s", conn_num + 1, countdown);
                            handle_go_transition(state, go_signal)?
                        }
                        Err(e) => {
                            error!("Failed to receive GO: {}", e);
                            failures_in_a_row += 1;
                            if failures_in_a_row >= MAX_FAILURES {
                                return Err(anyhow!("Max failures reached waiting for GO"));
                            }
                            handle_connection_failure(state, e.to_string())?
                        }
                    }
                }
                
                ConnectionState::Punching { conn_num, ref peer_info, ref strategy, start_at } => {
                    debug!("State: Punching (conn {})", conn_num);
                    
                    match punch_connection_with_strategy(
                        session.bound_sockets[socket_index].try_clone()?,
                        peer_info,
                        strategy,
                        start_at,
                        session.time_offset,
                        timeout,
                    ).await {
                        Ok(stream) => {
                            info!("Connection {}/{} established!", conn_num + 1, actual_tcp_connections);
                            failures_in_a_row = 0;
                            connection_stream = Some(stream);
                            handle_connection_success(state)?
                        }
                        Err(e) => {
                            error!("Connection {} failed: {}", conn_num + 1, e);
                            failures_in_a_row += 1;
                            handle_connection_failure(state, e.to_string())?
                        }
                    }
                }
                
                ConnectionState::Established { conn_num } => {
                    debug!("State: Established (conn {}) - TERMINAL", conn_num);
                    if let Some(stream) = connection_stream {
                        streams.push(stream);
                    }
                    break;
                }
                
                ConnectionState::Failed { conn_num, ref reason, attempt } => {
                    debug!("State: Failed (conn {}, attempt {})", conn_num, attempt);
                    
                    if failures_in_a_row >= MAX_FAILURES {
                        return Err(anyhow!("Max {} consecutive failures reached: {}", MAX_FAILURES, reason));
                    }
                    
                    warn!("Requesting retry for connection {} (failure {}/{})", conn_num + 1, failures_in_a_row, MAX_FAILURES);
                    
                    let retry_msg = format!(r#"{{"type":"retry_request","connection_num":{}}}"#, conn_num) + "\n";
                    relay_writer.write_all(retry_msg.as_bytes()).await?;
                    relay_writer.flush().await?;
                    info!("Sent retry_request for connection {}", conn_num + 1);
                    
                    handle_retry_request(state)?
                }
                
                ConnectionState::WaitingForRetry { conn_num, attempt } => {
                    debug!("State: WaitingForRetry (conn {}, attempt {})", conn_num, attempt);
                    
                    match wait_for_retry_granted_from_queue(&queues, conn_num, Duration::from_secs(30)).await {
                        Ok(()) => {
                            info!("Retry granted by server for connection {}", conn_num + 1);
                            
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
                                        
                                        if socket_index < session.bound_sockets.len() {
                                            session.bound_sockets[socket_index] = new_socket;
                                        } else {
                                            session.bound_sockets.push(new_socket);
                                        }
                                        
                                        info!("Retry: Bound new socket on port {} for connection {}", new_port, conn_num + 1);
                                        
                                        let add_msg = AddPortsMessage::new(session_id, vec![new_port]);
                                        let json = serde_json::to_string(&add_msg)? + "\n";
                                        relay_writer.write_all(json.as_bytes()).await?;
                                        relay_writer.flush().await?;
                                        info!("Sent add_ports for retry socket {}", new_port);
                                        
                                        match wait_for_ports_ack_from_queue(&queues, &[new_port], Duration::from_secs(30)).await {
                                            Ok(_) => info!("New port {} confirmed by server", new_port),
                                            Err(e) => warn!("Failed to get ACK for new port {}: {}", new_port, e),
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
                                return Err(anyhow!("Failed to bind socket for retry"));
                            }
                            
                            handle_retry_granted(state)?
                        }
                        Err(e) => {
                            warn!("Retry not granted for connection {}: {}", conn_num + 1, e);
                            failures_in_a_row += 1;
                            if failures_in_a_row >= MAX_FAILURES {
                                return Err(anyhow!("Max failures reached waiting for retry_granted"));
                            }
                            state
                        }
                    }
                }
                
                _ => {
                    return Err(anyhow!("Unexpected connection state: {:?}", state));
                }
            };
        }
    }
    
    queues.set_shutdown();
    debug!("Shutdown signal sent to message receiver task");
    
    if let Ok(ports) = peer_extra_ports_shared.lock() {
        session.peer_extra_ports = ports.clone();
        if !ports.is_empty() {
            info!("Final peer_extra_ports: {:?}", session.peer_extra_ports);
        }
    }
    
    Ok(streams)
}