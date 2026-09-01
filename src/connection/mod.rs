//! Multi-connection establishment through coordinated hole punching

use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use anyhow::{Result, anyhow};
use tracing::{info, error, warn, debug};

use crate::protocol::{AddPortsMessage, ConnEstablishedMessage, ConnAbandonedMessage};
use crate::punch::{punch_connection, current_timestamp, PunchOptions};
use crate::metrics::MetricsSink;
use crate::relay::{Session, create_bound_socket};

mod types;
mod message_queue;
mod message_receiver;
mod state_machine;
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
pub use queue_readers::{
    wait_for_peer_info_from_queue,
    wait_for_go_from_queue,
    wait_for_ports_ack_from_queue,
    wait_for_retry_granted_from_queue,
};


fn port_in_use(bound_sockets: &[socket2::Socket], port: u16, exclude_index: Option<usize>) -> bool {
    bound_sockets.iter().enumerate().any(|(idx, sock)| {
        if Some(idx) == exclude_index {
            return false;
        }
        sock.local_addr()
            .ok()
            .and_then(|addr| addr.as_socket().map(|s| s.port()))
            .map(|p| p == port)
            .unwrap_or(false)
    })
}

fn bind_ephemeral_unique(
    bound_sockets: &[socket2::Socket],
    exclude_index: Option<usize>,
) -> Result<(socket2::Socket, u16)> {
    for attempt in 0..10 {
        match create_bound_socket(0) {
            Ok(sock) => {
                let new_port = sock
                    .local_addr()?
                    .as_socket()
                    .map(|s| s.port())
                    .unwrap_or(0);
                if new_port == 0 {
                    continue;
                }
                if port_in_use(bound_sockets, new_port, exclude_index) {
                    debug!("Ephemeral port {} already in use, retrying...", new_port);
                    continue;
                }
                return Ok((sock, new_port));
            }
            Err(e) => {
                if attempt == 0 {
                    debug!("Failed to bind ephemeral port: {}", e);
                }
            }
        }
    }
    Err(anyhow!("Failed to bind unique ephemeral port after multiple attempts"))
}

async fn send_conn_established(
    relay_writer: &mut tokio::net::tcp::OwnedWriteHalf,
    conn_num: u32,
) -> Result<()> {
    let msg = ConnEstablishedMessage::new(conn_num);
    let json = serde_json::to_string(&msg)? + "\n";
    relay_writer.write_all(json.as_bytes()).await?;
    relay_writer.flush().await?;
    Ok(())
}

async fn send_conn_abandoned(
    relay_writer: &mut tokio::net::tcp::OwnedWriteHalf,
    conn_num: u32,
    reason: &str,
) -> Result<()> {
    let msg = ConnAbandonedMessage::new(conn_num, Some(reason.to_string()));
    let json = serde_json::to_string(&msg)? + "\n";
    relay_writer.write_all(json.as_bytes()).await?;
    relay_writer.flush().await?;
    Ok(())
}

/// Meldet neu gebundene Ports beim Relay und wartet auf die Bestaetigung.
///
/// Stand vorher dreimal fast gleich da — bei der Erstausstattung, beim
/// Nachbinden und bei der Wiederholung. Eine Stelle statt drei heisst auch:
/// eine Stelle, an der eine Korrektur ankommt.
async fn ports_melden(
    queues: &MessageQueues,
    relay_writer: &mut tokio::net::tcp::OwnedWriteHalf,
    session_id: &str,
    ports: &[u16],
) -> Result<()> {
    if ports.is_empty() {
        return Ok(());
    }
    let add_msg = AddPortsMessage::new(session_id, ports.to_vec());
    let json = serde_json::to_string(&add_msg)? + "\n";
    relay_writer.write_all(json.as_bytes()).await?;
    relay_writer.flush().await?;
    info!("Sent add_ports for {:?}", ports);

    match wait_for_ports_ack_from_queue(queues, ports, Duration::from_secs(30)).await {
        Ok(_) => info!("Ports {:?} confirmed by server", ports),
        // Kein harter Fehler: der Punch kann auch ohne Bestaetigung gelingen,
        // die Kandidatenliste der Gegenstelle ist dann nur aelter.
        Err(e) => warn!("No ACK for ports {:?}: {}", ports, e),
    }
    Ok(())
}

/// Bindet so lange Sockets nach, bis `index` belegt ist.
///
/// Wichtig ist die Invariante `bound_sockets.len() > index`: der Punch greift
/// spaeter ueber genau diesen Index zu. Wurde frueher ein Bind uebersprungen,
/// ohne dass etwas in die Liste kam, zeigte der Index hinter das Ende.
async fn sockets_bis(
    session: &mut Session,
    queues: &MessageQueues,
    relay_writer: &mut tokio::net::tcp::OwnedWriteHalf,
    session_id: &str,
    index: usize,
) -> Result<(), String> {
    while session.bound_sockets.len() <= index {
        let (sock, port) = bind_ephemeral_unique(&session.bound_sockets, None)
            .map_err(|e| format!("Failed to bind socket: {}", e))?;
        session.bound_sockets.push(sock);
        info!("Bound socket on port {} (index {})", port, session.bound_sockets.len() - 1);
        ports_melden(queues, relay_writer, session_id, &[port])
            .await
            .map_err(|e| format!("add_ports failed: {}", e))?;
    }
    Ok(())
}

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
    punch_opts: &PunchOptions,
    probe_from_bound: bool,
    auto_parallel: bool,
    max_attempts: u32,
    metrics: &MetricsSink,
) -> Result<Vec<TcpStream>> {
    info!("🚀 Starting queue-based connection establishment");
    
    let queues = MessageQueues::new();
    let receiver_handle = spawn_message_receiver(relay_reader, queues.clone());
    info!("✅ Message receiver task spawned");
    
    let mut streams = Vec::new();
    // Bricht die Steuerverbindung weg, ist die Abstimmung vorbei — die bereits
    // gepunchten Verbindungen sind davon aber unberuehrt, sie laufen direkt
    // zwischen den Peers. Frueher wurden sie mit weggeworfen und `--allow-fallback`
    // lief ins Leere.
    let mut transport_verloren = false;
    let mut failures_in_a_row = 0;
    // Frueher eine feste 5 an dieser Stelle, waehrend `--max-attempts` mit
    // Vorgabe 20 dokumentiert war und nirgends gelesen wurde.
    let max_failures = max_attempts.max(1);
    
    let (actual_tcp_connections, mut saved_first_peer_info) = if role == "receiver" {
        info!("Receiver: Waiting for initial peer_info to determine connection count...");
        
        // Read the first peer_info and SAVE it for connection 0
        let (peer_info, peer_tcp_connections) = wait_for_peer_info_from_queue(
            &queues,
            0,
            Duration::from_secs(120)
        ).await?;
        
        info!("Received initial peer_info: peer wants {} connections", peer_tcp_connections);
        info!("Receiver will establish all {} connections through state machine", peer_tcp_connections);
        
        (peer_tcp_connections, Some(peer_info))  // Save peer_info for connection 0
    } else {
        let current_socket_count = session.bound_sockets.len() as u32;
        
        if tcp_connections > current_socket_count {
            let needed_more = (tcp_connections - current_socket_count) as usize;
            info!("Sender: Binding {} more sockets...", needed_more);
            let mut new_ports = Vec::new();
            for _ in 0..needed_more {
                match bind_ephemeral_unique(&session.bound_sockets, None) {
                    Ok((sock, new_port)) => {
                        session.bound_sockets.push(sock);
                        new_ports.push(new_port);
                        debug!("Bound extra socket on port {}", new_port);
                    }
                    Err(e) => {
                        warn!("Failed to bind extra socket: {}", e);
                        break;
                    }
                }
            }
            
            info!("Bound {} additional sockets (total: {})", new_ports.len(), session.bound_sockets.len());
            ports_melden(&queues, &mut relay_writer, session_id, &new_ports).await?;
        }
        
        (tcp_connections, None)  // No saved peer_info for sender
    };
    
    for conn_num in 0..actual_tcp_connections {
        let socket_index = conn_num as usize;
        if conn_num + 1 == actual_tcp_connections {
            // Ab der letzten Verbindung ist ein Abbruch der Steuerverbindung
            // erwartbar statt alarmierend.
            queues.set_letzte_verbindung();
        }
        
        if let Err(grund) = sockets_bis(
            session, &queues, &mut relay_writer, session_id, socket_index
        ).await {
            warn!("Abandoning connection {}: {}", conn_num + 1, grund);
            let _ = send_conn_abandoned(&mut relay_writer, conn_num, &grund).await;
            failures_in_a_row = 0;
            continue;
        }

        info!("Starting state machine for connection {}/{}...", conn_num + 1, actual_tcp_connections);
        
        let mut state = ConnectionState::WaitingForPeerInfo { conn_num };
        let mut connection_stream: Option<TcpStream> = None;
        let mut abandon_reason: Option<String> = None;
        
        loop {
            state = match state {
                ConnectionState::WaitingForPeerInfo { conn_num } => {
                    debug!("State: WaitingForPeerInfo (conn {})", conn_num);
                    
                    // Check if we have cached peer_info for connection 0 (receiver only)
                    if conn_num == 0 && saved_first_peer_info.is_some() {
                        let peer_info = saved_first_peer_info.take().unwrap();
                        info!("Using cached peer_info for connection 1/{}", actual_tcp_connections);
                        handle_peer_info_transition(state, peer_info)?
                    } else {
                        // Normal flow: read from queue (for connections 1-7 or retry)
                        match wait_for_peer_info_from_queue(&queues, conn_num, Duration::from_secs(120)).await {
                            Ok((peer_info, _)) => {
                                info!("Received peer_info for connection {}/{}", conn_num + 1, actual_tcp_connections);
                                handle_peer_info_transition(state, peer_info)?
                            }
                            Err(e) => {
                                error!("Failed to receive peer_info: {}", e);
                                if e.to_string().contains("Transport lost") {
                                    transport_verloren = true;
                                    abandon_reason = Some(e.to_string());
                                } else if e.to_string().starts_with("Server error:") {
                                    return Err(e);
                                }
                                failures_in_a_row += 1;
                                if failures_in_a_row >= max_failures {
                                    abandon_reason = Some(format!("peer_info: {}", e));
                                }
                                handle_connection_failure(state, e.to_string())?
                            }
                        }
                    }
                }
                
                ConnectionState::WaitingForGO { conn_num, peer_info: _ } => {
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
                            if e.to_string().contains("Transport lost") {
                                transport_verloren = true;
                                abandon_reason = Some(e.to_string());
                            } else if e.to_string().starts_with("Server error:") {
                                return Err(e);
                            }
                            failures_in_a_row += 1;
                            if failures_in_a_row >= max_failures {
                                abandon_reason = Some(format!("go: {}", e));
                            }
                            handle_connection_failure(state, e.to_string())?
                        }
                    }
                }
                
                ConnectionState::Punching { conn_num, ref peer_info, start_at } => {
                    debug!("State: Punching (conn {})", conn_num);

                    // Zusaetzliche lokale Ports sind nur dann Ziehungen, wenn
                    // die Gegenstelle ein *Band* von uns abscannen muss. Kennt
                    // sie unseren Port genau — portbewahrende oder
                    // versatzstabile NAT —, dann liegt jedes Mapping auf einem
                    // anderen lokalen Port ausserhalb ihrer Kandidatenliste und
                    // bleibt wirkungslos. Die Entscheidung faellt anhand der
                    // *eigenen* Analyse, die der Relay mitschickt.
                    let mut wirksame_opts = punch_opts.clone();
                    if auto_parallel && wirksame_opts.parallel_ports > 1 {
                        let eigenes_band = peer_info
                            .own_nat_analysis
                            .as_ref()
                            .map(|a| a.needs_scan)
                            .unwrap_or(false);
                        if !eigenes_band {
                            info!(
                                "Local ports set to 1: our own NAT allocates predictably, \
                                 the peer knows exactly one port of ours"
                            );
                            wirksame_opts.parallel_ports = 1;
                        }
                    }
                    
                    let (punch_result, punch_report) = punch_connection(
                        session.bound_sockets[socket_index].try_clone()?,
                        peer_info,
                        &wirksame_opts,
                        start_at,
                        session.time_offset,
                        timeout,
                        conn_num,
                        session.mapping_stable,
                    ).await;
                    metrics.write(session_id, role, &wirksame_opts, probe_from_bound, &punch_report);

                    match punch_result {
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
                    if let Err(e) = send_conn_established(&mut relay_writer, conn_num).await {
                        warn!("Failed to notify server of connection {} establishment: {}", conn_num + 1, e);
                    }
                    if let Some(stream) = connection_stream {
                        streams.push(stream);
                    }
                    break;
                }
                
                ConnectionState::Failed { conn_num, ref reason } => {
                    debug!("State: Failed (conn {})", conn_num);
                    
                    if failures_in_a_row >= max_failures {
                        abandon_reason = Some(format!("max_failures: {}", reason));
                        ConnectionState::Failed {
                            conn_num,
                            reason: reason.to_string(),
                        }
                    } else {
                        warn!("Requesting retry for connection {} (failure {}/{})", conn_num + 1, failures_in_a_row, max_failures);
                        
                        let retry_msg = format!(r#"{{"type":"retry_request","connection_num":{}}}"#, conn_num) + "\n";
                        relay_writer.write_all(retry_msg.as_bytes()).await?;
                        relay_writer.flush().await?;
                        info!("Sent retry_request for connection {}", conn_num + 1);
                        
                        handle_retry_request(state)?
                    }
                }
                
                ConnectionState::WaitingForRetry { conn_num } => {
                    debug!("State: WaitingForRetry (conn {})", conn_num);
                    
                    match wait_for_retry_granted_from_queue(&queues, conn_num, Duration::from_secs(60)).await {
                        Ok(()) => {
                            info!("Retry granted by server for connection {}", conn_num + 1);
                            let exclude_index = if socket_index < session.bound_sockets.len() {
                                Some(socket_index)
                            } else {
                                None
                            };
                            match bind_ephemeral_unique(&session.bound_sockets, exclude_index) {
                                Ok((new_socket, new_port)) => {
                                    if socket_index < session.bound_sockets.len() {
                                        session.bound_sockets[socket_index] = new_socket;
                                    } else {
                                        session.bound_sockets.push(new_socket);
                                    }
                                    info!("Retry: bound new socket on port {} for connection {}",
                                          new_port, conn_num + 1);
                                    ports_melden(&queues, &mut relay_writer, session_id, &[new_port]).await?;
                                    handle_retry_granted(state)?
                                }
                                Err(e) => {
                                    let reason = format!("Failed to bind socket for retry: {}", e);
                                    error!("{}", reason);
                                    abandon_reason = Some(reason.clone());
                                    ConnectionState::Failed { conn_num, reason }
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Retry not granted for connection {}: {}", conn_num + 1, e);
                            if e.to_string().contains("Transport lost") {
                                transport_verloren = true;
                                abandon_reason = Some(e.to_string());
                            } else if e.to_string().starts_with("Server error:") {
                                return Err(e);
                            }
                            failures_in_a_row += 1;
                            if failures_in_a_row >= max_failures {
                                abandon_reason = Some(format!("retry_granted: {}", e));
                            }
                            // FIX: Don't return same state - transition to Failed
                            error!("Retry coordination failed for connection {}: {}", conn_num + 1, e);
                            ConnectionState::Failed {
                                conn_num,
                                reason: format!("Retry coordination failed: {}", e),
                            }
                        }
                    }
                }
                
            };
            
            if abandon_reason.is_some() {
                break;
            }
        }
        
        if let Some(reason) = abandon_reason.take() {
            warn!("Abandoning connection {}: {}", conn_num + 1, reason);
            let _ = send_conn_abandoned(&mut relay_writer, conn_num, &reason).await;
            failures_in_a_row = 0;
            if transport_verloren {
                warn!(
                    "Relay connection lost - continuing with the {} connection(s) already established",
                    streams.len()
                );
                break;
            }
            continue;
        }
    }
    
    queues.set_shutdown();
    // Der Leser haengt jetzt ohne Zeitgrenze in `read_line`; das Abschalten
    // bemerkt er nur, wenn wir ihn abbrechen. Hier ist das gefahrlos: es kommt
    // nichts mehr, worauf jemand wartet.
    receiver_handle.abort();
    debug!("Message receiver task stopped");

    Ok(streams)
}
