//! TCP File Transfer Client with NAT Traversal
//!
//! This client uses TCP hole punching to establish direct peer-to-peer
//! connections through NAT, then transfers files using TCP streams.

use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;
use clap::Parser;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use socket2::{Socket, Domain, Type, Protocol, SockAddr};
use anyhow::{Result, anyhow};
use tracing::{info, error, warn, Level, debug};
use tracing_subscriber::FmtSubscriber;

mod cli;
mod protocol;
mod punch;
mod transfer;

use cli::{Args, Mode, PredictionMode, parse_chunk_size, APP_VERSION};
use protocol::{RegisterMessage, RelayMessage, ProbeMessage, AddPortsMessage};
use punch::{punch_connection_with_strategy, PeerInfo, current_timestamp};
use transfer::{
    TcpSender,
    TcpReceiver,
    calculate_sha256,
    set_chunk_size,
    run_multi_sender,
    run_multi_receiver,
};

/// Session state for hole punch coordination
struct Session {
    peer_public_addr: Option<SocketAddr>,
    peer_addresses: Vec<protocol::relay::PeerAddressInfo>,
    peer_nat_analysis: Option<protocol::NATAnalysis>,
    same_network: bool,
    time_offset: f64,
    our_public_port: Option<u16>,
    our_delta: i32,
    port_preserved: bool,
    
    // Multi-TCP fields
    tcp_connections: u32,
    scan_budget: u32,
    punch_overshoot: f64,
    allow_fallback: bool,
    min_connections: u32,
    bound_sockets: Vec<Socket>,
    peer_extra_ports: Vec<u16>,
}

fn parse_host_port(input: &str) -> Result<(String, u16)> {
    let input = input.trim();
    if input.starts_with('[') {
        let end = input.find(']').ok_or_else(|| anyhow!("Invalid address"))?;
        let host = &input[1..end];
        let port = input[end + 1..].trim_start_matches(':').parse::<u16>()?;
        return Ok((host.to_string(), port));
    }
    let idx = input.rfind(':').ok_or_else(|| anyhow!("Invalid address"))?;
    let host = &input[..idx];
    let port = input[idx + 1..].parse::<u16>()?;
    Ok((host.to_string(), port))
}

fn resolve_host_port(host: &str, port: u16) -> Result<SocketAddr> {
    let mut addrs = (host, port).to_socket_addrs().map_err(|e| anyhow!("Failed to resolve {}: {}", host, e))?;
    addrs.next().ok_or_else(|| anyhow!("No addresses found"))
}

fn resolve_socket_addr(input: &str) -> Result<SocketAddr> {
    let (host, port) = parse_host_port(input)?;
    resolve_host_port(&host, port)
}

async fn do_nat_probing(probe_addr: SocketAddr, session_id: &str, count: u32) -> Result<()> {
    info!("🔍 Starting NAT probing ({} connections to {})...", count, probe_addr);
    let mut successful = 0;
    for i in 0..count {
        match TcpStream::connect(probe_addr).await {
            Ok(stream) => {
                let local_port = stream.local_addr().map(|a| a.port()).unwrap_or(0);
                let probe = ProbeMessage::new(session_id, local_port, i);
                let msg = serde_json::to_string(&probe).unwrap_or_default() + "\n";
                let (_, mut writer) = stream.into_split();
                if let Ok(_) = tokio::io::AsyncWriteExt::write_all(&mut writer, msg.as_bytes()).await {
                    successful += 1;
                    debug!("  Probe #{}: local port {}", i, local_port);
                }
            }
            Err(e) => warn!("  Probe #{} failed: {}", i, e),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    if successful >= 5 {
        info!("  ✓ Sent {}/{} probes successfully", successful, count);
    } else {
        warn!("  ⚠️ Only {}/{} probes succeeded", successful, count);
    }
    Ok(())
}

fn get_free_port() -> Result<u16> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.bind(&"0.0.0.0:0".parse::<SocketAddr>()?.into())?;
    Ok(socket.local_addr()?.as_socket().unwrap().port())
}

fn create_bound_socket(local_port: u16) -> Result<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.set_nodelay(true)?;
    let local_addr: SocketAddr = format!("0.0.0.0:{}", local_port).parse()?;
    socket.bind(&SockAddr::from(local_addr))?;
    Ok(socket)
}

fn compute_punch_task_count(desired: usize, overshoot: f64) -> usize {
    let overshoot = if overshoot < 1.0 { 1.0 } else { overshoot };
    let count = (desired as f64 * overshoot).ceil() as usize;
    count.max(desired).max(1)
}

/// Connect to relay server and handle the full protocol
async fn run_relay_protocol(
    server_addr: &str,
    session_id: &str,
    role: &str,
    local_port: u16,
    _timeout: Duration,
    probe_count: u32,
    prediction_mode: PredictionMode,
    prediction_range_extra_pct: f64,
    tcp_connections: u32,
    scan_budget: u32,
    punch_overshoot: f64,
    allow_fallback: bool,
    min_connections: u32,
    extra_ports: Vec<u16>,
    bound_sockets: Vec<Socket>,
) -> Result<(TcpStream, Session)> {
    info!("Connecting to relay server: {}", server_addr);
    let server_sock_addr = resolve_socket_addr(server_addr)?;
    
    // CRITICAL: Relay connection MUST use the SAME local_port as hole punching!
    // Otherwise NAT mapping will be wrong and punching will fail.
    let socket = create_bound_socket(local_port)?;
    socket.set_nonblocking(true)?;
    
    let _ = socket.connect(&SockAddr::from(server_sock_addr));
    let std_stream: std::net::TcpStream = socket.into();
    let stream = TcpStream::from_std(std_stream)?;
    stream.writable().await?;
    
    if let Err(e) = stream.peer_addr() {
        return Err(anyhow!("Failed to connect to relay server: {}", e));
    }
    info!("Connected to relay server");
    
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    
    let tcp_connections_payload = if tcp_connections > 1 { Some(tcp_connections) } else { None };

    let register = RegisterMessage::new(
        session_id,
        role,
        local_port,
        Some(prediction_mode.as_str().to_string()),
        Some(prediction_range_extra_pct),
        tcp_connections_payload,
        Some(scan_budget),
        Some(punch_overshoot),
        Some(allow_fallback),
        Some(min_connections),
        extra_ports,
    );
    let msg = serde_json::to_string(&register)? + "\n";
    writer.write_all(msg.as_bytes()).await?;
    writer.flush().await?;
    
    info!("Registered as {} for session {} (local_port={})", role, session_id, local_port);
    
    let register_sent_at = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs_f64();
    
    let mut session = Session {
        peer_public_addr: None,
        peer_addresses: vec![],
        peer_nat_analysis: None,
        same_network: false,
        time_offset: 0.0,
        our_public_port: None,
        our_delta: 0,
        port_preserved: true,
        tcp_connections,
        scan_budget,
        punch_overshoot,
        allow_fallback,
        min_connections,
        bound_sockets,
        peer_extra_ports: vec![],
    };
    
    loop {
        let mut line = String::new();
        let n = tokio::time::timeout(Duration::from_secs(120), reader.read_line(&mut line)).await
            .map_err(|_| anyhow!("Timeout waiting for server response"))??;
        
        if n == 0 { return Err(anyhow!("Server closed connection")); }
        
        let msg: RelayMessage = serde_json::from_str(&line)
            .map_err(|e| anyhow!("Failed to parse server message: {} - {}", e, line.trim()))?;
        
        match msg {
            RelayMessage::Registered { your_public_addr, server_time, server_times, probe_port, needs_probing, .. } => {
                if let Some((ip, port)) = RelayMessage::parse_addr(&your_public_addr) {
                    session.our_public_port = Some(port);
                    session.our_delta = port as i32 - local_port as i32;
                    session.port_preserved = session.our_delta == 0;
                    info!("✓ Registered! Public address: {}:{}", ip, port);
                    
                    // NEW: Robust time synchronization using median of multiple samples
                    if let Some(times) = server_times {
                        // Collect offsets from all timestamp samples
                        let mut offsets = Vec::new();
                        for srv_time in times {
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap()
                                .as_secs_f64();
                            let offset = srv_time - now;
                            offsets.push(offset);
                        }
                        
                        // Calculate median (robust against network jitter outliers)
                        offsets.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                        session.time_offset = offsets[offsets.len() / 2];
                        
                        info!("⏱️ Clock offset (median of {} samples): {:.3}s", offsets.len(), session.time_offset);
                        info!("   Range: {:.3}s to {:.3}s (spread: {:.3}s)", 
                              offsets.first().unwrap_or(&0.0),
                              offsets.last().unwrap_or(&0.0),
                              offsets.last().unwrap_or(&0.0) - offsets.first().unwrap_or(&0.0));
                    } else if let Some(srv_time) = server_time {
                        // Fallback to old RTT/2 method (for backward compatibility)
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs_f64();
                        let rtt = now - register_sent_at;
                        session.time_offset = srv_time - (register_sent_at + rtt / 2.0);
                        warn!("⚠️ Using legacy RTT/2 time sync (offset: {:.3}s) - server should send server_times array", session.time_offset);
                    } else {
                        warn!("⚠️ No time sync data received from server - synchronization may be inaccurate");
                        session.time_offset = 0.0;
                    }
                    
                    if needs_probing.unwrap_or(false) {
                        if let Some(pp) = probe_port {
                            let probe_addr = SocketAddr::new(server_sock_addr.ip(), pp);
                            let _ = do_nat_probing(probe_addr, session_id, probe_count).await;
                        }
                    }
                    
                    let probes_complete_msg = r#"{"type":"probes_complete"}"#.to_string() + "\n";
                    writer.write_all(probes_complete_msg.as_bytes()).await?;
                    writer.flush().await?;
                    info!("✓ Probes complete sent");
                    
                    // NEU: Return AFTER probes_complete - Multi-Connection Loop handles rest
                    let stream = reader.into_inner().reunite(writer)?;
                    return Ok((stream, session));
                }
            }
            
            // OLD PROTOCOL HANDLING (kept for backward compatibility, but should not be reached with new server)
            RelayMessage::PeerInfo { peer_public_addr, peer_local_port, peer_addresses, same_network, peer_nat_analysis, tcp_connections, scan_budget, punch_overshoot, allow_fallback, min_connections, peer_extra_ports, .. } => {
                if let Some((ip, port)) = RelayMessage::parse_addr(&peer_public_addr) {
                    let addr: SocketAddr = format!("{}:{}", ip, port).parse()?;
                    session.peer_public_addr = Some(addr);
                    session.peer_addresses = peer_addresses;
                    session.same_network = same_network;
                    session.peer_nat_analysis = peer_nat_analysis;
                    
                    session.tcp_connections = tcp_connections.unwrap_or(session.tcp_connections);
                    session.scan_budget = scan_budget.unwrap_or(session.scan_budget);
                    session.punch_overshoot = punch_overshoot.unwrap_or(session.punch_overshoot);
                    session.allow_fallback = allow_fallback.unwrap_or(session.allow_fallback);
                    session.min_connections = min_connections.unwrap_or(session.min_connections);
                    session.peer_extra_ports = peer_extra_ports;
                    
                    info!("✓ Peer info received! Peer: {} (local {})", addr, peer_local_port);
                    
                    // Dynamic Port Binding for Receiver
                    if role == "receiver" {
                        let desired = session.tcp_connections.max(1) as usize;
                        let current_count = session.bound_sockets.len();
                        let overshoot = session.punch_overshoot.max(1.0);
                        let needed_count = compute_punch_task_count(desired, overshoot);
                        
                        if current_count < needed_count {
                            let needed_more = needed_count - current_count;
                            info!("Sender wants {} connections. Have {}. Binding {} more...", desired, current_count, needed_more);
                            
                            let next_port = if let Some(last) = session.bound_sockets.last() {
                                last.local_addr().map(|a| a.as_socket().map(|s| s.port()).unwrap_or(0)).unwrap_or(0).wrapping_add(1)
                            } else { 0 };
                            
                            if next_port > 0 {
                                let mut new_ports = Vec::new();
                                let mut added_count = 0;
                                let mut attempt_counter = 0;
                                let mut current_cand = next_port;
                                
                                while added_count < needed_more && attempt_counter < 100 {
                                    match create_bound_socket(current_cand) {
                                        Ok(s) => {
                                            new_ports.push(current_cand);
                                            session.bound_sockets.push(s);
                                            added_count += 1;
                                        },
                                        Err(_) => {}
                                    }
                                    current_cand = current_cand.wrapping_add(1);
                                    attempt_counter += 1;
                                }
                                
                                if !new_ports.is_empty() {
                                    info!("Bound {} extra ports: {:?}", new_ports.len(), new_ports);
                                    let add_msg = AddPortsMessage::new(session_id, new_ports);
                                    let json = serde_json::to_string(&add_msg)? + "\n";
                                    writer.write_all(json.as_bytes()).await?;
                                    writer.flush().await?;
                                }
                            }
                        }
                    }
                    
                    let msg = r#"{"type":"ready"}"#.to_string() + "\n";
                    writer.write_all(msg.as_bytes()).await?;
                    writer.flush().await?;
                    info!("✓ READY sent, waiting for GO...");
                }
            }
            
            RelayMessage::PeerAddedPorts { ports } => {
                info!("Received {} additional ports from peer: {:?}", ports.len(), ports);
                session.peer_extra_ports.extend(ports);
            }
            
            // NEU: Go-Messages werden nun im Multi-Connection Loop behandelt
            // (nach probes_complete returnen wir und der Loop übernimmt)
            RelayMessage::Go { .. } => {
                warn!("Received GO in registration phase - should be handled in multi-connection loop");
            }
            
            RelayMessage::Ping {} => {
                let msg = r#"{"type":"keepalive"}"#.to_string() + "\n";
                writer.write_all(msg.as_bytes()).await?;
                writer.flush().await?;
            }
            
            RelayMessage::KeepaliveAck {} => {}
            
            RelayMessage::Error { message } => return Err(anyhow!("Server error: {}", message)),
        }
    }
}

/// GO Signal mit Zeitstempel
struct GoSignal {
    start_at: f64,
}

/// Wartet auf peer_info Message für eine bestimmte Connection
async fn receive_peer_info_for_connection(
    relay_reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    expected_conn_num: u32,
) -> Result<(PeerInfo, String, u32)> {
    loop {
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(120), relay_reader.read_line(&mut line))
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
async fn receive_go_for_connection(
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
async fn establish_multi_connections(
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

async fn run_sender(
    server_addr: &str,
    session_id: &str,
    file_path: &str,
    timeout: Duration,
    probe_count: u32,
    prediction_mode: PredictionMode,
    prediction_range_extra_pct: f64,
    tcp_connections: u32,
    scan_budget: u32,
    punch_overshoot: f64,
    allow_fallback: bool,
    min_connections: u32,
) -> Result<()> {
    info!("Calculating SHA256...");
    let (sha256, file_size) = calculate_sha256(file_path).await?;
    info!("SHA256: {}", transfer::sha256_to_hex(&sha256));
    info!("File size: {:.2} MB", file_size as f64 / 1048576.0);

    let local_port_base = get_free_port()?;
    info!("Using local port base: {}", local_port_base);

    let punch_tasks = compute_punch_task_count(tcp_connections.max(1) as usize, punch_overshoot);
    let mut bound_sockets = Vec::new();
    let mut extra_ports = Vec::new();
    let mut current_port = local_port_base;
    let mut added_count = 0;
    let mut attempt_counter = 0;

    while added_count < punch_tasks && attempt_counter < 100 {
        match create_bound_socket(current_port) {
            Ok(s) => {
                bound_sockets.push(s);
                extra_ports.push(current_port);
                added_count += 1;
            }
            Err(_) => {}
        }
        current_port = current_port.wrapping_add(1);
        attempt_counter += 1;
    }
    let local_port = *extra_ports.first().unwrap_or(&local_port_base);

    let (relay_stream, session) = run_relay_protocol(
        server_addr, session_id, "sender", local_port, timeout, probe_count,
        prediction_mode, prediction_range_extra_pct, tcp_connections, scan_budget,
        punch_overshoot, allow_fallback, min_connections, extra_ports, bound_sockets
    ).await?;

    // NEU: Split relay stream for Multi-Connection Loop
    let (relay_reader, relay_writer) = relay_stream.into_split();
    let relay_reader = BufReader::new(relay_reader);

    // NEU: Etabliere Connections mit strategie-basiertem Hole Punching
    let streams = establish_multi_connections(
        relay_reader,
        relay_writer,
        &session,
        session.tcp_connections,
        timeout,
    ).await?;

    // Validierung der etablierten Connections
    let min_required = if session.allow_fallback { 
        session.min_connections.max(1) as usize 
    } else { 
        session.tcp_connections as usize 
    };
    
    if streams.len() < min_required { 
        return Err(anyhow!(
            "Only established {} of {} required connections", 
            streams.len(), 
            min_required
        )); 
    }

    for s in &streams { info!("✅ Direct P2P: Local {} Remote {}", s.local_addr()?, s.peer_addr()?); }

    if session.tcp_connections > 1 || streams.len() > 1 {
        run_multi_sender(streams, file_path, file_size, sha256).await
    } else {
        let stream = streams.into_iter().next().unwrap();
        let mut sender = TcpSender::new_with_hash(stream, file_path, file_size, sha256);
        sender.run().await
    }
}

async fn run_receiver(
    server_addr: &str,
    session_id: &str,
    timeout: Duration,
    probe_count: u32,
    prediction_mode: PredictionMode,
    prediction_range_extra_pct: f64,
    tcp_connections: u32,
    scan_budget: u32,
    punch_overshoot: f64,
    allow_fallback: bool,
    min_connections: u32,
) -> Result<()> {
    let local_port_base = get_free_port()?;
    info!("Using local port base: {}", local_port_base);

    let punch_tasks = compute_punch_task_count(tcp_connections.max(1) as usize, punch_overshoot);
    let mut bound_sockets = Vec::new();
    let mut extra_ports = Vec::new();
    let mut current_port = local_port_base;
    let mut added_count = 0;
    let mut attempt_counter = 0;

    while added_count < punch_tasks && attempt_counter < 100 {
        match create_bound_socket(current_port) {
            Ok(s) => {
                bound_sockets.push(s);
                extra_ports.push(current_port);
                added_count += 1;
            }
            Err(_) => {}
        }
        current_port = current_port.wrapping_add(1);
        attempt_counter += 1;
    }
    let local_port = *extra_ports.first().unwrap_or(&local_port_base);

    let (relay_stream, session) = run_relay_protocol(
        server_addr, session_id, "receiver", local_port, timeout, probe_count,
        prediction_mode, prediction_range_extra_pct, tcp_connections, scan_budget,
        punch_overshoot, allow_fallback, min_connections, extra_ports, bound_sockets
    ).await?;

    // NEU: Split relay stream for Multi-Connection Loop
    let (relay_reader, relay_writer) = relay_stream.into_split();
    let relay_reader = BufReader::new(relay_reader);

    // NEU: Etabliere Connections mit strategie-basiertem Hole Punching
    let streams = establish_multi_connections(
        relay_reader,
        relay_writer,
        &session,
        session.tcp_connections,
        timeout,
    ).await?;

    // Validierung der etablierten Connections
    let min_required = if session.allow_fallback { 
        session.min_connections.max(1) as usize 
    } else { 
        session.tcp_connections as usize 
    };
    
    if streams.len() < min_required { 
        return Err(anyhow!(
            "Only established {} of {} required connections", 
            streams.len(), 
            min_required
        )); 
    }

    for s in &streams { info!("✅ Direct P2P: Local {} Remote {}", s.local_addr()?, s.peer_addr()?); }

    if session.tcp_connections > 1 || streams.len() > 1 {
        run_multi_receiver(streams).await
    } else {
        let stream = streams.into_iter().next().unwrap();
        let mut receiver = TcpReceiver::new(stream);
        receiver.run().await
    }
}

async fn run_probe_debug(server_addr: &str, session_id: &str, count: u32) -> Result<()> {
    let probe_addr = resolve_socket_addr(server_addr)?;
    println!("PROBE DEBUG MODE: {} -> {}", server_addr, probe_addr);
    // Simple mock logic for cleanup
    let _ = session_id;
    let _ = count;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let level = if args.debug { Level::DEBUG } else { Level::INFO };
    let _subscriber = FmtSubscriber::builder().with_max_level(level).with_target(false).with_file(false).with_line_number(false).init();

    if args.probe_debug {
        return run_probe_debug(&args.server, &args.session_id, args.probe_count).await;
    }

    let chunk_size = parse_chunk_size(&args.chunk)?;
    set_chunk_size(chunk_size);
    
    info!("TCP File Transfer Client v{} (ICE)", APP_VERSION);
    info!("===================================");
    info!("TCP connections: {}", args.tcp_connections);
    
    let timeout = Duration::from_secs(args.timeout);
    
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        error!("🛑 Ctrl+C received, exiting...");
        std::process::exit(1);
    });

    match args.mode {
        Mode::Send => {
            let file_path = args.file.as_ref().ok_or_else(|| anyhow!("--file required"))?;
            if !std::path::Path::new(file_path).exists() { return Err(anyhow!("File not found: {}", file_path)); }
            info!("Mode: SEND, File: {}, Session: {}", file_path, args.session_id);
            run_sender(
                &args.server, &args.session_id, file_path, timeout, args.probe_count,
                args.prediction_mode, args.prediction_range_extra_pct, args.tcp_connections as u32,
                args.scan_budget, args.punch_overshoot, args.allow_fallback, args.min_connections
            ).await
        }
        Mode::Receive => {
            info!("Mode: RECEIVE, Session: {}", args.session_id);
            run_receiver(
                &args.server, &args.session_id, timeout, args.probe_count,
                args.prediction_mode, args.prediction_range_extra_pct, args.tcp_connections as u32,
                args.scan_budget, args.punch_overshoot, args.allow_fallback, args.min_connections
            ).await
        }
    }
}
