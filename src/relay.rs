//! Relay Server Communication Module
//!
//! Handles connection to relay server, NAT probing, and session management.

use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use socket2::{Socket, Domain, Type, Protocol, SockAddr};
use anyhow::{Result, anyhow};
use tracing::{info, warn, debug};

use crate::protocol::{RegisterMessage, RelayMessage, ProbeMessage};
use crate::cli::PredictionMode;

/// Session state for hole punch coordination
pub struct Session {
    pub peer_public_addr: Option<SocketAddr>,
    pub peer_addresses: Vec<crate::protocol::relay::PeerAddressInfo>,
    pub peer_nat_analysis: Option<crate::protocol::NATAnalysis>,
    pub same_network: bool,
    pub time_offset: f64,
    pub our_public_port: Option<u16>,
    pub our_delta: i32,
    pub port_preserved: bool,
    
    // Multi-TCP fields
    pub tcp_connections: u32,
    pub allow_fallback: bool,
    pub min_connections: u32,
    pub bound_sockets: Vec<Socket>,
    pub peer_extra_ports: Vec<u16>,
    
    // Server connection info (for probing new ports)
    pub server_addr: SocketAddr,
    pub probe_port: Option<u16>,
    
    // PERF: RTT measurement for adaptive GO delay
    pub measured_rtt: f64,
}

pub fn parse_host_port(input: &str) -> Result<(String, u16)> {
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

pub fn resolve_host_port(host: &str, port: u16) -> Result<SocketAddr> {
    let mut addrs = (host, port).to_socket_addrs().map_err(|e| anyhow!("Failed to resolve {}: {}", host, e))?;
    addrs.next().ok_or_else(|| anyhow!("No addresses found"))
}

pub fn resolve_socket_addr(input: &str) -> Result<SocketAddr> {
    let (host, port) = parse_host_port(input)?;
    resolve_host_port(&host, port)
}

async fn do_nat_probing(probe_addr: SocketAddr, session_id: &str, count: u32) -> Result<()> {
    info!("Starting NAT probing ({} connections to {})...", count, probe_addr);
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
        info!("  Sent {}/{} probes successfully", successful, count);
    } else {
        warn!("  Only {}/{} probes succeeded", successful, count);
    }
    Ok(())
}

pub fn get_free_port() -> Result<u16> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.bind(&"0.0.0.0:0".parse::<SocketAddr>()?.into())?;
    Ok(socket.local_addr()?.as_socket().unwrap().port())
}

pub fn create_bound_socket(local_port: u16) -> Result<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.set_nodelay(true)?;
    let local_addr: SocketAddr = format!("0.0.0.0:{}", local_port).parse()?;
    socket.bind(&SockAddr::from(local_addr))?;
    Ok(socket)
}


/// Connect to relay server and handle the full protocol
pub async fn run_relay_protocol(
    server_addr: &str,
    session_id: &str,
    role: &str,
    local_port: u16,
    _timeout: Duration,
    probe_count: u32,
    prediction_mode: PredictionMode,
    prediction_range_extra_pct: f64,
    tcp_connections: u32,
    allow_fallback: bool,
    min_connections: u32,
    extra_ports: Vec<u16>,
    bound_sockets: Vec<Socket>,
) -> Result<(TcpStream, Session)> {
    info!("Connecting to relay server: {}", server_addr);
    let server_sock_addr = resolve_socket_addr(server_addr)?;
    
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
        allow_fallback,
        min_connections,
        bound_sockets,
        peer_extra_ports: vec![],
        server_addr: server_sock_addr,
        probe_port: None,
        measured_rtt: 0.0,
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
                    session.probe_port = probe_port;  // Store for later use
                    info!("Registered! Public address: {}:{}", ip, port);
                    
                    if let Some(times) = server_times {
                        // BUG-006 FIX: Improved time sync with RTT estimation
                        // The server sends timestamps taken 50ms apart. We received all of them
                        // at once, so we need to account for the network delay.
                        
                        let receive_time = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs_f64();
                        
                        // Estimate one-way delay as half the RTT
                        let rtt = receive_time - register_sent_at;
                        let one_way_delay = rtt / 2.0;
                        
                        // Use the LAST server timestamp (most recent) and adjust for one-way delay
                        // The last timestamp was taken just before sending the response
                        let mut offsets = Vec::new();
                        if let Some(&last_srv_time) = times.last() {
                            // Offset = server_time - (our_time_when_server_took_timestamp)
                            // our_time_when_server_took_timestamp ≈ receive_time - one_way_delay
                            let our_estimated_time = receive_time - one_way_delay;
                            let offset = last_srv_time - our_estimated_time;
                            offsets.push(offset);
                        }
                        
                        // Also compute offsets for each sample for statistics
                        // Server samples are 50ms apart, we received them at receive_time
                        let num_samples = times.len();
                        for (i, srv_time) in times.iter().enumerate() {
                            // Each earlier sample was taken (num_samples - 1 - i) * 50ms before the last one
                            let sample_age_offset = ((num_samples - 1 - i) as f64) * 0.05;
                            let our_estimated_time = receive_time - one_way_delay - sample_age_offset;
                            let offset = srv_time - our_estimated_time;
                            offsets.push(offset);
                        }
                        
                        // Calculate median (robust against network jitter outliers)
                        offsets.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                        session.time_offset = offsets[offsets.len() / 2];
                        
                        // PERF: Store RTT for adaptive GO delay
                        session.measured_rtt = rtt;
                        
                        info!("Clock offset (median of {} samples): {:.3}s (RTT: {:.3}s)", 
                              offsets.len(), session.time_offset, rtt);
                        debug!("   Offset range: {:.3}s to {:.3}s (spread: {:.3}s)", 
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
                        session.measured_rtt = rtt;  // PERF: Store RTT
                        warn!("Using legacy RTT/2 time sync (offset: {:.3}s) - server should send server_times array", session.time_offset);
                    } else {
                        warn!("No time sync data received from server - synchronization may be inaccurate");
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
                    info!("Probes complete sent");
                    
                    let stream = reader.into_inner().reunite(writer)?;
                    return Ok((stream, session));
                }
            }
            
            RelayMessage::PeerInfo { .. } => {
                warn!("Received peer_info during registration phase - ignoring");
            }
            
            RelayMessage::PeerAddedPorts { .. } => {
                debug!("Received peer_added_ports during registration phase - ignoring");
            }
            
            RelayMessage::PortsAddedAck { .. } => {
                debug!("Received PortsAddedAck during registration phase - ignoring");
            }
            
            RelayMessage::Go { .. } => {
                warn!("Received GO during registration phase - ignoring");
            }
            
            RelayMessage::Ping {} => {
                let msg = r#"{"type":"keepalive"}"#.to_string() + "\n";
                writer.write_all(msg.as_bytes()).await?;
                writer.flush().await?;
            }
            
            RelayMessage::KeepaliveAck {} => {}
            
            RelayMessage::Error { message } => return Err(anyhow!("Server error: {}", message)),
            
            // Retry Messages werden im Multi-Connection Loop verarbeitet
            RelayMessage::RetryRequest { .. } | RelayMessage::RetryGranted { .. } | RelayMessage::RetryRejected { .. } => {
                debug!("Received retry message during registration phase - ignoring");
            }
        }
    }
}
