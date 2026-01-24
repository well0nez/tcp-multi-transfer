//! Multi-Connection Management Module
//!
//! Handles establishing multiple TCP connections through coordinated hole punching cycles.

use std::net::SocketAddr;

// Tests Module
#[cfg(test)]
#[path = "connection_tests.rs"]
mod connection_tests;
use std::time::Duration;
use std::sync::{Arc, Mutex};
use std::collections::VecDeque;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use anyhow::{Result, anyhow};
use tracing::{info, error, warn, debug};

use crate::protocol::{RelayMessage, AddPortsMessage};
use crate::punch::{punch_connection_with_strategy, PeerInfo, current_timestamp};
use crate::relay::{Session, create_bound_socket};

/// GO Signal mit Zeitstempel
#[derive(Clone, Debug)]
pub struct GoSignal {
    pub start_at: f64,
}

// ============================================================================
// Phase 1.1: Zentrale Message-Queue-Infrastruktur
// ============================================================================

/// Zentrale, thread-safe Message-Queues für alle eingehenden Relay-Messages
///
/// Diese Struktur verhindert Race Conditions und Message-Loss durch:
/// - Zentrale Speicherung aller Messages in typ-spezifischen Queues
/// - Thread-safe Zugriff via Arc<Mutex<>>
/// - Connection-spezifisches Routing (via conn_num)
#[derive(Clone)]
pub struct MessageQueues {
    /// PeerInfo Messages: (conn_num, peer_info, strategy, tcp_connections)
    peer_infos: Arc<Mutex<VecDeque<(u32, PeerInfo, String, u32)>>>,
    
    /// GO Messages: (conn_num, signal)
    go_signals: Arc<Mutex<VecDeque<(u32, GoSignal)>>>,
    
    /// PortsAddedAck Messages: Vec<port>
    ports_acks: Arc<Mutex<VecDeque<Vec<u16>>>>,
    
    /// PeerAddedPorts Messages: Vec<port>
    peer_added_ports: Arc<Mutex<VecDeque<Vec<u16>>>>,
    
    /// RetryGranted Messages: conn_num
    retry_granted: Arc<Mutex<VecDeque<u32>>>,
    
    /// Error Messages: error_string
    errors: Arc<Mutex<VecDeque<String>>>,
    
    /// Shutdown Signal
    shutdown: Arc<Mutex<bool>>,
}

impl MessageQueues {
    /// Erstelle neue, leere Message-Queues
    pub fn new() -> Self {
        Self {
            peer_infos: Arc::new(Mutex::new(VecDeque::new())),
            go_signals: Arc::new(Mutex::new(VecDeque::new())),
            ports_acks: Arc::new(Mutex::new(VecDeque::new())),
            peer_added_ports: Arc::new(Mutex::new(VecDeque::new())),
            retry_granted: Arc::new(Mutex::new(VecDeque::new())),
            errors: Arc::new(Mutex::new(VecDeque::new())),
            shutdown: Arc::new(Mutex::new(false)),
        }
    }
    
    // --- PeerInfo Queue ---
    
    /// Füge PeerInfo für eine Connection hinzu
    pub fn push_peer_info(&self, conn_num: u32, info: PeerInfo, strategy: String, tcp_connections: u32) {
        if let Ok(mut queue) = self.peer_infos.lock() {
            queue.push_back((conn_num, info, strategy, tcp_connections));
        }
    }
    
    /// Hole PeerInfo für eine spezifische Connection (entfernt aus Queue)
    pub fn pop_peer_info(&self, conn_num: u32) -> Option<(PeerInfo, String, u32)> {
        if let Ok(mut queue) = self.peer_infos.lock() {
            // Suche nach passendem conn_num
            if let Some(pos) = queue.iter().position(|(num, _, _, _)| *num == conn_num) {
                if let Some((_, info, strategy, tcp_conns)) = queue.remove(pos) {
                    return Some((info, strategy, tcp_conns));
                }
            }
        }
        None
    }
    
    // --- GO Signal Queue ---
    
    /// Füge GO Signal für eine Connection hinzu
    pub fn push_go(&self, conn_num: u32, signal: GoSignal) {
        if let Ok(mut queue) = self.go_signals.lock() {
            queue.push_back((conn_num, signal));
        }
    }
    
    /// Hole GO Signal für eine spezifische Connection (entfernt aus Queue)
    pub fn pop_go(&self, conn_num: u32) -> Option<GoSignal> {
        if let Ok(mut queue) = self.go_signals.lock() {
            if let Some(pos) = queue.iter().position(|(num, _)| *num == conn_num) {
                if let Some((_, signal)) = queue.remove(pos) {
                    return Some(signal);
                }
            }
        }
        None
    }
    
    // --- Ports ACK Queue ---
    
    /// Füge PortsAddedAck hinzu
    pub fn push_ports_ack(&self, ports: Vec<u16>) {
        if let Ok(mut queue) = self.ports_acks.lock() {
            queue.push_back(ports);
        }
    }
    
    /// Hole nächste PortsAddedAck (entfernt aus Queue)
    pub fn pop_ports_ack(&self) -> Option<Vec<u16>> {
        if let Ok(mut queue) = self.ports_acks.lock() {
            queue.pop_front()
        } else {
            None
        }
    }
    
    // --- Peer Added Ports Queue ---
    
    /// Füge PeerAddedPorts hinzu
    pub fn push_peer_added_ports(&self, ports: Vec<u16>) {
        if let Ok(mut queue) = self.peer_added_ports.lock() {
            queue.push_back(ports);
        }
    }
    
    /// Hole alle PeerAddedPorts (NON-CONSUMING - für Notifications)
    pub fn get_peer_added_ports(&self) -> Vec<u16> {
        if let Ok(queue) = self.peer_added_ports.lock() {
            queue.iter().flatten().copied().collect()
        } else {
            Vec::new()
        }
    }
    
    // --- Retry Granted Queue ---
    
    /// Füge RetryGranted für eine Connection hinzu
    pub fn push_retry_granted(&self, conn_num: u32) {
        if let Ok(mut queue) = self.retry_granted.lock() {
            queue.push_back(conn_num);
        }
    }
    
    /// Hole RetryGranted für eine spezifische Connection (entfernt aus Queue)
    pub fn pop_retry_granted(&self, conn_num: u32) -> Option<u32> {
        if let Ok(mut queue) = self.retry_granted.lock() {
            if let Some(pos) = queue.iter().position(|num| *num == conn_num) {
                queue.remove(pos)
            } else {
                None
            }
        } else {
            None
        }
    }
    
    // --- Error Queue ---
    
    /// Füge Error-Message hinzu
    pub fn push_error(&self, error: String) {
        if let Ok(mut queue) = self.errors.lock() {
            queue.push_back(error);
        }
    }
    
    /// Prüfe ob Error vorliegt (NON-CONSUMING - liest nur)
    pub fn has_error(&self) -> Option<String> {
        if let Ok(queue) = self.errors.lock() {
            queue.front().cloned()
        } else {
            None
        }
    }
    
    // --- Shutdown Signal ---
    
    /// Setze Shutdown-Flag
    pub fn set_shutdown(&self) {
        if let Ok(mut flag) = self.shutdown.lock() {
            *flag = true;
        }
    }
    
    /// Prüfe ob Shutdown angefordert wurde
    pub fn is_shutdown(&self) -> bool {
        if let Ok(flag) = self.shutdown.lock() {
            *flag
        } else {
            false
        }
    }
}

// ============================================================================
// Phase 1.2: Central Message Receiver Task
// ============================================================================

/// Spawnt einen zentralen Message-Receiver Task
///
/// Dieser Task läuft asynchron und verarbeitet ALLE eingehenden Messages vom Server:
/// - Liest Messages vom relay_reader
/// - Parsed JSON zu RelayMessage
/// - Routet Messages zu den entsprechenden Queues
/// - Behandelt Fehler und Shutdown
///
/// # Returns
/// JoinHandle für den spawned Task
pub fn spawn_message_receiver(
    mut relay_reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
    queues: MessageQueues,
) -> tokio::task::JoinHandle<Result<()>> {
    tokio::spawn(async move {
        info!("Message receiver task started");
        
        loop {
            // Check für Shutdown
            if queues.is_shutdown() {
                info!("Message receiver shutting down");
                break;
            }
            
            let mut line = String::new();
            
            // Lese nächste Zeile mit Timeout (5s für Keepalive)
            match tokio::time::timeout(Duration::from_secs(5), relay_reader.read_line(&mut line)).await {
                Ok(Ok(0)) => {
                    // Connection geschlossen
                    error!("Connection closed by relay server");
                    queues.push_error("Connection lost".to_string());
                    break;
                }
                Ok(Err(e)) => {
                    // Read-Fehler
                    error!("Read error from relay server: {}", e);
                    queues.push_error(format!("Read error: {}", e));
                    break;
                }
                Ok(Ok(_)) => {
                    // Erfolgreich gelesen
                    if line.trim().is_empty() {
                        continue;  // Leere Zeilen überspringen
                    }
                    
                    // Parse JSON zu RelayMessage
                    match serde_json::from_str::<RelayMessage>(&line) {
                        Ok(msg) => {
                            // Route Message zu entsprechender Queue
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
                                    
                                    // Parse Peer-Adresse
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
                    // Timeout - normal für Keepalive
                    debug!("Read timeout (keepalive)");
                }
            }
        }
        
        info!("Message receiver task stopped");
        Ok(())
    })
}

// ============================================================================
// Phase 2: State Machine für Connection Management
// ============================================================================

/// Connection State für State Machine
#[derive(Debug, Clone)]
pub enum ConnectionState {
    /// Initial state - noch keine Aktionen durchgeführt
    #[allow(dead_code)]
    Initial,
    
    /// Warte auf PeerInfo vom Server
    WaitingForPeerInfo { conn_num: u32 },
    
    /// PeerInfo empfangen, warte auf GO Signal
    WaitingForGO { 
        conn_num: u32, 
        peer_info: PeerInfo,
        strategy: String,
    },
    
    /// GO empfangen, führe Hole Punching durch
    Punching { 
        conn_num: u32, 
        peer_info: PeerInfo,
        strategy: String,
        start_at: f64,
    },
    
    /// Connection erfolgreich etabliert
    Established { conn_num: u32 },
    
    /// Connection fehlgeschlagen
    Failed { 
        conn_num: u32, 
        reason: String,
        attempt: u32,
    },
    
    /// Warte auf Retry-Genehmigung
    WaitingForRetry { 
        conn_num: u32,
        attempt: u32,
    },
}

impl ConnectionState {
    /// Prüfe ob State ein Terminal-State ist (Established oder Failed mit max attempts)
    #[allow(dead_code)]
    pub fn is_terminal(&self) -> bool {
        matches!(self, ConnectionState::Established { .. })
    }
    
    /// Hole conn_num aus dem State
    #[allow(dead_code)]
    pub fn conn_num(&self) -> Option<u32> {
        match self {
            ConnectionState::Initial => None,
            ConnectionState::WaitingForPeerInfo { conn_num } => Some(*conn_num),
            ConnectionState::WaitingForGO { conn_num, .. } => Some(*conn_num),
            ConnectionState::Punching { conn_num, .. } => Some(*conn_num),
            ConnectionState::Established { conn_num } => Some(*conn_num),
            ConnectionState::Failed { conn_num, .. } => Some(*conn_num),
            ConnectionState::WaitingForRetry { conn_num, .. } => Some(*conn_num),
        }
    }
}

/// State Transition Result
pub type StateTransition = Result<ConnectionState>;

/// State Transition Handler - verarbeitet PeerInfo
pub fn handle_peer_info_transition(
    state: ConnectionState,
    peer_info: PeerInfo,
    strategy: String,
) -> StateTransition {
    match state {
        ConnectionState::WaitingForPeerInfo { conn_num } => {
            debug!("State transition: WaitingForPeerInfo -> WaitingForGO (conn {})", conn_num);
            Ok(ConnectionState::WaitingForGO {
                conn_num,
                peer_info,
                strategy,
            })
        }
        ConnectionState::WaitingForRetry { conn_num, .. } => {
            debug!("State transition: WaitingForRetry -> WaitingForGO (conn {})", conn_num);
            Ok(ConnectionState::WaitingForGO {
                conn_num,
                peer_info,
                strategy,
            })
        }
        _ => {
            Err(anyhow!("Invalid state transition: cannot handle PeerInfo in state {:?}", state))
        }
    }
}

/// State Transition Handler - verarbeitet GO Signal
pub fn handle_go_transition(
    state: ConnectionState,
    go_signal: GoSignal,
) -> StateTransition {
    match state {
        ConnectionState::WaitingForGO { conn_num, peer_info, strategy } => {
            debug!("State transition: WaitingForGO -> Punching (conn {})", conn_num);
            Ok(ConnectionState::Punching {
                conn_num,
                peer_info,
                strategy,
                start_at: go_signal.start_at,
            })
        }
        _ => {
            Err(anyhow!("Invalid state transition: cannot handle GO in state {:?}", state))
        }
    }
}

/// State Transition Handler - verarbeitet erfolgreiche Connection
pub fn handle_connection_success(
    state: ConnectionState,
) -> StateTransition {
    match state {
        ConnectionState::Punching { conn_num, .. } => {
            debug!("State transition: Punching -> Established (conn {})", conn_num);
            Ok(ConnectionState::Established { conn_num })
        }
        _ => {
            Err(anyhow!("Invalid state transition: cannot handle success in state {:?}", state))
        }
    }
}

/// State Transition Handler - verarbeitet Connection-Fehler
pub fn handle_connection_failure(
    state: ConnectionState,
    reason: String,
) -> StateTransition {
    match state {
        ConnectionState::Punching { conn_num, .. } => {
            // Bei Failure: Versuche Retry
            debug!("State transition: Punching -> Failed (conn {})", conn_num);
            Ok(ConnectionState::Failed {
                conn_num,
                reason,
                attempt: 1,
            })
        }
        ConnectionState::WaitingForPeerInfo { conn_num } => {
            debug!("State transition: WaitingForPeerInfo -> Failed (conn {})", conn_num);
            Ok(ConnectionState::Failed {
                conn_num,
                reason,
                attempt: 1,
            })
        }
        ConnectionState::WaitingForGO { conn_num, .. } => {
            debug!("State transition: WaitingForGO -> Failed (conn {})", conn_num);
            Ok(ConnectionState::Failed {
                conn_num,
                reason,
                attempt: 1,
            })
        }
        _ => {
            Err(anyhow!("Invalid state transition: cannot handle failure in state {:?}", state))
        }
    }
}

/// State Transition Handler - initiiere Retry
pub fn handle_retry_request(
    state: ConnectionState,
) -> StateTransition {
    match state {
        ConnectionState::Failed { conn_num, attempt, .. } => {
            debug!("State transition: Failed -> WaitingForRetry (conn {}, attempt {})", conn_num, attempt + 1);
            Ok(ConnectionState::WaitingForRetry {
                conn_num,
                attempt: attempt + 1,
            })
        }
        _ => {
            Err(anyhow!("Invalid state transition: cannot request retry in state {:?}", state))
        }
    }
}

/// State Transition Handler - Retry gewährt
pub fn handle_retry_granted(
    state: ConnectionState,
) -> StateTransition {
    match state {
        ConnectionState::WaitingForRetry { conn_num, attempt } => {
            debug!("State transition: WaitingForRetry -> WaitingForPeerInfo (conn {}, attempt {})", conn_num, attempt);
            Ok(ConnectionState::WaitingForPeerInfo { conn_num })
        }
        _ => {
            Err(anyhow!("Invalid state transition: cannot grant retry in state {:?}", state))
        }
    }
}

// ============================================================================
// Phase 3: Asynchrone Notification-Handling
// ============================================================================

/// Spawnt einen asynchronen Notification-Handler für PeerAddedPorts
///
/// Dieser Task läuft parallel zur Haupt-Connection-Etablierung und verarbeitet
/// PeerAddedPorts-Messages asynchron, ohne den Connection-Flow zu blockieren.
///
/// # Argumente
/// - `queues`: Message-Queues für Zugriff auf PeerAddedPorts
/// - `peer_extra_ports`: Shared State für gesammelte Ports
///
/// # Returns
/// JoinHandle für den spawned Task
pub fn spawn_notification_handler(
    queues: MessageQueues,
    peer_extra_ports: Arc<Mutex<Vec<u16>>>,
) -> tokio::task::JoinHandle<Result<()>> {
    tokio::spawn(async move {
        info!("Notification handler task started");
        
        let mut last_ports: Vec<u16> = Vec::new();  // Track last state for change detection
        
        loop {
            // Hole alle PeerAddedPorts aus Queue (non-consuming)
            let new_ports = queues.get_peer_added_ports();
            
            // NUR loggen und updaten wenn sich die Ports tatsächlich geändert haben!
            if new_ports != last_ports && !new_ports.is_empty() {
                if let Ok(mut ports) = peer_extra_ports.lock() {
                    // Update shared state mit neuen Ports
                    ports.clear();
                    ports.extend(new_ports.iter().copied());
                    info!("Updated peer_extra_ports: {:?}", *ports);
                    last_ports = new_ports.clone();
                }
            }
            
            // Shutdown-Check
            if queues.is_shutdown() {
                info!("Notification handler shutting down");
                break;
            }
            
            // Poll-Intervall (125ms - 25% höher für weniger CPU)
            tokio::time::sleep(Duration::from_millis(125)).await;
        }
        
        info!("Notification handler task stopped");
        Ok(())
    })
}

// ============================================================================
// Phase 1.3: Queue-Reader-Funktionen (non-blocking mit Timeout)
// ============================================================================

/// Wartet auf PeerInfo für eine spezifische Connection aus der Queue
///
/// Non-blocking Polling mit kurzen Sleep-Intervallen
/// # Argumente
/// - `queues`: Message-Queues
/// - `conn_num`: Connection-Nummer für die gewartet wird
/// - `timeout`: Maximale Wartezeit
pub async fn wait_for_peer_info_from_queue(
    queues: &MessageQueues,
    conn_num: u32,
    timeout: Duration,
) -> Result<(PeerInfo, String, u32)> {
    let start = std::time::Instant::now();
    
    loop {
        // Timeout-Check
        if start.elapsed() > timeout {
            return Err(anyhow!("Timeout waiting for peer_info (conn {})", conn_num));
        }
        
        // Error-Check
        if let Some(error) = queues.has_error() {
            return Err(anyhow!("Server error: {}", error));
        }
        
        // Versuche PeerInfo aus Queue zu holen
        if let Some((info, strategy, tcp_conns)) = queues.pop_peer_info(conn_num) {
            debug!("Got PeerInfo for conn {} from queue", conn_num);
            return Ok((info, strategy, tcp_conns));
        }
        
        // Kurz schlafen, dann erneut prüfen (13ms polling interval - 25% höher für weniger CPU)
        tokio::time::sleep(Duration::from_millis(13)).await;
    }
}

/// Wartet auf GO Signal für eine spezifische Connection aus der Queue
///
/// Non-blocking Polling mit kurzen Sleep-Intervallen
/// # Argumente
/// - `queues`: Message-Queues
/// - `conn_num`: Connection-Nummer für die gewartet wird
/// - `timeout`: Maximale Wartezeit
pub async fn wait_for_go_from_queue(
    queues: &MessageQueues,
    conn_num: u32,
    timeout: Duration,
) -> Result<GoSignal> {
    let start = std::time::Instant::now();
    
    loop {
        // Timeout-Check
        if start.elapsed() > timeout {
            return Err(anyhow!("Timeout waiting for GO (conn {})", conn_num));
        }
        
        // Error-Check
        if let Some(error) = queues.has_error() {
            return Err(anyhow!("Server error: {}", error));
        }
        
        // Versuche GO Signal aus Queue zu holen
        if let Some(signal) = queues.pop_go(conn_num) {
            debug!("Got GO signal for conn {} from queue", conn_num);
            return Ok(signal);
        }
        
        // Kurz schlafen, dann erneut prüfen (10ms polling interval)
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Wartet auf PortsAddedAck aus der Queue
///
/// Non-blocking Polling mit kurzen Sleep-Intervallen
/// Validiert dass die ACK'd Ports den erwarteten Ports entsprechen
/// # Argumente
/// - `queues`: Message-Queues
/// - `expected_ports`: Erwartete Ports die bestätigt werden sollen
/// - `timeout`: Maximale Wartezeit
pub async fn wait_for_ports_ack_from_queue(
    queues: &MessageQueues,
    expected_ports: &[u16],
    timeout: Duration,
) -> Result<()> {
    let start = std::time::Instant::now();
    
    loop {
        // Timeout-Check
        if start.elapsed() > timeout {
            return Err(anyhow!("Timeout waiting for ports_added_ack"));
        }
        
        // Error-Check
        if let Some(error) = queues.has_error() {
            return Err(anyhow!("Server error: {}", error));
        }
        
        // Versuche PortsAddedAck aus Queue zu holen
        if let Some(acked_ports) = queues.pop_ports_ack() {
            debug!("Got PortsAddedAck from queue: {:?}", acked_ports);
            
            // Validiere dass ACK'd Ports mit erwarteten Ports übereinstimmen
            let expected_set: std::collections::HashSet<_> = expected_ports.iter().copied().collect();
            let acked_set: std::collections::HashSet<_> = acked_ports.iter().copied().collect();
            
            if expected_set == acked_set {
                return Ok(());
            } else {
                warn!("ACK ports mismatch: expected {:?}, got {:?}", expected_ports, acked_ports);
                // Weiter warten auf korrektes ACK
            }
        }
        
        // Kurz schlafen, dann erneut prüfen (10ms polling interval)
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Wartet auf RetryGranted für eine spezifische Connection aus der Queue
///
/// Non-blocking Polling mit kurzen Sleep-Intervallen
/// # Argumente
/// - `queues`: Message-Queues
/// - `conn_num`: Connection-Nummer für die gewartet wird
/// - `timeout`: Maximale Wartezeit
pub async fn wait_for_retry_granted_from_queue(
    queues: &MessageQueues,
    conn_num: u32,
    timeout: Duration,
) -> Result<()> {
    let start = std::time::Instant::now();
    
    loop {
        // Timeout-Check
        if start.elapsed() > timeout {
            return Err(anyhow!("Timeout waiting for retry_granted (conn {})", conn_num));
        }
        
        // Error-Check
        if let Some(error) = queues.has_error() {
            return Err(anyhow!("Server error: {}", error));
        }
        
        // Versuche RetryGranted aus Queue zu holen
        if let Some(granted_conn) = queues.pop_retry_granted(conn_num) {
            if granted_conn == conn_num {
                debug!("Got RetryGranted for conn {} from queue", conn_num);
                return Ok(());
            } else {
                warn!("Got RetryGranted for wrong conn: {} (expected {})", granted_conn, conn_num);
            }
        }
        
        // Kurz schlafen, dann erneut prüfen (10ms polling interval)
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Etabliert mehrere Connections durch wiederholte Punch-Zyklen
///
/// **NEUE Queue-basierte Implementierung (Phase 1 Integration)**
/// - Verwendet MessageQueues für Race-Condition-freies Message-Handling
/// - Spawnt zentralen Message-Receiver Task
/// - Keine Messages gehen mehr verloren!
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
    // ========================================================================
    // Phase 1 Integration: Queue-basierte Message-Handling-Infrastruktur
    // ========================================================================
    
    info!("🚀 Starting queue-based connection establishment");
    
    // 1. Erstelle Message-Queues
    let queues = MessageQueues::new();
    
    // 2. Starte zentralen Message-Receiver Task
    let _receiver_handle = spawn_message_receiver(relay_reader, queues.clone());
    info!("✅ Message receiver task spawned");
    
    // 3. Phase 3: Starte asynchronen Notification-Handler für PeerAddedPorts
    let peer_extra_ports_shared = Arc::new(Mutex::new(Vec::new()));
    let _notification_handle = spawn_notification_handler(
        queues.clone(),
        peer_extra_ports_shared.clone(),
    );
    info!("✅ Notification handler task spawned");
    
    let mut streams = Vec::new();
    let mut failures_in_a_row = 0;
    const MAX_FAILURES: u32 = 5;
    
    // Für Receiver: Empfange ERSTE peer_info VOR der Schleife!
    let (actual_tcp_connections, start_conn) = if role == "receiver" {
        info!("Receiver: Waiting for initial peer_info (connection 1/?)...");
        
        // 1. Warte auf peer_info für conn=0 (QUEUE-BASIERT!)
        let (peer_info, punch_strategy, peer_tcp_connections) = wait_for_peer_info_from_queue(
            &queues,
            0,
            Duration::from_secs(120)
        ).await?;
        
        info!("Received initial peer_info: peer wants {} connections", peer_tcp_connections);
        
        info!("Received peer_info for connection 1/{}: strategy={}", peer_tcp_connections, punch_strategy);
        
        // 3. Sende READY
        let ready_msg = format!(r#"{{"type":"ready","connection_num":0}}"#) + "\n";
        relay_writer.write_all(ready_msg.as_bytes()).await?;
        relay_writer.flush().await?;
        info!("READY sent for connection 1/{}", peer_tcp_connections);
        
        // 4. Warte auf GO (QUEUE-BASIERT!)
        let go_signal = wait_for_go_from_queue(&queues, 0, Duration::from_secs(120)).await?;
        let countdown = go_signal.start_at - current_timestamp();
        info!("GO received for connection 1/{}! Start in {:.2}s", peer_tcp_connections, countdown);
        
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
        info!("Connection 1/{} established!", peer_tcp_connections);
        
        // Schleife startet bei 1 (erste Connection bereits etabliert)
        (peer_tcp_connections, 1)
    } else {
        // Sender: Check if we need to bind more sockets
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
                
                // Sender: NO probing needed for Port-Preserved NATs!
                // Just send add_ports message so server knows the bound ports
                if !new_ports.is_empty() {
                    info!("Sender: Sending add_ports for {} new ports (no probing needed for Port-Preserved NAT)", new_ports.len());
                    
                    let add_msg = AddPortsMessage::new(session_id, new_ports.clone());
                    let json = serde_json::to_string(&add_msg)? + "\n";
                    relay_writer.write_all(json.as_bytes()).await?;
                    relay_writer.flush().await?;
                    info!("Sent add_ports message");
                    
                    // Wait for ACK (QUEUE-BASIERT!)
                    match wait_for_ports_ack_from_queue(&queues, &new_ports, Duration::from_secs(30)).await {
                        Ok(_) => info!("New ports confirmed by server"),
                        Err(e) => warn!("Failed to get ACK for new ports: {}", e),
                    }
                }
            }
        }
        
        // Sender weiß schon, wie viele er will - Schleife startet bei 0
        (tcp_connections, 0)
    };
    
    // ========================================================================
    // Phase 2.3: Event-driven Connection Loop mit State Machine
    // ========================================================================
    
    // Hauptschleife für verbleibende Connections
    for conn_num in start_conn..actual_tcp_connections {
        let socket_index = conn_num as usize;
        
        // Ensure socket is available - bind on-demand if needed
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
        
        // Initialize State Machine
        let mut state = ConnectionState::WaitingForPeerInfo { conn_num };
        let mut connection_stream: Option<TcpStream> = None;
        
        // Event-driven State Machine Loop
        loop {
            state = match state {
                // State: WaitingForPeerInfo
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
                
                // State: WaitingForGO
                ConnectionState::WaitingForGO { conn_num, peer_info: _, strategy: _ } => {
                    debug!("State: WaitingForGO (conn {})", conn_num);
                    
                    // Send READY message
                    let ready_msg = format!(r#"{{"type":"ready","connection_num":{}}}"#, conn_num) + "\n";
                    relay_writer.write_all(ready_msg.as_bytes()).await?;
                    relay_writer.flush().await?;
                    info!("READY sent for connection {}", conn_num + 1);
                    
                    // Wait for GO signal
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
                
                // State: Punching
                ConnectionState::Punching { conn_num, ref peer_info, ref strategy, start_at } => {
                    debug!("State: Punching (conn {})", conn_num);
                    
                    // Perform hole punching
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
                            failures_in_a_row = 0;  // Reset on success
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
                
                // State: Established (Terminal)
                ConnectionState::Established { conn_num } => {
                    debug!("State: Established (conn {}) - TERMINAL", conn_num);
                    if let Some(stream) = connection_stream {
                        streams.push(stream);
                    }
                    break;  // Exit state machine, proceed to next connection
                }
                
                // State: Failed
                ConnectionState::Failed { conn_num, ref reason, attempt } => {
                    debug!("State: Failed (conn {}, attempt {})", conn_num, attempt);
                    
                    if failures_in_a_row >= MAX_FAILURES {
                        return Err(anyhow!("Max {} consecutive failures reached: {}", MAX_FAILURES, reason));
                    }
                    
                    warn!("Requesting retry for connection {} (failure {}/{})", conn_num + 1, failures_in_a_row, MAX_FAILURES);
                    
                    // Send retry_request to server
                    let retry_msg = format!(r#"{{"type":"retry_request","connection_num":{}}}"#, conn_num) + "\n";
                    relay_writer.write_all(retry_msg.as_bytes()).await?;
                    relay_writer.flush().await?;
                    info!("Sent retry_request for connection {}", conn_num + 1);
                    
                    handle_retry_request(state)?
                }
                
                // State: WaitingForRetry
                ConnectionState::WaitingForRetry { conn_num, attempt } => {
                    debug!("State: WaitingForRetry (conn {}, attempt {})", conn_num, attempt);
                    
                    // Wait for retry_granted from server
                    match wait_for_retry_granted_from_queue(&queues, conn_num, Duration::from_secs(30)).await {
                        Ok(()) => {
                            info!("Retry granted by server for connection {}", conn_num + 1);
                            
                            // Bind new socket for retry
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
                                        
                                        // Replace old socket with new one
                                        if socket_index < session.bound_sockets.len() {
                                            session.bound_sockets[socket_index] = new_socket;
                                        } else {
                                            session.bound_sockets.push(new_socket);
                                        }
                                        
                                        info!("Retry: Bound new socket on port {} for connection {}", new_port, conn_num + 1);
                                        
                                        // Send add_ports with new port
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
                            // Stay in WaitingForRetry state
                            state
                        }
                    }
                }
                
                // Unexpected state
                _ => {
                    return Err(anyhow!("Unexpected connection state: {:?}", state));
                }
            };
        }
    }
    
    // Cleanup: Signalisiere dem Message-Receiver Task, dass er stoppen soll
    queues.set_shutdown();
    debug!("Shutdown signal sent to message receiver task");
    
    // Phase 3: Übertrage gesammelte PeerAddedPorts zurück in die Session
    if let Ok(ports) = peer_extra_ports_shared.lock() {
        session.peer_extra_ports = ports.clone();
        if !ports.is_empty() {
            info!("Final peer_extra_ports: {:?}", session.peer_extra_ports);
        }
    }
    
    Ok(streams)
}


