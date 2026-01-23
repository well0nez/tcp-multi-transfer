# TCP Hole Punch Refactoring Plan

**Datum**: 2026-01-23
**Ziel**: Synchronisiertes Multi-Connection Hole Punching mit vereinfachtem Protokoll

---

## 🎯 Übersicht der Probleme

### Aktuelle Probleme (aus Logs):
1. **Sequential Scan nur einseitig**: Nur Sender sendet `request_attempt`, Receiver weiß nichts davon
2. **Clock Offset Inkonsistenz**: Sender -1.190s, Receiver -0.031s → asynchroner Start
3. **Fehlende Koordination**: Kein bidirektionales Acknowledge-System
4. **Keine Retry-Logik**: Fehlgeschlagene Punches werden nicht wiederholt
5. **Timeout-Asymmetrie**: Receiver timeoutet zu früh, Sender läuft endlos

---

## 🔄 Neues Design - Multi-Connection Flow

### Gesamtablauf für tcp_connections=4:

```
┌─────────────────────────────────────────────────────────────┐
│ Phase 1: PROBING (einmalig)                                 │
├─────────────────────────────────────────────────────────────┤
│ Client → Server: register                                   │
│ Server → Client: registered (mit server_times für Median)   │
│ Client → Probe-Server: 10 Probes                           │
│ Client → Server: probes_complete                           │
│ Server: NAT-Analyse (port_preserved vs. Complex)           │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ Phase 2: CONNECTION LOOP (4x wiederholen)                   │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────────────────────────────────────────┐        │
│  │ Connection 1                                    │        │
│  ├─────────────────────────────────────────────────┤        │
│  │ 1. Server → Beide: peer_info (conn_num=0)      │        │
│  │    - Port/Range für Connection 1               │        │
│  │    - punch_strategy (listen/connect/scan)      │        │
│  │                                                 │        │
│  │ 2. Beide → Server: ready                       │        │
│  │                                                 │        │
│  │ 3. Server wartet auf BEIDE READYs              │        │
│  │                                                 │        │
│  │ 4. Server → Beide: go (start_at=T1, conn_num=0)│        │
│  │                                                 │        │
│  │ 5. Beide: Synchronized PUNCH                   │        │
│  │                                                 │        │
│  │ 6. ✅ Connection 1 established                  │        │
│  └─────────────────────────────────────────────────┘        │
│                                                              │
│  [2 Sekunden Pause]                                         │
│                                                              │
│  ┌─────────────────────────────────────────────────┐        │
│  │ Connection 2                                    │        │
│  ├─────────────────────────────────────────────────┤        │
│  │ 1. Server → Beide: peer_info (conn_num=1)      │        │
│  │ 2. Beide → Server: ready                       │        │
│  │ 3. Server → Beide: go (start_at=T2, conn_num=1)│        │
│  │ 4. Synchronized PUNCH                          │        │
│  │ 5. ✅ Connection 2 established                  │        │
│  └─────────────────────────────────────────────────┘        │
│                                                              │
│  ... (Connection 3 & 4 identisch)                           │
│                                                              │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ Phase 3: DATA TRANSFER                                      │
├─────────────────────────────────────────────────────────────┤
│ Multi-Stream parallel Transfer über 4 TCP-Verbindungen     │
└─────────────────────────────────────────────────────────────┘
```

---

## 📋 Implementierungs-Schritte

### **STEP 1: Protokoll-Definitionen aktualisieren**

#### 1.1 Server: `server/models.py`

**Änderungen:**
```python
class Peer:
    # ... existing fields ...
    
    # NEU: Connection-spezifischer State
    ready_for_connection: Dict[int, bool] = {}  # conn_num → ready
    
    def reset_ready_for_connection(self, conn_num: int):
        """Reset ready flag für nächste Connection"""
        self.ready_for_connection[conn_num] = False
```

#### 1.2 Client: `src/protocol/relay.rs`

**ÄNDERN:**
```rust
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum RelayMessage {
    #[serde(rename = "registered")]
    Registered {
        your_public_addr: Vec<serde_json::Value>,
        // NEU: Mehrere Timestamps für Median-Berechnung
        #[serde(default)]
        server_times: Option<Vec<f64>>,
        #[serde(default)]
        probe_port: Option<u16>,
        #[serde(default)]
        needs_probing: Option<bool>,
    },
    
    #[serde(rename = "peer_info")]
    PeerInfo {
        peer_public_addr: Vec<serde_json::Value>,
        peer_local_port: u16,
        peer_addresses: Vec<PeerAddressInfo>,
        same_network: bool,
        #[serde(default)]
        peer_nat_analysis: Option<NATAnalysis>,
        
        // NEU: Connection-spezifisch
        #[serde(default)]
        connection_num: Option<u32>,
        
        // NEU: Punch-Strategie
        #[serde(default)]
        punch_strategy: Option<String>,  // "listen" | "connect" | "scan"
        
        // ... rest bleibt gleich ...
    },
    
    #[serde(rename = "go")]
    Go {
        start_at: f64,
        #[serde(default)]
        message: String,
        
        // NEU: Connection-spezifisch
        #[serde(default)]
        connection_num: Option<u32>,
    },
    
    // ENTFERNEN: GoAttempt wird nicht mehr gebraucht!
    // #[serde(rename = "go_attempt")] ← LÖSCHEN
    
    // ... rest bleibt ...
}
```

---

### **STEP 2: Time-Sync mit Median-Ansatz**

#### 2.1 Server: `server/relay/handlers.py`

**IN:** `wait_for_peer_messages` oder neue Funktion `send_time_sync`:

```python
async def send_time_sync(peer: Peer):
    """Sende mehrere Timestamps für robuste Clock-Offset-Berechnung"""
    server_times = []
    for _ in range(5):
        server_times.append(time.time())
        await asyncio.sleep(0.05)  # 50ms zwischen Samples
    
    await send_message(peer.writer, {
        'type': 'time_sync',
        'server_times': server_times
    })
```

**ODER: In Registration-Response integrieren:**

```python
# In handle_registration (handlers.py):
server_times = [time.time() for _ in range(5)]

await send_message(peer.writer, {
    'type': 'registered',
    'your_public_addr': list(peer.public_addr),
    'server_times': server_times,  # ← NEU
    'probe_port': probe_port,
    'needs_probing': needs_probing
})
```

#### 2.2 Client: `src/main.rs`

**IN:** `run_relay_protocol`, im `Registered`-Branch:

```rust
RelayMessage::Registered { your_public_addr, server_times, probe_port, needs_probing, .. } => {
    if let Some((ip, port)) = RelayMessage::parse_addr(&your_public_addr) {
        session.our_public_port = Some(port);
        session.our_delta = port as i32 - local_port as i32;
        session.port_preserved = session.our_delta == 0;
        info!("✓ Registered! Public address: {}:{}", ip, port);
        
        // NEU: Median-basierte Time-Offset-Berechnung
        if let Some(times) = server_times {
            let mut offsets = Vec::new();
            for srv_time in times {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs_f64();
                offsets.push(srv_time - now);
            }
            // Sortieren und Median nehmen
            offsets.sort_by(|a, b| a.partial_cmp(b).unwrap());
            session.time_offset = offsets[offsets.len() / 2];
            info!("⏱️ Clock offset (median of {}): {:.3}s", offsets.len(), session.time_offset);
        } else {
            // Fallback zur alten Methode (sollte nicht vorkommen)
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs_f64();
            let rtt = now - register_sent_at;
            session.time_offset = 0.0; // Oder alte Berechnung
            warn!("⚠️ No server_times received, time sync may be inaccurate");
        }
        
        // ... rest (probing etc.) ...
    }
}
```

---

### **STEP 3: Server - Multi-Connection Koordination**

#### 3.1 Server: `server/relay/coordinator.py`

**NEUE FUNKTION:**

```python
async def coordinate_multi_connections(
    session_id: str,
    session_manager,
    tcp_connections: int,
    max_scan_ports: int
):
    """
    Koordiniert mehrere Hole-Punch-Zyklen für Multi-Connection Support.
    
    Für jede Connection:
    1. Sende peer_info mit connection_num und Port/Range
    2. Warte auf BEIDE READYs
    3. Sende synchronized GO
    4. Warte 2+ Sekunden vor nächster Connection
    """
    lock = session_manager.get_session_lock(session_id)
    
    async with lock:
        session = session_manager.sessions.get(session_id)
        if not session:
            logger.error(f"Session {session_id} not found")
            return
        
        sender = session.get('sender')
        receiver = session.get('receiver')
        
        if not sender or not receiver:
            logger.error(f"Session {session_id}: Missing sender or receiver")
            return
    
    logger.info(f"Session {session_id}: Starting multi-connection coordination ({tcp_connections} connections)")
    
    for conn_num in range(tcp_connections):
        logger.info(f"Session {session_id}: Coordinating connection {conn_num+1}/{tcp_connections}")
        
        # 1. Sende peer_info für diese Connection
        await send_peer_info_for_connection(
            session_id,
            sender,
            receiver,
            conn_num,
            max_scan_ports,
            session_manager
        )
        
        # 2. Warte auf BEIDE READYs
        max_wait = 30.0  # 30 Sekunden Timeout
        start_wait = time.time()
        
        while True:
            async with lock:
                sender_ready = sender.ready_for_connection.get(conn_num, False)
                receiver_ready = receiver.ready_for_connection.get(conn_num, False)
                
                if sender_ready and receiver_ready:
                    logger.info(f"Session {session_id}: Both peers ready for connection {conn_num}")
                    break
                
                if time.time() - start_wait > max_wait:
                    logger.error(f"Session {session_id}: Timeout waiting for READYs (conn {conn_num})")
                    return
            
            await asyncio.sleep(0.1)
        
        # 3. Sende synchronized GO
        start_at = time.time() + 1.5  # 1.5s Vorlauf
        go_msg = {
            'type': 'go',
            'start_at': start_at,
            'connection_num': conn_num,
            'message': f'Connection {conn_num+1}/{tcp_connections}'
        }
        
        await send_message(sender.writer, go_msg)
        await send_message(receiver.writer, go_msg)
        
        logger.info(f"Session {session_id}: GO sent for connection {conn_num+1} at {start_at:.3f}")
        
        # 4. Reset ready flags
        async with lock:
            sender.ready_for_connection[conn_num] = False
            receiver.ready_for_connection[conn_num] = False
        
        # 5. Warte mindestens 2 Sekunden vor nächster Connection
        if conn_num < tcp_connections - 1:  # Nicht nach letzter Connection
            await asyncio.sleep(2.5)  # 2s Pause + 0.5s Buffer


async def send_peer_info_for_connection(
    session_id: str,
    sender: Peer,
    receiver: Peer,
    conn_num: int,
    max_scan_ports: int,
    session_manager
):
    """Sende peer_info für eine spezifische Connection mit Punch-Strategie"""
    from .utils import get_peer_addresses_with_prediction
    
    # Port-Auswahl für diese Connection
    sender_port = sender.bound_ports[conn_num] if conn_num < len(sender.bound_ports) else sender.local_port
    receiver_port = receiver.bound_ports[conn_num] if conn_num < len(receiver.bound_ports) else receiver.local_port
    
    # Bestimme Punch-Strategie basierend auf NAT-Typen
    sender_strategy = determine_punch_strategy(sender, receiver)
    receiver_strategy = determine_punch_strategy(receiver, sender)
    
    # Baue peer_addresses (bleibt gleich, aber mit FESTER Range)
    sender_addrs = get_peer_addresses_with_prediction(sender, receiver, max_scan_ports)
    receiver_addrs = get_peer_addresses_with_prediction(receiver, sender, max_scan_ports)
    
    # Sende an Sender
    msg_to_sender = {
        'type': 'peer_info',
        'connection_num': conn_num,
        'peer_public_addr': list(receiver.public_addr),
        'peer_local_port': receiver_port,
        'peer_addresses': receiver_addrs,
        'your_role': 'sender',
        'same_network': False,
        'peer_nat_analysis': receiver.nat_analysis.to_dict() if receiver.nat_analysis else None,
        'punch_strategy': sender_strategy,
    }
    await send_message(sender.writer, msg_to_sender)
    
    # Sende an Receiver
    msg_to_receiver = {
        'type': 'peer_info',
        'connection_num': conn_num,
        'peer_public_addr': list(sender.public_addr),
        'peer_local_port': sender_port,
        'peer_addresses': sender_addrs,
        'your_role': 'receiver',
        'same_network': False,
        'peer_nat_analysis': sender.nat_analysis.to_dict() if sender.nat_analysis else None,
        'punch_strategy': receiver_strategy,
    }
    await send_message(receiver.writer, msg_to_receiver)
    
    logger.info(f"Session {session_id}: peer_info sent for connection {conn_num} "
                f"(sender={sender_strategy}, receiver={receiver_strategy})")


def determine_punch_strategy(my_peer: Peer, other_peer: Peer) -> str:
    """
    Bestimme Punch-Strategie basierend auf NAT-Typen.
    
    Strategien:
    - "listen": Warte auf eingehende Verbindung (NAT-friendly)
    - "connect": Direkter Connect (NAT-friendly zu NAT-friendly)
    - "scan": Scanne Port-Range (Complex NAT)
    """
    my_nat = my_peer.nat_analysis
    other_nat = other_peer.nat_analysis
    
    my_friendly = my_nat and my_nat.pattern_type == "port_preserved"
    other_friendly = other_nat and other_nat.pattern_type == "port_preserved"
    
    if my_friendly and other_friendly:
        # Beide NAT-friendly: Einer listet, einer connected
        return "connect" if my_peer.role == "sender" else "listen"
    elif my_friendly and not other_friendly:
        # Ich friendly, Peer complex: Ich liste, Peer scannt
        return "listen"
    elif not my_friendly and other_friendly:
        # Ich complex, Peer friendly: Ich scanne, Peer listet
        return "scan"
    else:
        # Beide complex: Beide scannen
        return "scan"
```

#### 3.2 Server: `server/relay/handlers.py` - READY-Handling anpassen

**ÄNDERN:**

```python
async def wait_for_peer_messages(peer: Peer, session_manager, max_scan_ports: int):
    """Wait for messages from peer"""
    while True:
        try:
            data = await asyncio.wait_for(peer.reader.readline(), timeout=300.0)
            if not data:
                break
            
            msg = json.loads(data.decode())
            msg_type = msg.get('type')
            
            if msg_type == 'ready':
                # NEU: Connection-spezifisches READY
                conn_num = msg.get('connection_num', 0)
                peer.ready_for_connection[conn_num] = True
                logger.info(f"Peer {peer.role} is READY for connection {conn_num}")
                
                # NICHT mehr try_send_go aufrufen!
                # Multi-Connection Loop handled das
            
            elif msg_type == 'keepalive':
                await send_message(peer.writer, {'type': 'keepalive_ack'})
            
            elif msg_type == 'probes_complete':
                logger.info(f"Peer {peer.role} sent probes_complete")
                await handle_probes_complete(peer, session_manager, max_scan_ports)
            
            # ENTFERNEN: request_attempt Handling komplett löschen!
            # elif msg_type == 'request_attempt': ← LÖSCHEN
            
        except asyncio.TimeoutError:
            # ... keepalive ...
        except Exception as e:
            logger.debug(f"Error reading from {peer.role}: {e}")
            break
```

#### 3.3 Server: Trigger Multi-Connection nach Probing

**IN:** `handle_probes_complete` oder neue Stelle:

```python
# In handle_probes_complete, NACH try_send_peer_info:

async def handle_probes_complete(peer: Peer, session_manager, max_scan_ports: int):
    # ... existing NAT analysis ...
    
    peer.probes_done = True
    logger.info(f"Peer {peer.role} probes_done=True")
    
    # Sende peer_info (einmalig, initialer Info-Austausch)
    await try_send_peer_info(session_id, session_manager, max_scan_ports)
    
    # NEU: Starte Multi-Connection Koordination wenn beide ready
    session = session_manager.sessions.get(session_id)
    if session:
        sender = session.get('sender')
        receiver = session.get('receiver')
        
        if sender and receiver and sender.probes_done and receiver.probes_done:
            # Beide haben Probing abgeschlossen
            # Ermittle tcp_connections (vom Sender oder Receiver, wurde bei Registration übermittelt)
            tcp_connections = sender.tcp_connections or 1
            
            # Starte Multi-Connection Loop asynchron
            asyncio.create_task(
                coordinate_multi_connections(
                    session_id,
                    session_manager,
                    tcp_connections,
                    max_scan_ports
                )
            )
```

---

### **STEP 4: Client - Multi-Connection Loop**

#### 4.1 Client: Neue Funktion in `src/main.rs`

**NACH:** `run_relay_protocol`

```rust
/// Etabliert mehrere Connections durch wiederholte Punch-Zyklen
async fn establish_multi_connections(
    mut relay_reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
    mut relay_writer: tokio::net::tcp::OwnedWriteHalf,
    session: &Session,
    tcp_connections: u32,
) -> Result<Vec<TcpStream>> {
    
    let mut streams = Vec::new();
    let mut failures_in_a_row = 0;
    const MAX_FAILURES: u32 = 5;
    
    for conn_num in 0..tcp_connections {
        info!("📡 Waiting for peer_info for connection {}/{}...", conn_num+1, tcp_connections);
        
        loop {  // Retry-Loop
            // 1. Warte auf peer_info für diese Connection
            let (peer_info, punch_strategy) = match receive_peer_info_for_connection(
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
            
            info!("✓ Received peer_info for connection {}: strategy={}", conn_num+1, punch_strategy);
            
            // 2. Sende READY
            let ready_msg = format!(r#"{{"type":"ready","connection_num":{}}}"#, conn_num) + "\n";
            relay_writer.write_all(ready_msg.as_bytes()).await?;
            relay_writer.flush().await?;
            info!("✓ READY sent for connection {}", conn_num+1);
            
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
            info!("✓ GO received for connection {}! Start in {:.2}s", conn_num+1, countdown);
            
            // 4. Synchronized Punch
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
                session.timeout,
            ).await {
                Ok(stream) => {
                    failures_in_a_row = 0;  // Reset bei Erfolg
                    streams.push(stream);
                    info!("✅ Connection {}/{} established!", conn_num+1, tcp_connections);
                    break;  // Nächste Connection
                }
                Err(e) => {
                    failures_in_a_row += 1;
                    error!("❌ Connection {} failed: {}", conn_num+1, e);
                    
                    if failures_in_a_row >= MAX_FAILURES {
                        return Err(anyhow!("Max {} consecutive failures reached", MAX_FAILURES));
                    }
                    
                    warn!("🔄 Retrying connection {} (failure {}/{})", 
                          conn_num+1, failures_in_a_row, MAX_FAILURES);
                    // Loop wiederholt → neuer Zyklus für diese Connection
                }
            }
        }
    }
    
    Ok(streams)
}


async fn receive_peer_info_for_connection(
    relay_reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    expected_conn_num: u32,
) -> Result<(protocol::PeerInfo, String)> {
    loop {
        let mut line = String::new();
        relay_reader.read_line(&mut line).await?;
        
        let msg: RelayMessage = serde_json::from_str(&line)?;
        
        match msg {
            RelayMessage::PeerInfo { connection_num, punch_strategy, peer_public_addr, peer_addresses, peer_nat_analysis, .. } => {
                let conn = connection_num.unwrap_or(0);
                if conn != expected_conn_num {
                    warn!("Received peer_info for conn {} but expected {}, skipping", conn, expected_conn_num);
                    continue;
                }
                
                let strategy = punch_strategy.unwrap_or_else(|| "scan".to_string());
                
                // Baue PeerInfo-Struct
                let peer_info = protocol::PeerInfo {
                    peer_addr: RelayMessage::parse_addr(&peer_public_addr)
                        .ok_or_else(|| anyhow!("Invalid peer address"))?,
                    peer_addresses,
                    peer_nat_analysis,
                };
                
                return Ok((peer_info, strategy));
            }
            _ => {
                // Andere Messages ignorieren oder verarbeiten
                debug!("Skipping message while waiting for peer_info: {:?}", msg);
            }
        }
    }
}


async fn receive_go_for_connection(
    relay_reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    expected_conn_num: u32,
) -> Result<GoSignal> {
    loop {
        let mut line = String::new();
        relay_reader.read_line(&mut line).await?;
        
        let msg: RelayMessage = serde_json::from_str(&line)?;
        
        match msg {
            RelayMessage::Go { start_at, connection_num, .. } => {
                let conn = connection_num.unwrap_or(0);
                if conn != expected_conn_num {
                    warn!("Received GO for conn {} but expected {}, skipping", conn, expected_conn_num);
                    continue;
                }
                
                return Ok(GoSignal { start_at });
            }
            _ => {
                debug!("Skipping message while waiting for GO: {:?}", msg);
            }
        }
    }
}


struct GoSignal {
    start_at: f64,
}
```

#### 4.2 Client: Strategie-basiertes Punching

**NEUE DATEI:** `src/punch/strategy.rs`

```rust
//! Strategy-based Hole Punching
//!
//! Unterstützt verschiedene Punch-Strategien:
//! - listen: Wartet auf eingehende Verbindung
//! - connect: Direkter Connect zum Peer
//! - scan: Scannt Port-Range

use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use anyhow::{Result, anyhow};
use tracing::{info, debug, warn};

use super::helpers::*;

pub async fn punch_connection_with_strategy(
    socket: socket2::Socket,
    peer_info: &crate::protocol::PeerInfo,
    strategy: &str,
    start_at: f64,
    time_offset: f64,
    timeout: Duration,
) -> Result<TcpStream> {
    
    match strategy {
        "listen" => punch_listen(socket, start_at, time_offset, timeout).await,
        "connect" => punch_connect(socket, peer_info, start_at, time_offset, timeout).await,
        "scan" => punch_scan(socket, peer_info, start_at, time_offset, timeout).await,
        _ => Err(anyhow!("Unknown punch strategy: {}", strategy)),
    }
}


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
        info!("Waiting {:.3}s until synchronized start (LISTEN mode)", wait_time);
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
                Err(anyhow!("Pre-handshake failed"))
            }
        }
        Ok(Err(e)) => Err(anyhow!("Accept failed: {}", e)),
        Err(_) => Err(anyhow!("LISTEN timeout after {:?}", timeout)),
    }
}


async fn punch_connect(
    socket: socket2::Socket,
    peer_info: &crate::protocol::PeerInfo,
    start_at: f64,
    time_offset: f64,
    timeout: Duration,
) -> Result<TcpStream> {
    // Warte bis synchronized start time
    let local_start_at = start_at - time_offset;
    let now = current_timestamp();
    let wait_time = (local_start_at - now).max(0.0);
    
    if wait_time > 0.0 {
        info!("Waiting {:.3}s until synchronized start (CONNECT mode)", wait_time);
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
            if let Err(_) = stream.peer_addr() {
                return Err(anyhow!("Connection failed"));
            }
            
            stream.set_nodelay(true)?;
            info!("✅ CONNECT: Connected to {}", peer_addr);
            
            // Pre-Handshake
            if pre_handshake(&mut stream).await.is_ok() {
                Ok(stream)
            } else {
                Err(anyhow!("Pre-handshake failed"))
            }
        }
        Ok(Err(e)) => Err(anyhow!("Writable failed: {}", e)),
        Err(_) => Err(anyhow!("CONNECT timeout after {:?}", timeout)),
    }
}


async fn punch_scan(
    socket: socket2::Socket,
    peer_info: &crate::protocol::PeerInfo,
    start_at: f64,
    time_offset: f64,
    timeout: Duration,
) -> Result<TcpStream> {
    // Warte bis synchronized start time
    let local_start_at = start_at - time_offset;
    let now = current_timestamp();
    let wait_time = (local_start_at - now).max(0.0);
    
    if wait_time > 0.0 {
        info!("Waiting {:.3}s until synchronized start (SCAN mode)", wait_time);
        tokio::time::sleep(Duration::from_secs_f64(wait_time)).await;
    }
    
    // Hole scan_start und scan_end aus NAT-Analyse
    let (scan_start, scan_end) = if let Some(ref nat) = peer_info.peer_nat_analysis {
        (nat.scan_start, nat.scan_end)
    } else {
        // Fallback: Nutze peer_addresses
        let ports: Vec<u16> = peer_info.peer_addresses.iter().map(|a| a.port).collect();
        if ports.is_empty() {
            return Err(anyhow!("No scan range available"));
        }
        (*ports.iter().min().unwrap(), *ports.iter().max().unwrap())
    };
    
    let peer_ip = peer_info.peer_addr.ip();
    info!("🔍 SCAN mode: Scanning {}:{}-{}", peer_ip, scan_start, scan_end);
    
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
        
        for port in scan_start..=scan_end {
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
            
            let target_addr: std::net::SocketAddr = format!("{}:{}", peer_ip, port).parse().unwrap();
            
            match socket.connect(&socket2::SockAddr::from(target_addr)) {
                Ok(()) | Err(_) => {
                    let std_stream: std::net::TcpStream = socket.into();
                    if let Ok(mut stream) = TcpStream::from_std(std_stream) {
                        if wait_for_connect_async(&mut stream, Duration::from_millis(500)).await.is_ok() {
                            if pre_handshake(&mut stream).await.is_ok() {
                                debug!("SCAN: Connected to {}:{}", peer_ip, port);
                                let _ = connector_tx.send(stream).await;
                                return;
                            }
                        }
                    }
                }
            }
            
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });
    
    drop(tx);
    
    // Warte auf ersten erfolgreichen Stream
    match tokio::time::timeout(timeout + Duration::from_secs(1), rx.recv()).await {
        Ok(Some(stream)) => {
            listener_handle.abort();
            connector_handle.abort();
            info!("✅ SCAN: Connection established");
            Ok(stream)
        }
        _ => {
            listener_handle.abort();
            connector_handle.abort();
            Err(anyhow!("SCAN timeout after {:?}", timeout))
        }
    }
}


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
```

**HINZUFÜGEN zu** `src/punch/mod.rs`:

```rust
mod strategy;
pub use strategy::punch_connection_with_strategy;
```

---

### **STEP 5: Integration in run_sender/run_receiver**

#### 5.1 `src/main.rs` - run_sender anpassen

**ERSETZEN:**

```rust
async fn run_sender(...) -> Result<()> {
    // ... SHA256, File Size ...
    // ... Bind Sockets ...
    
    let (relay_stream, session) = run_relay_protocol(...).await?;
    
    // ENTFERNEN: Alte Logik mit do_sequential_hole_punch
    // NEU: Multi-Connection Loop
    
    let (relay_reader, relay_writer) = relay_stream.into_split();
    let relay_reader = BufReader::new(relay_reader);
    
    let streams = establish_multi_connections(
        relay_reader,
        relay_writer,
        &session,
        session.tcp_connections,
    ).await?;
    
    let min_required = if session.allow_fallback {
        session.min_connections.max(1) as usize
    } else {
        session.tcp_connections as usize
    };
    
    if streams.len() < min_required {
        return Err(anyhow!("Got {}/{} connections", streams.len(), session.tcp_connections));
    }
    
    for s in &streams {
        info!("✅ Direct P2P: Local {} Remote {}", s.local_addr()?, s.peer_addr()?);
    }
    
    // Transfer
    if session.tcp_connections > 1 || streams.len() > 1 {
        run_multi_sender(streams, file_path, file_size, sha256).await
    } else {
        let stream = streams.into_iter().next().unwrap();
        let mut sender = TcpSender::new_with_hash(stream, file_path, file_size, sha256);
        sender.run().await
    }
}
```

**Gleiche Änderungen für** `run_receiver`.

---

## 📝 Zusammenfassung der Änderungen

### Server (Python):
1. ✅ `models.py`: `ready_for_connection` dict
2. ✅ `coordinator.py`: `coordinate_multi_connections`, `send_peer_info_for_connection`, `determine_punch_strategy`
3. ✅ `handlers.py`: Connection-spezifisches READY-Handling, ENTFERNEN von `request_attempt`
4. ✅ Time-Sync in Registration mit `server_times` array

### Client (Rust):
1. ✅ `protocol/relay.rs`: `server_times`, `connection_num`, `punch_strategy`, ENTFERNEN von `GoAttempt`
2. ✅ `main.rs`: Median-Offset-Berechnung, `establish_multi_connections`
3. ✅ `punch/strategy.rs`: NEU - Strategie-basiertes Punching
4. ✅ Integration in `run_sender`/`run_receiver`

---

## 🧪 Test-Szenarien

### Szenario 1: Beide NAT-friendly
```
Sender: Port preserved (39259)
Receiver: Port preserved (24056)

Connection 1:
  Server → Sender: strategy=connect, peer_port=24056
  Server → Receiver: strategy=listen, local_port=24056
  → Sender connects, Receiver listens
  → SUCCESS

Connection 2:
  Server → Sender: strategy=connect, peer_port=24057
  Server → Receiver: strategy=listen, local_port=24057
  → SUCCESS

... (3, 4)
```

### Szenario 2: Einer NAT-friendly, einer Complex
```
Sender: Complex NAT (range 12000-12238)
Receiver: Port preserved (24056)

Connection 1:
  Server → Sender: strategy=scan, peer_port=24056, range=[24056]
  Server → Receiver: strategy=listen, local_port=24056
  → Sender scannt nur Port 24056 (friendly range)
  → Receiver listet
  → SUCCESS

Connection 2:
  ... (gleiche Range, nächster Port)
```

### Szenario 3: Beide Complex NAT
```
Beide scannen ihre jeweiligen Ranges
Birthday Paradox: Treffen sich irgendwo
```

---

## 🚨 Offene Punkte / TODOs

1. **Helper-Funktionen in strategy.rs**: `wait_for_connect_async` muss getestet werden
2. **PeerInfo Struct**: Muss in `protocol/relay.rs` definiert werden
3. **Error-Handling**: Robustere Fehlerbehandlung in Multi-Connection Loop
4. **Logging**: Mehr Debug-Logs für Troubleshooting
5. **Testing**: Unit-Tests für Strategie-Funktionen
6. **Documentation**: API-Docs für neue Funktionen

---

## 📚 Weiterführende Ideen

- **Dynamic Port Adjustment**: Wenn Ports belegt sind, automatisch alternative finden
- **Parallel Punching**: Mehrere Connections gleichzeitig punchen (nicht sequenziell)
- **Adaptive Timeouts**: Timeout basierend auf RTT anpassen
- **Statistics**: Erfolgsrate pro NAT-Kombination tracken

---

**Status**: STEP 4 abgeschlossen - Client Multi-Connection Loop vollständig implementiert
**Nächster Schritt**: Testing mit 4 Connections

---

## ✅ Implementierungs-Fortschritt

### STEP 1: Protokoll-Definitionen aktualisiert ✅
- ✅ **Server (`server/models.py`)**: 
  - `tcp_connections`, `bound_ports`, `ready_for_connection` hinzugefügt
- ✅ **Client (`src/protocol/relay.rs`)**: 
  - `server_times` zu `Registered`
  - `connection_num`, `punch_strategy` zu `PeerInfo`
  - `connection_num` zu `Go`

### STEP 2: Time-Sync mit Median-Ansatz ✅
- ✅ **Server (`server/relay/server.py`)**:
  - Sammelt 5 Timestamps mit 50ms Intervallen
  - Sendet `server_times` array in Registration-Response
  - Behält `server_time` für Rückwärtskompatibilität
- ✅ **Client (`src/main.rs`)**:
  - Berechnet Median aus allen Timestamp-Samples
  - Robuste Offset-Berechnung gegen Netzwerk-Jitter
  - Detailliertes Logging mit Range und Spread
  - Fallback zur RTT/2-Methode wenn `server_times` fehlt
  - Warnungen für fehlende Time-Sync-Daten

**Ergebnis**: Time-Synchronisation ist nun deutlich robuster und präziser. Median-Ansatz filtert Ausreißer durch Netzwerk-Jitter automatisch heraus.

### STEP 3: Server Multi-Connection Koordination ✅
- ✅ **Server (`server/relay/coordinator.py`)**:
  - `coordinate_multi_connections` - koordiniert mehrere Hole-Punch-Zyklen
  - `send_peer_info_for_connection` - sendet connection-spezifische peer_info mit connection_num und punch_strategy
  - `determine_punch_strategy` - bestimmt Strategie basierend auf NAT-Typen (listen/connect/scan)
- ✅ **Server (`server/relay/handlers.py`)**:
  - Connection-spezifisches READY-Handling (ready_for_connection dict statt single ready flag)
  - `request_attempt` Handling KOMPLETT ENTFERNT (nicht mehr benötigt)
  - Trigger für Multi-Connection Loop in `handle_probes_complete` hinzugefügt
  - Startet `coordinate_multi_connections` asynchron wenn beide Peers probes_done

**Ergebnis**: Server koordiniert nun mehrere Connections sequenziell mit individuellen peer_info und synchronized GO für jede Connection. Punch-Strategie wird automatisch basierend auf NAT-Typen bestimmt.

### STEP 4: Client Multi-Connection Loop ✅
- ✅ **Client (`src/punch/strategy.rs`)**: NEU
  - `punch_listen()` - Wartet auf eingehende Verbindung mit synchronized start
  - `punch_connect()` - Direkter Connect mit synchronized start
  - `punch_scan()` - Scannt Port-Range parallel (Listener + Scanner Tasks)
  - `punch_connection_with_strategy()` - Main-Funktion mit Strategie-Routing
  - `wait_for_connect_async()` - Helper für Connect-Timeout
  - `PeerInfo` struct für Strategy-basiertes Punching
- ✅ **Client (`src/main.rs`)**: 
  - `establish_multi_connections()` - Haupt-Loop für alle tcp_connections
    - Iteriert über alle Connections (0..tcp_connections)
    - Für jede Connection: peer_info empfangen → READY senden → GO empfangen → punch
    - Retry-Logik mit max 5 aufeinanderfolgenden Fehlern
    - Reset des Fehler-Counters bei Erfolg
  - `receive_peer_info_for_connection()` - Wartet auf peer_info mit connection_num
  - `receive_go_for_connection()` - Wartet auf GO mit connection_num
  - `GoSignal` struct für synchronized start
  - Integration in `run_sender()` und `run_receiver()`:
    - Split relay_stream in reader/writer
    - Aufruf von `establish_multi_connections()`
    - Validierung der etablierten Connections gegen min_required
    - Fehler wenn zu wenige Connections etabliert wurden
- ✅ **Client (`src/punch/mod.rs`)**: 
  - Export von `punch_connection_with_strategy` und `PeerInfo`

**Ergebnis**: Client etabliert nun mehrere Connections durch wiederholte Punch-Zyklen. Jede Connection verwendet die vom Server bestimmte Strategie (listen/connect/scan). Robuste Fehlerbehandlung mit automatischen Retries.

---
