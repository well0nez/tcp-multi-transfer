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
    pub time_offset: f64,
    
    // Multi-TCP fields
    pub tcp_connections: u32,
    pub allow_fallback: bool,
    pub min_connections: u32,
    pub bound_sockets: Vec<Socket>,
    
    // Server connection info (for probing new ports)
    pub server_addr: SocketAddr,
    pub probe_port: Option<u16>,
    /// Vergibt die eigene NAT pro 5-Tupel (true) oder pro Verbindung (false)?
    /// `None` = nicht ermittelt.
    pub mapping_stable: Option<bool>,
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
/// Sendet die NAT-Probes von den **gebundenen Punch-Ports** aus.
///
/// Die alte Variante nutzte `TcpStream::connect`, also einen vom Kernel
/// gewaehlten Ephemeralport. Serverseitig sucht `get_nat_port_for_local_port`
/// die Probes aber ueber genau den Punch-Port — der stand dort nie drin, also
/// fiel die Funktion immer in den Praediktionszweig und der Filter in
/// `handle_add_ports` lief leer.
///
/// Mit dieser Variante trifft der Nachschlag, und der primaere Kandidat wird
/// gemessen statt extrapoliert. Die Extrapolation bleibt trotzdem noetig: bei
/// symmetrischer NAT haengt das Mapping am Ziel, und das Ziel ist hier der
/// Probe-Server, nicht der Peer. Der Anker wird nur sauber vergleichbar.
async fn do_nat_probing_from_bound(
    probe_addr: SocketAddr,
    probe_addr2: Option<SocketAddr>,
    session_id: &str,
    bound_sockets: &[Socket],
    count: u32,
) -> Result<Option<bool>> {
    let ports: Vec<u16> = bound_sockets
        .iter()
        .filter_map(|s| s.local_addr().ok()?.as_socket().map(|a| a.port()))
        .collect();

    if ports.is_empty() {
        return Err(anyhow!("No bound ports available for probing"));
    }

    // Genug Proben, damit jedes Paar (lokaler Port, Ziel) mehrfach vorkommt —
    // sonst kann weder das Wiederholungsverhalten noch die Zielabhaengigkeit
    // bestimmt werden. Mit vier gebundenen Ports und den vorgegebenen zehn
    // Proben blieb je Paar hoechstens eine Probe uebrig, und die Erkennung
    // lieferte still "unbestimmt".
    let ziele = if probe_addr2.is_some() { 2 } else { 1 };
    let noetig = (ports.len() * ziele * 2) as u32;
    let count = count.max(noetig);
    if count > ports.len() as u32 * ziele as u32 {
        debug!("Probenzahl auf {} gesetzt ({} Ports x {} Ziele)", count, ports.len(), ziele);
    }

    info!("NAT probing: {} connections from {} bound port(s) to {}",
          count, ports.len(), probe_addr);

    let mut successful = 0;
    // (lokaler Port, Zielport) -> die vom Server gesehenen NAT-Ports
    let mut gesehen: std::collections::HashMap<(u16, u16), Vec<u16>> =
        std::collections::HashMap::new();

    for i in 0..count {
        // Reihum ueber die Punch-Ports, und abwechselnd gegen beide Zielports.
        //
        // Der Wechsel des Ziels hat zwei Gruende. Erstens misst er das
        // Mapping-Verhalten: derselbe lokale Port gegen zwei Ziele zeigt, ob
        // die NAT zielabhaengig vergibt. Zweitens vermeidet er ein
        // handfestes Problem — zwei Verbindungen mit identischem Fuenftupel
        // gehen nicht gleichzeitig, der Kernel antwortet mit
        // EADDRNOTAVAIL. Bei nur einem Ziel und einem gebundenen Port fielen
        // dadurch regelmaessig Proben aus.
        // Ziel je Probe wechseln, Port erst danach weiterschalten: so bekommt
        // jedes Paar (Port, Ziel) gleich viele Proben.
        let ziel = match (probe_addr2, (i as usize) % ziele) {
            (Some(zweit), 1) => zweit,
            _ => probe_addr,
        };
        let port = ports[((i as usize) / ziele) % ports.len()];

        // Die letzte Probe bleibt offen, bis der Server das Filterverhalten
        // geprueft hat — sonst testet er gegen ein bereits freigegebenes
        // Mapping und misst Vergesslichkeit statt Filterung.
        let letzte = i + 1 == count;
        match probe_once_from_port(ziel, session_id, port, i, letzte).await {
            Ok(seen) => {
                successful += 1;
                if let Some(nat) = seen {
                    gesehen.entry((port, ziel.port())).or_default().push(nat);
                }
                debug!("  Probe #{} from bound port {} to {} -> {:?}", i, port, ziel, seen);
            }
            Err(e) => warn!("  Probe #{} from port {} to {} failed: {}", i, port, ziel, e),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    info!("NAT probing done: {}/{} succeeded", successful, count);
    Ok(bewerte_mapping(&gesehen))
}

/// Vergibt die eigene NAT pro 5-Tupel oder pro Verbindung einen Port?
///
/// Mehrere Proben vom **selben** lokalen Port zum **selben** Ziel bilden
/// dasselbe 5-Tupel. Bekommt der Server dabei immer denselben Absenderport zu
/// sehen, ist das Mapping stabil und eine Vorspannung kann es fuer die spaetere
/// echte Verbindung offenhalten. Wechselt der Port, vergibt die NAT pro
/// Verbindung neu — dann ist jede Vorspannung wirkungslos, weil die echte
/// Verbindung ohnehin ein anderes Mapping bekommt.
///
/// `None` heisst: zu wenig Daten fuer eine Aussage.
fn bewerte_mapping(gesehen: &std::collections::HashMap<(u16, u16), Vec<u16>>) -> Option<bool> {
    let mut entschieden = false;
    for ports in gesehen.values() {
        if ports.len() < 2 {
            continue;
        }
        entschieden = true;
        if ports.iter().any(|p| *p != ports[0]) {
            return Some(false); // pro Verbindung
        }
    }
    if entschieden { Some(true) } else { None }
}

/// Eine einzelne Probe von einem bestimmten lokalen Port aus.
async fn probe_once_from_port(
    probe_addr: SocketAddr,
    session_id: &str,
    local_port: u16,
    probe_num: u32,
    filtertest: bool,
) -> Result<Option<u16>> {
    use crate::punch::{create_hole_punch_socket, bind_to_port};

    // Frischer Socket auf demselben Port — der gebundene bleibt unangetastet.
    // Moeglich, weil beide SO_REUSEADDR/SO_REUSEPORT gesetzt haben.
    let sock = create_hole_punch_socket()?;
    bind_to_port(&sock, local_port)?;
    sock.set_nonblocking(true)?;

    match sock.connect(&SockAddr::from(probe_addr)) {
        Ok(()) => {}
        Err(e) => {
            #[cfg(unix)]
            let in_progress = e.raw_os_error() == Some(libc::EINPROGRESS)
                || e.kind() == std::io::ErrorKind::WouldBlock;
            #[cfg(not(unix))]
            let in_progress = e.kind() == std::io::ErrorKind::WouldBlock;
            if !in_progress {
                return Err(anyhow!("connect: {}", e));
            }
        }
    }

    let std_stream: std::net::TcpStream = sock.into();
    let stream = TcpStream::from_std(std_stream)?;

    tokio::time::timeout(Duration::from_secs(5), stream.writable())
        .await
        .map_err(|_| anyhow!("Timed out while connecting"))??;
    stream.peer_addr().map_err(|e| anyhow!("not connected: {}", e))?;

    let probe = if filtertest {
        ProbeMessage::mit_filtertest(session_id, local_port, probe_num)
    } else {
        ProbeMessage::new(session_id, local_port, probe_num)
    };
    let msg = serde_json::to_string(&probe).unwrap_or_default() + "\n";
    let (reader, mut writer) = stream.into_split();
    tokio::io::AsyncWriteExt::write_all(&mut writer, msg.as_bytes()).await?;

    // Die Bestaetigung enthaelt den Port, den der Server als Absender gesehen
    // hat. Daraus laesst sich ablesen, ob die eigene NAT pro 5-Tupel oder pro
    // Verbindung vergibt — und das entscheidet, ob eine Vorspannung ueberhaupt
    // etwas bewirken kann.
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    // Beim Filtertest antwortet der Server erst nach seinem Rueckverbindungs-
    // versuch, der bis zu zwei Sekunden dauern darf.
    let wartezeit = if filtertest { Duration::from_secs(8) } else { Duration::from_secs(3) };
    match tokio::time::timeout(wartezeit, reader.read_line(&mut line)).await {
        Ok(Ok(n)) if n > 0 => {
            let seen = serde_json::from_str::<serde_json::Value>(&line)
                .ok()
                .and_then(|v| v.get("your_nat_port").and_then(|p| p.as_u64()))
                .map(|p| p as u16);
            Ok(seen)
        }
        _ => Ok(None),
    }
}

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
    probe_from_bound: bool,
    punch_ports: u32,
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
        Some(punch_ports.max(1)),
    );
    let msg = serde_json::to_string(&register)? + "\n";
    writer.write_all(msg.as_bytes()).await?;
    writer.flush().await?;
    
    info!("Registered as {} for session {} (local_port={})", role, session_id, local_port);
    
    let register_sent_at = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs_f64();
    
    let mut session = Session {
        time_offset: 0.0,
        tcp_connections,
        allow_fallback,
        min_connections,
        bound_sockets,
        server_addr: server_sock_addr,
        probe_port: None,
        mapping_stable: None,
    };
    
    loop {
        let mut line = String::new();
        let n = tokio::time::timeout(Duration::from_secs(120), reader.read_line(&mut line)).await
            .map_err(|_| anyhow!("Timeout waiting for server response"))??;
        
        if n == 0 { return Err(anyhow!("Server closed connection")); }
        
        let msg: RelayMessage = serde_json::from_str(&line)
            .map_err(|e| anyhow!("Failed to parse server message: {} - {}", e, line.trim()))?;
        
        match msg {
            RelayMessage::Registered { your_public_addr, server_time, probe_port, probe_port2, needs_probing, filter_test, .. } => {
                if let Some((ip, port)) = RelayMessage::parse_addr(&your_public_addr) {
                    session.probe_port = probe_port;
                    info!("Registered! Public address: {}:{}", ip, port);
                    
                    // Uhrenversatz aus einem Zeitstempel plus halber
                    // Umlaufzeit. Genauer muss es nicht sein: beide Seiten
                    // halten ihre Sockets das ganze Zeitbudget offen, die
                    // Fenster ueberlappen also um Sekunden.
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs_f64();
                    match server_time {
                        Some(srv_time) => {
                            let rtt = now - register_sent_at;
                            session.time_offset = srv_time - (register_sent_at + rtt / 2.0);
                            info!("Clock offset {:.3}s (round trip {:.3}s)", session.time_offset, rtt);
                        }
                        None => {
                            warn!("No time sync data from server - synchronization may be inaccurate");
                            session.time_offset = 0.0;
                        }
                    }

                    // Auch ohne Probing will der Server das Filterverhalten
                    // bestimmen — dafuer genuegt eine einzige gehaltene
                    // Verbindung vom spaeteren Punch-Port.
                    if !needs_probing.unwrap_or(false) && filter_test.unwrap_or(false) {
                        if let (Some(pp), Some(sock)) = (probe_port, session.bound_sockets.first()) {
                            let probe_addr = SocketAddr::new(server_sock_addr.ip(), pp);
                            let port = sock.local_addr().ok()
                                .and_then(|a| a.as_socket()).map(|a| a.port()).unwrap_or(0);
                            if port != 0 {
                                match probe_once_from_port(probe_addr, session_id, port, 0, true).await {
                                    Ok(_) => info!("Filter test of our own NAT requested"),
                                    Err(e) => warn!("Filter test not possible: {}", e),
                                }
                            }
                        }
                    }

                    if needs_probing.unwrap_or(false) {
                        if let Some(pp) = probe_port {
                            let probe_addr = SocketAddr::new(server_sock_addr.ip(), pp);
                            let probe_addr2 = probe_port2
                                .map(|p2| SocketAddr::new(server_sock_addr.ip(), p2));
                            if probe_from_bound {
                                match do_nat_probing_from_bound(
                                    probe_addr, probe_addr2, session_id,
                                    &session.bound_sockets, probe_count,
                                ).await {
                                    Ok(stable) => {
                                        session.mapping_stable = stable;
                                        match stable {
                                            Some(true) => info!("Own NAT: mapping stable per five-tuple"),
                                            Some(false) => info!("Own NAT: fresh port per connection"),
                                            None => info!("Own NAT: mapping behaviour undetermined"),
                                        }
                                    }
                                    Err(e) => warn!("NAT probing failed: {}", e),
                                }
                            } else {
                                // Referenzverhalten: Ephemeralports.
                                let _ = do_nat_probing(probe_addr, session_id, probe_count).await;
                            }
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
