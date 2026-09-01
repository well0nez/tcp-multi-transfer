//! Hole Punching Helper Functions
//!
//! Common utilities for TCP hole punching operations

use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use socket2::{Socket, Domain, Type, Protocol, SockAddr};
use anyhow::{Result, anyhow};


const PRE_HANDSHAKE_MAGIC: [u8; 4] = *b"HPCH";
/// Version 2 traegt zusaetzlich eine Zufallszahl je Socket.
const PRE_HANDSHAKE_VERSION: u8 = 2;
const PRE_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(1);

/// Get current Unix timestamp
pub fn current_timestamp() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}

/// Create a TCP socket with proper options for hole punching
pub fn create_hole_punch_socket() -> Result<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    
    // CRITICAL: Enable address reuse so multiple sockets can bind to same port
    socket.set_reuse_address(true)?;
    
    // CRITICAL on Unix: Enable port reuse for true simultaneous bind
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    
    // Disable Nagle for faster small packet transmission
    socket.set_nodelay(true)?;
    
    Ok(socket)
}

/// Bind a socket to the specified local port
pub fn bind_to_port(socket: &Socket, port: u16) -> Result<()> {
    let addr: SocketAddr = format!("0.0.0.0:{}", port).parse()?;
    socket.bind(&SockAddr::from(addr))?;
    Ok(())
}

/// Pre-Handshake: bestaetigt, dass am anderen Ende dieses Werkzeug sitzt, und
/// tauscht eine Zufallszahl je Socket aus.
///
/// Die Zufallszahl loest ein Problem, das erst mit mehreren gleichzeitigen
/// Verbindungen auftritt. Gelingt der Punch mehrfach, muessen **beide** Seiten
/// dieselbe Verbindung behalten und die uebrigen fallenlassen. Die frueher
/// dafuer benutzte Regel — das geordnete Paar aus lokalem und entferntem Port —
/// ist hinter NAT keine gemeinsame Groesse: die eine Seite sieht ihren lokalen
/// Port und den uebersetzten Port der Gegenstelle, die andere genau umgekehrt
/// *andere* Zahlen. Beide Seiten waehlten dann verschiedene Verbindungen, und
/// der Transfer brach mit "early eof" ab.
///
/// Die beiden Zufallszahlen dagegen gehoeren zur Verbindung selbst und sind auf
/// beiden Seiten dieselben, nur vertauscht. Das geordnete Paar daraus ist
/// symmetrisch.
///
/// Rueckgabe: das geordnete Paar (kleinere, groessere Zahl).
pub async fn pre_handshake(stream: &mut TcpStream) -> Result<(u64, u64)> {
    let eigen: u64 = rand::random();

    let mut out = [0u8; 13];
    out[..4].copy_from_slice(&PRE_HANDSHAKE_MAGIC);
    out[4] = PRE_HANDSHAKE_VERSION;
    out[5..].copy_from_slice(&eigen.to_be_bytes());

    tokio::time::timeout(PRE_HANDSHAKE_TIMEOUT, stream.write_all(&out)).await.map_err(|_| anyhow!("write timeout"))??;

    let mut buf = [0u8; 13];
    tokio::time::timeout(PRE_HANDSHAKE_TIMEOUT, stream.read_exact(&mut buf)).await.map_err(|_| anyhow!("read timeout"))??;

    if buf[..4] != PRE_HANDSHAKE_MAGIC || buf[4] != PRE_HANDSHAKE_VERSION {
        return Err(anyhow!("Pre-handshake mismatch"));
    }
    let mut fremd = [0u8; 8];
    fremd.copy_from_slice(&buf[5..]);
    let fremd = u64::from_be_bytes(fremd);

    Ok(if eigen <= fremd { (eigen, fremd) } else { (fremd, eigen) })
}


#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_create_socket() {
        let socket = create_hole_punch_socket().unwrap();
        bind_to_port(&socket, 0).unwrap();
        let addr = socket.local_addr().unwrap();
        println!("Bound to: {:?}", addr);
    }
}
