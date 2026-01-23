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
const PRE_HANDSHAKE_VERSION: u8 = 1;
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

/// Pre-handshake protocol to verify both peers are ready
pub async fn pre_handshake(stream: &mut TcpStream) -> Result<()> {
    let mut out = [0u8; 5];
    out[..4].copy_from_slice(&PRE_HANDSHAKE_MAGIC);
    out[4] = PRE_HANDSHAKE_VERSION;

    tokio::time::timeout(PRE_HANDSHAKE_TIMEOUT, stream.write_all(&out)).await.map_err(|_| anyhow!("write timeout"))??;

    let mut buf = [0u8; 5];
    tokio::time::timeout(PRE_HANDSHAKE_TIMEOUT, stream.read_exact(&mut buf)).await.map_err(|_| anyhow!("read timeout"))??;

    if buf[..4] != PRE_HANDSHAKE_MAGIC || buf[4] != PRE_HANDSHAKE_VERSION {
        return Err(anyhow!("Pre-handshake mismatch"));
    }
    Ok(())
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