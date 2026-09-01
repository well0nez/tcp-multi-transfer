//! Non-blocking queue polling functions with timeout handling

use std::time::Duration;
use anyhow::{Result, anyhow};
use tracing::debug;

use crate::punch::PeerInfo;
use super::message_queue::MessageQueues;
use super::types::GoSignal;

pub async fn wait_for_peer_info_from_queue(
    queues: &MessageQueues,
    conn_num: u32,
    timeout: Duration,
) -> Result<(PeerInfo, u32)> {
    let start = std::time::Instant::now();
    
    loop {
        if start.elapsed() > timeout {
            return Err(anyhow!("Timeout waiting for peer_info (conn {})", conn_num));
        }
        
        if let Some(error) = queues.has_error() {
            return Err(anyhow!("Server error: {}", error));
        }
        
        if let Some((info, tcp_conns)) = queues.pop_peer_info(conn_num) {
            debug!("Got PeerInfo for conn {} from queue", conn_num);
            return Ok((info, tcp_conns));
        }
        
        tokio::time::sleep(Duration::from_millis(13)).await;
    }
}

pub async fn wait_for_go_from_queue(
    queues: &MessageQueues,
    conn_num: u32,
    timeout: Duration,
) -> Result<GoSignal> {
    let start = std::time::Instant::now();
    
    loop {
        if start.elapsed() > timeout {
            return Err(anyhow!("Timeout waiting for GO (conn {})", conn_num));
        }
        
        if let Some(error) = queues.has_error() {
            return Err(anyhow!("Server error: {}", error));
        }
        
        if let Some(signal) = queues.pop_go(conn_num) {
            debug!("Got GO signal for conn {} from queue", conn_num);
            return Ok(signal);
        }
        
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

pub async fn wait_for_ports_ack_from_queue(
    queues: &MessageQueues,
    expected_ports: &[u16],
    timeout: Duration,
) -> Result<()> {
    let start = std::time::Instant::now();
    
    loop {
        if start.elapsed() > timeout {
            return Err(anyhow!("Timeout waiting for ports_added_ack"));
        }
        
        if let Some(error) = queues.has_error() {
            return Err(anyhow!("Server error: {}", error));
        }
        
        if let Some(acked_ports) = queues.pop_ports_ack() {
            debug!("Got PortsAddedAck from queue: {:?}", acked_ports);
            
            let expected_set: std::collections::HashSet<_> = expected_ports.iter().copied().collect();
            let acked_set: std::collections::HashSet<_> = acked_ports.iter().copied().collect();
            
            if expected_set == acked_set {
                return Ok(());
            } else {
                tracing::warn!("ACK ports mismatch: expected {:?}, got {:?}", expected_ports, acked_ports);
            }
        }
        
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

pub async fn wait_for_retry_granted_from_queue(
    queues: &MessageQueues,
    conn_num: u32,
    timeout: Duration,
) -> Result<()> {
    let start = std::time::Instant::now();
    
    loop {
        if start.elapsed() > timeout {
            return Err(anyhow!("Timeout waiting for retry_granted (conn {})", conn_num));
        }
        
        if let Some(error) = queues.has_error() {
            return Err(anyhow!("Server error: {}", error));
        }
        
        // Check for retry_rejected first (higher priority than granted)
        if let Some(reason) = queues.pop_retry_rejected(conn_num) {
            debug!("Got RetryRejected for conn {} from queue: {}", conn_num, reason);
            return Err(anyhow!("Retry rejected: {}", reason));
        }
        
        // `pop_retry_granted` filtert bereits nach Verbindungsnummer; ein
        // Treffer gehoert also immer uns.
        if queues.pop_retry_granted(conn_num).is_some() {
            debug!("Got RetryGranted for conn {} from queue", conn_num);
            return Ok(());
        }
        
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
