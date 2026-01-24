//! Async handler for PeerAddedPorts notifications

use std::sync::{Arc, Mutex};
use std::time::Duration;
use anyhow::Result;
use tracing::info;

use super::message_queue::MessageQueues;

pub fn spawn_notification_handler(
    queues: MessageQueues,
    peer_extra_ports: Arc<Mutex<Vec<u16>>>,
) -> tokio::task::JoinHandle<Result<()>> {
    tokio::spawn(async move {
        info!("Notification handler task started");
        
        let mut last_ports: Vec<u16> = Vec::new();
        
        loop {
            let new_ports = queues.get_peer_added_ports();
            
            if new_ports != last_ports && !new_ports.is_empty() {
                if let Ok(mut ports) = peer_extra_ports.lock() {
                    ports.clear();
                    ports.extend(new_ports.iter().copied());
                    info!("Updated peer_extra_ports: {:?}", *ports);
                    last_ports = new_ports.clone();
                }
            }
            
            if queues.is_shutdown() {
                info!("Notification handler shutting down");
                break;
            }
            
            tokio::time::sleep(Duration::from_millis(125)).await;
        }
        
        info!("Notification handler task stopped");
        Ok(())
    })
}