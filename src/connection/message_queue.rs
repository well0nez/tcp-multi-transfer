//! Thread-safe message queues preventing race conditions and message loss

use std::sync::{Arc, Mutex};
use std::collections::VecDeque;

use crate::punch::PeerInfo;
use super::types::GoSignal;

/// Thread-safe queues for all incoming relay messages
#[derive(Clone)]
pub struct MessageQueues {
    peer_infos: Arc<Mutex<VecDeque<(u32, PeerInfo, String, u32)>>>,
    go_signals: Arc<Mutex<VecDeque<(u32, GoSignal)>>>,
    ports_acks: Arc<Mutex<VecDeque<Vec<u16>>>>,
    peer_added_ports: Arc<Mutex<VecDeque<Vec<u16>>>>,
    retry_granted: Arc<Mutex<VecDeque<u32>>>,
    retry_rejected: Arc<Mutex<VecDeque<(u32, String)>>>,
    errors: Arc<Mutex<VecDeque<String>>>,
    shutdown: Arc<Mutex<bool>>,
}

impl MessageQueues {
    pub fn new() -> Self {
        Self {
            peer_infos: Arc::new(Mutex::new(VecDeque::new())),
            go_signals: Arc::new(Mutex::new(VecDeque::new())),
            ports_acks: Arc::new(Mutex::new(VecDeque::new())),
            peer_added_ports: Arc::new(Mutex::new(VecDeque::new())),
            retry_granted: Arc::new(Mutex::new(VecDeque::new())),
            retry_rejected: Arc::new(Mutex::new(VecDeque::new())),
            errors: Arc::new(Mutex::new(VecDeque::new())),
            shutdown: Arc::new(Mutex::new(false)),
        }
    }
    
    pub fn push_peer_info(&self, conn_num: u32, info: PeerInfo, strategy: String, tcp_connections: u32) {
        if let Ok(mut queue) = self.peer_infos.lock() {
            queue.push_back((conn_num, info, strategy, tcp_connections));
        }
    }
    
    pub fn pop_peer_info(&self, conn_num: u32) -> Option<(PeerInfo, String, u32)> {
        if let Ok(mut queue) = self.peer_infos.lock() {
            if let Some(pos) = queue.iter().position(|(num, _, _, _)| *num == conn_num) {
                if let Some((_, info, strategy, tcp_conns)) = queue.remove(pos) {
                    return Some((info, strategy, tcp_conns));
                }
            }
        }
        None
    }
    
    pub fn push_go(&self, conn_num: u32, signal: GoSignal) {
        if let Ok(mut queue) = self.go_signals.lock() {
            queue.push_back((conn_num, signal));
        }
    }
    
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
    
    pub fn push_ports_ack(&self, ports: Vec<u16>) {
        if let Ok(mut queue) = self.ports_acks.lock() {
            queue.push_back(ports);
        }
    }
    
    pub fn pop_ports_ack(&self) -> Option<Vec<u16>> {
        if let Ok(mut queue) = self.ports_acks.lock() {
            queue.pop_front()
        } else {
            None
        }
    }
    
    pub fn push_peer_added_ports(&self, ports: Vec<u16>) {
        if let Ok(mut queue) = self.peer_added_ports.lock() {
            queue.push_back(ports);
        }
    }
    
    /// Non-consuming read for notification handler
    pub fn get_peer_added_ports(&self) -> Vec<u16> {
        if let Ok(queue) = self.peer_added_ports.lock() {
            queue.iter().flatten().copied().collect()
        } else {
            Vec::new()
        }
    }
    
    pub fn push_retry_granted(&self, conn_num: u32) {
        if let Ok(mut queue) = self.retry_granted.lock() {
            queue.push_back(conn_num);
        }
    }
    
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
    
    pub fn push_retry_rejected(&self, conn_num: u32, reason: String) {
        if let Ok(mut queue) = self.retry_rejected.lock() {
            queue.push_back((conn_num, reason));
        }
    }
    
    pub fn pop_retry_rejected(&self, conn_num: u32) -> Option<String> {
        if let Ok(mut queue) = self.retry_rejected.lock() {
            if let Some(pos) = queue.iter().position(|(num, _)| *num == conn_num) {
                if let Some((_, reason)) = queue.remove(pos) {
                    return Some(reason);
                }
            }
        }
        None
    }
    
    pub fn push_error(&self, error: String) {
        if let Ok(mut queue) = self.errors.lock() {
            queue.push_back(error);
        }
    }
    
    /// Non-consuming error check
    pub fn has_error(&self) -> Option<String> {
        if let Ok(queue) = self.errors.lock() {
            queue.front().cloned()
        } else {
            None
        }
    }
    
    pub fn set_shutdown(&self) {
        if let Ok(mut flag) = self.shutdown.lock() {
            *flag = true;
        }
    }
    
    pub fn is_shutdown(&self) -> bool {
        if let Ok(flag) = self.shutdown.lock() {
            *flag
        } else {
            false
        }
    }
}