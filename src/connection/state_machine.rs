//! Connection state machine with validated transitions

use anyhow::{Result, anyhow};
use tracing::debug;

use crate::punch::PeerInfo;
use super::types::GoSignal;

#[derive(Debug, Clone)]
pub enum ConnectionState {
    WaitingForPeerInfo { conn_num: u32 },
    
    WaitingForGO { 
        conn_num: u32, 
        peer_info: PeerInfo,
    },
    
    Punching { 
        conn_num: u32, 
        peer_info: PeerInfo,
        start_at: f64,
    },
    
    Established { conn_num: u32 },
    
    Failed { 
        conn_num: u32, 
        reason: String,
    },
    
    WaitingForRetry { 
        conn_num: u32,
    },
}

pub type StateTransition = Result<ConnectionState>;

pub fn handle_peer_info_transition(
    state: ConnectionState,
    peer_info: PeerInfo,
) -> StateTransition {
    match state {
        ConnectionState::WaitingForPeerInfo { conn_num } => {
            debug!("State transition: WaitingForPeerInfo -> WaitingForGO (conn {})", conn_num);
            Ok(ConnectionState::WaitingForGO {
                conn_num,
                peer_info,
            })
        }
        _ => {
            Err(anyhow!("Invalid state transition: cannot handle PeerInfo in state {:?}", state))
        }
    }
}

pub fn handle_go_transition(
    state: ConnectionState,
    go_signal: GoSignal,
) -> StateTransition {
    match state {
        ConnectionState::WaitingForGO { conn_num, peer_info } => {
            debug!("State transition: WaitingForGO -> Punching (conn {})", conn_num);
            Ok(ConnectionState::Punching {
                conn_num,
                peer_info,
                start_at: go_signal.start_at,
            })
        }
        _ => {
            Err(anyhow!("Invalid state transition: cannot handle GO in state {:?}", state))
        }
    }
}

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

pub fn handle_connection_failure(
    state: ConnectionState,
    reason: String,
) -> StateTransition {
    match state {
        ConnectionState::Punching { conn_num, .. } => {
            debug!("State transition: Punching -> Failed (conn {})", conn_num);
            Ok(ConnectionState::Failed {
                conn_num,
                reason,
            })
        }
        ConnectionState::WaitingForPeerInfo { conn_num } => {
            debug!("State transition: WaitingForPeerInfo -> Failed (conn {})", conn_num);
            Ok(ConnectionState::Failed {
                conn_num,
                reason,
            })
        }
        ConnectionState::WaitingForGO { conn_num, .. } => {
            debug!("State transition: WaitingForGO -> Failed (conn {})", conn_num);
            Ok(ConnectionState::Failed {
                conn_num,
                reason,
            })
        }
        _ => {
            Err(anyhow!("Invalid state transition: cannot handle failure in state {:?}", state))
        }
    }
}

pub fn handle_retry_request(
    state: ConnectionState,
) -> StateTransition {
    match state {
        ConnectionState::Failed { conn_num, .. } => {
            debug!("State transition: Failed -> WaitingForRetry (conn {})", conn_num);
            Ok(ConnectionState::WaitingForRetry { conn_num })
        }
        _ => {
            Err(anyhow!("Invalid state transition: cannot request retry in state {:?}", state))
        }
    }
}

pub fn handle_retry_granted(
    state: ConnectionState,
) -> StateTransition {
    match state {
        ConnectionState::WaitingForRetry { conn_num } => {
            debug!("State transition: WaitingForRetry -> WaitingForPeerInfo (conn {})", conn_num);
            Ok(ConnectionState::WaitingForPeerInfo { conn_num })
        }
        _ => {
            Err(anyhow!("Invalid state transition: cannot grant retry in state {:?}", state))
        }
    }
}
