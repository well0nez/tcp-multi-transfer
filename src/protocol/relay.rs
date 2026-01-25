//! Relay Protocol Messages
//!
//! JSON-based protocol for communication with the relay server

use serde::{Deserialize, Serialize};

/// Client registration message to relay server
#[derive(Debug, Clone, Serialize)]
pub struct RegisterMessage {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub session_id: String,
    pub role: String,
    pub local_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prediction_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prediction_range_extra_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_connections: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_fallback: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_connections: Option<u32>,
    #[serde(default)]
    pub extra_ports: Vec<u16>,
}

impl RegisterMessage {
    pub fn new(
        session_id: &str,
        role: &str,
        local_port: u16,
        prediction_mode: Option<String>,
        prediction_range_extra_pct: Option<f64>,
        tcp_connections: Option<u32>,
        allow_fallback: Option<bool>,
        min_connections: Option<u32>,
        extra_ports: Vec<u16>,
    ) -> Self {
        Self {
            msg_type: "register".to_string(),
            session_id: session_id.to_string(),
            role: role.to_string(),
            local_port,
            private_ip: get_private_ip(),
            prediction_mode,
            prediction_range_extra_pct,
            tcp_connections,
            allow_fallback,
            min_connections,
            extra_ports,
        }
    }
}

fn get_private_ip() -> Option<String> {
    use std::net::UdpSocket;
    if let Ok(socket) = UdpSocket::bind("0.0.0.0:0") {
        if socket.connect("8.8.8.8:80").is_ok() {
            if let Ok(addr) = socket.local_addr() {
                return Some(addr.ip().to_string());
            }
        }
    }
    None
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename = "add_ports")]
pub struct AddPortsMessage {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub session_id: String,
    pub ports: Vec<u16>,
}

impl AddPortsMessage {
    pub fn new(session_id: &str, ports: Vec<u16>) -> Self {
        Self {
            msg_type: "add_ports".to_string(),
            session_id: session_id.to_string(),
            ports,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnEstablishedMessage {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub connection_num: u32,
}

impl ConnEstablishedMessage {
    pub fn new(connection_num: u32) -> Self {
        Self {
            msg_type: "conn_established".to_string(),
            connection_num,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnAbandonedMessage {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub connection_num: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl ConnAbandonedMessage {
    pub fn new(connection_num: u32, reason: Option<String>) -> Self {
        Self {
            msg_type: "conn_abandoned".to_string(),
            connection_num,
            reason,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ProbeMessage {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub session_id: String,
    pub local_port: u16,
    pub probe_num: u32,
}

impl ProbeMessage {
    pub fn new(session_id: &str, local_port: u16, probe_num: u32) -> Self {
        Self {
            msg_type: "probe".to_string(),
            session_id: session_id.to_string(),
            local_port,
            probe_num,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PeerAddressInfo {
    #[allow(dead_code)]
    pub ip: String,
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct NATAnalysis {
    // Essential fields for client hole punching
    #[serde(default)]
    #[allow(dead_code)]
    pub scan_start: u16,
    #[serde(default)]
    #[allow(dead_code)]
    pub scan_end: u16,
    #[serde(default)]
    #[allow(dead_code)]
    pub pattern_type: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub needs_scan: bool,

    // Ignore all other fields sent by server (predicted_port, error_range, delta_median, etc.)
    // This keeps the data available if we change our mind later
    #[serde(flatten)]
    #[allow(dead_code)]
    extra: std::collections::HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum RelayMessage {
    #[serde(rename = "registered")]
    Registered {
        your_public_addr: Vec<serde_json::Value>,
        // your_role: String, // Removed unused
        // session_id: String, // Removed unused
        #[serde(default)]
        server_time: Option<f64>,
        #[serde(default)]
        probe_port: Option<u16>,
        #[serde(default)]
        needs_probing: Option<bool>,
        #[serde(default)]
        server_times: Option<Vec<f64>>,
    },

    #[serde(rename = "peer_info")]
    PeerInfo {
        peer_public_addr: Vec<serde_json::Value>,
        peer_local_port: u16,
        peer_addresses: Vec<PeerAddressInfo>,
        // your_role: String, // Removed unused
        same_network: bool,
        #[serde(default)]
        peer_nat_analysis: Option<NATAnalysis>,
        #[serde(default)]
        tcp_connections: Option<u32>,
        #[serde(default)]
        allow_fallback: Option<bool>,
        #[serde(default)]
        min_connections: Option<u32>,
        #[serde(default)]
        peer_extra_ports: Vec<u16>,
        #[serde(default)]
        connection_num: Option<u32>,
        #[serde(default)]
        punch_strategy: Option<String>, // "listen" | "connect" | "scan"
    },

    #[serde(rename = "peer_added_ports")]
    PeerAddedPorts { ports: Vec<u16> },

    #[serde(rename = "ports_added_ack")]
    PortsAddedAck { ports: Vec<u16> },

    #[serde(rename = "go")]
    Go {
        start_at: f64,
        #[serde(default)]
        #[allow(dead_code)]
        message: String,
        #[serde(default)]
        connection_num: Option<u32>,
    },

    /// Retry Request: Client will Connection erneut versuchen
    #[serde(rename = "retry_request")]
    RetryRequest {
        #[allow(dead_code)]
        connection_num: u32,
    },

    /// Retry Granted: Server erlaubt Retry (beide Peers wollen)
    #[serde(rename = "retry_granted")]
    RetryGranted { connection_num: u32 },

    /// Retry Rejected: Server lehnt Retry ab (Peer fehlt oder Timeout)
    #[serde(rename = "retry_rejected")]
    RetryRejected { connection_num: u32, reason: String },

    #[serde(rename = "ping")]
    Ping {},

    #[serde(rename = "keepalive_ack")]
    KeepaliveAck {},

    #[serde(rename = "error")]
    Error { message: String },
}

impl RelayMessage {
    pub fn parse_addr(addr: &[serde_json::Value]) -> Option<(String, u16)> {
        if addr.len() != 2 {
            return None;
        }
        let ip = addr[0].as_str()?.to_string();
        let port_u64 = addr[1].as_u64()?;
        // BUG-010 FIX: Validate port range before truncation
        if port_u64 > 65535 {
            return None;
        }
        let port = port_u64 as u16;
        Some((ip, port))
    }
}
