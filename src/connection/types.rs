//! Shared types for connection management

/// GO Signal mit Zeitstempel
#[derive(Clone, Debug)]
pub struct GoSignal {
    pub start_at: f64,
}