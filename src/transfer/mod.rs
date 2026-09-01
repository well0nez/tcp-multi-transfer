//! Dateiuebertragung ueber die gepunchten Verbindungen.
//!
//! Es gibt **einen** Weg, auch bei nur einer Verbindung: Bloecke mit Kopf,
//! CRC32 und Quittung. Frueher lag daneben ein roher Bytestrom fuer den
//! Einzelfall, und welcher benutzt wurde, entschied jede Seite anhand ihres
//! *eigenen* `--tcp-connections`. Fiel eine Seite per `--allow-fallback` auf
//! eine Verbindung zurueck, redeten beide verschiedene Protokolle und der
//! Transfer starb im Handschlag. Gemessen kostet das Blockprotokoll nichts
//! (101,6 % des rohen Durchsatzes), also gibt es keinen Grund fuer zwei Wege.
//!
//! Optimizations:
//! - CHUNK_SIZE: 8MB (configurable via --chunk) - fewer syscalls
//! - BUFFER_SIZE: 16MB for efficient I/O
//! - TCP Socket buffers: 64MB send/recv (OS may cap lower)
//! - Pipeline Depth: 16 chunks (~128MB in flight)
//! - Periodic progress updates (200ms) with atomic byte counters
//! - SHA256 only at the end (from disk)
//! - CRC32 per chunk during transfer with ACK/NACK
//! - Pipelined I/O - Disk reads and network writes run in parallel!

mod helpers;
mod sender;
mod receiver;
mod bench;

// Re-export public API
pub use helpers::{calculate_sha256, sha256_to_hex};
pub use sender::run_multi_sender;
pub use receiver::run_multi_receiver;
pub use bench::{run_bench_sender, run_bench_receiver};

/// Was ein Transfer gekostet hat, nach Phasen getrennt.
///
/// Die bisher ausgegebene Rate teilt die Dateigroesse durch die Gesamtdauer —
/// darin stecken Handschlag, das Nachrechnen der SHA256 auf der Empfaengerseite
/// und das Wegschreiben auf die Platte. Fuer die Frage, wieviel von der Strecke
/// ankommt, zaehlt nur die Nutzlastphase. Beide Zahlen nebeneinander zeigen,
/// wieviel des Verlusts blosse Buchhaltung ist.
#[derive(Debug, Clone, Default)]
pub struct TransferReport {
    pub bytes: u64,
    pub streams: usize,
    /// Handschlag inklusive Dateiinformation.
    pub setup_ms: f64,
    /// Erstes bis letztes Nutzlastbyte.
    pub payload_ms: f64,
    /// Abschluss: DONE, Pruefsumme, Quittung.
    pub finish_ms: f64,
    pub total_ms: f64,
    /// Auskunft des Kernels ueber die Verbindung am Ende des Transfers.
    pub tcp_info: Option<serde_json::Value>,
}

impl TransferReport {
    pub fn to_json(&self) -> serde_json::Value {
        let rate = |ms: f64| {
            if ms <= 0.0 { 0.0 } else { self.bytes as f64 * 8.0 / 1e6 / (ms / 1000.0) }
        };
        serde_json::json!({
            "bytes": self.bytes,
            "streams": self.streams,
            "setup_ms": self.setup_ms,
            "payload_ms": self.payload_ms,
            "finish_ms": self.finish_ms,
            "total_ms": self.total_ms,
            "mbit_payload": rate(self.payload_ms),
            "mbit_gesamt": rate(self.total_ms),
            "tcp_info": self.tcp_info,
        })
    }
}

/// Zeitgrenze fuer einzelne Lese-/Schreibvorgaenge waehrend der Uebertragung.
/// Gross genug, dass ein stockender Mobilfunk-Uplink sie nicht ausloest.
pub(crate) const IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Zeitgrenze fuer die kurzen Protokollnachrichten (Handschlag, Quittungen).
pub(crate) const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// Default chunk size for reading/writing (8MB) - fewer syscalls
pub const DEFAULT_CHUNK_SIZE: usize = 8 * 1024 * 1024;

/// Global chunk size (set from main.rs)
static mut CHUNK_SIZE: usize = DEFAULT_CHUNK_SIZE;

/// Set the chunk size (called from main.rs)
pub fn set_chunk_size(size: usize) {
    unsafe {
        CHUNK_SIZE = size;
    }
}

/// Get the current chunk size
pub(crate) fn get_chunk_size() -> usize {
    unsafe { CHUNK_SIZE }
}

/// Kleinste sinnvolle Blockgroesse. Darunter ueberwiegt der Protokollaufwand
/// (Kopf, Pruefsumme, Quittung je Block).
const MIN_CHUNK: usize = 256 * 1024;

/// Blockgroesse fuer den Mehrstromtransfer.
///
/// Die Bloecke werden unter den Stroemen aufgeteilt. Ist die Datei kleiner als
/// `Bloecke × Stroeme`, bekommen nicht alle Stroeme etwas ab — bei der Vorgabe
/// von 8 MB und einer 1-MB-Datei entsteht genau *ein* Block, den ein einziger
/// Strom uebertraegt, waehrend die uebrigen leerlaufen. Angestrebt werden
/// deshalb mindestens zwei Bloecke je Strom.
///
/// Aufgerufen wird das **nur vom Sender**. Er teilt das Ergebnis in
/// STREAM_INFO mit; der Empfaenger rechnet nicht nach. Beidseitiges Rechnen
/// stimmte naemlich nur, solange beide Seiten dasselbe `--chunk` gesetzt
/// hatten — sonst zerfiel die Datei in verschieden viele Bloecke.
pub(crate) fn chunk_size_fuer(file_size: u64, streams: usize) -> usize {
    let konfiguriert = get_chunk_size();
    let streams = streams.max(1) as u64;
    let ziel = (file_size / (streams * 2)).max(1) as usize;
    ziel.clamp(MIN_CHUNK.min(konfiguriert), konfiguriert)
}
