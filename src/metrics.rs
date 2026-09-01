//! Ergebnisprotokoll fuer den A/B-Vergleich.
//!
//! Alte und neue Variante laufen im selben Binary und unterscheiden sich nur
//! durch Schalter. Damit ein Vergleich aussagekraeftig ist, muss jede Variante
//! dasselbe maschinenlesbare Protokoll schreiben — eine JSON-Zeile je
//! Punch-Versuch, anhaengend, damit mehrere Laeufe in dieselbe Datei koennen.

use std::io::Write;
use std::sync::Mutex;
use serde_json::json;
use tracing::warn;

/// Was bei einem Punch-Versuch herausgekommen ist.
#[derive(Debug, Clone, Default)]
pub struct PunchReport {
    pub conn_num: u32,
    pub outcome: &'static str,
    /// Millisekunden vom synchronisierten Start bis zum Ergebnis.
    pub elapsed_ms: f64,
    pub candidates_total: usize,
    pub candidates_lan: usize,
    /// Wieviele Kandidaten insgesamt zustande kamen (auch die verworfenen).
    pub candidates_seen: usize,
    /// Millisekunden bis zum ersten Kandidaten — davon zieht das Grace-Fenster ab.
    pub first_candidate_ms: f64,
    /// Hat das Grace-Fenster die Wahl tatsaechlich geaendert?
    pub grace_switch: bool,
    /// Tatsaechlich gewartetes Fenster in Millisekunden.
    pub grace_ms: u64,
    /// Lokale Port-Faecher je Ziel (Ziehungen).
    pub ports_per_target: usize,
    /// Wurden Ziele reihum bedient, weil das Budget nicht fuer alle reichte?
    pub rotating: bool,
    /// Aus welchem Fach der Gewinner kam. `None` = ueber den Listener.
    pub winner_slot: Option<usize>,
    pub winner_local_port: u16,
    pub winner_remote_port: u16,
    pub winner_is_lan: bool,
    /// Vergibt die eigene NAT pro 5-Tupel (true) oder pro Verbindung (false)?
    pub mapping_stable: Option<bool>,
    pub error: Option<String>,
}

/// Schreibziel. Ohne Pfad ist alles wirkungslos.
pub struct MetricsSink {
    path: Option<String>,
    label: Option<String>,
    lock: Mutex<()>,
}

impl MetricsSink {
    pub fn new(path: Option<String>, label: Option<String>) -> Self {
        Self { path, label, lock: Mutex::new(()) }
    }

    pub fn enabled(&self) -> bool {
        self.path.is_some()
    }

    /// Haengt eine Zeile an. Fehler werden geloggt, aber nie weitergereicht —
    /// eine kaputte Messung darf keinen Transfer abbrechen.
    pub fn write(&self, session_id: &str, role: &str, opts: &crate::punch::PunchOptions,
                 probe_from_bound: bool, report: &PunchReport) {
        if self.path.is_none() { return; }

        let line = json!({
            "ts": crate::punch::current_timestamp(),
            "record": "punch",
            "label": self.label,
            "session_id": session_id,
            "role": role,
            "conn_num": report.conn_num,
            "outcome": report.outcome,
            "elapsed_ms": report.elapsed_ms,
            "candidates_total": report.candidates_total,
            "candidates_lan": report.candidates_lan,
            "candidates_seen": report.candidates_seen,
            "first_candidate_ms": report.first_candidate_ms,
            "grace_switch": report.grace_switch,
            "grace_ms_effektiv": report.grace_ms,
            "ports_per_target": report.ports_per_target,
            "rotating": report.rotating,
            "winner_slot": report.winner_slot,
            "winner_local_port": report.winner_local_port,
            "winner_remote_port": report.winner_remote_port,
            "winner_is_lan": report.winner_is_lan,
            "mapping_stable": report.mapping_stable,
            "error": report.error,
            "opts": {
                "prefer_lan": opts.prefer_lan,
                "parallel_ports": opts.parallel_ports,
                "max_candidates": opts.max_candidates,
                "socket_budget": opts.socket_budget,
                "grace_ms": opts.grace.as_millis() as u64,
                "rotate_after_ms": opts.rotate_after.map(|d| d.as_millis() as u64),
                "retry_pause_ms": opts.retry_pause.as_millis() as u64,
                "probe_from_bound": probe_from_bound,
            },
        });

        self.append(line);
    }

    /// Zeile fuer alles, was kein Punch-Versuch ist (Streckenmessung,
    /// Phasenzeiten eines Transfers). Gemeinsame Felder werden ergaenzt, damit
    /// sich alle Zeilen derselben Reihe gleich auswerten lassen.
    pub fn write_record(&self, session_id: &str, role: &str, art: &str, mut daten: serde_json::Value) {
        if self.path.is_none() {
            return;
        }
        if let Some(obj) = daten.as_object_mut() {
            obj.insert("ts".into(), json!(crate::punch::current_timestamp()));
            obj.insert("label".into(), json!(self.label));
            obj.insert("session_id".into(), json!(session_id));
            obj.insert("role".into(), json!(role));
            obj.insert("record".into(), json!(art));
        }
        self.append(daten);
    }

    fn append(&self, line: serde_json::Value) {
        let Some(path) = self.path.as_deref() else { return };
        // Erst die vollstaendige Zeile bauen, dann *ein* write(). Zwei
        // Schreibaufrufe (Wert, dann Zeilenende) verschraenken sich, sobald
        // zwei Prozesse dieselbe Datei anhaengen — die Datei ist dann kein
        // gueltiges JSONL mehr.
        let mut zeile = line.to_string();
        zeile.push('\n');
        let _guard = self.lock.lock();
        let result = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .and_then(|mut f| f.write_all(zeile.as_bytes()));

        if let Err(e) = result {
            warn!("Could not write metrics line ({}): {}", path, e);
        }
    }
}
