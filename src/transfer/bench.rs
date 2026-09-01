//! Streckenmessung ueber die gepunchte Verbindung.
//!
//! Zweck: die Frage "Strecke oder Code?" beantworten, bevor am Transfercode
//! etwas geaendert wird. Der Transfer traegt Chunk-Protokoll, CRC32 je Chunk,
//! Quittungen, Plattenzugriff und SHA256 mit sich; keiner dieser Anteile ist
//! Teil der Strecke. Hier laeuft deshalb ausschliesslich der Kern: Bytes in den
//! Socket, Bytes aus dem Socket, sonst nichts.
//!
//! Gemessen wird auf der **Empfaengerseite** — nur dort ist bekannt, wann ein
//! Byte wirklich angekommen ist. Was der Sender in den Sendepuffer schreibt,
//! sagt ueber die Strecke nichts aus.
//!
//! Zusaetzlich wird eine Zeitreihe aufgezeichnet. Sie unterscheidet die beiden
//! Erklaerungen, die sich am Mittelwert nicht trennen lassen:
//!   * Slow Start — die Rate steigt ueber die ersten Sekunden an;
//!   * Policer/Verlust — die Rate ist von Anfang an gedeckelt oder bricht ein.
//!
//! Die Messung laeuft im selben Binary wie der Transfer und ueber dieselbe
//! gepunchte Verbindung, damit kein Unterschied in Build oder Pfad das Ergebnis
//! verfaelscht.

use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::info;

use super::helpers::configure_tcp_socket;

/// Rahmen: ein Typbyte, danach acht Byte Nutzlast (big endian).
const T_PARAMS: u8 = 0xB1;
const T_PING: u8 = 0xB2;
const T_PONG: u8 = 0xB3;
const T_GO: u8 = 0xB4;
const T_RESULT: u8 = 0xB5;

/// Blockgroesse fuer die Schreib-/Leseschleife. Gross genug, dass die
/// Syscall-Rate keine Rolle spielt, klein genug fuer eine feine Zeitreihe.
const IO_BLOCK: usize = 256 * 1024;

const CTRL_TIMEOUT: Duration = Duration::from_secs(30);

/// Vorlauf, der nicht in die Messung eingeht.
///
/// TCP faengt bei einem Ueberlastfenster von zehn Segmenten an und verdoppelt
/// je Umlauf. Bis die Strecke ausgelastet ist, vergehen bei 35 ms Umlaufzeit
/// und 30 Mbit/s rund vier Umlaeufe. Wer diese Anlaufphase mitmisst, misst
/// nicht die Strecke, sondern die Startdynamik — und benachteiligt systematisch
/// die Messung, die zuerst laeuft.
const AUFWAERM_BYTES: u64 = 2 * 1024 * 1024;

/// Ergebnis einer Streckenmessung.
#[derive(Debug, Clone)]
pub struct BenchResult {
    pub bytes: u64,
    /// Dauer vom ersten bis zum letzten empfangenen Byte.
    pub seconds: f64,
    pub mbit_s: f64,
    /// Zeit vom Absenden des Startsignals bis zum ersten empfangenen Byte.
    pub first_byte_ms: f64,
    /// Kleinste gemessene Umlaufzeit ueber die gepunchte Verbindung.
    pub rtt_min_ms: f64,
    pub rtt_med_ms: f64,
    pub rtt_max_ms: f64,
    /// Bytes je Abtastintervall, Empfaengerseite.
    pub samples: Vec<u64>,
    pub sample_ms: u64,
    pub streams: usize,
    /// Auskunft des Kernels ueber die erste Verbindung am Ende der Messung.
    pub tcp_info: Option<serde_json::Value>,
    pub puffer: Option<serde_json::Value>,
}

impl BenchResult {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "bytes": self.bytes,
            "seconds": self.seconds,
            "mbit_s": self.mbit_s,
            "first_byte_ms": self.first_byte_ms,
            "rtt_min_ms": self.rtt_min_ms,
            "rtt_med_ms": self.rtt_med_ms,
            "rtt_max_ms": self.rtt_max_ms,
            "sample_ms": self.sample_ms,
            "samples": self.samples,
            "streams": self.streams,
            "tcp_info": self.tcp_info,
            "puffer": self.puffer,
        })
    }
}

async fn write_frame(stream: &mut TcpStream, t: u8, v: u64) -> Result<()> {
    let mut buf = [0u8; 9];
    buf[0] = t;
    buf[1..].copy_from_slice(&v.to_be_bytes());
    tokio::time::timeout(CTRL_TIMEOUT, stream.write_all(&buf)).await??;
    tokio::time::timeout(CTRL_TIMEOUT, stream.flush()).await??;
    Ok(())
}

async fn read_frame(stream: &mut TcpStream) -> Result<(u8, u64)> {
    let mut buf = [0u8; 9];
    tokio::time::timeout(CTRL_TIMEOUT, stream.read_exact(&mut buf)).await??;
    let mut v = [0u8; 8];
    v.copy_from_slice(&buf[1..]);
    Ok((buf[0], u64::from_be_bytes(v)))
}

fn median(v: &mut Vec<f64>) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    v[v.len() / 2]
}

/// Umlaufzeit ueber die gepunchte Verbindung, gemessen mit 9-Byte-Rahmen.
///
/// Das ist die Groesse, aus der sich das Bandbreiten-Verzoegerungs-Produkt
/// berechnet — und damit die Frage, ob die Puffergroesse ueberhaupt binden
/// kann. Aus dem Log der Gegenstelle laesst sie sich nicht ableiten, weil dort
/// nur die Strecke zum Relay auftaucht.
async fn measure_rtt(stream: &mut TcpStream, probes: u32) -> Result<(f64, f64, f64)> {
    let mut werte = Vec::new();
    for i in 0..probes {
        let t0 = Instant::now();
        write_frame(stream, T_PING, i as u64).await?;
        let (t, _) = read_frame(stream).await?;
        if t != T_PONG {
            return Err(anyhow!("Expected PONG, got {:#x}", t));
        }
        werte.push(t0.elapsed().as_secs_f64() * 1000.0);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let min = werte.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = werte.iter().cloned().fold(0.0_f64, f64::max);
    let med = median(&mut werte.clone());
    Ok((min, med, max))
}

async fn answer_rtt(stream: &mut TcpStream, probes: u32) -> Result<()> {
    for _ in 0..probes {
        let (t, v) = read_frame(stream).await?;
        if t != T_PING {
            return Err(anyhow!("Expected PING, got {:#x}", t));
        }
        write_frame(stream, T_PONG, v).await?;
    }
    Ok(())
}

/// Senderseite: Umlaufzeit messen, dann `total_bytes` so schnell wie moeglich
/// hinausschreiben, danach das Ergebnis der Gegenstelle entgegennehmen.
/// Gibt die Verbindungen zurueck, damit im selben Lauf ein Dateitransfer
/// darueber folgen kann. Nur so liegen Streckenmessung und Transfer wenige
/// Sekunden auseinander *und* auf derselben Verbindung — bei einem Uplink, der
/// sich binnen einer Minute um den Faktor fuenf aendert, ist alles andere
/// nicht vergleichbar.
pub async fn run_bench_sender(
    mut streams: Vec<TcpStream>,
    total_bytes: u64,
    rtt_probes: u32,
    sample_ms: u64,
) -> Result<(BenchResult, Vec<TcpStream>)> {
    if streams.is_empty() {
        return Err(anyhow!("No connection for the measurement"));
    }
    for s in &streams {
        configure_tcp_socket(s)?;
    }
    let anzahl = streams.len() as u64;

    // Der Vorlauf wird mitgesendet, aber nicht mitgemessen.
    let brutto = total_bytes + AUFWAERM_BYTES;

    // Steuerung laeuft ueber die erste Verbindung.
    write_frame(&mut streams[0], T_PARAMS, brutto).await?;
    write_frame(&mut streams[0], T_PARAMS, sample_ms).await?;
    write_frame(&mut streams[0], T_PARAMS, rtt_probes as u64).await?;

    let (rtt_min, rtt_med, rtt_max) = measure_rtt(&mut streams[0], rtt_probes).await?;
    info!(
        "Round-trip over the punched connection: min {:.2} ms, median {:.2} ms, max {:.2} ms",
        rtt_min, rtt_med, rtt_max
    );

    // Startsignal: ab hier laeuft die Uhr auf beiden Seiten.
    write_frame(&mut streams[0], T_GO, 0).await?;
    let start = Instant::now();

    // Nutzlast ist bewusst konstant: es geht um die Strecke, nicht um
    // Kompressibilitaet. Auf dem Weg wird ohnehin nichts komprimiert.
    let block = Arc::new(vec![0x5Au8; IO_BLOCK]);

    let je_strom = brutto / anzahl;
    let rest = brutto % anzahl;

    let mut aufgaben = Vec::new();
    for (i, mut s) in streams.into_iter().enumerate() {
        let block = block.clone();
        let mut soll = je_strom + if (i as u64) < rest { 1 } else { 0 };
        aufgaben.push(tokio::spawn(async move {
            while soll > 0 {
                let n = std::cmp::min(soll as usize, IO_BLOCK);
                s.write_all(&block[..n]).await?;
                soll -= n as u64;
            }
            s.flush().await?;
            Ok::<TcpStream, anyhow::Error>(s)
        }));
    }

    let mut zurueck = Vec::new();
    for a in aufgaben {
        zurueck.push(a.await.map_err(|e| anyhow!("Send task aborted: {}", e))??);
    }
    let sende_dauer = start.elapsed().as_secs_f64();
    info!(
        "Sender done after {:.3}s ({:.2} Mbit/s written into the buffer)",
        sende_dauer,
        brutto as f64 * 8.0 / 1e6 / sende_dauer.max(1e-9)
    );

    // Ergebnis der Gegenstelle: Dauer in Mikrosekunden, danach die Zeitreihe.
    let mut steuer = zurueck.remove(0);
    let (t, dauer_us) = read_frame(&mut steuer).await?;
    if t != T_RESULT {
        return Err(anyhow!("Expected RESULT, got {:#x}", t));
    }
    let (_, first_byte_us) = read_frame(&mut steuer).await?;
    let (_, n_samples) = read_frame(&mut steuer).await?;
    let mut samples = Vec::with_capacity(n_samples as usize);
    for _ in 0..n_samples {
        let (_, v) = read_frame(&mut steuer).await?;
        samples.push(v);
    }

    let seconds = dauer_us as f64 / 1e6;
    let ergebnis = BenchResult {
        bytes: total_bytes,
        seconds,
        mbit_s: total_bytes as f64 * 8.0 / 1e6 / seconds.max(1e-9),
        first_byte_ms: first_byte_us as f64 / 1000.0,
        rtt_min_ms: rtt_min,
        rtt_med_ms: rtt_med,
        rtt_max_ms: rtt_max,
        samples,
        sample_ms,
        streams: anzahl as usize,
        tcp_info: crate::netinfo::tcp_info(&steuer),
        puffer: crate::netinfo::puffer(&steuer),
    };
    zurueck.insert(0, steuer);
    Ok((ergebnis, zurueck))
}

/// Empfaengerseite: Rahmen beantworten, dann bis zum Sollstand lesen und dabei
/// die Zeitreihe fuehren.
pub async fn run_bench_receiver(mut streams: Vec<TcpStream>) -> Result<(BenchResult, Vec<TcpStream>)> {
    if streams.is_empty() {
        return Err(anyhow!("No connection for the measurement"));
    }
    for s in &streams {
        configure_tcp_socket(s)?;
    }
    let anzahl = streams.len();

    let (_, brutto) = read_frame(&mut streams[0]).await?;
    let (_, sample_ms) = read_frame(&mut streams[0]).await?;
    let (_, rtt_probes) = read_frame(&mut streams[0]).await?;
    let total_bytes = brutto.saturating_sub(AUFWAERM_BYTES);
    info!("Path measurement: {} MB payload after {} MB warm-up over {} connection(s)",
          total_bytes / 1_048_576, AUFWAERM_BYTES / 1_048_576, anzahl);

    answer_rtt(&mut streams[0], rtt_probes as u32).await?;

    let (t, _) = read_frame(&mut streams[0]).await?;
    if t != T_GO {
        return Err(anyhow!("Expected GO, got {:#x}", t));
    }
    let go = Instant::now();

    let gelesen = Arc::new(AtomicU64::new(0));

    // Zeitreihe: ein Abtastwert je `sample_ms`, solange gelesen wird.
    //
    // Die Werte landen in einem geteilten Vektor und nicht im Rueckgabewert
    // der Aufgabe. Der Rueckgabewert waere naemlich unerreichbar: die Aufgabe
    // wird am Ende abgebrochen, und `await` auf eine abgebrochene Aufgabe
    // liefert immer einen Fehler — die Zeitreihe kam so nie an.
    let reihe_zaehler = gelesen.clone();
    let werte: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
    let werte_task = werte.clone();
    let reihe = tokio::spawn(async move {
        let mut letzter = 0u64;
        let mut tick = tokio::time::interval(Duration::from_millis(sample_ms.max(10)));
        tick.tick().await;
        loop {
            tick.tick().await;
            let jetzt = reihe_zaehler.load(Ordering::Relaxed);
            if let Ok(mut v) = werte_task.lock() {
                v.push(jetzt - letzter);
            }
            letzter = jetzt;
        }
    });

    let je_strom = brutto / anzahl as u64;
    let rest = brutto % anzahl as u64;

    let erstes_byte = Arc::new(AtomicU64::new(0));
    // Zeitpunkt, an dem der Vorlauf durch ist — ab da wird gemessen.
    let mess_start = Arc::new(AtomicU64::new(0));
    let mut aufgaben = Vec::new();
    for (i, mut s) in streams.into_iter().enumerate() {
        let gelesen = gelesen.clone();
        let erstes_byte = erstes_byte.clone();
        let mess_start = mess_start.clone();
        let mut soll = je_strom + if (i as u64) < rest { 1 } else { 0 };
        aufgaben.push(tokio::spawn(async move {
            let mut buf = vec![0u8; IO_BLOCK];
            while soll > 0 {
                let n = std::cmp::min(soll as usize, IO_BLOCK);
                let gelesen_jetzt = s.read(&mut buf[..n]).await?;
                if gelesen_jetzt == 0 {
                    return Err(anyhow!("Connection closed prematurely"));
                }
                erstes_byte
                    .compare_exchange(
                        0,
                        go.elapsed().as_micros() as u64,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    )
                    .ok();
                let bisher = gelesen.fetch_add(gelesen_jetzt as u64, Ordering::Relaxed)
                    + gelesen_jetzt as u64;
                if bisher >= AUFWAERM_BYTES {
                    mess_start
                        .compare_exchange(
                            0,
                            go.elapsed().as_micros() as u64,
                            Ordering::Relaxed,
                            Ordering::Relaxed,
                        )
                        .ok();
                }
                soll -= gelesen_jetzt as u64;
            }
            Ok::<TcpStream, anyhow::Error>(s)
        }));
    }

    let mut zurueck = Vec::new();
    for a in aufgaben {
        zurueck.push(a.await.map_err(|e| anyhow!("Read task aborted: {}", e))??);
    }
    let ende = go.elapsed();
    reihe.abort();
    let samples = werte.lock().map(|v| v.clone()).unwrap_or_default();

    let first_byte_us = erstes_byte.load(Ordering::Relaxed);
    // Gemessen wird vom Ende des Vorlaufs bis zum letzten Byte: die Wartezeit
    // auf das erste Byte ist Latenz, der Vorlauf ist Startdynamik.
    let ab_us = mess_start.load(Ordering::Relaxed).max(first_byte_us);
    let dauer_us = (ende.as_micros() as u64).saturating_sub(ab_us);

    let mut steuer = zurueck.remove(0);
    write_frame(&mut steuer, T_RESULT, dauer_us).await?;
    write_frame(&mut steuer, T_RESULT, first_byte_us).await?;
    write_frame(&mut steuer, T_RESULT, samples.len() as u64).await?;
    for v in &samples {
        write_frame(&mut steuer, T_RESULT, *v).await?;
    }

    let seconds = dauer_us as f64 / 1e6;
    let ergebnis = BenchResult {
        bytes: total_bytes,
        seconds,
        mbit_s: total_bytes as f64 * 8.0 / 1e6 / seconds.max(1e-9),
        first_byte_ms: first_byte_us as f64 / 1000.0,
        rtt_min_ms: 0.0,
        rtt_med_ms: 0.0,
        rtt_max_ms: 0.0,
        samples,
        sample_ms,
        streams: anzahl,
        tcp_info: crate::netinfo::tcp_info(&steuer),
        puffer: crate::netinfo::puffer(&steuer),
    };
    zurueck.insert(0, steuer);
    Ok((ergebnis, zurueck))
}
