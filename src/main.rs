//! TCP File Transfer Client with NAT Traversal
//!
//! This client uses TCP hole punching to establish direct peer-to-peer
//! connections through NAT, then transfers files using TCP streams.

use std::time::Duration;
use clap::Parser;
use tokio::io::BufReader;
use anyhow::{Result, anyhow};
use tracing::{info, error, Level};
use tracing_subscriber::{FmtSubscriber, fmt::time::FormatTime};

mod cli;
mod protocol;
mod punch;
mod transfer;
mod relay;
mod connection;
mod metrics;
mod netinfo;

use punch::PunchOptions;
use metrics::MetricsSink;
use clap::CommandFactory;
use cli::{Args, Mode, PredictionMode, parse_chunk_size, APP_VERSION};
use relay::{run_relay_protocol, get_free_port, create_bound_socket};
use connection::establish_multi_connections;
use transfer::{
    calculate_sha256,
    set_chunk_size,
    run_multi_sender,
    run_multi_receiver,
    run_bench_sender,
    run_bench_receiver,
};

/// Wieviel roh uebertragen werden soll, statt eine Datei zu schicken.
/// `None` = normaler Transfer.
#[derive(Debug, Clone, Copy)]
struct BenchOpts {
    megabytes: u64,
    rtt_probes: u32,
    sample_ms: u64,
    /// Nach der Streckenmessung denselben Umfang als Datei uebertragen.
    mit_transfer: bool,
}

struct LocalTime;

impl FormatTime for LocalTime {
    fn format_time(&self, w: &mut tracing_subscriber::fmt::format::Writer<'_>) -> std::fmt::Result {
        let now = chrono::Local::now();
        let centis = now.timestamp_subsec_millis() / 10;
        write!(w, "{}.{:02}", now.format("%Y-%m-%d %H:%M:%S"), centis)
    }
}

/// Eine Seite der Sitzung — Sender wie Empfaenger.
///
/// Beide Rollen taten bis auf zwei Stellen dasselbe: Ports binden, beim Relay
/// anmelden, Verbindungen punchen, Mindestzahl pruefen, uebertragen. Als zwei
/// Funktionen gepflegt, drifteten sie auseinander; jede Korrektur musste
/// zweimal gemacht werden.
async fn run_peer(
    role: &str,
    server_addr: &str,
    session_id: &str,
    file_path: &str,
    timeout: Duration,
    probe_count: u32,
    prediction_mode: PredictionMode,
    prediction_range_extra_pct: f64,
    tcp_connections: u32,
    allow_fallback: bool,
    min_connections: u32,
    punch_opts: PunchOptions,
    probe_from_bound: bool,
    auto_parallel: bool,
    max_attempts: u32,
    metrics: &MetricsSink,
    bench: Option<BenchOpts>,
) -> Result<()> {
    let sendend = role == "sender";
    let braucht_datei = sendend && bench.map(|b| b.mit_transfer).unwrap_or(true);

    let (sha256, file_size) = if braucht_datei {
        info!("Calculating SHA256...");
        let (h, size) = calculate_sha256(file_path).await?;
        info!("SHA256: {}", transfer::sha256_to_hex(&h));
        info!("File size: {:.2} MB", size as f64 / 1048576.0);
        (h, size)
    } else {
        ([0u8; 32], 0u64)
    };

    let local_port_base = get_free_port()?;
    info!("Using local port base: {}", local_port_base);

    // Je gewuenschter Verbindung ein Punch-Port. Belegte Ports werden
    // uebersprungen, deshalb die Obergrenze an Versuchen.
    let punch_tasks = tcp_connections.max(1) as usize;
    let mut bound_sockets = Vec::new();
    let mut extra_ports = Vec::new();
    let mut current_port = local_port_base;
    let mut attempt_counter = 0;
    while bound_sockets.len() < punch_tasks && attempt_counter < 100 {
        if let Ok(s) = create_bound_socket(current_port) {
            bound_sockets.push(s);
            extra_ports.push(current_port);
        }
        current_port = current_port.wrapping_add(1);
        attempt_counter += 1;
    }
    let local_port = *extra_ports.first().unwrap_or(&local_port_base);

    let (relay_stream, mut session) = run_relay_protocol(
        server_addr, session_id, role, local_port, timeout, probe_count,
        prediction_mode, prediction_range_extra_pct, tcp_connections,
        allow_fallback, min_connections, extra_ports, bound_sockets, probe_from_bound,
        punch_opts.parallel_ports as u32,
    ).await?;

    let (relay_reader, relay_writer) = relay_stream.into_split();
    let relay_reader = BufReader::new(relay_reader);

    let tcp_conns = session.tcp_connections;
    let srv_addr = session.server_addr;
    let probe_p = session.probe_port;
    let streams = establish_multi_connections(
        relay_reader, relay_writer, &mut session, tcp_conns, role, timeout,
        session_id, srv_addr, probe_p, &punch_opts, probe_from_bound,
        auto_parallel, max_attempts, metrics,
    ).await?;

    let min_required = if session.allow_fallback {
        session.min_connections.max(1) as usize
    } else {
        session.tcp_connections as usize
    };
    if streams.len() < min_required {
        return Err(anyhow!(
            "Only established {} of {} required connections",
            streams.len(), min_required
        ));
    }

    for s in &streams {
        info!("Direct P2P: Local {} Remote {}", s.local_addr()?, s.peer_addr()?);
    }

    let mut streams = streams;
    if let Some(b) = bench {
        let (ergebnis, zurueck) = if sendend {
            let (e, z) = run_bench_sender(
                streams, b.megabytes * 1_048_576, b.rtt_probes, b.sample_ms,
            ).await?;
            info!("Path: {:.2} Mbit/s over {} connection(s), median RTT {:.2} ms",
                  e.mbit_s, e.streams, e.rtt_med_ms);
            (e, z)
        } else {
            let (e, z) = run_bench_receiver(streams).await?;
            info!("Path: {:.2} Mbit/s over {} connection(s), first byte after {:.1} ms",
                  e.mbit_s, e.streams, e.first_byte_ms);
            (e, z)
        };
        metrics.write_record(session_id, role, "bench", ergebnis.to_json());
        if !b.mit_transfer {
            return Ok(());
        }
        // Derselbe Socket, wenige Sekunden spaeter: der einzige Vergleich, bei
        // dem sich die Strecke zwischen den beiden Messungen nicht aendern kann.
        info!("Path measurement done, now the same amount as a file transfer");
        streams = zurueck;
    }

    let report = if sendend {
        run_multi_sender(streams, file_path, file_size, sha256).await?
    } else {
        run_multi_receiver(streams).await?
    };
    metrics.write_record(session_id, role, "transfer", report.to_json());
    Ok(())
}

async fn run_probe_debug(server_addr: &str, session_id: &str, count: u32) -> Result<()> {
    let probe_addr = relay::resolve_socket_addr(server_addr)?;
    println!("PROBE DEBUG MODE: {} -> {}", server_addr, probe_addr);
    let _ = session_id;
    let _ = count;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Die dritte Hilfestufe. `-h` und `--help` zeigen die Schalter fuer den
    // Alltag; alles zum Feinjustieren und Messen kommt erst hier — sonst
    // erschlaegt die Liste den Zweck. Die Abfrage laeuft vor `parse()`, weil
    // sonst die Pflichtangaben (-s, -i, -m) eingefordert wuerden.
    if std::env::args().skip(1).any(|a| a == "-X" || a == "--help-all") {
        let mut cmd = Args::command().mut_args(|a| a.hide(false));
        cmd.print_help()?;
        println!();
        return Ok(());
    }

    let args = Args::parse();
    let level = if args.debug { Level::DEBUG } else { Level::INFO };
    let _subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(false)
        .with_file(false)
        .with_line_number(false)
        .with_timer(LocalTime)
        .init();

    if args.probe_debug {
        return run_probe_debug(&args.server, &args.session_id, args.probe_count).await;
    }

    let chunk_size = parse_chunk_size(&args.chunk)?;
    set_chunk_size(chunk_size);
    
    info!("tcp-multi-transfer v{} (ICE)", APP_VERSION);
    info!("===================================");
    info!("TCP connections: {}", args.tcp_connections);
    
    let timeout = Duration::from_secs(args.timeout);
    let sink = MetricsSink::new(args.metrics_file.clone(), args.metrics_label.clone());
    if sink.enabled() {
        info!("Writing metrics to {}", args.metrics_file.as_deref().unwrap_or("-"));
    }
    
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        error!("Ctrl+C received, exiting...");
        std::process::exit(1);
    });

    let bench = args.bench.map(|mb| BenchOpts {
        megabytes: mb,
        rtt_probes: args.bench_rtt,
        sample_ms: args.bench_sample_ms,
        mit_transfer: args.bench_then_transfer,
    });
    if bench.is_some() {
        info!("Path measurement instead of file transfer");
    }

    let (role, file_path) = match args.mode {
        Mode::Send => {
            let leer = String::new();
            let datei_noetig = bench.map(|b| b.mit_transfer).unwrap_or(true);
            let f = match (&args.file, datei_noetig) {
                (Some(f), _) => f.clone(),
                (None, false) => leer,
                (None, true) => return Err(anyhow!("--file required")),
            };
            if datei_noetig && !std::path::Path::new(&f).exists() {
                return Err(anyhow!("File not found: {}", f));
            }
            info!("Mode: SEND, File: {}, Session: {}", f, args.session_id);
            ("sender", f)
        }
        Mode::Receive => {
            info!("Mode: RECEIVE, Session: {}", args.session_id);
            ("receiver", String::new())
        }
    };

    run_peer(
        role, &args.server, &args.session_id, &file_path, timeout, args.probe_count,
        args.prediction_mode, args.prediction_range_extra_pct, args.tcp_connections as u32,
        args.allow_fallback, args.min_connections, args.punch_options(),
        args.probe_from_bound_ports(), args.auto_parallel, args.max_attempts, &sink, bench,
    ).await
}
