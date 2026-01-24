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

use cli::{Args, Mode, PredictionMode, parse_chunk_size, APP_VERSION};
use relay::{run_relay_protocol, get_free_port, create_bound_socket};
use connection::establish_multi_connections;
use transfer::{
    TcpSender,
    TcpReceiver,
    calculate_sha256,
    set_chunk_size,
    run_multi_sender,
    run_multi_receiver,
};

struct LocalTime;

impl FormatTime for LocalTime {
    fn format_time(&self, w: &mut dyn std::fmt::Write) -> std::fmt::Result {
        let now = chrono::Local::now();
        write!(w, "{}", now.format("%Y-%m-%d %H:%M:%S%.2f"))
    }
}

async fn run_sender(
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
) -> Result<()> {
    info!("Calculating SHA256...");
    let (sha256, file_size) = calculate_sha256(file_path).await?;
    info!("SHA256: {}", transfer::sha256_to_hex(&sha256));
    info!("File size: {:.2} MB", file_size as f64 / 1048576.0);

    let local_port_base = get_free_port()?;
    info!("Using local port base: {}", local_port_base);

    let punch_tasks = tcp_connections.max(1) as usize;
    let mut bound_sockets = Vec::new();
    let mut extra_ports = Vec::new();
    let mut current_port = local_port_base;
    let mut added_count = 0;
    let mut attempt_counter = 0;

    while added_count < punch_tasks && attempt_counter < 100 {
        match create_bound_socket(current_port) {
            Ok(s) => {
                bound_sockets.push(s);
                extra_ports.push(current_port);
                added_count += 1;
            }
            Err(_) => {}
        }
        current_port = current_port.wrapping_add(1);
        attempt_counter += 1;
    }
    let local_port = *extra_ports.first().unwrap_or(&local_port_base);

    let (relay_stream, mut session) = run_relay_protocol(
        server_addr, session_id, "sender", local_port, timeout, probe_count,
        prediction_mode, prediction_range_extra_pct, tcp_connections,
        allow_fallback, min_connections, extra_ports, bound_sockets
    ).await?;

    let (relay_reader, relay_writer) = relay_stream.into_split();
    let relay_reader = BufReader::new(relay_reader);

    let tcp_conns = session.tcp_connections;
    let srv_addr = session.server_addr;
    let probe_p = session.probe_port;
    let streams = establish_multi_connections(
        relay_reader,
        relay_writer,
        &mut session,
        tcp_conns,
        "sender",
        timeout,
        session_id,
        srv_addr,
        probe_p,
    ).await?;

    let min_required = if session.allow_fallback { 
        session.min_connections.max(1) as usize 
    } else { 
        session.tcp_connections as usize 
    };
    
    if streams.len() < min_required { 
        return Err(anyhow!(
            "Only established {} of {} required connections", 
            streams.len(), 
            min_required
        )); 
    }

    for s in &streams { info!("Direct P2P: Local {} Remote {}", s.local_addr()?, s.peer_addr()?); }

    if session.tcp_connections > 1 || streams.len() > 1 {
        run_multi_sender(streams, file_path, file_size, sha256).await
    } else {
        let stream = streams.into_iter().next().unwrap();
        let mut sender = TcpSender::new_with_hash(stream, file_path, file_size, sha256);
        sender.run().await
    }
}

async fn run_receiver(
    server_addr: &str,
    session_id: &str,
    timeout: Duration,
    probe_count: u32,
    prediction_mode: PredictionMode,
    prediction_range_extra_pct: f64,
    tcp_connections: u32,
    allow_fallback: bool,
    min_connections: u32,
) -> Result<()> {
    let local_port_base = get_free_port()?;
    info!("Using local port base: {}", local_port_base);

    let punch_tasks = tcp_connections.max(1) as usize;
    let mut bound_sockets = Vec::new();
    let mut extra_ports = Vec::new();
    let mut current_port = local_port_base;
    let mut added_count = 0;
    let mut attempt_counter = 0;

    while added_count < punch_tasks && attempt_counter < 100 {
        match create_bound_socket(current_port) {
            Ok(s) => {
                bound_sockets.push(s);
                extra_ports.push(current_port);
                added_count += 1;
            }
            Err(_) => {}
        }
        current_port = current_port.wrapping_add(1);
        attempt_counter += 1;
    }
    let local_port = *extra_ports.first().unwrap_or(&local_port_base);

    let (relay_stream, mut session) = run_relay_protocol(
        server_addr, session_id, "receiver", local_port, timeout, probe_count,
        prediction_mode, prediction_range_extra_pct, tcp_connections,
        allow_fallback, min_connections, extra_ports, bound_sockets
    ).await?;

    let (relay_reader, relay_writer) = relay_stream.into_split();
    let relay_reader = BufReader::new(relay_reader);

    let tcp_conns = session.tcp_connections;
    let srv_addr = session.server_addr;
    let probe_p = session.probe_port;
    let streams = establish_multi_connections(
        relay_reader,
        relay_writer,
        &mut session,
        tcp_conns,
        "receiver",
        timeout,
        session_id,
        srv_addr,
        probe_p,
    ).await?;

    let min_required = if session.allow_fallback { 
        session.min_connections.max(1) as usize 
    } else { 
        session.tcp_connections as usize 
    };
    
    if streams.len() < min_required { 
        return Err(anyhow!(
            "Only established {} of {} required connections", 
            streams.len(), 
            min_required
        )); 
    }

    for s in &streams { info!("Direct P2P: Local {} Remote {}", s.local_addr()?, s.peer_addr()?); }

    if session.tcp_connections > 1 || streams.len() > 1 {
        run_multi_receiver(streams).await
    } else {
        let stream = streams.into_iter().next().unwrap();
        let mut receiver = TcpReceiver::new(stream);
        receiver.run().await
    }
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
    
    info!("TCP File Transfer Client v{} (ICE)", APP_VERSION);
    info!("===================================");
    info!("TCP connections: {}", args.tcp_connections);
    
    let timeout = Duration::from_secs(args.timeout);
    
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        error!("Ctrl+C received, exiting...");
        std::process::exit(1);
    });

    match args.mode {
        Mode::Send => {
            let file_path = args.file.as_ref().ok_or_else(|| anyhow!("--file required"))?;
            if !std::path::Path::new(file_path).exists() { return Err(anyhow!("File not found: {}", file_path)); }
            info!("Mode: SEND, File: {}, Session: {}", file_path, args.session_id);
            run_sender(
                &args.server, &args.session_id, file_path, timeout, args.probe_count,
                args.prediction_mode, args.prediction_range_extra_pct, args.tcp_connections as u32,
                args.allow_fallback, args.min_connections
            ).await
        }
        Mode::Receive => {
            info!("Mode: RECEIVE, Session: {}", args.session_id);
            run_receiver(
                &args.server, &args.session_id, timeout, args.probe_count,
                args.prediction_mode, args.prediction_range_extra_pct, args.tcp_connections as u32,
                args.allow_fallback, args.min_connections
            ).await
        }
    }
}
