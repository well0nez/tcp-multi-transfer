# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project Overview

TCP file transfer client with NAT traversal (TCP hole punching). Uses a Python relay server to coordinate peer connections and Rust client for P2P file transfers. The system uses sophisticated NAT probing to predict port allocations and build candidate lists for successful hole punching even through difficult NAT types.

## Common Commands

### Building
```powershell
# Development build
cargo build

# Release build (optimized)
cargo build --release
```

Binary location:
- Dev: `target/debug/tcp-transfer-ice.exe` (Windows) or `target/debug/tcp-transfer-ice` (Unix)
- Release: `target/release/tcp-transfer-ice.exe` (Windows) or `target/release/tcp-transfer-ice` (Unix)

### Testing
```powershell
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test module
cargo test hole_punch::tests
```

### Code Quality
```powershell
# Check compilation without building
cargo check

# Run clippy (linter)
cargo clippy

# Format code
cargo fmt

# Format check without changing files
cargo fmt -- --check
```

### Running
```powershell
# Start the Python relay server (required before client usage)
python tcp_server_ice_NEW.py --port 9999 --probe-port 9998

# Receiver (start first)
.\target\release\tcp-transfer-ice.exe -s SERVER:9999 -i SESSION_ID -m receive

# Sender
.\target\release\tcp-transfer-ice.exe -s SERVER:9999 -i SESSION_ID -m send -f file.mp4

# Debug mode
.\target\release\tcp-transfer-ice.exe -s SERVER:9999 -i SESSION_ID -m receive --debug

# NAT probe debug (analyze port behavior)
.\target\release\tcp-transfer-ice.exe -s SERVER:9999 -i test -m receive --probe-debug --probe-count 25
```

## Architecture

### High-Level Flow
1. **Registration**: Both peers connect to relay server with session ID
2. **NAT Probing**: If needed, client opens multiple probe connections to analyze NAT port allocation behavior
3. **Port Prediction**: Relay server analyzes patterns (constant delta, small/medium/large range, random-like) and builds bounded candidate port list
4. **Synchronization**: Relay sends "go" signal with synchronized start timestamp (with clock offset compensation)
5. **Hole Punching**: Both peers simultaneously bind listener and initiate connections from same local port using SO_REUSEADDR/SO_REUSEPORT
6. **File Transfer**: Once connected, direct P2P TCP transfer with progress tracking and SHA256 verification

### Module Structure

#### `main.rs` - Entry point and relay protocol
- CLI argument parsing (clap)
- Relay server connection and protocol handling (JSON over TCP)
- NAT probing coordination (`do_nat_probing`)
- Local port management and socket binding
- Clock synchronization for hole punch timing
- Orchestrates hole punching and file transfer phases

Key functions:
- `run_relay_protocol()` - Handle full relay server protocol including registration, peer_info, and go signal
- `do_nat_probing()` - Send multiple probe connections to determine NAT port allocation pattern
- `create_bound_socket()` - Create socket with SO_REUSEADDR/SO_REUSEPORT for hole punching

#### `protocol.rs` - Message definitions
- Relay server protocol messages (JSON serialization via serde)
- `RegisterMessage`, `ReadyMessage`, `ProbeMessage` - Client to server
- `RelayMessage` enum - Server to client (registered, peer_info, go, error)
- `NATAnalysis` - NAT classification and port scan range
- `transfer` submodule - Binary protocol for file transfer over direct connection

#### `hole_punch.rs` - TCP hole punching implementation
- **Critical concept**: Uses "simultaneous open" - both peers must attempt connection at exactly same time
- Creates listener AND connector from same local port (enabled by SO_REUSEPORT/SO_REUSEADDR)
- Pre-handshake protocol (`HPCH` magic bytes) to deduplicate connections
- Tries multiple peer address candidates in parallel
- Grace window to accept connections slightly out of sync

Key functions:
- `do_hole_punch()` - Main entry with synchronized timing using server timestamp and clock offset
- `run_hole_punch()` - Spawns listener + multiple connector tasks, first successful connection wins
- `create_hole_punch_socket()` - Socket with reuse options and TCP_NODELAY
- `pre_handshake()` - Exchange magic bytes to identify connection pair

Critical implementation detail: Outgoing connections MUST come from same port as listener to create proper NAT mapping.

#### `transfer.rs` - High-performance file transfer
- **Optimizations**: 
  - Configurable chunk size (default 4MB via `--chunk` flag)
  - Large TCP buffers (64MB send/recv requested)
  - Pipelined I/O using tokio channels (depth=16 chunks)
  - Progress updates hybrid strategy (every 10MB OR 2 seconds)
  - SHA256 verification only at end (TCP guarantees in-flight integrity)
  
- `TcpSender` - Reads file from disk, sends over TCP with pipelining
- `TcpReceiver` - Receives file and writes to disk with buffering
- Binary protocol: HELLO → FILE_INFO → FILE_INFO_ACK → raw bytes → DONE → ACK

Key optimization: Reader task runs ahead of writer task via bounded channel, maximizing I/O parallelism.

### Relay Server (tcp_server_ice_NEW.py)
Python-based coordination server:
- Manages peer sessions and address exchange
- Runs NAT probing phase (observes local_port → public_port mappings)
- Computes port prediction model (delta-based or external-only modes)
- Classifies NAT patterns (port_preserved, constant_delta, small/medium/large_delta_range, random_like)
- Sends bounded candidate port lists (capped by --max-scan-ports)
- Synchronizes "go" signal with timestamps for clock compensation

## Development Patterns

### Socket Configuration
Always set these socket options for hole punching:
```rust
socket.set_reuse_address(true)?;
#[cfg(unix)]
socket.set_reuse_port(true)?;
socket.set_nodelay(true)?;
```

### Clock Synchronization
The system compensates for clock skew between peers and server:
- Server includes `server_time` in registered message
- Client calculates offset: `server_time - (local_sent_time + rtt/2)`
- Hole punch start time adjusted: `local_start_at = start_at - time_offset`

### NAT Port Prediction
Server builds port candidate list based on probe observations:
- **Port preserved** (delta=0): Single port
- **Constant delta**: `local_port + delta`
- **Small/medium/large range**: Contiguous window around predicted port
- **Random-like**: Sparse sampling (predicted + min/max boundaries + evenly spaced samples)

Client can use `--prediction-mode external` to predict from public ports only (ignores local port correlation).

Expand scan range with `--prediction-range-extra-pct` (e.g., 20-50%) for difficult NATs.

### Error Handling
Use `anyhow::Result` for most error handling. Use `thiserror` for custom error types only when pattern matching on errors is needed.

### Async Patterns
- All I/O uses tokio async runtime
- Use `tokio::spawn` for concurrent tasks (e.g., listener + multiple connectors)
- Use `tokio::select!` for racing operations
- Use bounded channels (`tokio::sync::mpsc`) for backpressure in pipelines

### Testing
Limited test coverage currently. Tests exist in `hole_punch.rs` for basic socket operations and local loopback. When adding tests:
- Use `#[tokio::test]` for async tests
- Test socket configuration and binding logic
- Integration tests should use actual relay server

## Windows-Specific Notes

This codebase is cross-platform but the user is on Windows (PowerShell):
- Binary outputs to `target\release\tcp-transfer-ice.exe`
- Use `cargo build` (no special configuration needed)
- CI builds for Windows, macOS, and Linux via GitHub Actions
- On Windows, socket2 crate provides SO_REUSEADDR (SO_REUSEPORT is Unix-only)

## Performance Tuning

### Transfer Speed
Adjust chunk size: `--chunk 8MB` (default 4MB)
- Larger chunks = fewer syscalls but more memory
- Optimal value depends on network bandwidth and latency

### NAT Traversal Success
For difficult symmetric/random NATs:
- Increase probe count: `--probe-count 25` (default 10)
- Widen scan range: `--prediction-range-extra-pct 50` (default 0)
- Relay server: `--max-scan-ports 1024` (default 512)
- Try external prediction: `--prediction-mode external`

### Debugging
- Client: `--debug` for detailed tracing logs
- Client: `--probe-debug` to analyze NAT port behavior only (no transfer)
- Server: Check relay logs for probe statistics and pattern classification

## File Organization

```
src/
├── main.rs          # CLI, relay protocol, orchestration
├── protocol.rs      # Message types (relay + transfer)
├── hole_punch.rs    # TCP hole punching logic
└── transfer.rs      # File transfer with pipelining

tcp_server_ice_NEW.py # Python relay server
Cargo.toml            # Dependencies and build config
.github/workflows/    # CI for build and release
```

## Important Constraints

### NAT Traversal Limitations
TCP hole punching is harder than UDP and may fail on:
- **Symmetric NAT**: Low success probability without wide port scanning
- **Carrier-Grade NAT (CGN)**: May block or throttle multiple connection attempts
- **Some enterprise firewalls**: May not allow simultaneous open

Success rates improve with larger scan windows but at cost of more connection attempts.

### Timing Sensitivity
The "simultaneous open" requires both peers to send SYN at nearly the same time:
- System uses server-provided synchronized timestamp
- Compensates for clock skew between peers
- Grace window (300ms) allows slight timing variations

### Port Binding Race Condition
When using `get_free_port()` + later bind, there's a small window where another process could claim the port. The code accepts this risk for simplicity.
