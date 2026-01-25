# Technical Notes - TCP Multi-Transfer

## NAT Pattern Detection Analysis

### Overview

The NAT analysis system detects and classifies NAT behavior to optimize hole punching. The `pattern_type` field in `NATAnalysis` categorizes the NAT type based on probing results.

### Pattern Types

| Pattern | Description | Predictability | Scan Required |
|---------|-------------|----------------|---------------|
| `port_preserved` | NAT port = Local port | Perfect | No (1 port) |
| `constant_delta` | NAT port = Local port + fixed offset | Perfect | No (1 port) |
| `small_delta_range` | Delta varies by ±5 | High | Small (~10 ports) |
| `medium_delta_range` | Delta varies by ±30 | Medium | Medium (~60 ports) |
| `large_delta_range` | Delta varies by ±100 | Low | Large (~200 ports) |
| `random_like` | No discernible pattern (CGNAT) | None | Full range scan |

### Current Usage

**Where `pattern_type` IS used:**

1. **Port Prediction** (`coordinator.py:get_nat_port_for_local_port()`)
   - Uses `port_preserved` to return local port directly
   - Uses delta values for offset-based prediction

2. **Scan Range Calculation** (`nat_analyzer.py:analyze_nat()`)
   - Sets `needs_scan` based on pattern
   - `constant_delta` and `port_preserved` → `needs_scan = False`

3. **Candidate Port Building** (`nat_analyzer.py:build_candidate_ports()`)
   - Special handling for `random_like` patterns
   - Samples port range differently for unpredictable NATs

**Where `pattern_type` is NOT used:**

1. **Strategy Selection** (`coordinator.py:determine_punch_strategy()`)
   - Always returns `"scan"` regardless of NAT type
   - Conservative approach that works universally

2. **Parallel vs Sequential Connections**
   - Always sequential, independent of NAT pattern
   - Reason: Port collision risk when multiple connections scan simultaneously

### Potential Optimizations (Not Implemented)

#### Strategy Selection Based on NAT Type

```python
def determine_punch_strategy(my_peer, other_peer) -> str:
    my_nat = my_peer.nat_analysis
    other_nat = other_peer.nat_analysis
    
    # If BOTH are port_preserved → simple connect might suffice
    if (my_nat and my_nat.pattern_type == "port_preserved" and
        other_nat and other_nat.pattern_type == "port_preserved"):
        return "direct"
    
    return "scan"
```

**Why not implemented:** The current approach works universally. The differentiation happens through the **number of ports** in `peer_addresses`, not through strategy changes.

#### Parallel Connections for Predictable NATs

```python
if (sender.nat_analysis.pattern_type in ["port_preserved", "constant_delta"] and
    receiver.nat_analysis.pattern_type in ["port_preserved", "constant_delta"]):
    await establish_parallel_connections(...)
else:
    await establish_sequential_connections(...)
```

**Why not implemented:** Port collision problem. When multiple tasks scan port ranges simultaneously, one connection might find another connection's port, leading to mismatched connections.

### Port Rate Prediction

Some NATs allocate ports sequentially over time. The system tracks this:

```python
# If probes show increasing ports over time:
t=0.0s: nat_port=60000
t=0.1s: nat_port=60002
t=0.2s: nat_port=60004

port_rate = 20 ports/second
predicted_shift = port_rate * delay * damping
```

This allows predicting where the NAT port will be when the actual hole punch happens (typically 1-2 seconds after probing).

---

## Bug Fixes Applied (v0.9.3-beta)

| Bug | Description | Fix |
|-----|-------------|-----|
| BUG-001 | Retry race condition - stale entries not cleaned | Added 60s timeout cleanup task |
| BUG-002 | Unbounded queues could cause OOM | Added MAX_QUEUE_SIZE = 100 with FIFO eviction |
| BUG-003 | Task leak at punch - connector tasks not cancelled | Added shutdown flag with AtomicBool |
| BUG-004 | Double-send of conn_established/abandoned | Added result_message_sent flag |
| BUG-005 | Half-open detection missing (2 min wait) | Added TCP Keepalive (30s idle, 10s interval) |
| BUG-006 | Time sync ignored network RTT | Added RTT-based correction with median offset |
| BUG-007 | Writer not flushed before close | Added `await writer.drain()` before close |
| BUG-008 | Bare exception handling swallowed errors | Changed to `except Exception as e:` with logging |
| BUG-009 | Unsafe static mut (undefined behavior) | Changed to AtomicUsize |
| BUG-010 | Port truncation without validation | Added validation for ports > 65535 |

---

## Performance Optimizations Applied (v0.9.3-beta)

| Optimization | Description | Impact |
|--------------|-------------|--------|
| Polling → Notify | Replaced sleep loops with tokio::sync::Notify | ~200ms less latency at transfer end |
| Adaptive GO Delay | RTT-based delay instead of fixed 1.5s | LAN: ~1s faster, WAN: more stable |
| SHA256 spawn_blocking | Moved hashing to blocking thread | Better async runtime utilization |
| CRC32 (verified) | crc32fast already uses SIMD | No change needed |

---

## Test Coverage

35 tests covering:
- Data models (Peer, NATAnalysis)
- Session management and locks
- NAT port prediction
- Adaptive GO delay formula
- Bounded queue behavior
- Retry timeout cleanup
- Double-send prevention
- Server/client protocol
- Concurrent access

Run with: `pytest tests/ -v`
