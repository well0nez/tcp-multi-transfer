# Changelog

## v0.10.0

Every number below was measured over a real path between a desktop behind carrier-grade
NAT and an office machine behind a port-preserving NAT, in paired runs that varied one
factor at a time. Details and the raw series are in the README.

### Breaking

- **Punch pre-handshake is now version 2** and carries a random 64-bit number per socket.
  A 0.9.x client and a 0.10 client cannot punch with each other.
  The old rule for picking a winner among several successful connections compared the
  ordered pair of local and remote port — which is not a shared quantity behind NAT, so
  the two sides picked *different* connections and the transfer died with `early eof`.
  With more than one local port that case is common, not rare.
- **TTL pre-opening removed** (`--preopen`, `--preopen-max`, `--preopen-lead-ms`).
  Measured without effect (13/16 without against 12/16 with), and on a NAT that allocates
  a fresh port per connection its premise does not hold in the first place.
- `--parallel-ports` is now `--punch-ports`, `--bench-und-transfer` is now
  `--bench-then-transfer`. Both old names keep working as aliases.

### Punching

- **Several local ports are held at the same time** while punching (`--punch-ports`,
  default 16). Each one is an independent draw from the band the local NAT allocates
  from, and only simultaneously held sockets count — a closed socket takes its mapping
  with it. Success per punch attempt at 64 covered ports rose from 23 % to 80 %
  (p < 0.0001), per session from 75 % to 100 %.
- **Connect sockets are held until the time budget expires** instead of being rebuilt
  every 600 ms. The old loop destroyed one mapping per cycle without adding one; that is
  why longer timeouts never helped.
- **The relay sizes the candidate list itself** from the measured port band and the
  client's port count, targeting 95 % per attempt: `k = N · (1 − (1 − P)^(1/m))`.
  Measured: 33 to 51 candidates instead of a flat 512. `--max-scan-ports` is now only a
  ceiling, and its default dropped from 512 to 64.
- Together these give **the same reliability with an eighth of the sockets** (48 instead
  of 370) and a faster punch (228 ms instead of 271 ms median).
- Extra local ports are switched off automatically when the local NAT allocates
  predictably — the relay now sends each peer its own analysis (`your_nat_analysis`).
- The wait for a better candidate is derived from how long the first one took instead of
  being fixed at 300 ms; a fixed value accounted for 74 % of the whole punch duration.
- Candidate lists are thinned evenly and kept inside the peer's observed band rather than
  truncated. A contiguous prefix covers only the bottom edge of the band; candidates
  outside the band are worthless when the budget is short.

### NAT analysis

- **Allocation, mapping and filtering are classified separately** (RFC 4787) instead of
  being conflated into one pattern, each with its own estimator.
- **Mapping behaviour** is measured against two probe ports; alternating them also avoids
  losing probes to `EADDRNOTAVAIL` from identical five-tuples.
- **Filtering behaviour** is measured: the relay connects back to the observed external
  port from a source port the client never contacted. The client holds its last probe
  open so the test runs against a live mapping. Runs for port-preserving peers too —
  there the answer decides whether the other side has to scan at all.
- **The port band is estimated with the order statistic.** `[min, max]` from `n` draws
  contains a fresh draw only with probability `(n−1)/(n+1)` — 81.8 % at ten probes,
  regardless of scan width. Widening by `0.25 · (max − min)` per side raises that to
  96.2 %, cross-validated over 558 recorded draws.
- **The rate model for time-based allocators now requires a significance test.** The old
  rule ("at least 60 % of consecutive differences positive") is satisfied by pure noise in
  a quarter of all cases and fired on 10 of 56 recordings of a demonstrably drift-free
  NAT, displacing the prediction by up to 32 ports.
- CGNAT port blocks are exploited where they are actually established. A block must be
  filled, not merely aligned — alignment alone happens by chance in 22 % of cases at a
  typical sample width, and a weaker rule fired on 9 of 56 recordings. A block may only
  narrow the range, never widen it.
- Candidates are spread proportionally across the band. A fixed integer step leaves a gap
  at the top end and, when even, covers only every second port.

### Transfer

- **Block size follows file size and stream count.** A fixed 8 MB meant a 1 MB file
  produced exactly one block, carried by a single stream while the others idled. At least
  two blocks per stream are now targeted, floor 256 KB. The sender decides and announces
  the value in STREAM_INFO (see "Fixed after review").
- Metrics now separate the payload rate from the rate over the whole wall clock — the
  latter includes the handshake and the receiver's SHA256 pass, which dominates for small
  files.

### Measurement

- `--bench <MB>` transfers raw bytes over the punched connection: no chunk protocol, no
  checksums, no disk. That is the reference the transfer code is measured against.
  `--bench-then-transfer` runs both in one session over the same connection.
- Metrics lines carry the kernel's own `TCP_INFO` accounting (`sndbuf_limited`,
  `rwnd_limited`, retransmits, `min_rtt`, `snd_cwnd`).
- Result: the transfer code costs nothing measurable — 101.6 % of the raw stream (median
  of ten paired runs, 95 % interval 94–111 %). The `TCP buffers ... (requested 64MB)` line
  is not a bottleneck: `sndbuf_limited` was zero in every run.
- Parallel connections bring no throughput on a mobile uplink: 101.5 % in one direction,
  85 % in the other.

### Fixed after review

- **Block size is announced by the sender** in STREAM_INFO instead of being derived
  independently on both sides. The derivation was clamped to the *local* `--chunk`, which
  is never transmitted: with different `--chunk` values the file split into a different
  number of blocks per side, which ended in an out-of-bounds index or a silent
  "Transfer incomplete". Chunk number, length and offset are now validated against the
  file size instead of being indexed blindly.
- **Received file names are reduced to their last path component.** The name came from
  FILE_INFO and was used as a path unchecked, so a sender could write outside the working
  directory - the checksum matched, being computed over the attacker's own data.
- **`--grace-ms` below 50 no longer panics.** `clamp` was called with a lower bound above
  the upper one.
- **Fixture recording works again.** It unpacked four-element probes while they carry five
  since mapping detection was added; a blanket `except` swallowed the error, so no fixture
  had been written at all.
- **The bench time series is no longer always empty.** The sampling task returned its
  values through its return value but was aborted, and awaiting an aborted task always
  yields an error.
- **`--chunk 0` is rejected** (minimum 64 KB). It produced a zero-length read buffer -
  SHA256 of the empty input for every file - and a division by zero in multi-stream mode.

### Fixed after the second review

- **Port parity detection removed.** It was meant to halve the scan space on NATs that
  preserve the parity of the local port. Two reasons against it, both found by
  recalculation: the evidence did not hold (with all probed local ports even — the client
  binds consecutive ports — "preserves parity" is indistinguishable from "always even"),
  and the damage was large. Candidates were anchored on the parity of `predicted_port`,
  which comes from a *median* that averages two values over an even count and can flip
  parity. Over 500 synthetic sessions, **245** ended up with every single candidate on the
  impossible parity. No measured NAT preserves parity (558 probes, 50:50).
- **A rejected duplicate registration no longer destroys the running session.** The
  cleanup path ran for the rejected peer as well, deleting the *innocent* counterpart and
  dropping the whole session, while the legitimate peer stayed connected and orphaned.
  Anyone who knows the session ID could end a transfer that way.
- **The final ACK in multi-stream mode is sent after the SHA256 check**, not on receiving
  DONE. The protocol says the ACK confirms a verified checksum; in multi-stream mode it
  was sent before hashing, so the sender could report success while the receiver failed
  verification.
- **`--max-attempts` does something now.** It was documented as 20 and read nowhere; the
  actual limit was a hard-coded 5. It is now the retry limit, default 5 — the value that
  was always in force.
- Removed the unused `dashmap` and `thiserror` dependencies.
- Corrected three comments that had come to contradict the code, two of them written for
  this release.

### Fixed after the third review round

Correctness:

- **The lost-wakeup race in the multi-stream sender.** A worker could check the queue,
  miss the last wakeup between check and registration, and sleep forever while the caller
  waited on it — the transfer never finished although all data had arrived.
- **`read_line` is no longer cut short by a timeout.** It is not cancellation-safe: a
  timeout firing mid-line discarded the bytes already consumed, so a multi-segment
  `peer_info` was lost and the session ran into the 120-second timeout. The timeout only
  existed to notice shutdown; the caller now aborts the task instead.
- **A failed on-demand bind no longer shifts the socket index.** Skipping a bind without
  pushing left later connections indexing past the end of the list.
- **Losing the relay no longer discards established connections.** Transport loss is now
  distinguished from a server error; already punched, direct connections survive and
  `--allow-fallback` can use them.
- **Individual streams may fail during setup** instead of tearing down the whole
  transfer. If the two sides end up with different stream counts, the dead one is dropped.
- **Probing covers each (local port, target) pair.** With four bound ports and ten probes
  at most one probe was left per pair, and mapping detection silently returned
  "undetermined".
- **The relay no longer sends while holding the session lock.** A peer with a full send
  buffer could hold the lock for minutes, blocking every handler of that session
  including the cleanup of the other peer.
- **The primary candidate no longer contradicts the band estimate.** For random-band NATs
  the delta extrapolation was used anyway — the very extrapolation `_als_band` had
  discarded as unfounded.
- **Coverage for a zero-width band** returns one candidate instead of the ceiling plus an
  invented hit probability.
- Retransmitted blocks are no longer counted twice in the progress bar; `--chunk` is
  bounded above as well as below; session locks are released with the session.

Structure:

- **One transfer protocol instead of two.** The raw-stream path for the single-connection
  case is gone. Which path was used had been decided from each side's *own*
  `--tcp-connections`, so a fallback to one connection on one side made the two sides
  speak different protocols. The block protocol costs nothing measurable (101.6 %).
- **`run_sender` and `run_receiver` merged** into one `run_peer` — they were 90 %
  identical, and the duplication had already caused drift.
- **Socket provisioning is one function** instead of three near-copies.
- **The connector task is a named function** instead of a 115-line closure nested four
  deep with ten captured variables.
- **`analyze_nat` is 100 lines shorter**: nested definitions became module functions and
  the classification ladder exists once instead of twice.
- **Session state in the relay is a dataclass**, not ad-hoc string keys spread over three
  files; `retry_requested` is a real field instead of being attached via `hasattr`.
- Removed the dead notification chain (`peer_added_ports` was collected into a field
  nobody read), dead session fields, an unreachable branch, a duplicated `sha256_file`,
  unused message types, and `count_lines.ps1`.
- The `attempt` counter in the state machine is gone: it was reset to 1 on every failure,
  never accumulated and steered nothing — while the logs claimed otherwise.

Time synchronisation:

- **Five timestamps 50 ms apart in a single message** have been replaced by one timestamp
  plus the client's own round-trip correction. A median over samples from one message is
  deterministically the third value; there was no independent jitter for it to defend
  against, and it cost 250 ms per registration.

### Tests

- **40 tests instead of 11.** The 56 recorded fixtures cover exactly one real NAT type;
  synthetic cases now cover the others — port preservation, constant offset, progressive
  allocator, port blocks, the three mapping behaviours, and the coverage calculation.
- **Eleven tests for the relay coordination, which had none at all.** They drive a real
  server on 127.0.0.1 with fake peers speaking the wire protocol: registration, rejected
  duplicates, `peer_info`/`ready`/`go` handshaking, sequential ordering of connections,
  retry agreement, and teardown on disconnect. That is the code the session-state
  refactor touches.
- `regression.sh` drives full transfers over loopback — one, two and four streams,
  mismatched `--chunk`, a small file across many streams, a tiny grace window, a rejected
  duplicate registration, and a path measurement with a time series.

### Validated over the real path after the rebuild

Everything above had only been exercised over loopback after the review fixes. Measured
again over the real desktop-to-office path:

- Desktop to office, 4 runs: **98.3 %** of the raw stream (median) — the block protocol
  now runs on a single connection too, and still costs nothing. That was the condition
  for dropping the raw path.
- Office to desktop, 10 runs: **95.5 %** (median of the second series), 10/10 without
  error. This direction is loss-limited, hence the spread.
- Punching, 10 sessions at the shipped defaults: **10/11 attempts, 10/10 sessions**,
  median 270 ms. The relay sized 42 to 52 candidates from measured bands of 241 to 299
  ports. Up to **seven** connections came up simultaneously per punch, so the symmetric
  pre-handshake key is exercised constantly.

Two documented gaps closed with a second public endpoint:

- **The mapping question does not apply to this NAT.** Two connections with an identical
  five-tuple get different external ports, so there is no reusable mapping for
  "endpoint-independent" or "address-dependent" to describe.
- **The band measured at the relay also holds towards a different address** — 24966-25201
  against one server, 24987-25194 against another, fourteen draws each. That is the
  assumption the whole prediction rests on, and it had only been shown across ports on
  one address before.
- **The band moves between days** (5056-5307 one day, 24966-25201 the next). Probing is
  per session for that reason; nothing derived from it may be cached.

### Help output

- All program output and CLI help is English; code comments stay German.
- `-h` and `--help` show the switches for everyday use; `-X` adds every tuning and
  measurement switch.
