# Transfer Optimization Backlog (Deferred)
Date: 2026-01-24

Context: Items deferred from the throughput optimization review. Each entry lists the reason for deferral and code references.

1) Per-stream sliding window / pipeline (Deferred)
- Reason: requires protocol changes and out-of-order ACK handling; higher risk of regressions.
- References:
  - src/transfer/sender.rs:295-313 (send header+data then wait for ACK per chunk)
  - src/transfer/sender.rs:109-113 (read_chunk_ack_message)

2) Contiguous chunk assignment (Deferred)
- Reason: needs new scheduling policy; interacts with retry/NACK logic and per-stream fairness.
- References:
  - src/transfer/sender.rs:204-206 (pending queue of all chunks)
  - src/transfer/sender.rs:271-275 (pop_front assigns next chunk)

3) ACK/NACK batching (Deferred)
- Reason: protocol change on both sender and receiver; requires compatibility strategy.
- References:
  - src/transfer/receiver.rs:329-361 (per-chunk ACK/NACK on receive)
  - src/transfer/sender.rs:302-313 (per-chunk ACK wait)

4) Chunk size tuning / auto-configuration (Deferred)
- Reason: needs RTT/BDP measurement and safe bounds per OS/connection.
- References:
  - src/transfer/mod.rs:22-37 (default chunk size and global override)
  - src/cli.rs:94-112 (CLI chunk parsing)
