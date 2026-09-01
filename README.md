# tcp-multi-transfer

File transfer over a direct TCP connection between two peers behind NAT, established by
hole punching. Rust client, Python relay.

Current version: v0.10.0. Successor to the single-connection prototype at
https://github.com/well0nez/tcp-transfer-ice.

Every number in this document was measured over a real path between a desktop behind
carrier-grade NAT and an office machine behind a port-preserving NAT, in paired runs that
varied one factor at a time. Where something is unmeasured, it says so.

## How it works

1. Both peers connect to the relay with the same session ID.
2. The relay probes each peer's NAT: how it allocates external ports, whether its mapping
   is reusable, and whether it filters by source port.
3. From that it derives, for each peer, the list of ports the *other* side has to open.
4. Both peers punch at a synchronized moment: a listener on the bound port, and connect
   attempts from several local ports at once.
5. The file is transferred over the direct connection that comes up, in blocks with CRC32
   per block, verified by SHA256 at the end.

For multiple connections the relay coordinates **one at a time**: it sends `peer_info`
and `GO` for connection *n* and waits for both peers to report `conn_established` or
`conn_abandoned` before moving on. Retries are symmetric — one only starts after both
peers asked for it and supplied fresh ports.

## Why it works: coverage times draws

Let `N` be the width of the port band your own NAT allocates from, `k` the number of
ports the peer opens, and `m` the number of local ports **held open at the same time**.
The punch succeeds as soon as the set of mappings you hold and the set of ports the peer
opened intersect:

```
P(hit) = 1 − (1 − k/N)^m
```

The word *simultaneously* carries the whole argument. A closed socket takes its mapping
with it, and an incoming SYN for it earns a RST — so ports tried one after another do
**not** accumulate. That is why longer timeouts bought nothing in earlier measurements
(5/6 against 6/6 for 90 s instead of 25 s) while a wider scan did: the product `m · k`
is the lever, not the duration. The connect sockets are therefore held open until the
time budget expires and are only rebuilt after a rejection, where the mapping is lost
anyway.

Measured over the real path (carrier NAT with per-connection allocation on one side,
port-preserving NAT on the other, `k = 64`, `N = 251`, paired runs, only `m` varied):

| `m` | model | measured, per attempt | per session |
| --- | --- | --- | --- |
| 1 | 25 % | **23 %** (12/52) | 75 % (12/16) |
| 8 | 91 % | **80 %** (16/20) | 100 % (16/16) |

`p < 0.0001` on the test for equal proportions.

Used the other way round, the same model saves load. Twelve paired runs per row:

| setup | sockets | per attempt | per session | punch | whole run |
| --- | --- | --- | --- | --- | --- |
| full (k = all, m = 8) | 370 | 12/12 = 100 % | 12/12 | 271 ms | 17.2 s |
| lean, candidates spread over the widened band | 48 | 12/17 = 71 % | 12/12 | 262 ms | 22.1 s |
| lean, candidates inside the observed band | 48 | 12/12 = **100 %** | 12/12 | **228 ms** | **16.5 s** |

The middle row missed the model's 88.5 % because of an interaction with the band
estimate: 32 candidates spread over the *widened* range (~375 wide) while the NAT only
allocates within 251 — about eleven of them landed outside and were worthless. **The
order-statistic margin only pays when the budget covers the band densely.** Of `k`
candidates spread evenly over a width `R`, only `k · W/R` land inside the band of width
`W` that is actually used. Candidates are therefore placed inside `[min, max]` whenever
the budget is short, on both the server and the client side. That closes the gap
(71 % → 100 %, p = 0.039): **the same reliability as 370 sockets, with an eighth of
them**, and a faster punch.


## What the relay measures

### 1. Allocation — how the NAT picks the external port


| `allocation` | Estimator | Scan needed |
| --- | --- | --- |
| `portbewahrend` | external port = local port | no |
| `versatzstabil` | external port = local port + median(delta) | only the delta's error range |
| `fortlaufend` | delta plus a time-based lead (see below) | error range |
| `zufaellig_im_band` | **no point estimate** — the band is the answer | full band |

For a random allocator a point prediction is meaningless, so the band is estimated
instead, and it is estimated with the order statistic rather than the raw extremes:

> With `n` uniform draws from a band of width `W`, the expected spread of the sample is
> only `W·(n−1)/(n+1)`. Taking `[min, max]` as the band therefore **understates** it, and
> a fresh draw lands inside with probability only `(n−1)/(n+1)` — 81.8 % at `n = 10`,
> **regardless of how wide you scan**.

Measured against 558 real probes of the same carrier NAT (56 sessions): mean observed
spread 198.3 against a true band of 251, expected 205.4. Uniformity survives a
chi-squared test (6.5 on 9 degrees of freedom). The band is therefore widened by
`0.25 · (max − min)` on each side. Leave-one-out cross-validation over those 558 real
draws: **81.5 % → 96.2 %** of held-out draws fall inside the estimated band.

Two further properties are exploited when they are actually established:

- **Port parity.** If the NAT preserves the parity of the local port (RFC 4787 advises
  against it; plenty of devices do it anyway), only every second port can occur and the
  candidate list skips the rest — the same budget then covers twice the band. Requires
  at least eight consistent pairs (`P = 2⁻⁷`).
- **CGNAT port blocks.** If every observation falls inside one aligned power-of-two
  block, the block bounds the band. The alignment alone is not evidence: a sample of
  width `s` falls inside *some* aligned block of size `B` by chance with probability
  `(B − s)/B` — at `s = 200, B = 256` that is 22 %, and a weaker rule fired on 9 of the
  56 real sessions whose true band demonstrably crosses block boundaries. A block is
  only accepted below 5 % chance probability, and it may only **narrow** the range,
  never widen it.

### 2. Mapping behaviour (RFC 4787)


Probes go to **two** relay ports, so the mapping can be classified:

- `pro_verbindung` — two connections with an identical five-tuple already get different
  external ports. There is no reusable mapping at all; the port measured at the relay
  says nothing about the port towards the peer, and only the band estimate remains.
- `endpunktunabhaengig` — the same local port yields the same external port against
  different targets. The relay's measurement then transfers to the peer: one candidate,
  no scan.
- `portabhaengig` — a separate but internally stable port per target.

Both relay probe ports share one address, so address dependence cannot be separated
from endpoint independence here. Saying so is cheaper than guessing: a second relay
address would settle it.

### 3. Filtering behaviour (RFC 4787)


After probing, the relay opens a connection **back** to the observed external port from
a source port the client never contacted. `ECONNREFUSED` means the NAT forwarded the SYN
and the client's kernel answered — filtering depends on the address only, and the peer
does not need to scan our ports at all. A timeout means the NAT dropped it: filtering is
address *and* port dependent, and only the coordinated punch helps.

### Time-based allocation


For a genuinely progressing allocator the port is a function of time, not of the local
port, so the prediction gets a lead of `port_rate · prediction_delay · RATE_DAMPING`.
That model is now gated by a significance test, because the previous rule — "at least
60 % of consecutive differences positive" — is satisfied by **pure noise** in a quarter
of all cases (nine differences, `P(X ≥ 6) = 25.4 %`). On the 56 recorded sessions of a
demonstrably drift-free NAT (median correlation between port and time: +0.07) it fired
10 times and displaced the prediction by up to 32 ports. It now requires both a sign
test at 5 % and a coefficient of determination of at least 0.5, and is silent on all 56.

### The band applies to any peer, and it moves


The whole method rests on one assumption: the band measured against the relay also
describes the ports this NAT will hand out towards an arbitrary peer. Measured against
two different public addresses, fourteen draws each:

| target | band | median |
|---|---|---|
| 5.45.97.166 | 24966-25201 | 25100 |
| 148.251.116.102 | 24987-25194 | 25089 |

88 % overlap over a 235-port span - exactly what fourteen draws from one shared band look
like. The two are indistinguishable.

The same measurement settles the RFC 4787 mapping question for this NAT, and not the way
the taxonomy expects: **two connections with an identical five-tuple get different
external ports.** There is no reusable mapping at all, so "endpoint-independent" versus
"address-dependent" does not apply. What remains is the band, which is why the band is
the method rather than a fallback.

The band is stable over hours but **not over days**: it sat at 5056-5307 one day and at
24966-25201 the next. Probing happens per session for that reason, and nothing derived
from it may be cached across sessions.

### Prediction plausibility


A prediction that contradicts the measurements it came from is not used. Where the
allocation is classified as random, the extrapolated port is replaced by the median of
the observed ports. `prediction_source` in the analysis records which path was taken
(`extrapoliert` or `median_beobachtet`).

Where the delta is stable, the extrapolation is kept unchanged - predicting a port
outside the observed band is normal there, because the prediction is made for a
different local port than the one probed.

The scan range is also guaranteed to contain the predicted port. Without that invariant,
`build_candidate_ports` silently dropped the single most important candidate, and the
windowing used for a tight `--max-scan-ports` centred on a port outside its own range.

### Probing from the bound punch ports


Probes are sent **from the sockets that will later be used for punching**, not from
ephemeral ports chosen by the kernel. This matters because the delta model extrapolates
from the probe's local port to the punch port: if the two come from unrelated port
populations, the resulting delta describes nothing.

Measured against a carrier-grade NAT, probing from ephemeral ports produced predictions
that were off by 3400-7200 ports (and in five of eight runs collapsed to the `MIN_PORT`
clamp of 1024). Probing from the bound ports brought the same NAT down to 16-74 ports of
error.

Alternating the two probe ports also avoids a practical problem: two connections with an
identical five-tuple cannot exist at once, and the kernel answers the second one with
`EADDRNOTAVAIL`. With a single target and a single bound port, probes were regularly
lost that way.

Use `--probe-from-bound false` to restore the old behaviour for comparison.

## Sizing the punch

### The relay sizes the coverage itself


A fixed number is wrong for every NAT but one, so the relay derives `k` from what it
measured. Solving the model for `k`:

```
k = N · (1 − (1 − P)^(1/m))
```

`m` is the number of local ports the peer holds — it announces that at registration —
and `N` is the width of its port band, estimated unbiasedly from the probe spread as
`spread · (n+1)/(n−1)`. The target `P` is the hit rate per attempt (0.95); with up to
five retries that makes a session practically certain. `--max-scan-ports` is now only
the ceiling.

Measured over the real path: band 270–298 ports, 16 held ports → **47 to 51 candidates**
instead of a flat 512, four out of four punches on the first attempt, 244–503 ms. A NAT
with twice the band automatically gets twice the candidates.

Where nothing has to be scanned — port-preserving or stable-offset NAT — the answer is
one candidate.

The obvious next idea — buy the same product from the other side by letting a small
socket budget walk a wide band over time — was measured and **refuted**. The filter entry
a SYN creates does outlive its socket (conntrack keeps `SYN_SENT` for about two minutes),
but the *drawing* side retransmits an unanswered SYN at 0, 1, 3, 7, 15 and 31 seconds, so
the opportunities cluster in the first second, when a rotating scanner has only a
fraction of its holes open. Ten paired runs over 256 candidates:

| setup | per attempt | per session |
| --- | --- | --- |
| 256 simultaneous sockets | **77 %** (10/13) | 100 % (10/10) |
| 16 sockets, cycled every 800 ms | **23 %** (7/30) | 70 % (7/10) |

Coverage has to be simultaneous on **both** sides. Cycling therefore remains only as a
fallback when the candidate list exceeds the socket budget, where it still beats dropping
the excess.

### When extra local ports are useless


Extra local ports only pay off if the peer has to scan a *band* of yours. If it knows
your port exactly — port-preserving or stable-offset NAT — then every mapping on a
different local port lies outside its candidate list and is dead weight. The relay
therefore sends each peer **its own** NAT analysis (`your_nat_analysis`), and the client
switches the slots off when `needs_scan` is false.

The TTL pre-opening that used to sit here has been removed. Paired runs against a
carrier NAT that allocates per connection: 13/16 without it against 12/16 with it, and
8/8 against 8/8 once the scan covered the full band. No contribution, so it is not spent
there — and on a per-connection allocator its premise does not hold in the first place,
because the mapping it holds open is not the one the real connection gets.

### Choosing the same connection on both sides


With several port slots the punch can succeed more than once, and both sides must keep
the *same* connection. The rule used to be the ordered pair of local and remote port —
which is not a shared quantity behind NAT: each side sees its own local port and the
peer's *translated* port, so the two sides compute different keys, pick different
connections and the transfer dies with `early eof`. The pre-handshake therefore carries
a random 64-bit number per socket; the ordered pair of the two numbers belongs to the
connection itself and is identical on both sides.

### Knobs that predate the model

Two options survive from before the relay sized coverage itself. Both still work; neither
is needed any more.

- `--prediction-range-extra-pct` widens the scan window by a percentage. The order
  statistic now does that job with a derivation behind it (see above), so leave it at 0
  unless you are reproducing an old measurement.
- `--prediction-mode external` predicts from the observed public ports alone, ignoring
  the local-port delta. It was meant for NATs whose allocation is target-dependent; on
  such a NAT the band estimate carries the prediction anyway.

`--max-scan-ports` is now a ceiling, not a target. Raising it does not widen the scan —
the relay asks for what the measured band and the peer's port count require.

## Throughput


Ten paired runs over the real path (Desktop behind carrier NAT ↔ office, 16 MB each,
raw stream and file transfer over the same connection):

| | median | range |
| --- | --- | --- |
| raw stream | 25.7 Mbit/s | 19.7 – 33.5 |
| file transfer | 27.4 Mbit/s | 17.1 – 35.6 |
| **share** | **101.6 %** | 95 % interval 94 – 111 % |

The transfer code costs nothing measurable. What the path delivers, the transfer
delivers. Two consequences for reading the numbers:

- The `TCP buffers: send=8MB recv=8MB (requested 64MB)` line is not a bottleneck. The
  kernel reports twice the value it stores, so the effective buffer is `wmem_max` = 4 MB,
  and at 35 ms round-trip that supports about 900 Mbit/s. `sndbuf_limited` was **zero
  microseconds in every single run** — measured, not assumed.
- The throughput printed at the end of a transfer divides the file size by the *total*
  wall clock, which includes the handshake and the receiver's SHA256 pass. The metrics
  line separates `mbit_payload` from `mbit_gesamt`; for 16 MB the difference is about
  2 %, for a 1 MB file it dominates.

What the path does show is heavy buffering: minimum round-trip 33–37 ms, but 300–900 ms
under load, with a congestion window around 1260 segments (1.8 MB) against a
bandwidth-delay product of roughly 130 kB. A single CUBIC flow fills a queue of about a
second. Loss is sporadic (0 in nine of ten runs, 115 segments in one).

Two further measurements bound the question:

- **Parallel streams change nothing.** Six paired runs of 32 MB, one stream against four:
  28.6 against 29.0 Mbit/s median — 101.5 %. A single stream already takes everything the
  path gives.
- **The punched path is not the bottleneck.** The same measurement against a well
  connected public server without NAT gave 20.8–23.3 Mbit/s, *below* the 26–33 Mbit/s of
  the punched peer-to-peer path at the same time of day.

The reverse direction fails differently: 20–104 retransmits per run, round-trip only
69–378 ms under load and a congestion window of 181–290 segments. The uplink buffers, the
downlink drops.

## Usage


### Prerequisites


Start the relay server:
```bash
python3 run_server.py --port 9999 --probe-port 9998
```
Ensure both ports are reachable from the public Internet.

Relay server options:
```
  --host <HOST>             Host to bind to [default: 0.0.0.0]
  --port <PORT>             Main port [default: 9999]
  --probe-port <PORT>       Probe port for NAT analysis [default: 9998]
  --probe-port2 <PORT>      Second probe port; only with it can mapping behaviour be classified [default: 9997]
  --max-scan-ports <N>      Max candidate ports sent to clients [default: 64]
```

### Receiver (start first)


```bash
./tcp-multi-transfer -s relay-server:9999 -i my-session -m receive
```

### Sender


```bash
./tcp-multi-transfer -s relay-server:9999 -i my-session -m send -f myfile.mp4
```

### Options

`-h` lists the switches for everyday use, `--help` the same, `-X` adds every tuning and
measurement switch. The everyday list:

```
Multi-TCP file transfer with NAT traversal (hole punching)

Usage: tmt-neu [OPTIONS] --server <SERVER> --session-id <SESSION_ID> --mode <MODE>

Options:
  -s, --server <SERVER>          Relay server address (host:port)
  -i, --session-id <SESSION_ID>  Session ID (both sender and receiver must use the same ID)
  -m, --mode <MODE>              Mode: send or receive [possible values: send, receive]
  -f, --file <FILE>              File to send (sender mode only)
      --timeout <TIMEOUT>        Hole punch timeout in seconds [default: 30]
      --debug                    Enable debug logging
      --chunk <CHUNK>            Chunk size for transfer (e.g., 512KB, 1MB, 2MB) [default: 8MB]
  -h, --help                     Print help
  -V, --version                  Print version

Multi-TCP:
      --tcp-connections <TCP_CONNECTIONS>
          Number of parallel TCP connections (multi TCP) [default: 1]
      --allow-fallback
          Allow fallback to fewer connections if punch fails
      --min-connections <MIN_CONNECTIONS>
          Minimum number of connections required (if fallback allowed) [default: 1]

Punch:
      --punch-ports <PUNCH_PORTS>  Local ports held simultaneously while punching [default: 16]
      --prefer-lan <PREFER_LAN>    Prefer LAN candidates when both peers are behind the same NAT [default: true] [possible values: true, false]

Measurement:
      --metrics-file <METRICS_FILE>    Append one JSON line per punch attempt and transfer to this file
      --metrics-label <METRICS_LABEL>  Free-text label written into every metrics line
      --bench <BENCH>                  Measure the path with N MB of raw traffic instead of sending a file
      --bench-then-transfer            Follow the path measurement with a file transfer over the same connection

Advanced switches for tuning and measurement: -X
```

### Punch options


| Option | Default | Effect |
| --- | --- | --- |
| `--punch-ports <n>` | `16` | How many local ports are held **at the same time** per target. Each one is an independent draw from the band your own NAT allocates from. Only useful when that allocation is unpredictable, and switched off automatically otherwise — see below. |
| `--socket-budget <n>` | `512` | Upper bound on `targets × ports`. Keeps a wide candidate list times several ports from exhausting the socket table. |
| `--max-candidates <n>` | `0` (all) | Only touch this many of the peer's candidates. The list is **thinned evenly** and kept inside the peer's *observed* band, not truncated — see below. Mainly a lever for A/B measurements. |
| `--rotate-after-ms <ms>` | `0` (= 800) | Cycle time for the fallback that kicks in when the socket budget cannot cover every candidate. Measured to be much worse than having enough sockets, so it is a fallback and not a default — see below. |
| `--grace-ms <ms>` | `300` | Upper bound on how long to keep collecting further candidates after the first one, so both sides pick the same connection. |
| `--grace-adaptiv <bool>` | `true` | Derive that wait from how long the first candidate took instead of fixing it. Measured: first candidate after 107 ms median, while a fixed 300 ms accounted for 74 % of the whole punch. |
| `--retry-pause-ms <ms>` | `100` | Pause after a *rejected* attempt before drawing again. |
| `--prefer-lan <bool>` | `true` | Prefer LAN candidates when both peers are behind the same public address. This is a correctness fix rather than an optimization: many consumer routers cannot hairpin, so two peers behind the same NAT may not reach each other through the public address at all. |
| `--probe-from-bound <bool>` | `true` | Probe from the bound punch ports (see above). |
| `--auto-parallel <bool>` | `true` | Set the port slots to 1 automatically when your own NAT allocates predictably. |
| `--max-attempts <n>` | `5` | How many failures in a row before a connection is given up. Used to be documented as 20 and read nowhere while a hard-coded 5 was in force. |
| `--legacy` | off | Turns all of the above off at once. Intended for before/after comparison. |
| `--metrics-file <path>` | - | Append one JSON line per punch attempt and per transfer. |
| `--metrics-label <text>` | - | Free-text label written into every metrics line. |

## Measuring changes


Old and new behaviour live in the **same binary** and differ only by flags, so an A/B
comparison cannot be skewed by different builds. Each punch attempt appends a JSON line
containing the outcome, the time from the synchronized start, the number of candidates,
how many candidates were seen in total, which port slot won, and whether the local NAT
allocates a fresh port per connection.

`--bench <MB>` replaces the file transfer with a raw byte stream over the punched
connection — no chunk protocol, no checksums, no disk. That is the reference the
transfer code is measured against. `--bench-then-transfer` runs both in the same session
over the **same** connection, seconds apart; with an uplink that changes by a factor of
five within a minute, nothing else is comparable. Both write a metrics line including
the kernel's own `TCP_INFO` accounting (`sndbuf_limited`, `rwnd_limited`, retransmits,
`min_rtt`, `snd_cwnd`).

The relay can record NAT analyses as golden fixtures by setting `TMT_FIXTURE_DIR`. Each
fixture holds the probe set, the analysis parameters and the resulting analysis.
`tests/` replays them and adds synthetic cases for the NAT types the recordings do not
contain:

```bash
python3 -m unittest discover -s tests   # analyzer + relay coordination
./regression.sh                          # full transfers over loopback
```

`regression.sh` starts a relay on 127.0.0.1 and drives real transfers through it: one,
two and four streams, mismatched `--chunk` on the two sides, a small file across many
streams, a tiny grace window, a rejected duplicate registration, and a path measurement.
It is the check to run after touching the transfer or coordination code.

## Building


```bash
cargo build --release
```

The binary will be at `target/release/tcp-multi-transfer`.

## Protocol

### Relay Server Protocol (JSON over TCP)


1. **Registration**: Client sends `{"type": "register", "session_id": "...", "role": "sender|receiver", "local_port": 12345}`
   - Optional for Multi-TCP: `"tcp_connections": N` and `"extra_ports": [..]`
   - `"punch_ports": N` — how many local ports the client holds while punching. The
     relay sizes the peer's candidate list from it (see above).
2. **Registered**: Server responds `{"type": "registered", "your_public_addr": ["ip", port], "needs_probing": true|false, "probe_port": 9998}`
   - `"probe_port2"` — second probe port, needed to classify mapping behaviour.
   - `"filter_test": true` — the relay offers the filter test even when no port band
     has to be estimated.
3. **Probing**: Client connects to the probe ports and sends
   `{"type": "probe", "session_id": "...", "local_port": N, "probe_num": i}`; the server
   answers `{"type": "probe_ack", "your_nat_port": N}`.
   - `"hold": true` on the last probe asks the server to run the filter test **while
     that connection is still open**, so it tests a live mapping. The ack is delayed
     until the test is done.
4. **Peer Info**: When both peers are connected, server sends `{"type": "peer_info", "peer_public_addr": ["ip", port], "peer_addresses": [...], "peer_nat_analysis": {...}}`
   - `"your_nat_analysis"` — the peer's *own* analysis. Only with it can a client decide
     whether extra local ports are draws or dead weight.
   - Multi-connection hints include `connection_num` and `peer_extra_ports` when available.

### Punch pre-handshake (binary over the punched TCP connection)


`[magic "HPCH"][version=2][random u64]`, exchanged in both directions before a candidate
counts. The random number per socket is what lets both sides agree on the same
connection when the punch succeeds more than once; the ordered pair of the two numbers
belongs to the connection and is identical on both ends.

**Version 2 is not compatible with version 1.** A 0.9.x client and a 0.10 client cannot
punch with each other.

### File Transfer Protocol (Binary over direct TCP)


1. **HELLO**: Both peers exchange `[type=1][len][role]`
2. **FILE_INFO**: Sender sends `[type=2][name_len][size][filename][sha256]`
   - The receiver reduces the name to its last path component before using it.
2b. **STREAM_INFO** (multi-stream only): `[type=8][stream_index][total_streams][chunk_size]`
   on every stream. The **sender** decides the block size; deriving it on both sides
   independently only agrees while both use the same `--chunk`.
3. **FILE_INFO_ACK**: Receiver acknowledges `[type=3]`
4. **Data Stream**: Raw file bytes (TCP handles reliability)
5. **DONE**: Sender signals completion `[type=5]`
6. **ACK**: Receiver confirms SHA256 verified `[type=6]`

## Troubleshooting

### The punch fails

Read the relay log first — it states what it measured:

```
NAT Analysis: allocation=zufaellig_im_band mapping=pro_verbindung filtering=adress_und_portabhaengig
NAT Analysis: band ~273 ports, peer holds 16 port(s) -> 47 candidates (ceiling 64), expected hit rate 95% per attempt
```

- **`allocation=portbewahrend` or `versatzstabil` on both sides** — the punch should
  succeed on the first attempt. If it does not, the problem is filtering or timing, not
  prediction.
- **`allocation=zufaellig_im_band`** — the hit rate per attempt follows the model above.
  If it is far below what the relay expects, the band estimate is wrong; raise
  `--probe-count` so the order statistic has more to work with.
- **`filtering=adress_und_portabhaengig` on both sides** with wide random bands on both
  — this is the hard case. Both sides must hit a matching pair of ports at once, and the
  probability is the product of two small numbers. `--punch-ports` higher on both sides
  helps; a relayed fallback would help more, and this tool does not have one.
- **`mapping=unbestimmt`** with several bound sockets — probing spread too thin. It
  raises the probe count on its own now; if you pinned `--probe-count`, unpin it.

### The transfer is slower than expected

A peer-to-peer connection cannot be faster than the weaker of two legs: the sender's
upload and the receiver's download. Measure both separately against the relay with
`--bench` before suspecting the tool. The Throughput section has the numbers from a real
path and what limited them.

### Debug output

`--debug` for detailed logging, `-X` for every tuning and measurement switch.

## References


These papers and implementations informed the NAT probing and prediction approach:

- Kazuhiro Tobe, Akihiro Shimoda, Shigeki Goto. "Extended UDP Multiple Hole Punching Method to Traverse Large Scale NATs." https://pdfs.semanticscholar.org/953d/438516e9b2eb2bf35528de3e1fb0e9b164f8.pdf
- Daniel Maier, Oliver Haase, Juergen Waesch, Marcel Waldvogel. "NAT Hole Punching Revisited." Technical Report No. KN-2011-DiSy-02. https://kops.uni-konstanz.de/server/api/core/bitstreams/29a35a1d-40f1-4290-9d03-dae21f2b9c36/content
- Simon Keller, Tobias Hossfeld, Sebastian von Mammen. "Edge-Case Integration into Established NAT Traversal Techniques." IEEE ICCE 2022. https://downloads.hci.informatik.uni-wuerzburg.de/2022-icce-keller.pdf
- Chongyc/natblaster (GitHub). https://github.com/chongyc/natblaster

Influence summary (high level):
- Multi-probe port prediction and bounded scan lists for CGN/LSN-style NATs.
- Progressing vs random symmetric NAT handling, including rate-based forward shift and heuristics.
- Practical scanning strategies and implementation patterns for NAT probing.

## License


MIT
