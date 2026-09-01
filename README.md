# tcp-multi-transfer

Send a file directly between two machines behind NAT. No relay in the data path — the
relay only introduces the peers, then they punch a hole and talk to each other.

Rust client, Python relay. SHA256 end to end.

## Install

Grab a binary from [releases](https://github.com/well0nez/tcp-multi-transfer/releases),
or build it:

```bash
cargo build --release        # target/release/tcp-multi-transfer
```

The relay needs Python 3 and two reachable ports (9999 and 9998 by default).

## Use it

Start the relay somewhere with a public address:

```bash
python3 run_server.py
```

Receiver first, then the sender, both with the same session ID:

```bash
./tcp-multi-transfer -s relay:9999 -i my-session -m receive
./tcp-multi-transfer -s relay:9999 -i my-session -m send -f video.mp4
```

That is all. The defaults are derived from measurements — there is nothing to tune for a
normal transfer.

## What happens

1. Both peers register with the relay under the same session ID.
2. The relay probes each NAT: how it hands out external ports, whether its mapping is
   reusable, whether it filters by source port.
3. From that it works out which ports each side has to open for the other.
4. Both punch at a synchronized moment. Several local ports at once, because a NAT that
   allocates unpredictably needs several tries in parallel to be hit.
5. The file goes over the direct connection, in blocks with a checksum each, verified by
   SHA256 at the end.

Multiple connections (`--tcp-connections`) are punched one at a time so both sides stay
in step. On the mobile link this was measured *not* to increase throughput — the
bottleneck is the path, not the number of streams.

## Options

`-h` for everyday use, `-X` adds every tuning and measurement switch.

```
Multi-TCP file transfer with NAT traversal (hole punching)

Usage: tcp-multi-transfer [OPTIONS] --server <SERVER> --session-id <SESSION_ID> --mode <MODE>

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

## Why it works

The punch succeeds when the set of NAT mappings one side holds **at the same time**
intersects the set of ports the other side has opened:

```
P = 1 − (1 − k/N)^m
```

`m` local ports held, `k` ports covered by the peer, `N` the width of the band the NAT
allocates from. Only *simultaneously* held sockets count — a closed socket takes its
mapping with it. That is why a longer timeout never helped and a wider scan did.

The relay measures `N` per session and works out the `k` it needs from the `m` the client
reports. On the measured path that is 42 to 52 candidates instead of a flat 512: the same
reliability with an eighth of the sockets.

The derivation, the NAT taxonomy behind it, the throughput measurements and the wire
protocol are in **[docs/nat-und-punching.md](docs/nat-und-punching.md)**. What changed in
this release and why is in [CHANGELOG.md](CHANGELOG.md).

## Tests

```bash
python3 -m unittest discover -s tests   # analyzer against recorded fixtures, relay coordination
./regression.sh                          # real transfers over loopback
```

Both run in CI on every push, alongside a warning-free build on Linux, macOS and Windows.

## Troubleshooting


## License



MIT
