# Phase 2 TAP Multiqueue Calibration

Date: 2026-07-18. Base revision: `00c942f` plus the Stage 5 working tree.

## Environment

- Linux `6.12.85+deb13-amd64`, x86_64.
- 4 physical cores / 8 logical CPUs.
- Release workspace build.
- Host mihomo TUN mode was active and SOCKS5 listened on `127.0.0.1:7890`.
- This calibration deliberately used `--direct --host-loopback`; all payload
  stayed on host loopback, so the result measures TAP/reactor scaling rather
  than mihomo or external routing.

## Method

The benchmark starts 32 concurrent namespace TCP sources and 32 host sinks.
Each flow transfers 64 MiB, for 2 GiB per run. Worker counts 1 and 4 each run
three times with the same binaries and topology:

```sh
cargo build --release --workspace
uv run scripts/bench_tcp_phase2_multiqueue.py \
  --workers 1,4 --flows 32 --bytes-per-flow 67108864 --repeats 3 \
  --output /tmp/yayatht-phase2-multiqueue.json
```

## Results

| Workers | Run 1 Gbit/s | Run 2 Gbit/s | Run 3 Gbit/s | Median Gbit/s |
|---:|---:|---:|---:|---:|
| 1 | 19.55 | 19.56 | 19.19 | 19.55 |
| 4 | 33.72 | 30.84 | 30.28 | 30.84 |

Four workers improved median aggregate throughput by 57.8%. The gain is not
linear because source/sink work, memory copies, and four data-plane workers
share four physical cores, but it clears the Stage 5 requirement that
multiqueue demonstrate a material multi-flow win. Single-flow performance is
not expected to improve.

The default remains `--workers 1` for stable single-flow behavior and minimal
resource use. Multi-flow workloads can opt into `--workers 4`; the rootless
suite separately covers TCP, UDP, DNS, flow affinity, shutdown, and aggregated
status under that configuration.
