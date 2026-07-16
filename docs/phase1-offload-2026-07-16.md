# Phase 1 TAP Offload Validation (2026-07-16)

## Purpose

Measure the throughput and CPU effect of the Phase 1 core offload
deliverable — `IFF_VNET_HDR` + `TUNSETOFFLOAD(TUN_F_CSUM|TSO4|TSO6)`
with checksum offload, GRO super-frame receive, and TSO super-frame
transmit — against the same binary with `--tap-offload=off`, and check
the design acceptance line of 15 Gbit/s-class single-core direct
throughput (`rust-namespace-proxy-design.md` §13.2, revision ca68f9e).

## Environment

- Kernel: Linux 6.12.85+deb13-amd64 x86_64; host mihomo TUN active
  (`tun=on;proxy7890=listening`). Direct and local-proxy scenarios use
  host loopback and do not traverse the host TUN.
- yayatht release build at the TSO transmit commit (`eac2b49`); flow
  socket send buffer 256 KiB (default); all other limits default.
- Harness: `scripts/bench_tcp_phase1a.py`, 1 warmup + 3 runs per cell,
  medians reported. The sink, source, proxy, and the entire yayatht
  instance (supervisor + data plane) are pinned to **one shared CPU**
  (`--cpu 0`), so throughput is a strict whole-stack single-core figure
  and `cpu/wall` is the children's CPU seconds per wall second.
- Comparator baselines for pasta/nsproxy/proxy-ns are unchanged from
  `phase1a-performance-comparison-2026-07-14.md` (offload-off yayatht
  reproduces its ~6.4-6.6 Gbit/s 32-flow direct figure).

## Results (medians of 3 runs)

### Direct, MTU 32000

| flows | MiB/flow | offload on | offload off | gain | cpu/wall on | cpu/wall off |
| ----- | -------- | ---------- | ----------- | ---- | ----------- | ------------ |
| 32    | 4        | 8.76 Gbit/s | 6.36 Gbit/s | +38% | 1.27 | 1.22 |
| 1     | 64       | 9.42 Gbit/s | 6.94 Gbit/s | +36% | 1.61 | 1.38 |
| 32    | 64       | 11.54 Gbit/s | 7.90 Gbit/s | +46% | 1.02 | 1.01 |

The 4 MiB single-flow cell is dominated by connect and short-flow
effects (~1.6-1.8 Gbit/s both modes, high variance) and is not a
steady-state figure; the 64 MiB cells are.

### Direct, MTU 1500, 16 MiB/flow

| flows | offload on | offload off | gain |
| ----- | ---------- | ----------- | ---- |
| 1     | 4.86 Gbit/s | 1.30 Gbit/s | 3.7x |
| 32    | 9.89 Gbit/s | 1.03 Gbit/s | 9.6x |

With offload the MTU 1500 configuration reaches the same order as MTU
32000 (9.9 vs 11.5 Gbit/s at 32 flows): aggregation and checksum
offload deliver the large-MTU benefit without a jumbo namespace MTU,
as the design revision projected (§4.4).

### Local SOCKS5 proxy, MTU 32000, 32 flows, 4 MiB/flow

| offload | throughput | fairness (min) | connect p99 |
| ------- | ---------- | -------------- | ----------- |
| on      | 4.63 Gbit/s | 0.998 | 26 ms |
| off     | 3.69 Gbit/s | 0.998 | 24 ms |

No proxy-path regression; +25% aggregate. Connect p99 is unchanged by
offload — that is the separate handshake-latency backlog item (#2).

## Acceptance verdict

- Offload is the projected primary lever: +36-46% at MTU 32000 and up
  to 9.6x at MTU 1500, with byte-exact integrity enforced by the
  harness sink and the rootless integration matrix (which runs the
  full fault-injection set through the offload path, plus explicit
  `gso_frames_rx`/`gso_frames_tx` engagement assertions).
- The 15 Gbit/s-class single-core line is **not yet met**: 11.5 Gbit/s
  at 32 flows / MTU 32000 under the strictest interpretation (sink,
  source, and the whole instance sharing one core; `cpu/wall` ~1.0
  shows that core saturated by the composite, not the data plane
  alone). Remaining per-byte costs are the two copies per direction
  (socket peek into the frame, TUN copy) and per-frame syscalls; the
  design backlog assigns those to TAP multiqueue (#3, Phase 2) and
  io_uring + `SEND_ZC` (#4, Phase 2/3). No further single-reactor
  offload lever is left open here.

## Reproduction

```sh
cargo build --release
python3 scripts/bench_tcp_phase1a.py --scenarios direct --flows 1,32 \
    --tap-offload on            # and: --tap-offload off
python3 scripts/bench_tcp_phase1a.py --scenarios direct --flows 1,32 \
    --mib-per-flow 64 --tap-offload on
python3 scripts/bench_tcp_phase1a.py --scenarios direct --flows 1,32 \
    --mib-per-flow 16 --tap-mtu 1500 --tap-offload on
python3 scripts/bench_tcp_phase1a.py --scenarios local-proxy \
    --protocols socks5 --flows 32 --tap-offload on
```
