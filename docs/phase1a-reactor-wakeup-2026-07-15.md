# Phase 1A Reactor Wakeup Calibration (2026-07-15)

## Scope

This document records the same-host A/B comparison for the reactor wakeup
changes that implement items 1 and 2 of the remaining-work list in
`phase1a-performance-comparison-2026-07-14.md`:

1. Writable socket interest is armed only while a writable event can make
   progress (`38b1a82`).
2. Upstream ACK progress is event-driven through `SOF_TIMESTAMPING_TX_ACK`
   error-queue messages, with writable-interest polling as the fallback for
   kernels that reject the option (`e89b595`).
3. The advertised namespace window is no longer bounded by the upstream peer
   window (`8d3bbe1`); see the stall analysis below.

The measurements are calibration data, not publication-quality statistics.
Each value is the median of three measured runs after one warmup, on the
same host within the same session, with the baseline binary built from
`cbafc7b` (the state before these changes).

## Environment

- Date: 2026-07-15.
- Kernel: Linux 6.12.85, x86_64.
- Host networking: mihomo TUN mode enabled.
- CPU affinity: benchmark children pinned to CPU 0.
- Transfer: 4 MiB per flow.
- yayatht TAP MTU: 32000; per-flow send-buffer quota: 256 KiB.
- Numeric local-proxy target: `198.51.100.77`, redirected to `172.16.10.5`.
- Baseline: `cbafc7b`. New: `8d3bbe1`.

## Silly-window stall found during validation

The first validation pass was bimodal: single-flow SOCKS5 completed in either
9--12 ms or about 217 ms. An in-reactor event trace showed the chain:

1. The pinned proxy process was starved and its receive window collapsed, so
   `tcpi_snd_wnd` bounded the advertised namespace window to 3200 bytes,
   below one 31960-byte MSS, while the upstream socket buffer sat empty.
2. The namespace sender deferred under sender-side silly-window avoidance
   rather than fragment a full-MSS segment into the sub-MSS window.
3. When the proxy drained its buffer, the window reopening arrived as a pure
   ACK: no payload, no newly acknowledged bytes. Neither `EPOLLIN` nor a TX
   ACK timestamp fired, so the event-driven reactor never re-advertised a
   wider window.
4. The namespace persist timer forced 3200 bytes through roughly 200 ms
   later, whose TAP activity finally refreshed the window.

The polling baseline never exposed this because the busy loop re-read
`TCP_INFO` continuously. The fix drops the peer-window term from the window
computation: peer backpressure still propagates through send-buffer
occupancy, and a window bounded by occupancy can only close while
acknowledgment wakeups are outstanding. Twelve repeated single-flow SOCKS5
passes after the fix completed in 11--19 ms with no stall.

## Same-session A/B results

| Case | Baseline | New | Baseline | New | Baseline | New |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
|  | Gibit/s | Gibit/s | connect p99 | connect p99 | completion p99 | completion p99 |
| direct / 1 | 1.801 | 3.672 | 8.5 ms | 3.1 ms | 17.3 ms | 8.4 ms |
| direct / 32 | 6.117 | 6.322 | 16.5 ms | 16.3 ms | 159.8 ms | 153.4 ms |
| SOCKS5 / 1 | 1.130 | 1.982 | 5.4 ms | 4.5 ms | 27.6 ms | 15.7 ms |
| SOCKS5 / 32 | 2.654 | 3.722 | 18.0 ms | 22.5 ms | 376.2 ms | 266.8 ms |
| HTTP / 1 | 1.037 | 1.808 | 3.9 ms | 4.9 ms | 30.0 ms | 17.2 ms |
| HTTP / 32 | 2.714 | 3.637 | 20.8 ms | 24.5 ms | 367.6 ms | 266.1 ms |

Jain fairness stayed at 0.999--1.000 in every 32-flow case. Median 32-flow
child CPU fell from 0.25--0.26 s to 0.20 s for the proxy paths and from
0.19 s to 0.18 s direct. Single-flow local-proxy completion (15.7--17.2 ms)
is now below the nsproxy reference measured on 2026-07-14 (21.9--23.5 ms);
these were separate sessions, so treat that comparison as indicative.

## Real mihomo context

The production path through `127.0.0.1:7890` with TUN enabled:

| Protocol / flows | Throughput | Connect p99 | Completion p99 | Fairness |
| --- | ---: | ---: | ---: | ---: |
| SOCKS5 / 32 | 4.045 Gibit/s | 16.9 ms | 246.3 ms | 0.989 |
| HTTP / 32 | 4.264 Gibit/s | 23.2 ms | 231.1 ms | 0.950 |

This matches the best previously recorded mihomo results (3.9--4.3 Gibit/s),
so the wakeup changes did not regress the production path.

## Remaining performance work

Carried forward from the 2026-07-14 list:

1. Evaluate `IFF_VNET_HDR`, TCP GSO, and checksum offload to reduce frame and
   checksum work without increasing the namespace-visible MTU beyond 32000.
2. Use TAP multiqueue and flow-hashed reactors when scaling beyond the
   single-reactor ceiling, now about 6.3 Gibit/s direct and 3.6--3.7 Gibit/s
   through the local explicit proxy.
3. Isolate the real-mihomo 128-flow fairness result before attributing it to
   the adapter.
