# Phase 1A Exit Audit

## Decision

**PARTIAL / NO-GO for Phase 1B DNS work.**

The proposed ordering was correct: explicit proxy calibration, kernel
capability degradation, instance resource limits, and the TCP fault matrix are
more fundamental than DNS interception. The former short-flow blocker is now
explained and removed: it was cumulative transfer time from an unscaled receive
window, per-segment ACK refresh overhead, and nested TCP coalescing, not a
100 ms reactor stall. Linux 5.11 has not been exercised on an actual 5.11
kernel, and real-mihomo 128-flow fairness remains variable.

DNS proxy-tcp should therefore remain blocked. The current TCP adapter remains
the working implementation, but the kernel-compatibility and high-concurrency
calibration gates do not yet justify freezing it for Phase 1B.

## Delivered in this audit

- `FlowSide` now records `{ interface, local_endpoint, logical_peer,
  transport_peer }`. Namespace lookup and packet generation derive their tuple
  from the active initiating side instead of retaining a second copy in
  `Flow`.
- `TCP_INFO` fields are gated by the length returned by `getsockopt()`.
  `tcpi_bytes_acked`, `tcpi_snd_wnd`, and `tcpi_unacked` are never assumed to
  exist merely because the build headers contain them.
- TCP `SO_PEEK_OFF` is probed per activated flow. Unsupported sockets use a
  bounded scatter/iovec prefix skip without consuming retransmit storage.
- Missing `tcpi_bytes_acked` uses a conservative ACK path: submitted bytes are
  acknowledged only when the socket output queue is empty and
  `tcpi_unacked == 0`. The advertised window is limited to 8 KiB in this mode.
- `tcpi_snd_wnd` availability is still probed and reported, but since
  `8d3bbe1` the advertised namespace window is bounded by send-buffer
  occupancy rather than by the upstream peer window; see
  `phase1a-reactor-wakeup-2026-07-15.md` for the silly-window stall this
  removed.
- Capability and degraded-flow counters are exported through `yayatht status
  --json`; degraded flows also emit a structured warning.
- Instances have configurable global pending and socket-retained byte limits,
  per-flow receive/send socket quotas, high/low-water backpressure, and a hard
  data-plane `RLIMIT_NOFILE` derived from `max_tcp_flows + 32`.
- Status metrics include current, peak, and configured pending/retained bytes,
  active and peak flows, socket buffers, frame-pool exhaustion, zero windows,
  resource-limit hits, capability modes, and the fd budget.
- Fault injection covers a lost SYN-ACK, lost data retransmission, lost FIN,
  lost FIN-ACK, repeated-loss backoff and retry limit, bidirectional
  half-close, proxy death during handshake and after a partial write, and a
  rootless local sequence wrap.
- `scripts/bench_tcp_phase1a.py` runs direct, local proxy, and mihomo matrices
  with 1/8/32/128 flows. It reports aggregate throughput, child and proxy CPU,
  connect and completion p50/p99, per-flow throughput range, Jain fairness,
  revisions, numeric targets, requested TAP MTU and send-buffer size, and
  mihomo TUN state.
- TCP Window Scale is negotiated when the namespace offers it. The flow keeps
  a monotonic receive-window right edge, and upstream ACK state is refreshed
  once per touched flow per TAP batch instead of once per segment.
- Forwarding sockets use `TCP_NODELAY`. The configurable TAP MTU defaults to
  32000, while the dynamically sized frame pool remains bounded to 16 MiB and
  exports its effective dimensions through status metrics.

## Validation environment

- Date: 2026-07-14.
- Kernel: Linux 6.12.85, x86_64.
- Host networking: mihomo TUN enabled; table 2022 and the `198.18.0.0/30` TUN
  route were present.
- External proxy: `127.0.0.1:7890`.
- mihomo: Meta v1.19.24, linux/amd64, Go 1.26.2.
- CPU affinity: benchmark children pinned to CPU 0. The already-running mihomo
  process was not repinned; its `/proc` CPU delta is reported separately.
- Numeric real-proxy target: `172.16.10.5`, the host's non-TUN IPv4 address.
- Numeric local-proxy logical target: `198.51.100.77`; the benchmark proxy
  redirects the same port to `172.16.10.5`. This prevents local-address bypass
  while keeping DNS out of the path.
- yayatht baseline revision: `d3ad8fb` for the original wide matrices.
- yayatht post-fix benchmark revision: `f8524cf`.
- Official pasta: `6ef3d1c86ffc690a17a9a4445df4a741446bcd44`.
- proxy-dev pasta: `c7568f543bdf69684e175b237298fb444c51669d`.
- nsproxy: `2029a6257f53aef19451ac99fb5e160f76f7c179`.
- proxy-ns: `5d08d18f9171d7e65fabad06ee81021d9bca0a21`.

The original wide matrix used 4 MiB per flow and one measured pass. The
post-fix matrices used one warmup followed by three measured passes; the
single-flow short-transfer check used one warmup and five measured passes.
These are calibration results, not publication-quality statistics.

The fresh same-host comparison against official pasta, proxy-dev pasta,
nsproxy, and proxy-ns is recorded in
`docs/phase1a-performance-comparison-2026-07-14.md`.

## Direct adapter gate

The existing 128 MiB single-flow test was repeated twice after resource limits
were added:

| Backend | Median throughput | Observed range |
| --- | ---: | ---: |
| yayatht direct | 1.346 Gibit/s | 1.340--1.352 Gibit/s |
| pasta 6ef3d1c direct | 0.202 Gibit/s | 0.201--0.203 Gibit/s |

The 4 MiB-per-flow concurrency pass was:

| Flows | yayatht | pasta 6ef3d1c |
| ---: | ---: | ---: |
| 1 | 0.339 Gibit/s | 0.049 Gibit/s |
| 8 | 0.255 Gibit/s | 0.185 Gibit/s |
| 32 | 0.527 Gibit/s | 0.360 Gibit/s |
| 128 | 0.800 Gibit/s | 0.823 Gibit/s |

The bulk direct target remains satisfied. At 128 short concurrent flows pasta
slightly led aggregate throughput, while yayatht's Jain fairness was 0.446
versus pasta's 0.723. This fairness result should be retained as a regression
target even though aggregate direct throughput passes.

The post-fix 32000-MTU direct matrix, using 4 MiB per flow, was:

| Flows | Throughput | Completion p99 | Fairness |
| ---: | ---: | ---: | ---: |
| 1 | 1.783 Gibit/s | 17.4 ms | 1.000 |
| 8 | 4.923 Gibit/s | 49.4 ms | 1.000 |
| 32 | 6.679 Gibit/s | 143.8 ms | 0.995 |
| 128 | 6.414 Gibit/s | 617.5 ms | 0.997 |

## Local explicit-proxy calibration

The following comparator tables are the pre-fix baseline.

All backends below used the same Rust benchmark proxy and the same redirected
numeric target. Values are aggregate Gibit/s for one 4 MiB transfer per flow.

### SOCKS5 no-auth

| Flows | yayatht | proxy-dev c7568f5 | nsproxy |
| ---: | ---: | ---: | ---: |
| 1 | 0.205 | 3.050 | 1.382 |
| 8 | 0.174 | 0.078 | 3.187 |
| 32 | 0.499 | 0.298 | 3.969 |
| 128 | 0.536 | 0.796 | 3.863 |

### HTTP CONNECT

| Flows | yayatht | proxy-dev c7568f5 | nsproxy |
| ---: | ---: | ---: | ---: |
| 1 | 0.029 | 2.695 | 1.306 |
| 8 | 0.263 | 0.350 | 3.242 |
| 32 | 0.504 | 0.456 | 3.705 |
| 128 | 0.497 | 1.051 | 3.634 |

The one-flow pass contained retransmission-sized noise, so it was repeated five
times with one warmup. Median results were:

| Protocol/backend | Throughput | Child CPU | Connect p99 | Completion p99 |
| --- | ---: | ---: | ---: | ---: |
| SOCKS5 yayatht | 0.236 Gibit/s | 0.153 s | 6.98 ms | 132.37 ms |
| SOCKS5 proxy-dev | 2.655 Gibit/s | 0.056 s | 0.81 ms | 11.71 ms |
| SOCKS5 nsproxy | 1.386 Gibit/s | 0.031 s | 1.61 ms | 22.44 ms |
| HTTP yayatht | 0.223 Gibit/s | 0.160 s | 6.29 ms | 139.85 ms |
| HTTP proxy-dev | 2.803 Gibit/s | 0.059 s | 0.74 ms | 10.96 ms |
| HTTP nsproxy | 1.398 Gibit/s | 0.031 s | 1.74 ms | 22.17 ms |

The proxy handshake itself accounts for only about 6--9 ms of yayatht's p99.
The remaining roughly 100 ms short-flow completion penalty is therefore not
explained by SOCKS5 or HTTP parsing alone. It is consistent with an adapter
ACK/window/timer cadence and is the main no-go item.

### SOCKS5 username/password

| Flows | yayatht throughput | yayatht fairness | nsproxy throughput | nsproxy fairness |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 0.229 | 1.000 | 1.418 | 1.000 |
| 8 | 0.263 | 0.478 | 3.514 | 0.945 |
| 32 | 0.514 | 0.430 | 3.818 | 0.989 |
| 128 | 0.507 | 0.864 | 4.036 | 0.962 |

proxy-dev's authenticated SOCKS5 run did not complete within 10 seconds. This
is recorded as a proxy-dev limitation, alongside its blocking handshake, old
TCP core, and credential exposure through argv; it is not used as a yayatht
correctness oracle.

nsproxy uses a different TUN/lwIP architecture and is not a like-for-like TCP
adapter baseline. Its results nevertheless show that the local proxy and sink
were not the bottleneck.

### Post-fix re-run

The original 132--140 ms result did not contain a 100 ms idle period: strace
showed a smooth reactor cycle with no 100 ms gaps, ruling out a timer stall.
At 0.23 Gibit/s, transferring 4 MiB itself takes about 140 ms. The limiting
chain was:

1. No Window Scale capped each end-to-end ACK round at 64 KiB: the SYN-ACK
   never offered the kind-3 option and the advertised window was clamped to
   `u16::MAX`.
2. Each received segment triggered about eleven `getsockopt` calls (TCP_INFO,
   queue depths, buffers) plus one immediate bare ACK. Sharing one refresh at
   the end of the TAP batch cut a 4 MiB transfer from 33483 to 391
   `getsockopt` calls.
3. Nagle on the forwarding socket coupled short tails to upstream delayed ACKs.
4. MTU 1500 framing cost roughly 2900 TAP read and socket write pairs per
   4 MiB transfer; MTU 32000 reduces the same transfer to about 130 frames.

Widening the window exposed a separate correctness bug: recomputing the
advertised window from instantaneous free space could retreat an already
promised right edge. The flow now tracks an absolute, monotonic receive edge.

The complete local re-run used MTU 32000 and the bounded 256 KiB per-flow
socket buffers:

| Protocol | Flows | Throughput | Completion p99 | Fairness |
| --- | ---: | ---: | ---: | ---: |
| SOCKS5 | 1 | 1.091 Gibit/s | 28.6 ms | 1.000 |
| SOCKS5 | 8 | 2.719 Gibit/s | 90.3 ms | 1.000 |
| SOCKS5 | 32 | 3.710 Gibit/s | 263.7 ms | 0.998 |
| SOCKS5 | 128 | 3.686 Gibit/s | 1.082 s | 0.981 |
| SOCKS5 auth | 1 | 0.894 Gibit/s | 34.9 ms | 1.000 |
| SOCKS5 auth | 8 | 2.781 Gibit/s | 88.7 ms | 1.000 |
| SOCKS5 auth | 32 | 3.850 Gibit/s | 254.4 ms | 0.999 |
| SOCKS5 auth | 128 | 3.668 Gibit/s | 1.088 s | 0.986 |
| HTTP | 1 | 0.926 Gibit/s | 33.7 ms | 1.000 |
| HTTP | 8 | 2.766 Gibit/s | 88.9 ms | 1.000 |
| HTTP | 32 | 3.633 Gibit/s | 270.1 ms | 0.999 |
| HTTP | 128 | 3.656 Gibit/s | 1.093 s | 0.974 |

Five-run single-flow medians were 37.5 ms for SOCKS5 and 32.5 ms for HTTP in
an earlier focused pass. Raising `--tcp-send-buffer-bytes` from 256 KiB to
4 MiB produced 33.4/36.6 ms rather than a stable improvement, so the bounded
default remains unchanged.

An isolated SOCKS5 MTU sweep showed that 32000 is the multi-flow knee on this
host:

| MTU | 1-flow throughput | 32-flow throughput | 32-flow fairness |
| ---: | ---: | ---: | ---: |
| 1500 | 0.556 Gibit/s | 0.514 Gibit/s | 0.638 |
| 16000 | 0.812 Gibit/s | 3.219 Gibit/s | 0.999 |
| 32000 | 0.852 Gibit/s | 3.689 Gibit/s | 1.000 |
| 65520 | 1.015 Gibit/s | 3.257 Gibit/s | 0.991 |

The 65520 setting improves one flow but regresses aggregate 32-flow throughput;
32000 therefore remains the default while all four values stay available for
deployment-specific calibration.

## Real mihomo interoperability

The real deployment path used `127.0.0.1:7890` with TUN enabled. The pre-fix
selected repeated results were:

| Protocol/flows | Throughput | Child CPU | Connect p99 | Completion p99 | Fairness |
| --- | ---: | ---: | ---: | ---: | ---: |
| SOCKS5 / 32 | 0.869 Gibit/s | 1.178 s | 16.11 ms | 1.145 s | 0.998 |
| HTTP / 32 | 0.843 Gibit/s | 1.215 s | 33.25 ms | 1.181 s | 0.998 |
| SOCKS5 / 128 | 0.424 Gibit/s | 9.447 s | 280.42 ms | 9.386 s | 0.945 |
| HTTP / 128 | 0.388 Gibit/s | 10.334 s | 196.68 ms | 9.803 s | 0.936 |

One initial 32-flow pass fell to 0.096--0.121 Gibit/s. After a warmup, three
repeats were stable at 0.863--0.885 Gibit/s for SOCKS5 and
0.820--0.860 Gibit/s for HTTP. This transient is attributed to the shared host
TUN/deployment environment rather than recorded as an adapter regression.

The post-fix three-run medians were:

| Protocol/flows | Throughput | Connect p99 | Completion p99 | Fairness |
| --- | ---: | ---: | ---: | ---: |
| SOCKS5 / 32 | 3.948 Gibit/s | 26.7 ms | 247.3 ms | 0.997 |
| HTTP / 32 | 4.342 Gibit/s | 36.0 ms | 224.8 ms | 0.985 |
| SOCKS5 / 128 | 4.959 Gibit/s | 203.6 ms | 804.6 ms | 0.728 |
| HTTP / 128 | 4.510 Gibit/s | 184.3 ms | 879.3 ms | 0.759 |

Aggregate throughput is strong, but 128-flow fairness varied materially from
the local result and remains an open host-TUN/high-concurrency calibration
item. It is not attributed to yayatht without an isolated proxy environment.

proxy-ns could not be exercised from the source-tree binary in this
environment. A private config was supplied, but the binary exited with status
1 and no diagnostic output; it also had no installed file capabilities. This
is an unavailable comparator, not a yayatht interoperability failure.

## Capability and resource gates

The running 6.12 kernel exposes `SO_PEEK_OFF`, `tcpi_bytes_acked`, and
`tcpi_snd_wnd`. A rootless integration test forcibly disables all three
capabilities and completes a TCP echo through the iovec, conservative-ACK, and
fixed-window fallbacks. Prefix-length unit tests cover older `TCP_INFO`
layouts.

This proves the fallback logic is reachable, but not the complete Linux 5.11
runtime contract. A real 5.11 VM or CI worker is still required before release.

Default instance resource bounds are:

| Resource | Default hard bound |
| --- | ---: |
| Global pending namespace-to-socket payload | 64 MiB |
| Global socket-retained unacked payload | 64 MiB |
| Per-flow `SO_RCVBUF` quota | 256 KiB |
| Per-flow `SO_SNDBUF` quota | 256 KiB |
| TAP MTU | 32000 bytes, configurable 1280--65520 |
| TAP frame pool payload capacity | at most 16 MiB |
| TCP flows | 4096 |
| Data-plane `RLIMIT_NOFILE` | 4128 |
| Worst configured socket-buffer budget | 2 GiB |

The limits are enforced and exported. The 2 GiB theoretical default socket
budget is explicit now, but should be reviewed before a production default is
frozen.

## Fault matrix

The serial rootless suite passes all 25 integration cases, including:

- consecutive data loss and a lost first retransmission;
- lost SYN-ACK, FIN, and FIN-ACK;
- live zero-window persistence;
- bidirectional half-close;
- proxy exit during handshake;
- proxy exit after a partial write with a subsequent flow succeeding;
- local sequence wrap during a live transfer;
- conservative kernel-capability fallback;
- global pending and retained byte caps.

Unit tests additionally verify wrapped partial ACK accounting, namespace
sequence wrap, exponential retransmission backoff, and the maximum retry count.

## Exit checklist

| Gate | Result | Reason |
| --- | --- | --- |
| Direct benchmark reaches pasta target | PASS | Bulk direct remains 1.340--1.352 Gibit/s versus pasta 0.201--0.203 Gibit/s. |
| SOCKS5/HTTP has no unexplained severe degradation | PASS | Repeated local 4 MiB single-flow completion is about 29--35 ms; the former 132--140 ms result is explained and removed. |
| Multi-flow proxy calibration is stable | **PARTIAL** | Local fairness is 0.97+ through 128 flows and real-mihomo 32-flow fairness is strong, but real-mihomo 128-flow fairness varied around 0.73--0.76. |
| Fault matrix passes | PASS | 25 rootless integration tests plus retry/wrap unit tests pass. |
| Missing old-kernel capabilities have fallbacks | IMPLEMENTED | All degraded paths pass forced tests; actual Linux 5.11 validation remains pending. |
| Multi-flow memory and fd have hard instance limits | PASS | Global bytes, per-flow buffers, flow count, and fd rlimit are enforced and observable. |
| Go/no-go report exists | PASS | This document records the current decision and evidence. |

## Required work before reconsidering GO

1. Separate real-mihomo 128-flow host-TUN variance from yayatht behavior in an
   isolated proxy environment and retain the local fairness result as a gate.
2. Add an actual Linux 5.11 validation job, not only forced capability
   suppression on 6.12.
3. Decide whether the default 2 GiB worst-case socket-buffer budget is
   acceptable or lower the default flow/buffer settings.
4. Re-run proxy-ns only in an environment with its required installation and
   capability model; do not grant host file capabilities merely to satisfy a
   benchmark.

Until these are resolved, do not start DNS proxy-tcp or freeze the final
seccomp/rlimit profile around a still-changing TCP data path.
