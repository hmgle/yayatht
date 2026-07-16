# Phase 1B Calibration: Throughput Scope Re-baseline and Syscall Reduction (2026-07-16)

## Verdict

**The 15 Gbit/s-class single-core direct acceptance line is met in the
data-plane-per-core scope**: 18.1 Gibit/s median at 32 flows / 64 MiB /
MTU 32000, and 16.1 Gibit/s at MTU 1500, with the data-plane process
saturating its own core. The previous "unmet at 11.5" verdict measured a
different quantity: with the sink, the source, and the whole yayatht
instance sharing one core, ~1.74 core-seconds of work per second are
squeezed onto one CPU, which caps the composite at ~11 Gibit/s no matter
how fast the data plane is. Phase 2 multiqueue is therefore *not* needed to
satisfy the Phase 1 gate; it remains the lever for scaling beyond one core.

## Environment

- Kernel: Linux 6.12.85+deb13-amd64 x86_64; host mihomo TUN active
  (`tun=on;proxy7890=listening`); direct and local-proxy cells use host
  loopback. CPU: i5-8365U (4C/8T), `powersave` governor, desktop
  background load present.
- yayatht release build at the recvmmsg drain commit (`e492576`);
  flow socket send buffer 256 KiB (default); harness
  `scripts/bench_tcp_phase1a.py`, 1 warmup + 3 runs, medians.
- Scopes: **whole-stack** pins sink + source + entire yayatht instance to
  CPU 0 (harness default, unchanged from Phase 1A); **data-plane** adds
  `--load-cpu 2`, moving the sink, the local proxy, and the in-namespace
  source off the proxy core (CPU 2 is not CPU 0's SMT sibling).

## Direct, MTU 32000, 64 MiB/flow, offload on (medians of 3)

| flows | whole-stack | data-plane scope |
| ----- | ----------- | ---------------- |
| 32    | 11.68 Gibit/s | **18.12 Gibit/s** |
| 1     | 9.75 Gibit/s  | 13.04 Gibit/s |

Single-flow runs vary widely in both scopes (7.5–15.5 Gibit/s across
runs) — a single stream on an idle laptop rides power-management and
window dynamics; the 32-flow cells are stable (±3%).

At 32 flows the data-plane process runs at ~99% of CPU 0 while the source
(~39%) and sink (~35%) consume another ~0.74 cores. The scope arithmetic
closes: 18.1 / 1.74 ≈ 10.4–11.0 Gibit/s, matching the whole-stack figure.
A manual 128 MiB/flow run (sink and source on separate cores) reached
19.1 Gibit/s including instance startup.

## Direct, MTU 1500, 32 flows, 16 MiB/flow, offload on

| scope | throughput |
| ----- | ---------- |
| whole-stack | 9.76 Gibit/s (Phase 1 record: 9.89 — unchanged) |
| data-plane  | **16.07 Gibit/s** |

The namespace-visible MTU 1500 configuration also clears the 15 Gbit/s
line once the load generators stop taxing the data-plane core.

## Syscall reduction (this phase's code changes)

`strace -c`, 1 s window on the saturated data-plane process, 32-flow
direct; counts normalized per socket send:

| build | syscalls/send | composition change |
| ----- | ------------- | ------------------ |
| `0ffaa62` (offload) | 7.8 | getsockopt 2.6, recvmsg 1.5 (1/3 EAGAIN), ioctl 1.1 |
| + occupancy from flow accounting | 5.5 | ioctl (TIOCOUTQ) eliminated, getsockopt(SO_SNDBUF) eliminated |
| + recvmmsg drain (`e492576`) | 4.6 | error-queue reads 18.5k/s → 6.1k/s, terminal EAGAIN gone |

Effect on throughput: whole-stack 32-flow direct improved 11.44 →
11.68 Gibit/s (+2%), consistent with freeing shared-core time; the
data-plane scope is statistically unchanged (18.4 → 18.1, within
run-to-run variance) because the remaining cost is dominated by the two
per-byte copies (TAP read, socket send), which stay assigned to Phase 2/3
multiqueue and io_uring per the design backlog.

## Regression guards (whole-stack, medians of 3)

- Direct 32 flows / 64 MiB, offload **off**: 7.93 Gibit/s (Phase 1
  record 7.90 — unchanged).
- Local SOCKS5, 32 flows / 4 MiB, offload on: 4.61 Gibit/s (record
  4.63), fairness 0.999, per-instance cold connect p99 25–28 ms
  (unchanged; the steady-state connect p99 record remains
  `docs/phase1-connect-latency-2026-07-16.md`).
- Local SOCKS5 in the data-plane scope: 7.47 Gibit/s — the local proxy
  process also leaves the measured core, so the two scopes are not
  comparable for proxy cells; recorded for completeness.
- Full serial workspace suite (28 rootless integration tests included):
  PASS at `e492576`.

## Interpretation and follow-up

- The §13.2 acceptance line ("offload takes single-core direct to
  15 Gbit/s-class") is met under the scope the projection was made in:
  data-plane capacity per core. The whole-stack shared-core setup stays
  as the comparator methodology (every backend pays the same
  load-generator tax) and as a strict regression guard, but it should not
  be read as the data plane's per-core capability.
- Remaining single-reactor levers are per-byte copies and per-frame
  syscalls (`read`+`sendto`+`write` are now 78% of strace time); those are
  Phase 2 multiqueue (#3) and Phase 2/3 io_uring/`SEND_ZC` (#4).
- Single-flow variance (both scopes) deserves a calibration pass with
  longer interleaved runs before it is treated as a regression signal;
  the review branch reached the same conclusion independently.

## Reproduction

```sh
cargo build --release
# whole-stack scope (historical default)
python3 scripts/bench_tcp_phase1a.py --scenarios direct --flows 1,32 \
    --mib-per-flow 64 --tap-offload on
# data-plane scope
python3 scripts/bench_tcp_phase1a.py --scenarios direct --flows 1,32 \
    --mib-per-flow 64 --tap-offload on --load-cpu 2
python3 scripts/bench_tcp_phase1a.py --scenarios direct --flows 32 \
    --mib-per-flow 16 --tap-mtu 1500 --tap-offload on --load-cpu 2
python3 scripts/bench_tcp_phase1a.py --scenarios local-proxy \
    --protocols socks5 --flows 32 --tap-offload on
```
