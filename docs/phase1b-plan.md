# Phase 1B Plan: Throughput Acceptance Re-baseline and Single-Reactor Syscall Reduction

## Background

Phase 1 landed TAP offload (`docs/phase1-offload-2026-07-16.md`) and closed
the connect-latency backlog item. The 15 Gbit/s-class single-core direct
acceptance line (`rust-namespace-proxy-design.md` §13.2) was recorded as
unmet at 11.5 Gbit/s. The parallel `review` branch implementation reached the
same verdict (8.4 Gibit/s under its 4 MiB cells, `phase1b-exit-audit.md` on
that branch) and left the gate open. Phase 1B re-examines the causal chain
"offload lands, therefore 15 Gbit/s" before pulling Phase 2 multiqueue
forward.

## Diagnosis: the gate was measured in an over-strict scope

The Phase 1A harness pins the sink, the source, and the entire yayatht
instance to **one shared CPU** (`--cpu 0`). Measured on the benchmark machine
(i5-8365U, Linux 6.12.85, offload on, MTU 32000, 32 flows):

- Whole-stack single core (harness default): 11.44 Gibit/s median,
  reproduced at `0ffaa62`.
- Data plane alone on CPU 0, sink on CPU 2, source on CPU 3, 128 MiB/flow:
  **19.1 Gibit/s** including instance startup; the data-plane process runs at
  ~99% of its core while the source (~39%) and sink (~35%) consume ~0.74
  additional cores.

The two figures are arithmetically consistent: 1.74 core-seconds of total
work per second squeezed onto one core caps composite throughput at
19.1 / 1.74 ≈ 11.0 Gibit/s. Under the shared-core scope, meeting 15 Gbit/s
would require a data plane able to move 15 Gbit/s in ~0.42 of a core —
roughly 36 Gbit/s per core — which offload alone never promised.

Conclusion: the §4.4 projection ("offload takes single-core direct from ~6.6
to 15–20 Gbit/s") holds **for the data-plane-per-core scope** that the
pasta-style comparison implies. The causal chain was not over-full; the
acceptance measurement conflated data-plane capacity with load-generator
overhead. The whole-stack scope remains valuable as a strict regression
guard, but it is the wrong scope for the 15 Gbit/s line.

## Remaining single-reactor waste (strace, saturated data plane)

A 1 s `strace -c` window on the saturated data-plane process (32 flows,
direct, offload on) shows per-second counts: 24.4k `getsockopt`, 13.9k
`recvmsg` (4.6k EAGAIN), 9.9k `ioctl`, 9.3k `sendto`, 9.3k `read`, 5.2k
`write`. Sources:

- Every upstream ACK refresh costs three syscalls: `getsockopt(TCP_INFO)`
  plus `getsockopt(SO_SNDBUF)` and `ioctl(TIOCOUTQ)` inside
  `send_buffer_available`. The last two are redundant: the flow already
  tracks `upstream_submitted` (bytes accepted by the socket) and
  `upstream_acked` (from the same `TCP_INFO` read), so the kernel send-queue
  occupancy is `upstream_unacked()` and the buffer capacity is fixed at
  socket setup.
- Every error-queue wakeup drains TX ACK timestamps one `recvmsg` at a time
  and always ends on an EAGAIN, preceded by a `getsockopt(SO_ERROR)` probe.

Per-byte copy costs (TAP read copy, socket send copy) remain assigned to
Phase 2 multiqueue (#3) and Phase 2/3 io_uring (#4); Phase 1B does not pull
them forward.

## Stages

### Stage 1: Benchmark scope separation

**Goal**: the harness can measure both scopes reproducibly.
**Changes**: `--load-cpu N` pins the sink, the local proxy, and the
in-namespace transfer command (via a `taskset` wrapper) to CPU N while the
proxy instance stays on `--cpu`; both values are recorded in every CSV row.
Default behavior (no `--load-cpu`) is unchanged.
**Success criteria**: with `--load-cpu`, the data-plane process is the only
benchmark load on `--cpu`; results record the pinning.
**Tests**: harness runs in both modes; Python AST parse.
**Status**: Complete

### Stage 2: Zero-syscall send-buffer occupancy

**Goal**: drop `getsockopt(SO_SNDBUF)` + `ioctl(TIOCOUTQ)` from the ACK
refresh path.
**Changes**: cache the effective send-buffer capacity once at flow
activation; compute occupancy as `upstream_unacked()` in
`update_namespace_window`. The estimate is conservative (acked lags reality
between `TCP_INFO` reads) except for still-unacked proxy handshake bytes,
which are bounded by the handshake size and clear within one RTT.
**Success criteria**: strace shows ~2 fewer syscalls per refresh; no
regression in the rootless matrix (zero-window, retransmit, 16 MiB pause
cases); direct throughput not worse in either scope.
**Tests**: flow-level unit test for the occupancy bound; full serial
workspace suite.
**Status**: Complete

### Stage 3: Error-queue drain batching

**Goal**: cut per-wakeup error-queue syscalls.
**Changes**: drain TX ACK timestamps with `recvmmsg` (batch of 8) instead of
one `recvmsg` per message; keep the terminal-EAGAIN semantics so
level-triggered `EPOLLERR` still clears.
**Success criteria**: fewer `recvmsg` calls per second at saturation; no
change in ACK-progress behavior (watchdog tests still pass).
**Tests**: existing watchdog/timestamp suppression tests; serial workspace
suite.
**Status**: Complete

### Stage 4: Re-calibration and acceptance record

**Goal**: recorded evidence for the re-based acceptance verdict.
**Changes**: run the direct matrix in both scopes (1/32 flows, 64 MiB;
MTU 1500 spot check; local SOCKS5 spot check), write
`docs/phase1b-calibration-2026-07-16.md`, update `docs/phase1-progress.md`,
and annotate the design-doc gate interpretation.
**Success criteria**: data-plane-scope direct ≥ 15 Gbit/s-class recorded
with medians; whole-stack scope shows no regression against 11.44.
**Status**: Complete — 18.12 Gibit/s data-plane scope, 11.68 whole-stack
(`docs/phase1b-calibration-2026-07-16.md`)

## Non-goals

- TAP multiqueue, io_uring, `MSG_ZEROCOPY`/`SEND_ZC` (stay in Phase 2/3).
- Revisiting the whole-stack pinning as a comparator methodology: cross-tool
  comparisons keep the shared-core setup, which remains fair because every
  backend pays the same load-generator tax.
