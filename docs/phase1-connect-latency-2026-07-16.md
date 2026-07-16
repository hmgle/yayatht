# Phase 1 Connect-Latency Convergence (2026-07-16)

## Purpose

Close design backlog #2 (`rust-namespace-proxy-design.md` §13.2/§13.3,
revision ca68f9e): single-flow connect p99 was reported at ~14 ms
(direct) and ~24-26 ms (local SOCKS5) against a < 3 ms target.

## Diagnosis

The reported number is not produced by the handshake code path.

- Data-plane timeline (debug logs, cold instance): ARP reply, SYN
  receipt, and SYN-ACK queueing complete within **~250 us**; the
  remaining ~10 ms elapsed before the namespace kernel's first frames
  reached the TAP.
- A pre-populated permanent neighbor entry does not help (8.7 vs 8.1 ms
  control): the cost is not ARP resolution.
- Isolated cold first-connects (fresh instance, 3-5 s idle gaps) vary
  7-26 ms; the same measurement inside a warm instance is 0.1-0.3 ms
  from the second connect on.
- Pinning the whole chain to one CPU kept busy by a nice-19 spinner
  drops the **cold** first-connect to **0.17-0.30 ms** on the same
  binary. The machine runs the `powersave` governor with cpuidle
  states to C10 (890 us exit latency): a first connect crosses ~6
  process wakeups (source, data plane twice, sink), each landing on an
  idle low-frequency core, and strace's perturbation alone shrinks the
  latency (8-11 ms → 1.5-5 ms). The cost is platform power management,
  multiplied by the length of the wakeup chain.
- pasta under the same isolated-cold protocol: 0.25-0.84 ms. Its chain
  is one wakeup shorter (blocking upstream connect completes inside the
  syscall for loopback) and its single process is hot from its own
  startup, so it largely dodges the penalty. The comparative gap is
  therefore real but architectural (wakeup count and warmth), not a
  handshake state-machine defect.

## Change

`handle_tcp` now probes the just-launched nonblocking upstream connect
with a zero-timeout poll: when the kernel already completed the
handshake — the normal case for loopback and local-proxy targets —
activation (SYN-ACK, or the proxy greeting flush) happens in the same
SYN wakeup instead of sleeping until the `EPOLLOUT` event. A probed
pending error takes the existing `finish_transport_connect` failure
path; slow targets remain fully event-driven. Debug-level
ARP/SYN/SYN-ACK timeline logs and `scripts/bench_connect_latency.py`
(cold, warm, and spin-bounded protocols) keep the breakdown
reproducible.

## Results

Direct path, `bench_connect_latency.py` (6 cold instances / 20 warm
rounds; spin = chain pinned to one busy core):

| protocol | connect latency |
| -------- | --------------- |
| warm steady-state (idle machine) | p50 0.14 ms, p99 0.18 ms |
| cold first-connect, spin-bounded | 0.18-0.26 ms |
| cold first-connect, idle machine | p50 13 ms, max 21 ms |

Local SOCKS5 through `tcp-bench-proxy` (warm loop, 20 rounds):
steady-state p50 **0.38 ms**, p99 **0.55 ms** (first connect 7.2 ms,
same platform effect).

Phase 1A harness protocol (fresh instance per run, first-connect-only,
idle machine) after the change: direct 12.4 ms, socks5 16.9 ms,
socks5-auth 14.9 ms, http 13.3 ms (medians of 3).

## Verdict

- The < 3 ms target is met by the software path with a wide margin:
  0.14 ms direct / 0.55 ms SOCKS5 p99 at steady state, and 0.2 ms even
  for cold connects once platform power management is bounded.
- The residual double-digit numbers under the harness protocol measure
  an idle laptop's wakeup physics on the very first connect of a fresh
  instance. They are not closable from the handshake state machine;
  the remaining levers are fewer wakeups per connect (io_uring batching,
  Phase 2/3 backlog) and, for latency-sensitive deployments, an opt-in
  reactor busy-poll window — deliberately not implemented now because
  it trades idle CPU for latency and belongs with the io_uring backend
  decision.
- Comparisons against pasta/nsproxy must equalize the protocol
  (cold-vs-warm and CPU-idle state); the earlier 14-vs-0.5 ms table
  compared our cold path against a hotter-by-construction process.

## Reproduction

```sh
cargo build --release
python3 scripts/bench_connect_latency.py --cold 6 --warm 20
python3 scripts/bench_connect_latency.py --cold 4 --warm 20 --spin
python3 scripts/bench_tcp_phase1a.py --scenarios direct,local-proxy \
    --protocols socks5,socks5-auth,http --flows 1
```
