# Implementation Plan: Connect-Latency Convergence (Phase 1 backlog #2)

Design basis: `rust-namespace-proxy-design.md` §13.2/§13.3 (revision
ca68f9e) — single-flow connect p99 must converge from ~14 ms (direct)
/ ~24-26 ms (local SOCKS5) toward < 3 ms without giving up nonblocking
concurrency. The cost is constant per connect (not a tail), also on the
direct path, so the root cause must be measured before touching the
handshake state machine.

## Stage 1: Connect-latency diagnosis

**Goal**: A measured breakdown showing where the ~14 ms lives:
harness measurement semantics, warm-vs-cold instance behavior, and the
reactor-side SYN → upstream connect → SYN-ACK timeline.
**Success Criteria**: The dominant contributor is identified with
numbers, reproducible by a documented experiment.
**Tests**: Experiment scripts/commands recorded; no product change yet.
**Status**: Complete — the data-plane path is ~250 us even cold; the
14 ms class is platform power management (powersave governor + deep
cpuidle exits across the multi-process wakeup chain) on first connects
of an idle machine. pasta dodges most of it with one fewer wakeup and
a hot-by-construction single process.

## Stage 2: Fix the dominant cost + handshake metrics

**Goal**: Remove the dominant contributor (candidates per design doc:
fewer handshake event round-trips, earlier upstream connect launch;
`optimistic_syn_ack` only if semantics-preserving options fall short);
export a permanent handshake-latency signal through status metrics.
**Success Criteria**: Warm-instance connect latency at or under the
target on the direct path; proxy paths improved proportionally; full
serial matrix passes.
**Tests**: Unit tests beside changed logic; rootless matrix; a latency
assertion only if it can be made robust under CI load.
**Status**: Complete — zero-timeout writable probe finishes immediate
upstream handshakes (loopback, local proxy) in the SYN wakeup, saving
one sleep/wake round trip; debug-level handshake timeline logs;
`scripts/bench_connect_latency.py` measures cold/warm/spin protocols.
Steady state 0.13-0.18 ms; spin-bounded cold 0.18-0.26 ms.

## Stage 3: Benchmark validation + docs closeout

**Goal**: `bench_tcp_phase1a.py` direct + local-proxy (socks5,
socks5-auth, http) at flows 1/32 confirming connect p99 against the
< 3 ms line; results and verdict recorded in `docs/`;
`phase1-progress.md` updated; this file removed.
**Success Criteria**: Reproducible results doc; no throughput or
fairness regression from Stage 2.
**Tests**: Benchmark runs; final serial workspace suite.
**Status**: Not Started
