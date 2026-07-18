# Phase 1 Progress

## TCP Proxy Milestone

- Added bounded, nonblocking SOCKS5 CONNECT and HTTP CONNECT state machines.
- SOCKS5 supports no-auth and RFC 1929 username/password authentication.
- HTTP CONNECT supports Basic authentication.
- The data plane connects the transport socket to the configured proxy while
  retaining the namespace destination as the logical flow target.
- SYN-ACK is delayed until proxy negotiation succeeds. The upstream
  `TCP_INFO.bytes_acked` baseline is recorded after negotiation so proxy
  handshake bytes do not advance namespace application ACKs.
- Proxy replies are parsed from `MSG_PEEK` data and only the validated response
  prefix is consumed, preserving target data already queued after the reply.
- Multiple namespace-bound segments can remain in flight up to the advertised
  window. Segment metadata is tracked without copying payload; new sends use a
  socket peek offset and retransmission rebuilds the oldest unacknowledged
  frame from the retained socket prefix.
- Flow construction records distinct initiating and target sides, including
  separate logical and transport endpoints. Entries pass through explicit
  `NEW -> INITIATED -> TARGETED -> TYPED -> ACTIVE` states before reactor events
  can use them.
- Namespace receive windows now follow the upstream TCP send window, available
  socket send-buffer space and a bounded per-flow pending queue. Payload outside
  the advertised window is rejected without advancing sequence state, and the
  namespace receive window is also applied as an upstream `TCP_WINDOW_CLAMP`.
- Namespace zero windows activate a TCP persist probe with bounded exponential
  backoff. Probe frames reuse retained socket data, do not advance `snd_nxt`, and
  are cancelled immediately when a non-zero window is observed.
- TAP output frames now come from a fixed startup pool. Socket payload is peeked
  directly into the final frame, and each readiness event can schedule a bounded
  batch of MSS-sized segments without steady-state frame or payload allocation.
- Rootless fault injection can discard new namespace-bound TCP data after
  sequence commitment. The integration suite drops two consecutive segments
  and verifies timeout retransmission plus cumulative ACK recovery without a
  copied retransmit payload.
- A live zero-window integration case pauses the namespace reader while the
  host sends 16 MiB, verifies that a persist probe is emitted, then confirms the
  full byte count after the reader resumes.
- `FlowSide` is now the endpoint source of truth, with separate local, logical,
  and transport endpoints for both initiating and target sides.
- The kernel baseline is Linux 6.6 LTS (design revision ca68f9e). `SO_PEEK_OFF`,
  a complete `TCP_INFO` (`tcpi_bytes_acked`), and `SOF_TIMESTAMPING_TX_ACK` are
  assumed present: capability probing, the iovec peek fallback, the
  conservative-ACK fallback, the fixed fallback window, and the fallback fast
  timer tick were removed. A socket that rejects these options fails its flow
  at activation instead of degrading. The timer watchdog remains as the
  recovery path for dropped TX ACK timestamp notifications.
- TAP offload is negotiated by default (`IFF_VNET_HDR` +
  `TUNSETOFFLOAD(TUN_F_CSUM|TSO4|TSO6)`, `--tap-offload=off` reverts to the
  plain frame layout): every TAP frame carries a legacy `virtio_net_hdr`,
  received `NEEDS_CSUM`/`DATA_VALID` frames skip software checksum
  verification and GRO super-frames up to the 16-bit IP limit are forwarded
  upstream in one write, transmitted TCP frames seed pseudo-header sums for
  the kernel to complete, and namespace-bound sends beyond one MSS leave as
  TSO super-frames drawn from a dedicated maximum-size pool with graceful
  degradation to MTU frames. Offload state and `gso_frames_rx/tx` counters
  are exported through status metrics; the integration matrix runs on the
  offload path and asserts engagement in both directions. Validation:
  `docs/phase1-offload-2026-07-16.md` (+36-46% direct at MTU 32000, up to
  9.6x at MTU 1500, +25% local SOCKS5, no regression).
- Global pending and socket-retained byte limits, per-flow socket quotas, and a
  max-flow-derived data-plane RLIMIT_NOFILE provide hard instance boundaries.
  High pending watermarks publish zero windows across active flows.
- The rootless fault matrix covers SYN-ACK, retransmission, FIN/FIN-ACK,
  half-close, proxy termination, partial writes, and sequence wrap.
- The Phase 1A benchmark covers direct, local SOCKS5/auth/HTTP, and real mihomo
  paths at 1/8/32/128 flows with throughput, CPU, p50/p99, connect latency, and
  fairness.
- TCP Window Scale, a monotonic advertised receive edge, TAP-batch ACK refresh,
  and `TCP_NODELAY` remove the cumulative short-flow slowdown without a 1 ms
  polling path.
- Socket writable interest is armed only while a writable event can make
  progress, and upstream ACK progress is event-driven through
  `SOF_TIMESTAMPING_TX_ACK` error-queue wakeups with a writable-poll fallback
  for kernels that reject the option. The advertised namespace window is
  bounded by send-buffer occupancy, not the upstream peer window, so the
  event-driven reactor cannot strand a sub-MSS window behind sender-side
  silly-window avoidance.
- The TAP MTU is configurable from 1280 through 65520 and defaults to 32000.
  Its dynamically sized frame pool stays within a 16 MiB payload budget and
  exports its effective dimensions through status metrics.
- Credential files are opened before namespace creation with `O_NOFOLLOW`,
  owner and mode checks. Supervisor and ns-init copies are dropped before the
  target namespace is cloned.

## Verification Environment

Rootless integration tests use loopback SOCKS5 and HTTP mock servers. This is
an intentional deviation from the normal mihomo endpoint at `127.0.0.1:7890`
so the tests validate protocol behavior without depending on host proxy state,
DNS, or external routing.

- Immediate upstream handshakes (loopback, local proxy) finish inside the
  SYN wakeup through a zero-timeout writable probe instead of a second
  reactor wakeup. Connect latency converged: steady-state p99 0.18 ms
  direct / 0.55 ms local SOCKS5, spin-bounded cold 0.2 ms — the < 3 ms
  design target is met by the software path; the double-digit
  first-connect numbers on an idle machine are platform power management
  across the wakeup chain, quantified with pasta comparison in
  `docs/phase1-connect-latency-2026-07-16.md` and reproducible via
  `scripts/bench_connect_latency.py`.

- Phase 1B closed the 15 Gbit/s-class single-core acceptance line by
  separating the measurement scopes: the harness's historical pinning put
  the sink, source, and whole instance on one shared core, capping the
  composite at ~11 Gibit/s regardless of data-plane speed. With
  `--load-cpu` moving the load generators off the proxy core, direct
  throughput is 18.1 Gibit/s at 32 flows / MTU 32000 and 16.1 Gibit/s at
  MTU 1500 — the gate is met without pulling Phase 2 multiqueue forward.
  The ACK-refresh path also dropped from 7.8 to 4.6 syscalls per socket
  send (send-buffer occupancy derived from flow accounting instead of
  `SO_SNDBUF`/`TIOCOUTQ`; error-queue timestamps drained via `recvmmsg`),
  improving the whole-stack scope 11.44 → 11.68 Gibit/s. Plan:
  `docs/phase1b-plan.md`; evidence:
  `docs/phase1b-calibration-2026-07-16.md`.

- Phase 1C lifted the Phase 1A DNS no-go (its kernel-compatibility gate
  dissolved with the 6.6 baseline; its calibration gate closed in
  Phase 1B) and delivered DNS `proxy-tcp` (design §9 mode 1) with the
  resolver bind mount. The namespace resolver points at the virtual
  gateway through an instance-owned `resolv.conf` bind-mounted by
  ns-init; gateway 53/UDP is converted to DNS-over-TCP on one dedicated
  resolver connection tunneled separately from all flow traffic, with
  upstream ID rewrite for concurrent same-ID transactions, response
  ID/question validation, EDNS0 payload sizing, TC truncation, FORMERR/
  SERVFAIL synthesis, a 5 s per-query timeout, and a 15 s idle
  disconnect; gateway 53/TCP keeps stream semantics through the normal
  flow machinery with its logical target rewritten to the resolver.
  `--dns off` restores the previous behavior; without a usable resolver
  the instance stays leak-free (SERVFAIL/RST) instead of failing
  TCP-only workloads. `dns_*` metrics are exported through status. Plan
  and verification: `docs/phase1c-plan.md`.

## Phase 1 functional close

Phase 1 functional deliverables are complete on the tree that opens Phase 2
(`ed317d6` and descendants): the TCP proxy MVP, TAP offload (backlog #1),
connect-latency convergence (backlog #2), the data-plane-per-core
throughput gate (Phase 1B), and DNS `proxy-tcp` with the resolver bind
mount (Phase 1C). The exit items that did **not** land in Phase 1 move into
Phase 2 explicitly instead of staying on this list — the sandbox as
Stage 1, so UDP does not expand the attack surface before a lock-down path
exists, and the soak/oracle work as Stage 6 quality gates. See
`docs/phase2-plan.md`.

## Remaining Phase 1 Work (dispositions)

- Per-byte copy costs (TAP read, socket send) dominate the remaining
  single-reactor profile; scaling past ~18 Gibit/s per core belongs to
  multiqueue (#3, Phase 2 Stage 5) and io_uring/`SEND_ZC` (#4, Phase 3)
  per the design backlog.
- Single-flow direct throughput variance needs longer interleaved
  calibration runs before it can gate anything (quality, unscheduled).
- Real-mihomo 128-flow fairness was rerun in Phase 2 Stage 6 and improved to
  a 0.861 median, but isolated-host attribution remains open.
- The 2 GiB TCP socket-buffer budget was reviewed in Phase 2 Stage 6; UDP and
  total ceilings are now exported and a low-memory profile is documented.
- A deterministic resolver-socket no-leak oracle passed both DNS proxy modes
  in Phase 2 Stage 6; all-interface pcap remains open because capture tools
  are unavailable on the host.
- Supervisor/ns-init generated seccomp profiles and the 1-hour mixed soak
  completed in Phase 2 Stage 6. The data-plane profile, pivoted empty tmpfs,
  and `RLIMIT_CORE=0` landed earlier in Phase 2 Stage 1.
