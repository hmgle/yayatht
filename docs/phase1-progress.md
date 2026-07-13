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
- Credential files are opened before namespace creation with `O_NOFOLLOW`,
  owner and mode checks. Supervisor and ns-init copies are dropped before the
  target namespace is cloned.

## Verification Environment

Rootless integration tests use loopback SOCKS5 and HTTP mock servers. This is
an intentional deviation from the normal mihomo endpoint at `127.0.0.1:7890`
so the tests validate protocol behavior without depending on host proxy state,
DNS, or external routing.

## Remaining Phase 1 Work

- Add repeated retransmission loss and FIN loss beyond the current consecutive
  data-segment loss coverage.
- Extend the reproducible direct benchmark to multiple flows, latency and a
  non-local destination; the initial single-flow results are recorded in
  `docs/phase1-calibration.md`.
- DNS proxy-tcp and resolver mount isolation.
- Generated seccomp profiles, pivoted data-plane filesystem, and rlimits.
- Structured metrics export, failure matrix expansion, and 24-hour soak tests.
