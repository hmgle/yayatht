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
- Credential files are opened before namespace creation with `O_NOFOLLOW`,
  owner and mode checks. Supervisor and ns-init copies are dropped before the
  target namespace is cloned.

## Verification Environment

Rootless integration tests use loopback SOCKS5 and HTTP mock servers. This is
an intentional deviation from the normal mihomo endpoint at `127.0.0.1:7890`
so the tests validate protocol behavior without depending on host proxy state,
DNS, or external routing.

## Remaining Phase 1 Work

- Zero-window probes and broader loss and retransmission injection.
- Bounded handshake-pending namespace payload queues.
- DNS proxy-tcp and resolver mount isolation.
- Generated seccomp profiles, pivoted data-plane filesystem, and rlimits.
- Structured metrics export, failure matrix expansion, and 24-hour soak tests.
