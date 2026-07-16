# Phase 1C Plan: DNS proxy-tcp and Resolver Mount

Date: 2026-07-16. Branch: `phase1b` (continues after `fbe64bd`).

## Why now: re-evaluating the Phase 1A no-go

`docs/phase1a-exit-audit.md` blocked DNS proxy-tcp on two gates. Both have
since dissolved:

1. **Kernel-compatibility gate** ("Linux 5.11 has not been exercised on an
   actual 5.11 kernel"): the project subsequently moved the baseline to
   Linux 6.6 LTS (design revision ca68f9e) and removed the capability
   probing and degraded paths entirely. There is no 5.11 surface left to
   exercise; a socket that rejects the baseline options fails its flow at
   activation.
2. **High-concurrency calibration gate**: Phase 1B closed the 15 Gbit/s-class
   throughput acceptance line (18.1 Gibit/s data-plane-per-core,
   `docs/phase1b-calibration-2026-07-16.md`) and explained the earlier
   shortfall as whole-stack pinning arithmetic. The TCP adapter's shape is
   stable enough to build DNS on.

Remaining audit concern — real-mihomo 128-flow fairness variance — is a host
TUN-path attribution question, not a TCP-adapter freeze blocker; it stays on
the Phase 1 remaining-work list.

**Decision: GO.** DNS proxy-tcp plus the resolver bind mount is the last
functional Phase 1 deliverable (design §15 Phase 1; supervisor/subreaper
already exists). Multiqueue (#3) and io_uring (#4) remain parked in
Phase 2/3 per the backlog; the per-core throughput gate is met, so no
performance work is pulled forward.

## Scope (design §9)

Implement mode 1, `proxy-tcp`, and an `off` escape hatch:

- Namespace resolver points at the virtual gateway via a bind-mounted
  `resolv.conf`; 53/UDP and 53/TCP to the gateway are intercepted.
- UDP queries are converted to DNS TCP framing and forwarded over a
  dedicated upstream TCP connection established through the configured
  upstream (proxy tunnel via the existing `Handshake` state machine, or a
  direct host socket). The connection is reused across transactions and
  never shares a business tunnel; it reconnects on demand and closes after
  a 15 s idle period.
- TCP/53 keeps stream semantics: the flow's logical target is rewritten to
  the configured resolver and the existing flow machinery carries it.
- Handled per design: EDNS0 advertised payload size, TC truncation
  fallback, multiple concurrent transactions (upstream ID rewrite so
  same-ID queries from different sources cannot collide), out-of-order
  responses, response ID + question-section validation, per-query timeout
  (5 s) answered with SERVFAIL, malformed queries answered with FORMERR,
  replies routed to the original source endpoint.

Out of scope, per design phasing: `proxy-udp` (needs SOCKS5 UDP ASSOCIATE,
Phase 2), `fake-ip` (Phase 4), `direct` resolver mode (explicit leak mode;
add when a user asks for it — selecting it now errors), general
(non-53) UDP forwarding, and connection pools beyond one resolver
connection (allowed by design, not required; add under a measured need).

## Configuration and defaults

- `--dns proxy-tcp|off`, default `proxy-tcp` (design: the default
  prioritizes correctness and leak prevention).
- `--dns-upstream <ADDR>`: explicit resolver, port defaults to 53.
  Otherwise the first `nameserver` in the host `/etc/resolv.conf` is used.
- **No resolver determinable** (this host's NetworkManager-generated
  `/etc/resolv.conf` has no `nameserver` lines at all): the instance still
  starts, still mounts the gateway `resolv.conf`, and answers every
  intercepted query SERVFAIL (TCP/53 gets RST), with one prominent startup
  warning naming `--dns-upstream`. This keeps DNS leak-free by default
  without failing TCP-only workloads at startup.
- Loopback resolver behind a proxy upstream gets a startup warning (the
  proxy connects to its *own* loopback), but is honored — the local-mihomo
  environment resolves this way on purpose.

## Stages

### Stage 1: Decision record and config surface

**Goal**: This document, audit addendum, `--dns`/`--dns-upstream` plumbed
from CLI through `LaunchConfig` into the reactor `Config`.
**Success Criteria**: `--dns off` reproduces today's behavior; invalid
combinations rejected with clear errors.
**Tests**: config validation unit tests.
**Status**: Complete (`c576fa3`)

### Stage 2: Resolver bind mount and TCP/53 redirect

**Goal**: `resolv.conf` with the gateway nameserver(s) written to the
instance directory and bind-mounted over `/etc/resolv.conf` by ns-init;
gateway:53 TCP flows redirected to the resolver.
**Success Criteria**: `cat /etc/resolv.conf` in the namespace shows the
gateway; a TCP/53 connection reaches the resolver through the proxy.
**Tests**: rootless integration cases for both.
**Status**: Complete (`9057111`)

### Stage 3: UDP parsing and the DNS transaction engine

**Goal**: UDP/53 interception, DNS-over-TCP upstream client, transaction
table with ID rewrite, EDNS0/TC/FORMERR/SERVFAIL handling, `dns_*` metrics.
**Success Criteria**: pure-logic unit tests for framing, ID allocation,
question validation, truncation, and error synthesis all pass.
**Tests**: unit tests beside `dns.rs` and `packet/udp.rs`.
**Status**: Complete (`4995fef`)

### Stage 4: Integration matrix, docs, gates

**Goal**: end-to-end rootless coverage and closure documentation.
**Success Criteria**: UDP query via mock SOCKS5 + mock TCP resolver;
out-of-order responses; concurrent same-ID queries; TC fallback retried
over TCP/53; FORMERR; timeout SERVFAIL; busybox `nslookup` smoke; docs
updated; `cargo fmt --check`, `clippy -D warnings`, serial workspace tests
all green.
**Tests**: new cases in `crates/cli/tests/rootless.rs`.
**Status**: Complete

## Verification (2026-07-16)

- `cargo fmt --all --check`, `cargo clippy --workspace --all-targets
  --all-features -- -D warnings`, and `cargo test --workspace --
  --test-threads=1` (39 rootless integration tests, 11 of them new DNS
  cases) all pass. `cargo deny` is not installed on this host, unchanged
  from the Phase 1A/1B audits.
- New rootless coverage: resolv.conf mount contents (`--dns off`
  contrast), TCP/53 redirect target through mock SOCKS5, no-resolver RST,
  UDP query through a dedicated proxy tunnel, out-of-order responses to
  concurrent same-ID queries, TC truncation with TCP retry, EDNS0 payload
  sizing, FORMERR, timeout SERVFAIL, and a busybox `nslookup` smoke test.
- Live check in the documented host environment: `yayatht run --socks5
  127.0.0.1:7890 --dns-upstream 1.1.1.1 -- busybox nslookup example.com
  192.0.2.1` resolves A and AAAA through mihomo.
- One EOF-ordering bug was found by the same-ID integration test and
  fixed: responses buffered ahead of a resolver EOF are answered before
  the teardown SERVFAILs the remainder.
