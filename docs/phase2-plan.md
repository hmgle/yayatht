# Phase 2 Plan: Sandbox, UDP, SOCKS5 UDP ASSOCIATE, Multiqueue

Date: 2026-07-17. Branch: `phase2` (opens after Phase 1C `ed317d6`).

## Where Phase 1 ends

Phase 1 functional deliverables are complete on this tree: the TCP proxy MVP
(SOCKS5 no-auth/RFC 1929 + HTTP CONNECT Basic, windowed retransmit,
zero-window persist, fault matrix), TAP offload (backlog #1), connect-latency
convergence (backlog #2), the data-plane-per-core throughput gate
(18.1 Gibit/s, Phase 1B), and DNS `proxy-tcp` with the resolver bind mount
(Phase 1C). The serial workspace suite carries 39 rootless integration tests,
11 of them DNS.

Three Phase 1 exit items are *not* done and are carried here rather than
silently dropped:

- **Data-plane sandbox** (design §5.3): generated seccomp profiles, a pivoted
  data-plane filesystem, and `RLIMIT_CORE=0`. Today the data plane only drops
  capabilities, sets `NO_NEW_PRIVS`, and caps `RLIMIT_NOFILE`.
- **24-hour soak** and the **DNS no-leak capture oracle** (design §12/§14).
- Quality items: real-mihomo 128-flow fairness attribution and the 2 GiB
  worst-case socket-buffer budget review.

Phase 2 (design §15) adds UDP forwarding, SOCKS5 UDP ASSOCIATE, DNS
`proxy-udp`, IPv6 parity, and TAP multiqueue. UDP multiplies the fd and
syscall surface, so the sandbox lands **first**: the lock-down path must
exist before the attack surface grows.

## Scope

Aligned with design §15 Phase 2, §5.3, §8, §9 and §11:

1. **Data-plane sandbox** (Stage 1): `syscalls.toml` manifest → build-time
   generated allowlist → hand-rolled cBPF loaded via `seccomp(2)`;
   `pivot_root` to an empty tmpfs; `RLIMIT_CORE=0`; `--sandbox on|off`.
2. **UDP core, direct/host-loopback** (Stage 2): association key
   `(family, source ip, source port)` with endpoint-independent mapping,
   logical five-tuple flows, timeout classes (DNS 15 s / one-shot 30 s /
   stream 120 s), per-flow bind+connect host sockets, `IP_RECVERR`/
   `IPV6_RECVERR` to synthesized ICMP, `udp_*` metrics, fd budget.
3. **SOCKS5 UDP ASSOCIATE** (Stage 3): RFC 1928 command 3 reusing the
   existing handshake/auth machinery, relay socket bound before ASSOCIATE,
   BND parsing with unspecified→control-peer fallback, `FRAG=0` only,
   control-EOF invalidation with jittered exponential backoff rebuild,
   association-failure isolation; HTTP CONNECT UDP answers ICMP Port
   Unreachable.
4. **DNS `proxy-udp` + IPv6 parity** (Stage 4): resolver queries relayed
   verbatim over a per-source-endpoint association (SOCKS5 only; default
   stays `proxy-tcp`); IPv6 UDP/DNS/NDP cases.
5. **TAP multiqueue + per-worker reactors** (Stage 5, backlog #3):
   `IFF_MULTI_QUEUE`, one reactor/buffer-pool/flow-slab/timer set per
   worker, kernel flow-hash affinity, supervisor-side status aggregation,
   `--workers` default 1 until calibration proves multi-worker wins.
6. **Exit work** (Stage 6): supervisor and ns-init seccomp profiles, soak
   harness, DNS no-leak oracle, memory-budget review, real-proxy interop
   notes, exit audit.

### Non-goals (unchanged phasing)

- io_uring / provided buffers / `SEND_ZC`: Phase 3 (backlog #4).
- Local-port bypass, splice pools, PGO/SIMD polish: Phase 3.
- FakeDNS and ping sockets: Phase 4.
- DNS `direct` leak mode: on explicit user request only.
- SOCKS5 fragmentation (`FRAG≠0`): dropped and counted, per design §8.1.

## Configuration and defaults

- `--sandbox on|off`, default `on`. `off` disables seccomp, the filesystem
  pivot and the core-dump clamp for diagnosis and logs a prominent warning.
- `--udp on|off`, default `on`. `off` preserves today's drop-all behavior.
- `--max-udp-flows` (default 8192) and `--max-udp-associations` (default
  2048), both feeding the data-plane `RLIMIT_NOFILE` arithmetic
  (`tcp + udp + 2·associations + headroom`).
- `--dns proxy-udp` joins `proxy-tcp|off`; valid only with `--socks5`.
- `--workers` (default 1), Stage 5.

## Design decisions

1. **No new dependencies for seccomp.** The manifest is parsed by a
   restricted hand-written reader in `build.rs`; the generated table
   references `libc::SYS_*` constants so a missing syscall number on any
   CI target (x86_64/aarch64 × gnu/musl) is a compile error — the §5.3
   fail-at-build gate. The filter is a short, auditable cBPF program:
   arch guard, allowlist, default `SECCOMP_RET_KILL_PROCESS` in release
   and in tests. Debug builds accept `YAYATHT_SECCOMP_TRACE=1` to switch
   the default action to `SECCOMP_RET_LOG` for manifest development; trace
   output never relaxes the profile automatically.
2. **Sandbox order in the data-plane child**: receive TAP fd → rlimits
   (`NOFILE`, `CORE=0`) → `pivot_root` to an empty tmpfs (the child already
   owns a private mount namespace) → drop capabilities → `NO_NEW_PRIVS` →
   load seccomp → report Ready. `pivot_root` necessarily precedes the final
   capability drop because it requires `CAP_SYS_ADMIN` in the child's user
   namespace. The control socket, TAP fd
   and stderr are already-open fds and keep working after the pivot; every
   address the data plane dials (proxy, resolver) is parsed to a
   `SocketAddr` before the namespaces are created, so nothing resolves
   names or touches the filesystem at runtime.
3. **Role scope**: Stage 1 locks the data plane only — it parses hostile
   traffic. Supervisor and ns-init profiles are declared in the manifest
   from the start but enforced in Stage 6, after the UDP/associate work
   stops moving their syscall footprint.
4. **UDP engine mirrors `dns.rs`**: a pure, unit-testable engine in
   `dataplane/src/udp.rs` owns the association/flow indices, limits and
   timeout policy; the reactor owns sockets and epoll registration.
   Direct-path sockets are bind+connected per five-tuple so the kernel
   filters foreign peers (strict EIF for free).
5. **SOCKS5 UDP header codec lives in `proxy-proto`** (it is proxy wire
   format, not IP), as `socks5_udp`; ASSOCIATE is a `Command` parameter on
   the existing `Handshake`, not a second state machine.
6. **DNS `proxy-udp` does not reuse the `dns.rs` transaction engine.** The
   proxy-tcp engine multiplexes clients onto one upstream stream and must
   rewrite IDs; over per-endpoint associations the datagram is relayed
   verbatim, the client's own ID round-trips, and loss is the stub
   resolver's retransmit problem (counted, documented). Interception keeps
   the logical target `gateway:53` so replies synthesize exactly like
   `proxy-tcp` replies.
7. **Multiqueue trusts the kernel TAP flow hash first**; software steering
   is added only if a test demonstrates cross-queue drift. Budgets (frame
   pools, slabs) divide by worker count with a floor; TCP flows belong to
   the queue that saw them, associations to their source endpoint's
   worker, and the DNS resolver connection becomes per-worker.
8. **fd budget**: the data-plane `RLIMIT_NOFILE` generalizes to
   `max_tcp_flows + max_udp_flows + 2·max_udp_associations + 32`
   (default 16416). The rootless assertion on the old `4096 + 32` value is
   updated deliberately with this change.

## Stages

### Stage 0: Plan and narrative

**Goal**: This document; `docs/phase1-progress.md` records the functional
close and where each leftover went; `README.md` matches the shipped
surface.
**Success Criteria**: docs match code reality; no behavior change.
**Tests**: none (docs only).
**Status**: Complete

### Stage 1: Data-plane sandbox

**Goal**: `syscalls.toml` + `build.rs` codegen + `sys::seccomp` cBPF
loader; `mount::isolate_filesystem()` pivot; `RLIMIT_CORE=0`;
`SandboxConfig` plumbed from `--sandbox`; supervisor wiring in
`data_plane_child`; manifest calibrated against a traced release binary.
**Success Criteria**: the default run path works fully sandboxed; a
forbidden syscall kills the data plane and tears the instance down; status
keeps answering after the pivot.
**Tests**: seccomp/manifest unit tests; rootless
`sandbox_on_by_default_runs_busybox_echo`, `sandbox_off_runs_busybox_echo`,
`forbidden_syscall_kills_the_data_plane`,
`pivoted_data_plane_still_serves_status`.
**Status**: Complete (2026-07-17). The release-shaped syscall profile was
calibrated with debug `SECCOMP_RET_LOG` plus `strace -ff`; `poll(2)` for the
immediate-connect probe was the only steady-state addition found by the TCP
echo trace. The serial workspace suite now carries 43 rootless tests.

### Stage 2: UDP core (direct / host-loopback)

**Goal**: `packet::icmp` writers; `dataplane::udp` engine; reactor demux
for non-DNS UDP; per-flow host sockets with error-queue handling; ICMP
synthesis toward the namespace; limits and `udp_*` metrics; CLI plumbing.
**Success Criteria**: UDP echo round-trips both families under
`--direct --host-loopback`; port-unreachable surfaces as ICMP in the
namespace; limits refuse and count; DNS regression stays green.
**Tests**: engine/ICMP unit tests; rootless `direct_udp_echo_round_trips`,
`ipv6_direct_udp_echo_round_trips`,
`udp_port_unreachable_synthesizes_icmpv4`,
`udp_off_drops_namespace_datagrams`.
**Status**: Complete (2026-07-18). Direct UDP uses one bind+connected socket
per logical five-tuple, with source-endpoint association accounting, bounded
receive/truncation handling, error-queue attribution, and synthesized ICMP.
The serial suite carries 47 active rootless tests plus one ignored in-namespace
UDP client helper; SOCKS5 and HTTP UDP policy remain Stage 3 work.

### Stage 3: SOCKS5 UDP ASSOCIATE

**Goal**: `Command::UdpAssociate` on the handshake with BND retention;
`socks5_udp` header codec; association lifecycle in the reactor (bind
before ASSOCIATE, next-cycle activation, relay-source validation,
EOF→jittered backoff rebuild); mock SOCKS5-UDP relay in test-support;
HTTP CONNECT UDP → ICMP Port Unreachable.
**Success Criteria**: UDP echo through the mock relay; one association
serves multiple targets (EIM); control death rebuilds without touching
TCP flows or other associations.
**Tests**: codec/BND unit tests; rootless
`socks5_udp_echo_round_trips_through_association`,
`association_reuses_one_socket_for_multiple_targets`,
`control_eof_rebuilds_association_with_backoff`,
`http_connect_udp_returns_port_unreachable`,
`association_failure_leaves_tcp_flows_untouched`.
**Status**: Complete for numeric relay addresses (2026-07-18). The mock uses
separate control/relay sockets and covers unspecified-BND fallback, EIM,
control-EOF jittered rebuild, HTTP rejection, and TCP-flow isolation. Domain
BND values are parsed without blocking but remain in bounded rebuild until
Stage 4 provides the association DNS path. The suite carries 52 active
rootless tests plus one ignored in-namespace helper.

### Stage 4: DNS proxy-udp and IPv6 parity

**Goal**: `DnsMode::ProxyUdp` (SOCKS5 only), gateway:53/UDP riding the
association path with the DNS timeout class; IPv6 UDP/DNS/NDP coverage.
**Success Criteria**: mode switch works end to end through the mock relay;
`proxy-tcp` remains the default; IPv6 cases green.
**Tests**: rootless `proxy_udp_requires_socks5`,
`udp_dns_resolves_through_an_association`,
`ipv6_udp_dns_resolves_through_association`.
**Status**: Not Started

### Stage 5: TAP multiqueue / per-worker reactors

**Goal**: `IFF_MULTI_QUEUE` TAP creation, N reactors with per-worker
pools/slabs/timers, supervisor fan-out of status/shutdown with metric
merge, `--workers` (default 1), recorded scaling calibration.
**Success Criteria**: workers=1 is byte-for-byte today's semantics (all
existing tests green); a 4-worker run passes TCP/UDP/DNS cases; multi-flow
aggregate scaling evidence recorded.
**Tests**: rootless `default_is_single_worker`,
`four_workers_preserve_tcp_echo`, `four_workers_preserve_udp_and_dns`,
`status_aggregates_worker_metrics`; benchmark extension.
**Status**: Not Started

### Stage 6: Exit work

**Goal**: enforce supervisor/ns-init profiles; `scripts/soak_phase2.py`;
DNS no-leak oracle script; memory-budget review note; real-proxy interop
notes; `docs/phase2-exit-audit.md` with a GO/partial verdict.
**Success Criteria**: honest exit audit with evidence; remaining risks
named.
**Tests**: role-profile negative tests; soak/oracle runs documented.
**Status**: Not Started

## Verification

Every stage lands only with:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace -- --test-threads=1
```

all green, and commits stay atomic per stage (config/core/wire-up/tests
split when useful). The host environment for live checks is the documented
mihomo TUN setup with SOCKS5 at `127.0.0.1:7890`; rootless tests keep using
local mocks on purpose.
