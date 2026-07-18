# Phase 2 Exit Audit

Date: 2026-07-18. Kernel: `6.12.85+deb13-amd64`. Host networking: mihomo
TUN mode, SOCKS5 on `127.0.0.1:7890`.

## Verdict

**PARTIAL GO.** Phase 2 functional scope is complete for numeric proxy and
resolver endpoints: role sandboxing, direct UDP, SOCKS5 UDP ASSOCIATE, DNS
`proxy-udp`, IPv6 mock parity, and TAP multiqueue all pass their deterministic
tests. The revised 1-hour mixed soak passed with stable worker RSS and fd
counts.

The exit verdict remains partial rather than full GO for three explicit
reasons: domain-form SOCKS5 BND addresses have no pre-relay asynchronous DNS
path; this host lacks packet-capture tools for an all-interface pcap oracle;
and real-proxy IPv6 plus isolated 128-flow fairness attribution are not
available in the current host network. These are not reported as completed.

## Delivered Scope

- Generated default-kill seccomp profiles now enforce data-plane,
  namespace-init, and supervisor boundaries. Data-plane filesystem pivot and
  `RLIMIT_CORE=0` remain enabled by default.
- IPv4/IPv6 direct UDP has bounded five-tuple flows, endpoint associations,
  timeout classes, error queues, ICMP synthesis, and hard fd/flow limits.
- SOCKS5 UDP ASSOCIATE has strict wire parsing, one association per source
  endpoint, bounded pending queues, control-EOF rebuild, and failure
  isolation. HTTP CONNECT returns ICMP Port Unreachable for UDP.
- DNS `proxy-udp` relays verbatim queries and preserves gateway:53 as the
  namespace-visible reply source. `proxy-tcp` remains the default.
- TAP multiqueue runs one sandboxed reactor process per queue, divides
  resource budgets, treats any worker death as fatal, and merges status
  metrics. Default remains one worker.

## Sandbox Evidence

The role manifests are generated from `crates/sys/syscalls.toml`. ns-init
installs its filter only after forking the target, so the target command does
not inherit it. The target uses `PDEATHSIG=SIGKILL`, preventing a command leak
if ns-init is killed. Supervisor filtering starts after all setup fds are
nonblocking and retains only steady status, signal, wait, memory, and private
runtime-cleanup calls.

Negative rootless tests deliberately call an absent `getpid` syscall:

- `forbidden_syscall_kills_the_data_plane`
- `forbidden_syscall_kills_namespace_init`
- `forbidden_syscall_kills_supervisor`

All three are killed by the default action. Positive status, signal, cleanup,
TCP, UDP, and DNS paths exercise the enforced profiles.

## Multiqueue Calibration

The release benchmark used direct host-loopback, 32 flows x 64 MiB, three
runs per worker count. One worker reached a 19.55 Gbit/s median; four workers
reached 30.84 Gbit/s, a 57.8% gain. Full method and raw run values are in
`docs/phase2-multiqueue-calibration-2026-07-18.md`.

## One-Hour Soak

The soak duration was revised from 24 hours to 1 hour on 2026-07-18. The
release command was:

```sh
uv run scripts/soak_phase2.py \
  --output /tmp/yayatht-phase2-soak-1h.json
```

The harness ran four workers and local TCP echo, UDP echo, and proxy-tcp DNS
resolver services. Results:

| Measure | Result |
| --- | ---: |
| Wall duration | 3601.67 s |
| Completed mixed iterations | 34,894 |
| TCP payload | 142,925,824 bytes |
| UDP payload | 35,731,456 bytes |
| DNS queries | 34,894 |
| Worker RSS, initial / final / peak | 27,408 / 30,288 / 30,288 KiB |
| Worker fds, initial / final / peak | 38 / 338 / 346 |

RSS reached 30,288 KiB at three minutes and remained exactly there through
the final sample. Fds reached the UDP timeout working set and oscillated in a
narrow range rather than growing with the 34k cumulative flow count. A manual
midpoint status sample showed equal TCP created/closed counts, zero active
TCP flows, about 300 active UDP flows, and zero UDP queue or limit drops.

## DNS No-Leak Oracle

`scripts/dns_no_leak_oracle.py` binds TCP and UDP capture sentinels at the
configured resolver tuple while local SOCKS mocks answer inside CONNECT and
UDP ASSOCIATE. Both `proxy-tcp` and `proxy-udp` returned valid answers with
`id=ok`; the resolver sentinels captured zero direct connections or
datagrams. This avoids false success from a nonfunctional query path.

`dumpcap`, `tshark`, and `tcpdump` are absent on this host. The socket oracle
is deterministic for the configured resolver but is not an all-interface
pcap assertion. A capture-capable CI/host run remains open.

## Memory Review

The old 2 GiB figure counted TCP buffers only. Default maximum socket ceilings
are about 3 GiB in direct mode and 2.5 GiB in SOCKS5 mode; kernel buffers are
charged on demand for active queue occupancy, not reserved at startup. Status
now exports TCP, UDP, and total configured ceilings. The defaults are retained
for this performance-oriented tree, with a documented low-memory profile and
cgroup residual risk in `docs/phase2-memory-budget-review.md`.

## Real Proxy Evidence

Against Mihomo Meta v1.19.24, IPv4 TCP CONNECT, DNS `proxy-tcp`, DNS
`proxy-udp`, and general SOCKS5 UDP passed. External IPv6 resolver attempts
were unavailable for both TCP and UDP transports on this host. A new 128-flow
SOCKS5 run produced 6.126-6.626 Gibit/s and Jain fairness 0.838-0.888 (median
0.861), improved from Phase 1 but below local-proxy fairness. See
`docs/phase2-real-proxy-interoperability.md`.

## Exit Checklist

| Gate | Result | Evidence |
| --- | --- | --- |
| Data-plane sandbox default-kill | PASS | Positive matrix plus forbidden-syscall kill. |
| Supervisor/ns-init seccomp enforced | PASS | Role negative tests and normal cleanup/status paths. |
| Direct and SOCKS5 UDP functional | PASS | IPv4/IPv6 mock rootless matrix and real IPv4 mihomo. |
| DNS proxy-udp and IPv6 parity | PASS | Verbatim-ID IPv4/IPv6 rootless cases. |
| Four-worker correctness and scaling | PASS | TCP/UDP/DNS/status tests; 57.8% median gain. |
| One-hour resource soak | PASS | 34,894 iterations; RSS/fd plateau. |
| DNS no-leak oracle | PARTIAL | Socket capture PASS; all-interface pcap unavailable. |
| Memory budget reviewed and observable | PASS | Full socket ceilings exported and documented. |
| Real proxy interoperability | PARTIAL | IPv4 PASS; external IPv6 unavailable; fairness not isolated. |
| Domain BND interoperability | PARTIAL | Safe rejection/rebuild only; async resolution absent. |

## Remaining Work

1. Resolve domain-form SOCKS5 BND addresses asynchronously without allowing
   blocking libc resolution in a reactor or leaking DNS.
2. Run an all-interface pcap no-leak oracle on a capture-capable host.
3. Repeat IPv6 and 128-flow fairness against an isolated external proxy host
   with known dual-stack routing.
4. Derive a future production preset from cgroup memory rather than using the
   performance-oriented default ceilings unchanged on every machine.
