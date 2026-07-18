# yayatht

`yayatht` runs a command in private Linux user, network, mount, IPC, UTS and
PID namespaces and adapts traffic from a TAP device to host sockets.

The current `0.1.0` tree completes the Phase 2 functional surface described
in `docs/phase2-plan.md`; the exit audit records a PARTIAL GO with explicit
interoperability and capture gaps. IPv4 and IPv6 TCP can use an explicit
direct route, SOCKS5 CONNECT, or HTTP CONNECT. SOCKS5 supports no-auth and
RFC 1929 username/password authentication; HTTP CONNECT supports Basic
authentication. DNS is proxied by default (`proxy-tcp`): the namespace
resolver points at the virtual gateway and queries are carried as
DNS-over-TCP through the configured upstream. IPv4 and IPv6 UDP forwarding
is enabled for direct routes, including host-loopback mapping, and SOCKS5
uses one standards-compliant UDP ASSOCIATE per namespace source endpoint.
`--udp off` restores drop-all behavior for non-DNS datagrams. SOCKS5 can
also carry gateway DNS over the association with `--dns proxy-udp`; the
default remains `proxy-tcp`. `--workers COUNT` enables one share-nothing
reactor per TAP queue; it defaults to 1, while 4 workers are calibrated for
multi-flow workloads. The data-plane sandbox is enabled by default: it uses
generated role-specific seccomp allowlists; the data plane additionally
pivots to an empty tmpfs and disables core dumps. `--sandbox off` is
available for diagnosis and emits a warning.

## Build

```sh
cargo build --release
```

Linux 6.6 or newer with unprivileged user namespaces and `/dev/net/tun` is
required. No setuid binary or host capability is used.

## Run

```sh
target/release/yayatht run --direct --host-loopback -- \
  busybox nc 192.0.2.1 8080
```

`--host-loopback` maps the synthetic gateway to the host loopback address on
the same port. It is disabled by default. `--workers 4` enables TAP
multiqueue for multi-flow workloads; each worker owns an independent reactor,
flow tables, timers, and buffer pools.

To use the host SOCKS5 proxy from the reference environment:

```sh
target/release/yayatht run --socks5 127.0.0.1:7890 -- \
  busybox nslookup example.com
```

DNS defaults to `proxy-tcp`: queries to the gateway resolver are tunneled
through the proxy as DNS-over-TCP. `--dns-upstream ADDR` overrides the
resolver (otherwise the first host `nameserver` is used) and `--dns off`
restores the DNS-less behavior. With SOCKS5, `--dns proxy-udp` instead
relays the original query over a per-source-endpoint UDP association; it
requires `--udp on`.

HTTP CONNECT uses `--http-connect ADDR`. Authentication credentials must be
provided through `--proxy-username-file` and `--proxy-password-file`; both
files must be regular files owned by the invoking user with no group or other
permissions. A single trailing line ending is removed.

The default filesystem mode is network isolation only. The command can still
access files available to the invoking user and must not be treated as an
untrusted filesystem sandbox. The empty filesystem described above belongs
only to the separate data-plane process, not to the target command.

Phase 2 verification and remaining risks are summarized in
`docs/phase2-exit-audit.md`. The reproducible 1-hour soak and DNS no-leak
socket oracle are `scripts/soak_phase2.py` and
`scripts/dns_no_leak_oracle.py`.
