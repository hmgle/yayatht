# yayatht

`yayatht` runs a command in private Linux user, network, mount, IPC, UTS and
PID namespaces and adapts traffic from a TAP device to host sockets.

The current `0.1.0` tree completes the Phase 1 functional surface and is
entering Phase 2 (`docs/phase2-plan.md`). IPv4 and IPv6 TCP can use an
explicit direct route, SOCKS5 CONNECT, or HTTP CONNECT. SOCKS5 supports
no-auth and RFC 1929 username/password authentication; HTTP CONNECT supports
Basic authentication. DNS is proxied by default (`proxy-tcp`): the namespace
resolver points at the virtual gateway and queries are carried as
DNS-over-TCP through the configured upstream. General UDP forwarding, SOCKS5
UDP ASSOCIATE, and TAP multiqueue are the remaining Phase 2 work. The
data-plane sandbox is enabled by default: it uses a generated seccomp
allowlist, pivots to an empty tmpfs, and disables core dumps. `--sandbox off`
is available for diagnosis and emits a warning.

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
the same port. It is disabled by default.

To use the host SOCKS5 proxy from the reference environment:

```sh
target/release/yayatht run --socks5 127.0.0.1:7890 -- \
  busybox nslookup example.com
```

DNS defaults to `proxy-tcp`: queries to the gateway resolver are tunneled
through the proxy as DNS-over-TCP. `--dns-upstream ADDR` overrides the
resolver (otherwise the first host `nameserver` is used) and `--dns off`
restores the DNS-less behavior.

HTTP CONNECT uses `--http-connect ADDR`. Authentication credentials must be
provided through `--proxy-username-file` and `--proxy-password-file`; both
files must be regular files owned by the invoking user with no group or other
permissions. A single trailing line ending is removed.

The default filesystem mode is network isolation only. The command can still
access files available to the invoking user and must not be treated as an
untrusted filesystem sandbox. The empty filesystem described above belongs
only to the separate data-plane process, not to the target command.
