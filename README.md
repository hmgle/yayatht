# yayatht

`yayatht` runs a command in private Linux user, network, mount, IPC, UTS and
PID namespaces and adapts traffic from a TAP device to host sockets.

The current `0.1.0` tree is entering Phase 1. IPv4 and IPv6 TCP can use an
explicit direct route, SOCKS5 CONNECT, or HTTP CONNECT. SOCKS5 supports
no-auth and RFC 1929 username/password authentication; HTTP CONNECT supports
Basic authentication. DNS forwarding, UDP forwarding, and the data-plane
sandbox are not exposed yet.

## Build

```sh
cargo build --release
```

Linux 5.11 or newer with unprivileged user namespaces and `/dev/net/tun` is
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
  curl --resolve example.com:80:93.184.216.34 http://example.com/
```

The explicit address mapping is required until the Phase 1 DNS proxy is
implemented.

HTTP CONNECT uses `--http-connect ADDR`. Authentication credentials must be
provided through `--proxy-username-file` and `--proxy-password-file`; both
files must be regular files owned by the invoking user with no group or other
permissions. A single trailing line ending is removed.

The default filesystem mode is network isolation only. The command can still
access files available to the invoking user and must not be treated as an
untrusted filesystem sandbox.
