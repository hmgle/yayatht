# yayatht

`yayatht` runs a command in private Linux user, network, mount, IPC, UTS and
PID namespaces and adapts traffic from a TAP device to host sockets.

The current `0.1.0` tree is the Phase 0 feasibility implementation. It only
supports explicitly selected direct TCP forwarding. SOCKS5, HTTP CONNECT,
DNS forwarding and UDP forwarding are intentionally not exposed yet.

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

The default filesystem mode is network isolation only. The command can still
access files available to the invoking user and must not be treated as an
untrusted filesystem sandbox.
