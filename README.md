# yayatht

[![CI](https://github.com/hmgle/yayatht/actions/workflows/ci.yml/badge.svg)](https://github.com/hmgle/yayatht/actions/workflows/ci.yml)
[![License: GPL-3.0-only](https://img.shields.io/badge/license-GPL--3.0--only-blue.svg)](COPYING)
[![MSRV: Rust 1.93](https://img.shields.io/badge/MSRV-1.93-dea584.svg)](Cargo.toml)
[![Platform: Linux](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](https://www.kernel.org/)

`yayatht` runs a command in private, rootless Linux namespaces and adapts
traffic from a TAP device to host sockets. TCP can be connected directly or
through SOCKS5 and HTTP CONNECT proxies. Direct UDP, SOCKS5 UDP ASSOCIATE,
DNS interception, TAP offload, and multiple data-plane workers are supported.

> [!WARNING]
> Version 0.1.0 is an experimental pre-release. Interfaces and behavior may
> change, and yayatht should not be treated as a security boundary for
> untrusted commands or as a critical production dependency.

## Name

`yayatht` means **Yet Another YATHT**. YATHT itself expands to
**Yet Another Traffic Handoff Transport** and is the name of the earlier,
related [hmgle/yatht](https://github.com/hmgle/yatht) project. The repeated
"Yet Another" is intentional and distinguishes this rootless namespace
implementation from that project.

## Requirements

- Linux 6.6 or newer.
- Unprivileged user namespaces enabled.
- A usable `/dev/net/tun`.
- Rust 1.93 or newer to build from source.

No setuid binary, root privilege, or host file capability is required.

## Installation

Build and install the current source:

```sh
git clone https://github.com/hmgle/yayatht.git
cd yayatht
cargo build --release
install -Dm755 target/release/yayatht ~/.local/bin/yayatht
```

Make sure `~/.local/bin` is on `PATH`, or invoke
`target/release/yayatht` directly from the checkout.

## Quick Start

Run a command with direct outbound networking:

```sh
yayatht run --direct -- busybox wget -qO- http://example.com/
```

Map the namespace's synthetic gateway `192.0.2.1` to host loopback:

```sh
yayatht run --direct --host-loopback -- \
  busybox nc 192.0.2.1 8080
```

Use a numeric SOCKS5 or HTTP CONNECT proxy address:

```sh
yayatht run --socks5 127.0.0.1:1080 -- busybox wget -qO- http://example.com/

yayatht run --http-connect 127.0.0.1:3128 -- \
  busybox wget -qO- http://example.com/
```

For proxy authentication, provide both `--proxy-username-file` and
`--proxy-password-file`. Each must be a regular file owned by the invoking
user with no group or other permissions, for example mode `0600`. A single
trailing CRLF or LF is removed, and each value must contain 1 to 255 bytes.

## DNS and UDP

DNS interception defaults to `--dns proxy-tcp`. The namespace resolver
points to the synthetic gateway, and queries are sent to the selected resolver
as DNS over TCP through the configured upstream. By default yayatht uses the
first nameserver in the host's `/etc/resolv.conf`; use
`--dns-upstream IP[:PORT]` to select another numeric resolver.

`--dns proxy-udp` preserves UDP DNS and sends it through SOCKS5 UDP
ASSOCIATE. It requires `--socks5` and `--udp on`. `--dns off` leaves the
target command's resolver configuration unchanged.

UDP forwarding defaults to `--udp on`. Direct mode uses connected host UDP
sockets. SOCKS5 uses one UDP association per namespace source endpoint. HTTP
CONNECT does not support UDP.

## Configuration Reference

Exactly one upstream option is required.

| Option | Default | Description |
| --- | --- | --- |
| `--direct` | - | Connect namespace TCP and UDP flows directly. |
| `--socks5 ADDR` | - | Route traffic through a numeric SOCKS5 proxy. |
| `--http-connect ADDR` | - | Route TCP through a numeric HTTP CONNECT proxy. |
| `--proxy-username-file PATH` | - | Read a protected proxy username. Requires the password file. |
| `--proxy-password-file PATH` | - | Read a protected proxy password. Requires the username file. |
| `--host-loopback` | off | Map the synthetic gateway to host loopback; valid only with `--direct`. |
| `--dns MODE` | `proxy-tcp` | Use `proxy-tcp`, `proxy-udp`, or `off`. |
| `--dns-upstream ADDR` | host resolver | Numeric resolver IP or IP:port. |
| `--udp on\|off` | `on` | Enable or disable non-DNS UDP forwarding. |
| `--no-ipv4` | off | Disable IPv4 in the namespace. |
| `--no-ipv6` | off | Disable IPv6 in the namespace. |
| `--name NAME` | generated | Assign an instance name for status queries. |
| `--runtime-dir ROOT` | `$XDG_RUNTIME_DIR/yayatht` | Store instance runtime state below ROOT. |
| `--workers COUNT` | `1` | Use 1 to 256 TAP queues and data-plane reactors. |
| `--sandbox on\|off` | `on` | Enable role-specific seccomp and data-plane filesystem isolation. |
| `--tap-mtu BYTES` | `32000` | Set the TAP MTU from 1280 to 65520. |
| `--tap-offload on\|off` | `on` | Negotiate `vnet_hdr`, checksum, GSO, and GRO offloads. |
| `--max-tcp-flows COUNT` | `4096` | Global TCP flow limit, 1 to 1048576. |
| `--max-udp-flows COUNT` | `8192` | Global UDP flow limit, 1 to 1048576. |
| `--max-udp-associations COUNT` | `2048` | Global SOCKS5 association limit, 1 to 1048576. |
| `--max-pending-tcp-bytes BYTES` | `67108864` | Global queued TCP byte limit, 16 KiB to 1 TiB. |
| `--max-retained-tcp-bytes BYTES` | `67108864` | Global retransmission byte limit, 16 KiB to 1 TiB. |
| `--tcp-receive-buffer-bytes BYTES` | `262144` | Per-flow host receive buffer, 16 KiB to 16 MiB. |
| `--tcp-send-buffer-bytes BYTES` | `262144` | Per-flow host send buffer, 16 KiB to 16 MiB. |

At least one IP family must remain enabled. Every flow count must be at least
the worker count, and each global TCP byte limit must provide at least 16 KiB
per worker.

Run `yayatht run --help` for the command-line source of truth.

## Instance Status

Give a long-running instance a name and query it from another shell:

```sh
yayatht run --name build-net --socks5 127.0.0.1:1080 -- make
yayatht status --name build-net
yayatht status --name build-net --json
```

Pass the same `--runtime-dir` to both commands when overriding the default.

## Security Model

The target runs in private user, network, mount, IPC, UTS, and PID namespaces.
The separate data-plane processes use role-specific seccomp filters, disable
core dumps, and pivot to an empty tmpfs when the sandbox is enabled.

The target command's filesystem is not isolated from files already accessible
to the invoking user. The target command must therefore be trusted. Disabling
`--sandbox` also disables seccomp, data-plane filesystem isolation, and the
core-dump clamp, and is intended only for diagnosis.

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## Development

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace -- --test-threads=1
cargo check --workspace --all-targets
cargo deny check
```

Rootless integration tests require the same kernel, user-namespace, and TUN
prerequisites as the program. The scripts under `scripts/` provide benchmark,
soak, and DNS no-leak diagnostics; each script documents its inputs through
`--help`.

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) and the
[Code of Conduct](CODE_OF_CONDUCT.md) before opening a pull request.

## License

Copyright (C) 2026 hmgle.

yayatht is free software licensed under the
[GNU General Public License, version 3 only](COPYING), identified by
`GPL-3.0-only`.

## Acknowledgements

The implementation was informed by Linux UAPI documentation, public network
protocol specifications, and behavioral comparison with passt/pasta and other
rootless proxy projects. Exact sources, revisions, and licensing boundaries
are recorded in [docs/provenance.md](docs/provenance.md).
