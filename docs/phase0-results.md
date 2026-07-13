# Phase 0 Results

## Environment

- Kernel: Linux 6.12.85, x86_64.
- Rust validation toolchain: stable 1.94.1; workspace MSRV is 1.93.
- Unprivileged user namespaces: enabled.
- `/dev/net/tun`: available to the invoking user.
- `SO_PEEK_OFF` on TCP: supported by the running kernel.
- Host networking: mihomo TUN mode enabled; all acceptance traffic therefore
  used host loopback and did not depend on the host default route.

## Verified

- Supervisor, data-plane and namespace PID 1 process topology starts without
  root, setuid or host file capabilities.
- uid/gid maps, private mount/PID/network namespaces, TAP creation, rtnetlink
  address/route setup and `SCM_RIGHTS` fd transfer complete successfully.
- Target exit codes are preserved and instance directories are removed only
  when their nonce matches.
- The status Unix socket reports the running process and namespace metadata.
- Static BusyBox completes IPv4 and IPv6 TCP echo through the direct adapter.
- IPv6 neighbor discovery uses a Hop Limit of 255 and synthetic addresses are
  installed with `IFA_F_NODAD` to avoid startup races.
- `cargo test --workspace -- --test-threads=1` passes rootless IPv4, IPv6,
  status, cleanup, name collision and injected startup failure cases.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
  passes on the validation host.

## TCP Decision

The custom adapter is viable for continued Phase 1 work, but the Phase 0
implementation intentionally permits only one unacknowledged segment toward
the namespace at a time. Before calling it a proxy MVP, Phase 1 must add a
windowed segment scheduler, broader loss/zero-window tests, handshake pending
queues and 24-hour stress coverage. The smoltcp fallback remains available if
those correctness gates fail.

## Not Yet Implemented

- SOCKS5, HTTP CONNECT and authentication.
- DNS, UDP forwarding and SOCKS5 UDP ASSOCIATE.
- seccomp, pivot_root and generated syscall manifests.
- pcap replay/fuzz jobs, packetdrill and performance comparison with pasta.
