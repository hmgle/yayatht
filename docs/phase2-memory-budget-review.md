# Phase 2 Memory Budget Review

Date: 2026-07-18.

## Decision

Retain the Phase 2 defaults for the performance-oriented `0.1.0` tree, but
treat them as capacity ceilings rather than a suitable reservation for every
host. The original 2 GiB figure covers TCP socket buffers only. Phase 2 UDP
raises the maximum configured socket ceiling to about 3 GiB in direct mode or
2.5 GiB with SOCKS5.

These buffers are charged by the kernel only for active sockets and actual
queue occupancy; they are not allocated in full at startup. The limits still
matter under adversarial or sustained high-concurrency workloads, so status
now exports all three values:

- `max_socket_buffer_bytes`: TCP ceiling, retained for compatibility.
- `max_udp_socket_buffer_bytes`: direct-flow or SOCKS association ceiling.
- `max_total_socket_buffer_bytes`: TCP + UDP + resolver socket ceiling.

## Default Ceilings

| Component | Calculation | Ceiling |
| --- | ---: | ---: |
| TCP sockets | 4096 flows x (256 KiB receive + 256 KiB send) | 2 GiB |
| Direct UDP sockets | 8192 flows x (64 KiB receive + 64 KiB send) | 1 GiB |
| SOCKS5 UDP sockets | 2048 associations x 2 sockets x 128 KiB | 512 MiB |
| Per-worker proxy-tcp resolver | 64 KiB receive + 64 KiB send | 128 KiB |
| Global pending TCP payload | configured hard cap | 64 MiB |
| Global retained TCP payload | configured hard cap | 64 MiB |
| TAP MTU/GSO pools | divided across workers | at most 20 MiB total |

Direct and SOCKS5 UDP ceilings are mutually exclusive. HTTP CONNECT creates
no UDP sockets. Multiqueue divides flow and byte limits across workers, so it
does not multiply these configured totals; each worker does add a resolver
socket, fixed reactor storage, and a 32-fd runtime headroom.

SOCKS pending datagrams are additionally bounded to 64 KiB per active
association. Flow tables and hash indices are capacity-bounded but their
metadata is process memory rather than socket-buffer accounting. The soak
result in `docs/phase2-exit-audit.md` records observed RSS and fd behavior.

## Low-Memory Profile

Operators on smaller machines should lower limits explicitly. For example:

```sh
yayatht run --direct --max-tcp-flows 1024 --max-udp-flows 2048 \
  --max-udp-associations 512 \
  --tcp-receive-buffer-bytes 131072 --tcp-send-buffer-bytes 131072 \
  --max-pending-tcp-bytes 16777216 --max-retained-tcp-bytes 16777216 \
  -- COMMAND...
```

That profile caps TCP sockets at 256 MiB and direct UDP sockets at 256 MiB,
plus 32 MiB of global TCP payload. The fixed 64 KiB per-direction UDP socket
quota remains large enough for maximum-size UDP datagrams.

## Residual Risk

The default is still too high for an unconstrained memory cgroup if thousands
of flows simultaneously fill both directions. A future production preset
should derive limits from the cgroup memory budget. Phase 2 does not silently
guess such a value because doing so would change throughput and concurrency
semantics across hosts.
