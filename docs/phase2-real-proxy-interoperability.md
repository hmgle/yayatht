# Phase 2 Real Proxy Interoperability

Date: 2026-07-18. yayatht base revision: `3457e73` plus Stage 6 role
sandboxing. Proxy: Mihomo Meta v1.19.24 (`127.0.0.1:7890`), host TUN mode
enabled with policy table 2022.

## Functional Matrix

| Path | Result | Evidence |
| --- | --- | --- |
| SOCKS5 TCP CONNECT, IPv4 | PASS | HTTP request to `1.1.1.1:80` returned `HTTP/1.1 200 OK`. |
| DNS `proxy-tcp`, IPv4 resolver | PASS | `1.1.1.1:53`, two A answers, `rcode=0`, `id=ok`. |
| DNS `proxy-udp`, IPv4 resolver | PASS | `1.1.1.1:53`, two A answers, `rcode=0`, `id=ok`. |
| General SOCKS5 UDP, IPv4 | PASS | Direct namespace query to `1.1.1.1:53`, two A answers, `id=ok`. |
| General SOCKS5 UDP, IPv6 | ENVIRONMENT UNAVAILABLE | Query to `2606:4700:4700::1111` timed out. |
| DNS over IPv6 resolver | ENVIRONMENT UNAVAILABLE | proxy-tcp returned SERVFAIL and proxy-udp timed out to the same resolver. |

The IPv6 failures are consistent across TCP and UDP resolver transports and
the host has no usable external IPv6 route. They do not contradict the local
rootless IPv6 TCP/UDP/DNS cases, which pass with deterministic mocks. The
real mihomo UDP success also confirms its returned numeric or unspecified BND
form interoperates with the association implementation. Domain-form BND
remains untested and unsupported by the sandboxed reactor.

## 128-Flow Fairness

The Phase 1A harness was rerun against real mihomo with one warmup and three
measured runs, 128 flows x 4 MiB, MTU 32000, offload enabled, and the numeric
host target `172.16.10.5`:

```sh
uv run scripts/bench_tcp_phase1a.py --scenarios mihomo \
  --protocols socks5 --flows 128 --mib-per-flow 4 \
  --runs 3 --warmups 1 --target 172.16.10.5
```

| Run | Throughput Gibit/s | Connect p99 ms | Completion p99 ms | Jain fairness |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 6.548 | 167.2 | 604.3 | 0.838 |
| 2 | 6.126 | 156.4 | 645.7 | 0.888 |
| 3 | 6.626 | 119.0 | 598.5 | 0.861 |

Median throughput is 6.548 Gibit/s and median fairness is 0.861. This is
better and less variable than the Phase 1 median fairness of 0.728, but it
does not reach the 0.97+ local-proxy result. The path still shares CPU,
mihomo, and the host TUN policy layer, so the remaining gap cannot be
attributed solely to yayatht. An isolated external proxy host remains the
required experiment for causal attribution.
