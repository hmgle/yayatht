# Phase 1 TCP Calibration

## Reproducible direct benchmark

The repository includes `scripts/bench_tcp_direct.py` and the
`tcp-bench-io` test-support binary. The source waits for a receiver completion
acknowledgment, and the receiver verifies the exact byte count before reporting
a result. This avoids treating data accepted by the namespace kernel, but not
yet delivered through the adapter, as completed traffic.

The initial comparison used:

- Date: 2026-07-13.
- Kernel: Linux 6.12.85, x86_64.
- CPU affinity: all benchmark children pinned to CPU 0.
- IPv4, MTU 1500, one flow, 128 MiB per measured run.
- One warmup followed by five interleaved measured runs.
- `yayatht` commit `49b694f`, direct host-loopback mapping.
- Official pasta commit `6ef3d1c86ffc690a17a9a4445df4a741446bcd44`,
  including its AVX2 binary.
- pasta used `--config-net --no-splice`; TCP/UDP port forwarding was disabled.
- Both targets reached a listener on host loopback through their synthetic or
  mapped gateway, so external routing and the host mihomo TUN layer were not in
  the measured data path.

The benchmark command was:

```sh
uv run scripts/bench_tcp_direct.py \
  --pasta /tmp/yayatht-passt-6ef3d1c/pasta \
  --pasta-target 172.16.10.1 \
  --mib 128 --runs 5 --warmups 1 --cpu 0
```

| Backend | Median elapsed | Median throughput | Observed range | Median child CPU |
| --- | ---: | ---: | ---: | ---: |
| yayatht | 0.745 s | 1.342 Gibit/s | 1.247--1.364 Gibit/s | 0.699 s |
| pasta | 5.611 s | 0.178 Gibit/s | 0.176--0.200 Gibit/s | 0.542 s |

For this narrow MTU-1500, no-splice path, yayatht reached about 7.5 times the
median pasta throughput. The pasta wall time was mostly not accounted for by
child CPU time, suggesting an ACK, timer or flow-control cadence limitation on
this path rather than CPU saturation. This is an observation, not yet a root
cause.

These results must not be generalized to pasta's default large MTU, local
splice, multiple flows, remote routes, UDP, or vhost-user. The next performance
gate should add 1/8/32/128 flows, latency sampling, default-MTU pasta, and a
non-local destination while continuing to report exact versions and host
routing state.

## Phase 1A explicit-proxy harness

`scripts/bench_tcp_phase1a.py` now supplies the broader gate. It uses the
`tcp-bench-io` multi-flow client/server and a numeric-target `tcp-bench-proxy`
for local SOCKS5 no-auth, RFC 1929 username/password, and HTTP CONNECT runs.
The same runner can compare:

- yayatht direct with official pasta;
- yayatht proxy mode with proxy-dev pasta and nsproxy;
- yayatht SOCKS5/HTTP with the real mihomo endpoint at `127.0.0.1:7890`;
- proxy-ns when its external installation/capability requirements are met.

Each CSV row includes aggregate throughput, child and proxy CPU, connect and
completion p50/p99, Jain fairness, per-flow throughput range, numeric target,
revisions, kernel, and mihomo TUN state. The current results and no-go decision
are recorded in `docs/phase1a-exit-audit.md`.

Example full calibration command:

```sh
uv run scripts/bench_tcp_phase1a.py \
  --pasta /tmp/passt-upstream-review/pasta.avx2 \
  --proxy-dev ../passt-github/pasta \
  --nsproxy ../nsproxy/build3/nsproxy \
  --proxy-ns ../proxy-ns/proxy-ns \
  --target 172.16.10.5 \
  --flows 1,8,32,128 \
  --mib-per-flow 4 --runs 3 --warmups 1 --cpu 0
```

proxy-dev results must retain the explicit limitation label: its proxy
handshake is blocking, its TCP core is old, and authenticated credentials are
passed in argv. It is a historical implementation-cost comparison, not a
protocol oracle.
