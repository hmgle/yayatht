# Phase 1A Post-Fix Performance Comparison

## Scope

This document records the fresh same-host comparison requested after the
short-flow fixes. It is separate from the historical baseline in
`phase1a-exit-audit.md` so later work can distinguish post-fix behavior from
the original MTU-1500 and unscaled-window results.

The measurements are calibration data, not publication-quality statistics.
Each reported value is the median of three measured runs after one warmup.

## Environment

- Date: 2026-07-14.
- Kernel: Linux 6.12.85, x86_64.
- Host networking: mihomo TUN mode enabled.
- CPU affinity: benchmark children pinned to CPU 0.
- Transfer: 4 MiB per flow.
- yayatht TAP MTU: 32000.
- yayatht per-flow send-buffer quota: 256 KiB.
- Numeric local-proxy target: `198.51.100.77`, redirected to
  `172.16.10.5` by the benchmark proxy.
- yayatht data-plane implementation: `f8524cf`.
- Comparison harness after the backend option correction: `bc33fb8`.
- Official pasta: `6ef3d1c86ffc690a17a9a4445df4a741446bcd44`.
- proxy-dev pasta: `c7568f543bdf69684e175b237298fb444c51669d`.
- nsproxy: `2029a6257f53aef19451ac99fb5e160f76f7c179`, build3.
- proxy-ns: `5d08d18f9171d7e65fabad06ee81021d9bca0a21`.

The nsproxy build uses its own approximately 36K link MTU. Official pasta and
proxy-dev pasta were passed MTU 32000. All comparisons use the same Rust source
and sink and the same local SOCKS5/HTTP benchmark proxy.

## Direct TCP

Official pasta was run with `--config-net --no-splice` and the same requested
MTU. A second pass removed `--no-splice`; the result changed by less than the
run-to-run variance because this outbound case does not use pasta's favorable
local port-forward splice path.

| Flows | yayatht throughput | pasta throughput | Ratio | yayatht p99 | pasta p99 |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 1.704 Gibit/s | 0.048 Gibit/s | 35.5x | 17.2 ms | 654.0 ms |
| 32 | 6.641 Gibit/s | 1.258 Gibit/s | 5.3x | 148.0 ms | 784.2 ms |
| 128 | 6.439 Gibit/s | 2.180 Gibit/s | 3.0x | 609.1 ms | 1.820 s |

The splice-enabled pasta pass produced 0.049/1.282/2.142 Gibit/s for
1/32/128 flows respectively, so it does not change the conclusion for this
case.

## Explicit Proxy Versus nsproxy

| Protocol | Flows | yayatht | nsproxy | Difference | yayatht p99 | nsproxy p99 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| SOCKS5 | 1 | 0.875 | 1.416 | -38.2% | 35.3 ms | 21.9 ms |
| HTTP | 1 | 0.923 | 1.309 | -29.5% | 33.8 ms | 23.5 ms |
| SOCKS5 | 32 | 3.724 | 3.729 | -0.1% | 267.8 ms | 258.1 ms |
| HTTP | 32 | 3.682 | 3.842 | -4.2% | 265.4 ms | 249.6 ms |
| SOCKS5 | 128 | 3.690 | 3.915 | -5.7% | 1.079 s | 1.008 s |
| HTTP | 128 | 3.623 | 3.853 | -6.0% | 1.097 s | 1.026 s |

Throughput values are Gibit/s. yayatht used roughly twice the child CPU at one
flow and about 10--15% more at 32/128 flows. Its Jain fairness stayed between
0.986 and 1.000. nsproxy showed large SOCKS5 fairness variance in this pinned
same-CPU pass while its aggregate throughput and completion time stayed stable;
that variance is not treated as an architectural nsproxy result.

The one-flow completion gap is mostly connection setup:

| Backend | SOCKS5 connect p99 | HTTP connect p99 |
| --- | ---: | ---: |
| yayatht | 14.0 ms | 13.2 ms |
| nsproxy | 1.7 ms | 1.5 ms |
| proxy-dev pasta | 0.5 ms | 0.7 ms |

After subtracting connect time, yayatht and nsproxy have similar one-flow data
transfer time. The next latency target is therefore proxy handshake scheduling,
not another MTU increase.

## Explicit Proxy Versus proxy-dev Pasta

This backend is a historical implementation-cost comparator. It has a blocking
proxy handshake, a legacy TCP core, and exposes authentication through argv;
it is not a correctness or security oracle.

| Protocol | Flows | yayatht | proxy-dev | Ratio | yayatht p99 | proxy-dev p99 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| SOCKS5 | 1 | 0.746 | 3.752 | 0.20x | 41.8 ms | 8.3 ms |
| HTTP | 1 | 0.761 | 3.260 | 0.23x | 41.0 ms | 9.4 ms |
| SOCKS5 | 32 | 3.755 | 1.218 | 3.08x | 260.6 ms | 818.5 ms |
| HTTP | 32 | 3.738 | 1.264 | 2.96x | 261.5 ms | 788.5 ms |
| SOCKS5 | 128 | 3.598 | 1.885 | 1.91x | 1.105 s | 1.947 s |
| HTTP | 128 | 3.611 | 1.988 | 1.82x | 1.104 s | 1.779 s |

proxy-dev wins short single-flow completion with its blocking handshake and
legacy TCP path. It loses aggregate throughput and fairness once concurrency
rises.

## proxy-dev Harness Compatibility

The first combined comparison failed before startup because the harness passed
`-c <proxy-ns.json>` to proxy-dev pasta. Revision `c7568f5` does not implement
`-c`; its proxy is configured with `--proxy`, `--proxy-type`, `--proxy-user`,
and `--proxy-passwd`.

The recorded proxy-dev matrix was initially recovered with a temporary wrapper
that removed the leading `-c PATH` pair and then executed the unchanged binary.
The root cause was then fixed in harness revision `bc33fb8`:

- proxy-dev pasta receives `-q -f` and its supported proxy CLI options;
- proxy-ns receives `-q -c <generated-private-json>` plus CLI overrides.

A direct one-flow validation after the fix completed successfully without the
wrapper. Future runs must use the corrected harness rather than recreating the
temporary wrapper.

## proxy-ns Availability

proxy-ns still exited with status 1 and no stdout or stderr after the private
configuration was passed to the correct backend. It therefore has no valid
performance result in this environment. Do not record its startup failure as
zero throughput and do not grant host file capabilities only to obtain a
benchmark number.

## Real mihomo Context

The same yayatht implementation reached these production-path medians through
`127.0.0.1:7890`:

| Protocol/flows | Throughput | Completion p99 | Fairness |
| --- | ---: | ---: | ---: |
| SOCKS5 / 32 | 3.948 Gibit/s | 247.3 ms | 0.997 |
| HTTP / 32 | 4.342 Gibit/s | 224.8 ms | 0.985 |
| SOCKS5 / 128 | 4.959 Gibit/s | 804.6 ms | 0.728 |
| HTTP / 128 | 4.510 Gibit/s | 879.3 ms | 0.759 |

The 128-flow fairness difference from the local proxy remains a host-TUN or
high-concurrency isolation item.

## Remaining Performance Work

Items 1 and 2 were implemented on 2026-07-15; the results and a
silly-window stall found during their validation are recorded in
`phase1a-reactor-wakeup-2026-07-15.md`.

1. Done (`38b1a82`): writable interest is armed only while a writable event
   can make progress.
2. Done (`e89b595`): upstream ACK progress is event-driven through
   `SOF_TIMESTAMPING_TX_ACK`, with writable-interest polling as the
   compatibility fallback.
3. Evaluate `IFF_VNET_HDR`, TCP GSO, and checksum offload to reduce frame and
   checksum work without increasing the namespace-visible MTU beyond 32000.
4. Use TAP multiqueue and flow-hashed reactors when scaling beyond the current
   single-reactor ceiling of about 6.6 Gibit/s direct and 3.7--4.0 Gibit/s
   through the local explicit proxy.
5. Isolate the real-mihomo 128-flow fairness result before attributing it to the
   adapter.
