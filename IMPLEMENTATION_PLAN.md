# Implementation Plan: Kernel 6.6 Baseline + TAP Offload (Phase 1 core offload)

Design basis: `rproxy-ns/docs/rust-namespace-proxy-design.md` revision ca68f9e
(2026-07-16) — performance-first redirection, minimum kernel 6.6 LTS,
optimization backlog #1 (`IFF_VNET_HDR` + `TUNSETOFFLOAD` GSO/GRO/csum
offload) as the Phase 1 core deliverable. Acceptance line: single-core direct
throughput from ~6.6 Gbit/s toward 15 Gbit/s.

## Stage 1: 6.6 baseline cleanup (delete 5.11 compat paths)

**Goal**: The hot path assumes `SO_PEEK_OFF`, complete `TCP_INFO`
(`tcpi_bytes_acked`), and `SOF_TIMESTAMPING_TX_ACK` exist.
**Success Criteria**: Capability probing, conservative-ACK fallback,
iovec-peek fallback, `FALLBACK_ACK_WINDOW`, and the fallback fast-tick
machinery are gone; setup failures fail the flow instead of degrading it;
watchdog dropped-notification recovery is preserved; docs state Linux 6.6+.
**Tests**: Existing watchdog suppression test adapted to timestamps-on
semantics; truncated-`TCP_INFO` unit test; full serial workspace suite.
**Status**: Complete

## Stage 2: vnet_hdr frame layout plumbing (zeroed header)

**Goal**: TAP opens with `IFF_TAP|IFF_NO_PI|IFF_VNET_HDR`; every TAP
read/write carries a 10-byte legacy `virtio_net_hdr` (all zero); full
software checksums unchanged; `--tap-offload {on,off}` plumbed CLI →
namespace → dataplane (off reproduces today's exact behavior).
**Success Criteria**: Full rootless matrix passes in both modes; RX frames
with unexpected vnet flags are counted as parse drops.
**Tests**: vnet header encode/decode unit tests; matrix in both modes.
**Status**: Complete

## Stage 3: checksum offload + GRO large-frame receive

**Goal**: `TUNSETOFFLOAD(TUN_F_CSUM|TUN_F_TSO4|TUN_F_TSO6)`; RX accepts
NEEDS_CSUM/GSO frames up to 64 KiB without checksum verification; TX sets
NEEDS_CSUM with pseudo-header partial sums; software full checksums remain
only on the offload-off path.
**Success Criteria**: Large-upload integration case observes
`gso_frames_rx > 0` with byte-exact delivery; both modes pass the matrix.
**Tests**: pseudo-header partial-sum unit tests; upload integrity case.
**Status**: Not Started

## Stage 4: TSO large-frame transmit

**Goal**: host→namespace sends carry up to `min(65535 − L3 headers, window,
retained)` payload in one frame with `gso_type=TCPV4/6`, `gso_size=mss`;
two-tier buffer pool (MTU tier + GSO tier) with graceful degradation to
per-MSS frames on GSO-pool exhaustion; retransmits rebuild as TSO frames.
**Success Criteria**: Large-download case observes `gso_frames_tx > 0` with
byte-exact delivery; loss/zero-window/half-close injections pass in both
modes.
**Tests**: `plan_send` bound unit tests; partial-ACK of oversized
`SentSegment`; download integrity case.
**Status**: Not Started

## Stage 5: benchmark validation + docs closeout

**Goal**: `scripts/bench_tcp_phase1a.py` direct 1/32 flows × offload on/off
× MTU 32000/1500, plus local SOCKS5 rerun; results and acceptance-line
verdict recorded in `docs/`; progress doc updated; this file removed.
**Success Criteria**: Reproducible results doc with environment and
comparator commands; no proxy-path regression.
**Tests**: Benchmark harness runs; final serial workspace suite.
**Status**: Not Started
