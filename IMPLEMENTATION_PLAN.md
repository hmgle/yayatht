# Short-flow completion latency fix

Diagnosis (2026-07-14): the ~100 ms 4 MiB single-flow completion penalty is not
a timer stall. It is sustained low throughput caused by (a) missing TCP window
scaling, capping in-flight data at 64 KiB end-to-end, and (b) ~11 getsockopt
calls plus one immediate bare ACK per forwarded segment.

## Stage 1: Window scale option in packet layer

**Goal**: Parse window-scale from SYN options; emit it in headers.
**Success Criteria**: `TcpSegment::window_scale()` returns the shift; header
writer emits kind-3 option when requested.
**Tests**: option parse/emit unit tests beside existing MSS tests.
**Status**: Complete

## Stage 2: Wide window model in tcp-adapter

**Goal**: Track peer/local window shifts; scale peer window on receive; widen
advertised window past u16.
**Success Criteria**: `available_namespace_window` uses scaled peer window;
on-wire window field derived via local shift.
**Tests**: flow unit tests for scaled receive/advertise paths.
**Status**: Not Started

## Stage 3: Negotiate window scaling in the reactor

**Goal**: Offer wscale on SYN-ACK when the namespace SYN offered it; remove
the u16::MAX advertised-window clamp.
**Success Criteria**: single-flow direct benchmark shows >64 KiB in flight.
**Tests**: reactor SYN handling unit tests; rootless integration suite.
**Status**: Not Started

## Stage 4: Batch ACK refresh per TAP batch

**Goal**: Defer refresh_upstream_ack to once per flow per TAP batch instead of
per segment.
**Success Criteria**: getsockopt count per segment drops by ~an order of
magnitude; one ACK per batch per flow.
**Tests**: existing serial workspace suite; strace count check.
**Status**: Not Started

## Stage 5: Re-run Phase 1A calibration matrix

**Goal**: Repeat the full local matrix and record results in
docs/phase1a-exit-audit.md.
**Success Criteria**: single-flow 4 MiB completion p99 comparable to nsproxy
(tens of ms), no regression at 8/32/128 flows.
**Status**: Not Started
