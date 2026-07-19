#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 hmgle
# SPDX-License-Identifier: GPL-3.0-only


"""Calibrate yayatht multi-flow TCP scaling across TAP worker counts."""

from __future__ import annotations

import argparse
import json
import platform
import socket
import statistics
import subprocess
import time
from pathlib import Path


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("expected a positive integer")
    return parsed


def worker_counts(value: str) -> list[int]:
    counts = [positive_int(field.strip()) for field in value.split(",")]
    if not counts:
        raise argparse.ArgumentTypeError("expected at least one worker count")
    return counts


def executable(path: Path) -> Path:
    resolved = path.resolve()
    if not resolved.is_file():
        raise SystemExit(f"benchmark executable is missing: {resolved}")
    return resolved


def unused_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def run_once(
    yayatht: Path,
    io_binary: Path,
    workers: int,
    flows: int,
    bytes_per_flow: int,
    timeout: float,
) -> dict[str, object]:
    port = unused_port()
    sink = subprocess.Popen(
        [
            str(io_binary),
            "multi-sink",
            str(port),
            str(flows),
            str(bytes_per_flow),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    command = [
        str(yayatht),
        "run",
        "--direct",
        "--host-loopback",
        "--no-ipv6",
        "--dns",
        "off",
        "--workers",
        str(workers),
        "--",
        str(io_binary),
        "multi-source",
        "192.0.2.1",
        str(port),
        str(flows),
        str(bytes_per_flow),
    ]
    started = time.monotonic()
    try:
        source = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
        sink_stdout, sink_stderr = sink.communicate(timeout=timeout)
    except BaseException:
        sink.kill()
        sink.communicate()
        raise
    elapsed = time.monotonic() - started
    if source.returncode != 0:
        raise RuntimeError(
            f"yayatht run failed ({source.returncode}): {source.stderr.strip()}"
        )
    if sink.returncode != 0:
        raise RuntimeError(f"sink failed ({sink.returncode}): {sink_stderr.strip()}")
    result = json.loads(source.stdout)
    received = int(sink_stdout.strip())
    expected = flows * bytes_per_flow
    if received != expected:
        raise RuntimeError(f"sink received {received} bytes, expected {expected}")
    wall_seconds = float(result["wall_seconds"])
    return {
        "workers": workers,
        "flows": flows,
        "bytes_per_flow": bytes_per_flow,
        "wall_seconds": wall_seconds,
        "process_seconds": elapsed,
        "aggregate_gbit_s": expected * 8 / wall_seconds / 1_000_000_000,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--yayatht", type=Path, default=Path("target/release/yayatht"))
    parser.add_argument(
        "--io-binary", type=Path, default=Path("target/release/tcp-bench-io")
    )
    parser.add_argument("--workers", type=worker_counts, default=worker_counts("1,4"))
    parser.add_argument("--flows", type=positive_int, default=32)
    parser.add_argument("--bytes-per-flow", type=positive_int, default=64 * 1024 * 1024)
    parser.add_argument("--repeats", type=positive_int, default=3)
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    yayatht = executable(args.yayatht)
    io_binary = executable(args.io_binary)
    runs: list[dict[str, object]] = []
    for workers in args.workers:
        for repeat in range(1, args.repeats + 1):
            result = run_once(
                yayatht,
                io_binary,
                workers,
                args.flows,
                args.bytes_per_flow,
                args.timeout,
            )
            result["repeat"] = repeat
            runs.append(result)
            print(json.dumps(result), flush=True)

    medians = {
        str(workers): statistics.median(
            float(run["aggregate_gbit_s"])
            for run in runs
            if run["workers"] == workers
        )
        for workers in args.workers
    }
    report = {
        "schema": 1,
        "kernel": platform.release(),
        "machine": platform.machine(),
        "command": {
            "workers": args.workers,
            "flows": args.flows,
            "bytes_per_flow": args.bytes_per_flow,
            "repeats": args.repeats,
        },
        "runs": runs,
        "median_aggregate_gbit_s": medians,
    }
    serialized = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.write_text(serialized)
    print(serialized, end="")


if __name__ == "__main__":
    main()
