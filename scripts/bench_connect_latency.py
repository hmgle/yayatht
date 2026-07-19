#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 hmgle
# SPDX-License-Identifier: GPL-3.0-only


"""Measure namespace TCP connect latency through yayatht.

Two protocols are reported:

- cold: N isolated instances with an idle gap between them; each measures
  one first-connect. This is dominated by platform power management on an
  idle machine (cpuidle exit latency and frequency ramp across the
  multi-process wakeup chain), not by the data-plane code path.
- warm: one instance running N sequential single-connect rounds; rounds
  after the first measure the steady-state software path.

--spin keeps one CPU busy at nice 19 and pins the whole chain to it,
bounding the platform effects to expose the software-path floor.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import signal
import statistics
import subprocess
import sys
import time
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--yayatht", type=Path, default=Path("target/release/yayatht"))
    parser.add_argument(
        "--io-binary", type=Path, default=Path("target/release/tcp-bench-io")
    )
    parser.add_argument("--cold", type=int, default=6)
    parser.add_argument("--warm", type=int, default=20)
    parser.add_argument("--gap", type=float, default=3.0)
    parser.add_argument("--cpu", type=int, default=0)
    parser.add_argument("--spin", action="store_true")
    parser.add_argument("--tap-offload", default="on", choices=["on", "off"])
    return parser.parse_args()


def unused_port() -> int:
    return 20000 + random.randrange(20000)


def affinity(cpu: int | None):
    def apply() -> None:
        if cpu is not None:
            os.sched_setaffinity(0, {cpu})

    return apply


def run_rounds(args: argparse.Namespace, rounds: int, cpu: int | None) -> list[float]:
    """One instance, `rounds` sequential single-connect transfers."""
    port = unused_port()
    sink = subprocess.Popen(
        [str(args.io_binary), "multi-sink", str(port), str(rounds), "1"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        preexec_fn=affinity(cpu),
    )
    time.sleep(0.2)
    script = (
        f"for i in $(seq {rounds}); do "
        f"{args.io_binary} multi-source 192.0.2.1 {port} 1 1; done"
    )
    client = subprocess.run(
        [
            str(args.yayatht),
            "run",
            "--direct",
            "--host-loopback",
            "--no-ipv6",
            "--tap-offload",
            args.tap_offload,
            "--name",
            f"connlat-{os.getpid()}-{port}",
            "--",
            "sh",
            "-c",
            script,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        check=False,
        preexec_fn=affinity(cpu),
    )
    sink.wait(timeout=10)
    if client.returncode != 0:
        raise RuntimeError(client.stderr.decode(errors="replace"))
    values = []
    for line in client.stdout.decode().splitlines():
        line = line.strip()
        if line:
            result = json.loads(line)
            values.append(result["flows"][0]["connect_seconds"] * 1000)
    if len(values) != rounds:
        raise RuntimeError(f"expected {rounds} rounds, parsed {len(values)}")
    return values


def summary(label: str, values: list[float]) -> None:
    ordered = sorted(values)
    p99 = ordered[min(len(ordered) - 1, int(len(ordered) * 0.99))]
    print(
        f"{label}: n={len(values)} min={ordered[0]:.2f} "
        f"p50={statistics.median(ordered):.2f} p99={p99:.2f} "
        f"max={ordered[-1]:.2f} ms"
    )


def main() -> int:
    args = parse_args()
    for path in (args.yayatht, args.io_binary):
        if not path.is_file() or not os.access(path, os.X_OK):
            raise SystemExit(f"not executable: {path}")
    spinner = None
    cpu = args.cpu if args.spin else None
    if args.spin:
        spinner = subprocess.Popen(
            ["sh", "-c", "while :; do :; done"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=affinity(args.cpu),
        )
        os.system(f"renice -n 19 -p {spinner.pid} >/dev/null")
        time.sleep(0.3)
    try:
        cold = []
        for index in range(args.cold):
            if index > 0:
                time.sleep(args.gap)
            cold.extend(run_rounds(args, 1, cpu))
            print(f"cold {index + 1}/{args.cold}: {cold[-1]:.2f} ms", file=sys.stderr)
        warm_all = run_rounds(args, args.warm, cpu)
        mode = "spin" if args.spin else "idle"
        summary(f"cold first-connect ({mode})", cold)
        summary(f"warm first-connect ({mode})", warm_all[:1])
        summary(f"warm steady-state ({mode})", warm_all[1:])
    finally:
        if spinner is not None:
            spinner.send_signal(signal.SIGKILL)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
