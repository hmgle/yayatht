#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 hmgle
# SPDX-License-Identifier: GPL-3.0-only


"""Compare yayatht and pasta direct TCP adapters on one CPU."""

from __future__ import annotations

import argparse
import csv
import os
import resource
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Usage:
    user: float
    system: float

    @classmethod
    def children(cls) -> "Usage":
        value = resource.getrusage(resource.RUSAGE_CHILDREN)
        return cls(value.ru_utime, value.ru_stime)

    def subtract(self, previous: "Usage") -> "Usage":
        return Usage(self.user - previous.user, self.system - previous.system)


@dataclass(frozen=True)
class Result:
    backend: str
    run: int
    byte_count: int
    seconds: float
    user_seconds: float
    system_seconds: float

    @property
    def gibibits_per_second(self) -> float:
        return self.byte_count * 8 / self.seconds / (1024**3)


def affinity(cpu: int):
    def apply() -> None:
        os.sched_setaffinity(0, {cpu})

    return apply


def unused_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def backend_command(
    backend: str,
    yayatht: Path,
    pasta: Path,
    io_binary: Path,
    pasta_target: str,
    port: int,
    byte_count: int,
) -> list[str]:
    target = "192.0.2.1" if backend == "yayatht" else pasta_target
    transfer = [str(io_binary), "source", target, str(port), str(byte_count)]
    if backend == "yayatht":
        return [
            str(yayatht),
            "run",
            "--direct",
            "--host-loopback",
            "--no-ipv6",
            "--",
            *transfer,
        ]
    return [
        str(pasta),
        "-q",
        "-f",
        "-4",
        "-m",
        "1500",
        "--config-net",
        "--no-splice",
        "-t",
        "none",
        "-u",
        "none",
        "-T",
        "none",
        "-U",
        "none",
        "--",
        *transfer,
    ]


def run_transfer(
    backend: str,
    run: int,
    yayatht: Path,
    pasta: Path,
    io_binary: Path,
    pasta_target: str,
    mib: int,
    cpu: int,
) -> Result:
    port = unused_port()
    byte_count = mib * 1024 * 1024
    server = subprocess.Popen(
        [str(io_binary), "sink", str(port), str(byte_count)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        preexec_fn=affinity(cpu),
    )
    time.sleep(0.05)
    before = Usage.children()
    started = time.perf_counter()
    command = backend_command(
        backend,
        yayatht,
        pasta,
        io_binary,
        pasta_target,
        port,
        byte_count,
    )
    client = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        timeout=180,
        check=False,
        preexec_fn=affinity(cpu),
    )
    if client.returncode != 0:
        server.terminate()
        server.wait(timeout=5)
        client_error = client.stderr.decode(errors="replace")
        server_error = server.stderr.read().decode(errors="replace")
        raise RuntimeError(
            f"{backend} client failed with {client.returncode}\n"
            f"client stderr:\n{client_error}\nserver stderr:\n{server_error}"
        )
    try:
        server.wait(timeout=30)
    except subprocess.TimeoutExpired:
        server.terminate()
        server.wait(timeout=5)
        raise RuntimeError(f"{backend} receiver did not observe EOF") from None
    elapsed = time.perf_counter() - started
    usage = Usage.children().subtract(before)
    received_text = server.stdout.read().decode(errors="replace").strip()
    server_error = server.stderr.read().decode(errors="replace")
    if client.returncode != 0 or server.returncode != 0:
        client_error = client.stderr.decode(errors="replace")
        raise RuntimeError(
            f"{backend} failed: client={client.returncode} server={server.returncode}\n"
            f"client stderr:\n{client_error}\nserver stderr:\n{server_error}"
        )
    if received_text != str(byte_count):
        raise RuntimeError(
            f"{backend} received {received_text or 'no byte count'}, expected {byte_count}"
        )
    return Result(
        backend=backend,
        run=run,
        byte_count=byte_count,
        seconds=elapsed,
        user_seconds=usage.user,
        system_seconds=usage.system,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--yayatht", type=Path, default=Path("target/release/yayatht"))
    parser.add_argument("--pasta", type=Path, required=True)
    parser.add_argument(
        "--pasta-target",
        required=True,
        help="gateway address that pasta maps to host loopback",
    )
    parser.add_argument(
        "--io-binary",
        type=Path,
        default=Path("target/release/tcp-bench-io"),
    )
    parser.add_argument("--mib", type=int, default=1024)
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--cpu", type=int, default=0)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.mib <= 0 or args.runs <= 0 or args.warmups < 0:
        raise SystemExit("mib and runs must be positive; warmups must be non-negative")
    args.yayatht = Path(os.path.abspath(args.yayatht))
    args.pasta = Path(os.path.abspath(args.pasta))
    args.io_binary = Path(os.path.abspath(args.io_binary))
    for executable in (args.yayatht, args.pasta, args.io_binary):
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise SystemExit(f"not executable: {executable}")

    for backend in ("yayatht", "pasta"):
        for warmup in range(args.warmups):
            run_transfer(
                backend,
                -(warmup + 1),
                args.yayatht,
                args.pasta,
                args.io_binary,
                args.pasta_target,
                args.mib,
                args.cpu,
            )

    writer = csv.writer(sys.stdout, lineterminator="\n")
    writer.writerow(
        [
            "backend",
            "run",
            "bytes",
            "seconds",
            "gibibits_per_second",
            "user_seconds",
            "system_seconds",
        ]
    )
    for run in range(1, args.runs + 1):
        for backend in ("yayatht", "pasta"):
            result = run_transfer(
                backend,
                run,
                args.yayatht,
                args.pasta,
                args.io_binary,
                args.pasta_target,
                args.mib,
                args.cpu,
            )
            writer.writerow(
                [
                    result.backend,
                    result.run,
                    result.byte_count,
                    f"{result.seconds:.6f}",
                    f"{result.gibibits_per_second:.3f}",
                    f"{result.user_seconds:.6f}",
                    f"{result.system_seconds:.6f}",
                ]
            )
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
