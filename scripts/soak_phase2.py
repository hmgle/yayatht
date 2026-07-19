#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 hmgle
# SPDX-License-Identifier: GPL-3.0-only


"""Run a bounded Phase 2 TCP/UDP/DNS soak and sample worker resources."""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path


def executable(path: Path) -> Path:
    resolved = path.resolve()
    if not resolved.is_file():
        raise SystemExit(f"required executable is missing: {resolved}")
    return resolved


def tcp_echo(listener: socket.socket, stop: threading.Event) -> None:
    listener.settimeout(0.2)
    while not stop.is_set():
        try:
            stream, _ = listener.accept()
        except TimeoutError:
            continue
        threading.Thread(target=echo_stream, args=(stream,), daemon=True).start()


def echo_stream(stream: socket.socket) -> None:
    with stream:
        while payload := stream.recv(65536):
            stream.sendall(payload)


def udp_echo(sock: socket.socket, stop: threading.Event) -> None:
    sock.settimeout(0.2)
    while not stop.is_set():
        try:
            payload, peer = sock.recvfrom(65535)
        except TimeoutError:
            continue
        sock.sendto(payload, peer)


def dns_answer(query: bytes) -> bytes:
    offset = 12
    while query[offset] != 0:
        offset += query[offset] + 1
    question_end = offset + 5
    return b"".join(
        [
            query[:2],
            b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00",
            query[12:question_end],
            b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x01\x00\x04",
            b"\xc0\x00\x02\x37",
        ]
    )


def dns_server(listener: socket.socket, stop: threading.Event) -> None:
    listener.settimeout(0.2)
    while not stop.is_set():
        try:
            stream, _ = listener.accept()
        except TimeoutError:
            continue
        threading.Thread(target=dns_stream, args=(stream,), daemon=True).start()


def read_exact(stream: socket.socket, length: int) -> bytes | None:
    payload = bytearray()
    while len(payload) < length:
        chunk = stream.recv(length - len(payload))
        if not chunk:
            return None
        payload.extend(chunk)
    return bytes(payload)


def dns_stream(stream: socket.socket) -> None:
    with stream:
        while prefix := read_exact(stream, 2):
            length = int.from_bytes(prefix, "big")
            query = read_exact(stream, length)
            if query is None:
                return
            answer = dns_answer(query)
            stream.sendall(len(answer).to_bytes(2, "big") + answer)


def tcp_listener() -> socket.socket:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    return listener


def worker_resources(status: dict[str, object]) -> tuple[int, int]:
    rss_kib = 0
    descriptors = 0
    for raw_pid in status["dataplane_worker_pids"]:
        pid = int(raw_pid)
        fields = Path(f"/proc/{pid}/status").read_text().splitlines()
        vmrss = next(line for line in fields if line.startswith("VmRSS:"))
        rss_kib += int(vmrss.split()[1])
        descriptors += len(list(Path(f"/proc/{pid}/fd").iterdir()))
    return rss_kib, descriptors


def query_status(yayatht: Path, runtime: Path, name: str) -> dict[str, object]:
    result = subprocess.run(
        [
            str(yayatht),
            "status",
            "--runtime-dir",
            str(runtime),
            "--name",
            name,
            "--json",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=5,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"status failed: {result.stderr.strip()}")
    return json.loads(result.stdout)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--yayatht", type=Path, default=Path("target/release/yayatht"))
    parser.add_argument(
        "--client", type=Path, default=Path("target/release/phase2-soak-client")
    )
    parser.add_argument("--duration-seconds", type=int, default=60 * 60)
    parser.add_argument("--sample-seconds", type=float, default=60.0)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.duration_seconds <= 0 or args.sample_seconds <= 0 or args.workers <= 0:
        raise SystemExit("duration, sample interval, and workers must be positive")
    yayatht = executable(args.yayatht)
    client = executable(args.client)

    stop = threading.Event()
    tcp = tcp_listener()
    dns = tcp_listener()
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    servers = [
        threading.Thread(target=tcp_echo, args=(tcp, stop), daemon=True),
        threading.Thread(target=udp_echo, args=(udp, stop), daemon=True),
        threading.Thread(target=dns_server, args=(dns, stop), daemon=True),
    ]
    for server in servers:
        server.start()

    started = time.monotonic()
    samples: list[dict[str, object]] = []
    try:
        with tempfile.TemporaryDirectory(prefix="yayatht-phase2-soak-") as directory:
            runtime = Path(directory)
            os.chmod(runtime, 0o700)
            name = f"soak-{os.getpid()}"
            command = [
                str(yayatht),
                "run",
                "--direct",
                "--host-loopback",
                "--no-ipv6",
                "--workers",
                str(args.workers),
                "--dns-upstream",
                f"127.0.0.1:{dns.getsockname()[1]}",
                "--runtime-dir",
                str(runtime),
                "--name",
                name,
                "--",
                str(client),
                str(args.duration_seconds),
                f"192.0.2.1:{tcp.getsockname()[1]}",
                f"192.0.2.1:{udp.getsockname()[1]}",
                "192.0.2.1:53",
            ]
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            control = runtime / name / "control.sock"
            deadline = time.monotonic() + 10
            while not control.exists() and process.poll() is None:
                if time.monotonic() >= deadline:
                    process.kill()
                    raise RuntimeError("instance control socket did not appear")
                time.sleep(0.02)
            while process.poll() is None:
                try:
                    status = query_status(yayatht, runtime, name)
                    rss_kib, descriptors = worker_resources(status)
                    samples.append(
                        {
                            "elapsed_seconds": time.monotonic() - started,
                            "worker_rss_kib": rss_kib,
                            "worker_fds": descriptors,
                            "tcp_created": status["dataplane"]["tcp_created"],
                            "udp_created": status["dataplane"]["udp_created"],
                            "dns_queries": status["dataplane"]["dns_queries"],
                        }
                    )
                except (FileNotFoundError, RuntimeError):
                    if process.poll() is not None:
                        break
                    if not samples:
                        time.sleep(0.02)
                        continue
                    raise
                time.sleep(min(args.sample_seconds, 0.2 if not samples else args.sample_seconds))
            stdout, stderr = process.communicate(timeout=10)
            returncode = process.returncode
    finally:
        stop.set()
        for server in servers:
            server.join(timeout=1)
        for sock in [tcp, udp, dns]:
            sock.close()

    if returncode != 0:
        raise SystemExit(f"soak workload failed ({returncode}): {stderr.strip()}")
    if not samples:
        raise SystemExit("soak completed without a resource sample")
    report = {
        "schema": 1,
        "duration_seconds": time.monotonic() - started,
        "requested_duration_seconds": args.duration_seconds,
        "workers": args.workers,
        "client_summary": stdout.strip(),
        "samples": samples,
        "worker_rss_kib": {
            "initial": samples[0]["worker_rss_kib"],
            "final": samples[-1]["worker_rss_kib"],
            "peak": max(int(sample["worker_rss_kib"]) for sample in samples),
        },
        "worker_fds": {
            "initial": samples[0]["worker_fds"],
            "final": samples[-1]["worker_fds"],
            "peak": max(int(sample["worker_fds"]) for sample in samples),
        },
    }
    serialized = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.write_text(serialized)
    print(serialized, end="")


if __name__ == "__main__":
    main()
