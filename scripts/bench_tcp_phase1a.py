#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 hmgle
# SPDX-License-Identifier: GPL-3.0-only


"""Run the Phase 1A direct and explicit-proxy TCP calibration matrix."""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import math
import os
import resource
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


PROXY_USER = "phase1a-user"
PROXY_PASSWORD = "phase1a-password"


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
class Backend:
    name: str
    executable: Path
    kind: str
    limitation: str = ""


@dataclass
class ProxyRuntime:
    kind: str
    address: str
    process: subprocess.Popen[bytes] | None
    observed_pid: int | None


def load_cpu(args: argparse.Namespace) -> int:
    """CPU for benchmark load generators (sink, local proxy, transfer).

    Defaults to the proxy CPU so the historical whole-stack single-core
    scope is preserved; `--load-cpu` moves the load off the proxy core so
    the run measures data-plane-per-core capacity instead.
    """
    return args.cpu if args.load_cpu is None else args.load_cpu


def affinity(cpu: int):
    def apply() -> None:
        os.sched_setaffinity(0, {cpu})

    return apply


def unused_port(bind: str = "127.0.0.1") -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((bind, 0))
        return sock.getsockname()[1]


def run_text(command: list[str]) -> str:
    result = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
        text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else "unavailable"


def mihomo_version(path: Path | None) -> str:
    if path is None:
        return "not configured"
    return run_text([str(path), "-v"]).replace("\n", "; ")


def git_revision(path: Path | None) -> str:
    if path is None:
        return ""
    return run_text(["git", "-C", str(path), "rev-parse", "HEAD"])


def executable_revision(executable: Path) -> str:
    for parent in (executable.parent, *executable.parents):
        if (parent / ".git").exists():
            return git_revision(parent)
    return ""


def detect_target() -> str:
    result = run_text(["ip", "-4", "-o", "addr", "show", "scope", "global"])
    benchmark_range = ipaddress.ip_network("198.18.0.0/15")
    candidates: list[str] = []
    for line in result.splitlines():
        fields = line.split()
        if "inet" not in fields:
            continue
        address = fields[fields.index("inet") + 1].split("/", 1)[0]
        parsed = ipaddress.ip_address(address)
        if not parsed.is_loopback and parsed not in benchmark_range:
            candidates.append(address)
    if not candidates:
        raise SystemExit("unable to detect a host target; pass --target")
    return candidates[0]


def mihomo_tun_state() -> str:
    rules = run_text(["ip", "rule", "show"])
    routes = run_text(["ip", "route", "show", "table", "all"])
    listener = run_text(["ss", "-ltn"])
    enabled = "lookup 2022" in rules and "198.18.0.0/30" in routes
    proxy = "127.0.0.1:7890" in listener
    return f"tun={'on' if enabled else 'off'};proxy7890={'listening' if proxy else 'absent'}"


def find_process(name: str) -> int | None:
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if (entry / "comm").read_text().strip() == name:
                return int(entry.name)
        except (OSError, ValueError):
            continue
    return None


def process_cpu_seconds(pid: int | None) -> float | None:
    if pid is None:
        return None
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
        fields = stat[stat.rfind(")") + 2 :].split()
        ticks = int(fields[11]) + int(fields[12])
        return ticks / os.sysconf("SC_CLK_TCK")
    except (OSError, ValueError, IndexError):
        return None


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    rank = max(1, math.ceil(len(ordered) * fraction))
    return ordered[min(rank, len(ordered)) - 1]


def jain_fairness(values: list[float]) -> float:
    if not values or not any(values):
        return 0.0
    total = sum(values)
    return total * total / (len(values) * sum(value * value for value in values))


@contextmanager
def credentials() -> Iterator[tuple[Path, Path, Path]]:
    with tempfile.TemporaryDirectory(prefix="yayatht-phase1a-") as directory:
        root = Path(directory)
        username = root / "username"
        password = root / "password"
        proxy_ns_config = root / "proxy-ns.json"
        username.write_text(PROXY_USER)
        password.write_text(PROXY_PASSWORD)
        username.chmod(0o600)
        password.chmod(0o600)
        proxy_ns_config.write_text(
            json.dumps(
                {
                    "tun_name": "yaybench0",
                    "tun_ip": "10.79.0.1/24",
                    "socks5_address": "127.0.0.1:7890",
                    "username": "",
                    "password": "",
                    "fake_dns": False,
                    "fake_network": "240.0.0.0/4",
                    "dns_server": "9.9.9.9",
                    "udp_session_timeout": "1m0s",
                }
            )
        )
        proxy_ns_config.chmod(0o600)
        yield username, password, proxy_ns_config


@contextmanager
def proxy_runtime(
    scenario: str,
    protocol: str,
    proxy_binary: Path,
    external_proxy: str,
    redirect_host: str,
    cpu: int,
) -> Iterator[ProxyRuntime]:
    if scenario == "mihomo":
        yield ProxyRuntime("mihomo", external_proxy, None, find_process("mihomo"))
        return
    if scenario != "local-proxy":
        yield ProxyRuntime("none", "", None, None)
        return
    port = unused_port()
    command = [
        str(proxy_binary),
        "http" if protocol == "http" else "socks5",
        str(port),
        redirect_host,
    ]
    if protocol == "socks5-auth":
        command.extend([PROXY_USER, PROXY_PASSWORD])
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        preexec_fn=affinity(cpu),
    )
    assert process.stdout is not None
    ready = process.stdout.readline().decode(errors="replace").strip()
    if not ready.startswith("READY "):
        error = process.stderr.read().decode(errors="replace") if process.stderr else ""
        process.terminate()
        process.wait(timeout=5)
        raise RuntimeError(f"local proxy failed to start: {ready}\n{error}")
    runtime = ProxyRuntime("local", f"127.0.0.1:{port}", process, process.pid)
    try:
        yield runtime
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def split_address(address: str) -> tuple[str, str]:
    host, port = address.rsplit(":", 1)
    return host.strip("[]"), port


def backend_command(
    backend: Backend,
    protocol: str,
    proxy: str,
    transfer: list[str],
    pasta_target: str,
    tap_mtu: int,
    tap_offload: str,
    tcp_send_buffer_bytes: int,
    username_file: Path,
    password_file: Path,
    proxy_ns_config: Path,
) -> list[str] | None:
    if backend.kind == "yayatht-direct":
        transfer[2] = "192.0.2.1"
        return [
            str(backend.executable),
            "run",
            "--direct",
            "--host-loopback",
            "--no-ipv6",
            "--tap-mtu",
            str(tap_mtu),
            "--tap-offload",
            tap_offload,
            "--tcp-send-buffer-bytes",
            str(tcp_send_buffer_bytes),
            "--",
            *transfer,
        ]
    if backend.kind == "pasta-direct":
        transfer[2] = pasta_target
        return [
            str(backend.executable),
            "-q",
            "-f",
            "-4",
            "-m",
            str(tap_mtu),
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
    if backend.kind == "yayatht":
        option = "--http-connect" if protocol == "http" else "--socks5"
        command = [
            str(backend.executable),
            "run",
            option,
            proxy,
            "--no-ipv6",
            "--tap-mtu",
            str(tap_mtu),
            "--tap-offload",
            tap_offload,
            "--tcp-send-buffer-bytes",
            str(tcp_send_buffer_bytes),
        ]
        if protocol == "socks5-auth":
            command.extend(
                [
                    "--proxy-username-file",
                    str(username_file),
                    "--proxy-password-file",
                    str(password_file),
                ]
            )
        return [*command, "--", *transfer]
    if backend.kind == "proxy-dev":
        proxy_type = "http" if protocol == "http" else "socks5"
        command = [
            str(backend.executable),
            "-q",
            "-f",
            "-4",
            "-m",
            str(tap_mtu),
            "--config-net",
            "-t",
            "none",
            "-u",
            "none",
            "-T",
            "none",
            "-U",
            "none",
            f"--proxy={proxy}",
            f"--proxy-type={proxy_type}",
        ]
        if protocol == "socks5-auth":
            command.extend(
                [f"--proxy-user={PROXY_USER}", f"--proxy-passwd={PROXY_PASSWORD}"]
            )
        return [*command, "--", *transfer]
    if backend.kind == "nsproxy":
        host, port = split_address(proxy)
        command = [str(backend.executable), "-q", "-d", "off", "-s", host, "-p", port]
        if protocol == "http":
            command.append("-H")
        if protocol == "socks5-auth":
            command.extend(["-a", f"{PROXY_USER}:{PROXY_PASSWORD}"])
        return [*command, *transfer]
    if backend.kind == "proxy-ns":
        if protocol == "http":
            return None
        command = [
            str(backend.executable),
            "-q",
            "-c",
            str(proxy_ns_config),
            "--tun-name=yaybench0",
            "--tun-ip=10.79.0.1/24",
            f"--socks5-address={proxy}",
            "--fake-dns=false",
            "--dns-server=9.9.9.9",
        ]
        if protocol == "socks5-auth":
            command.extend([f"--username={PROXY_USER}", f"--password={PROXY_PASSWORD}"])
        return [*command, *transfer]
    raise AssertionError(f"unknown backend kind {backend.kind}")


def run_case(
    backend: Backend,
    scenario: str,
    protocol: str,
    proxy: ProxyRuntime,
    flow_count: int,
    byte_count: int,
    run: int,
    args: argparse.Namespace,
    username_file: Path,
    password_file: Path,
    proxy_ns_config: Path,
) -> dict[str, object]:
    port = unused_port("0.0.0.0")
    server = subprocess.Popen(
        [
            str(args.io_binary),
            "multi-sink",
            str(port),
            str(flow_count),
            str(byte_count),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        preexec_fn=affinity(load_cpu(args)),
    )
    time.sleep(0.05)
    transfer = [
        str(args.io_binary),
        "multi-source",
        args.local_target if scenario == "local-proxy" else args.target,
        str(port),
        str(flow_count),
        str(byte_count),
    ]
    command = backend_command(
        backend,
        protocol,
        proxy.address,
        transfer,
        args.pasta_target,
        args.tap_mtu,
        args.tap_offload,
        args.tcp_send_buffer_bytes,
        username_file,
        password_file,
        proxy_ns_config,
    )
    if command is None:
        server.terminate()
        server.wait(timeout=5)
        raise RuntimeError(f"{backend.name} does not support {protocol}")
    if args.load_cpu is not None:
        # Every backend command ends with the transfer argv; the in-namespace
        # source inherits the backend's affinity, so a taskset wrapper moves
        # it onto the load CPU while the proxy instance stays on args.cpu.
        command = [
            *command[: len(command) - len(transfer)],
            "taskset",
            "-c",
            str(args.load_cpu),
            *transfer,
        ]
    before_usage = Usage.children()
    proxy_cpu_before = process_cpu_seconds(proxy.observed_pid)
    started = time.perf_counter()
    try:
        client = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=args.timeout,
            check=False,
            preexec_fn=affinity(args.cpu),
        )
    except Exception:
        server.terminate()
        server.wait(timeout=5)
        raise
    command_seconds = time.perf_counter() - started
    if client.returncode != 0:
        server.terminate()
        server.wait(timeout=5)
        stdout = client.stdout.decode(errors="replace")
        stderr = client.stderr.decode(errors="replace")
        raise RuntimeError(
            f"client exited {client.returncode}:\nstdout:\n{stdout}\nstderr:\n{stderr}"
        )
    try:
        server.wait(timeout=30)
    except subprocess.TimeoutExpired:
        server.terminate()
        server.wait(timeout=5)
        raise RuntimeError("receiver did not observe every flow") from None
    usage = Usage.children().subtract(before_usage)
    proxy_cpu_after = process_cpu_seconds(proxy.observed_pid)
    server_output = (
        server.stdout.read().decode(errors="replace").strip() if server.stdout else ""
    )
    server_error = (
        server.stderr.read().decode(errors="replace") if server.stderr else ""
    )
    if server.returncode != 0:
        raise RuntimeError(f"sink exited {server.returncode}:\n{server_error}")
    expected = flow_count * byte_count
    if server_output != str(expected):
        raise RuntimeError(
            f"sink received {server_output or 'nothing'}, expected {expected}"
        )
    result = json.loads(client.stdout)
    flow_results = result["flows"]
    connect = [float(flow["connect_seconds"]) for flow in flow_results]
    completion = [float(flow["completion_seconds"]) for flow in flow_results]
    transfer_seconds = [float(flow["transfer_seconds"]) for flow in flow_results]
    throughputs = [byte_count * 8 / seconds for seconds in transfer_seconds]
    wall_seconds = float(result["wall_seconds"])
    proxy_cpu = None
    if proxy_cpu_before is not None and proxy_cpu_after is not None:
        proxy_cpu = proxy_cpu_after - proxy_cpu_before
    return {
        "scenario": scenario,
        "protocol": protocol,
        "proxy_kind": proxy.kind,
        "proxy_address": proxy.address,
        "backend": backend.name,
        "backend_kind": backend.kind,
        "backend_revision": executable_revision(backend.executable),
        "backend_limitation": backend.limitation,
        "run": run,
        "flows": flow_count,
        "bytes_per_flow": byte_count,
        "total_bytes": expected,
        "transfer_wall_seconds": wall_seconds,
        "command_wall_seconds": command_seconds,
        "gibibits_per_second": expected * 8 / wall_seconds / (1024**3),
        "child_cpu_seconds": usage.user + usage.system,
        "child_user_seconds": usage.user,
        "child_system_seconds": usage.system,
        "proxy_cpu_seconds": proxy_cpu if proxy_cpu is not None else "",
        "connect_p50_ms": percentile(connect, 0.50) * 1000,
        "connect_p99_ms": percentile(connect, 0.99) * 1000,
        "completion_p50_ms": percentile(completion, 0.50) * 1000,
        "completion_p99_ms": percentile(completion, 0.99) * 1000,
        "fairness_jain": jain_fairness(throughputs),
        "flow_throughput_min_mib_s": min(throughputs) / 8 / (1024**2),
        "flow_throughput_median_mib_s": statistics.median(throughputs) / 8 / (1024**2),
        "flow_throughput_max_mib_s": max(throughputs) / 8 / (1024**2),
        "target": transfer[2],
        "cpu": args.cpu,
        "load_cpu": "" if args.load_cpu is None else args.load_cpu,
        "requested_tap_mtu": args.tap_mtu,
        "requested_tap_offload": args.tap_offload,
        "requested_tcp_send_buffer_bytes": args.tcp_send_buffer_bytes,
        "kernel": run_text(["uname", "-srmo"]),
        "mihomo_version": mihomo_version(args.mihomo),
        "mihomo_tun_state": mihomo_tun_state(),
        "status": "ok",
        "error": "",
    }


def error_record(
    backend: Backend,
    scenario: str,
    protocol: str,
    proxy: ProxyRuntime,
    flow_count: int,
    byte_count: int,
    run: int,
    args: argparse.Namespace,
    error: Exception,
) -> dict[str, object]:
    return {
        "scenario": scenario,
        "protocol": protocol,
        "proxy_kind": proxy.kind,
        "proxy_address": proxy.address,
        "backend": backend.name,
        "backend_kind": backend.kind,
        "backend_revision": executable_revision(backend.executable),
        "backend_limitation": backend.limitation,
        "run": run,
        "flows": flow_count,
        "bytes_per_flow": byte_count,
        "total_bytes": flow_count * byte_count,
        "target": args.target,
        "cpu": args.cpu,
        "load_cpu": "" if args.load_cpu is None else args.load_cpu,
        "requested_tap_mtu": args.tap_mtu,
        "requested_tap_offload": args.tap_offload,
        "requested_tcp_send_buffer_bytes": args.tcp_send_buffer_bytes,
        "kernel": run_text(["uname", "-srmo"]),
        "mihomo_version": mihomo_version(args.mihomo),
        "mihomo_tun_state": mihomo_tun_state(),
        "status": "error",
        "error": str(error).replace("\n", " | ")[:2000],
    }


def parse_csv_ints(value: str) -> list[int]:
    return [int(item) for item in value.split(",") if item]


def parse_csv_strings(value: str) -> list[str]:
    return [item for item in value.split(",") if item]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--yayatht", type=Path, default=Path("target/release/yayatht"))
    parser.add_argument("--pasta", type=Path)
    parser.add_argument("--proxy-dev", type=Path)
    parser.add_argument("--nsproxy", type=Path)
    parser.add_argument("--proxy-ns", type=Path)
    parser.add_argument(
        "--io-binary", type=Path, default=Path("target/release/tcp-bench-io")
    )
    parser.add_argument(
        "--proxy-binary", type=Path, default=Path("target/release/tcp-bench-proxy")
    )
    parser.add_argument(
        "--mihomo",
        type=Path,
        help="mihomo executable (default: find mihomo on PATH when needed)",
    )
    parser.add_argument("--external-proxy", default="127.0.0.1:7890")
    parser.add_argument(
        "--target", help="numeric host address reachable through the proxy"
    )
    parser.add_argument(
        "--local-target",
        default="198.51.100.77",
        help="numeric logical target redirected by the local benchmark proxy",
    )
    parser.add_argument("--pasta-target", default="172.16.10.1")
    parser.add_argument("--scenarios", default="direct,local-proxy,mihomo")
    parser.add_argument("--protocols", default="socks5,socks5-auth,http")
    parser.add_argument("--flows", default="1,8,32,128")
    parser.add_argument("--mib-per-flow", type=int, default=4)
    parser.add_argument("--tap-mtu", type=int, default=32000)
    parser.add_argument("--tap-offload", default="on", choices=["on", "off"])
    parser.add_argument("--tcp-send-buffer-bytes", type=int, default=256 * 1024)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--cpu", type=int, default=0)
    parser.add_argument("--load-cpu", type=int, default=None)
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--fail-fast", action="store_true")
    return parser.parse_args()


def validate_executable(
    path: Path | None, label: str, required: bool = False
) -> Path | None:
    if path is None:
        if required:
            raise SystemExit(f"{label} is required")
        return None
    if not path.is_absolute() and path.parent == Path("."):
        discovered = shutil.which(str(path))
        path = Path(discovered) if discovered is not None else path
    path = Path(os.path.abspath(path))
    if not path.is_file() or not os.access(path, os.X_OK):
        raise SystemExit(f"not executable: {path}")
    return path


def main() -> int:
    args = parse_args()
    args.scenarios = parse_csv_strings(args.scenarios)
    args.protocols = parse_csv_strings(args.protocols)
    args.flows = parse_csv_ints(args.flows)
    if args.target is None:
        args.target = detect_target()
    if (
        args.mib_per_flow <= 0
        or args.runs <= 0
        or args.warmups < 0
        or not 1280 <= args.tap_mtu <= 65520
        or not 16 * 1024 <= args.tcp_send_buffer_bytes <= 16 * 1024 * 1024
        or not args.flows
        or any(flow <= 0 for flow in args.flows)
    ):
        raise SystemExit("flow, size, run counts, or TAP MTU are invalid")
    if args.load_cpu is not None:
        if args.load_cpu < 0 or args.load_cpu == args.cpu:
            raise SystemExit("--load-cpu must name a CPU different from --cpu")
        if shutil.which("taskset") is None:
            raise SystemExit("--load-cpu requires taskset on PATH")
    args.yayatht = validate_executable(args.yayatht, "yayatht", required=True)
    args.io_binary = validate_executable(args.io_binary, "tcp-bench-io", required=True)
    args.proxy_binary = validate_executable(
        args.proxy_binary, "tcp-bench-proxy", required="local-proxy" in args.scenarios
    )
    args.pasta = validate_executable(args.pasta, "pasta")
    args.proxy_dev = validate_executable(args.proxy_dev, "proxy-dev pasta")
    args.nsproxy = validate_executable(args.nsproxy, "nsproxy")
    args.proxy_ns = validate_executable(args.proxy_ns, "proxy-ns")
    if args.mihomo is None and "mihomo" in args.scenarios:
        discovered = shutil.which("mihomo")
        if discovered is not None:
            args.mihomo = Path(discovered)
    args.mihomo = validate_executable(
        args.mihomo, "mihomo", required="mihomo" in args.scenarios
    )

    direct_backends = [Backend("yayatht-direct", args.yayatht, "yayatht-direct")]
    if args.pasta:
        direct_backends.append(
            Backend("pasta-6ef3d1c-direct", args.pasta, "pasta-direct")
        )
    proxy_backends = [Backend("yayatht", args.yayatht, "yayatht")]
    if args.proxy_dev:
        proxy_backends.append(
            Backend(
                "pasta-proxy-dev-c7568f5",
                args.proxy_dev,
                "proxy-dev",
                "blocking handshake; legacy TCP core; argv credentials",
            )
        )
    if args.nsproxy:
        proxy_backends.append(Backend("nsproxy", args.nsproxy, "nsproxy"))
    if args.proxy_ns:
        proxy_backends.append(Backend("proxy-ns", args.proxy_ns, "proxy-ns"))

    records: list[dict[str, object]] = []
    byte_count = args.mib_per_flow * 1024 * 1024
    with credentials() as (username_file, password_file, proxy_ns_config):
        for scenario in args.scenarios:
            protocols = ["direct"] if scenario == "direct" else args.protocols
            backends = direct_backends if scenario == "direct" else proxy_backends
            for protocol in protocols:
                if scenario == "mihomo" and protocol == "socks5-auth":
                    continue
                with proxy_runtime(
                    scenario,
                    protocol,
                    args.proxy_binary,
                    args.external_proxy,
                    args.target,
                    load_cpu(args),
                ) as proxy:
                    for flow_count in args.flows:
                        for backend in backends:
                            if backend.kind == "proxy-ns" and protocol == "http":
                                continue
                            for warmup in range(args.warmups):
                                print(
                                    f"warmup {scenario}/{protocol}/{backend.name}/"
                                    f"flows={flow_count}",
                                    file=sys.stderr,
                                    flush=True,
                                )
                                try:
                                    run_case(
                                        backend,
                                        scenario,
                                        protocol,
                                        proxy,
                                        flow_count,
                                        byte_count,
                                        -(warmup + 1),
                                        args,
                                        username_file,
                                        password_file,
                                        proxy_ns_config,
                                    )
                                except Exception as error:
                                    if args.fail_fast:
                                        raise
                                    print(
                                        f"warmup failed: {scenario}/{protocol}/{backend.name}/"
                                        f"{flow_count}: {error}",
                                        file=sys.stderr,
                                    )
                                    break
                            for run in range(1, args.runs + 1):
                                print(
                                    f"run {run} {scenario}/{protocol}/{backend.name}/"
                                    f"flows={flow_count}",
                                    file=sys.stderr,
                                    flush=True,
                                )
                                try:
                                    record = run_case(
                                        backend,
                                        scenario,
                                        protocol,
                                        proxy,
                                        flow_count,
                                        byte_count,
                                        run,
                                        args,
                                        username_file,
                                        password_file,
                                        proxy_ns_config,
                                    )
                                except Exception as error:
                                    if args.fail_fast:
                                        raise
                                    record = error_record(
                                        backend,
                                        scenario,
                                        protocol,
                                        proxy,
                                        flow_count,
                                        byte_count,
                                        run,
                                        args,
                                        error,
                                    )
                                records.append(record)

    fieldnames = sorted({key for record in records for key in record})
    writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    writer.writerows(records)
    return 0 if all(record["status"] == "ok" for record in records) else 1


if __name__ == "__main__":
    raise SystemExit(main())
