#!/usr/bin/env python3

"""Capture direct resolver access while exercising proxy-tcp and proxy-udp."""

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


def read_exact(stream: socket.socket, length: int) -> bytes:
    payload = bytearray()
    while len(payload) < length:
        chunk = stream.recv(length - len(payload))
        if not chunk:
            raise RuntimeError("unexpected SOCKS/DNS EOF")
        payload.extend(chunk)
    return bytes(payload)


def read_socks_address(stream: socket.socket, atyp: int) -> tuple[str, int]:
    if atyp == 1:
        host = socket.inet_ntop(socket.AF_INET, read_exact(stream, 4))
    elif atyp == 4:
        host = socket.inet_ntop(socket.AF_INET6, read_exact(stream, 16))
    elif atyp == 3:
        host = read_exact(stream, read_exact(stream, 1)[0]).decode()
    else:
        raise RuntimeError(f"unsupported SOCKS address type {atyp}")
    return host, int.from_bytes(read_exact(stream, 2), "big")


def socks_handshake(stream: socket.socket) -> tuple[int, tuple[str, int]]:
    version, methods = read_exact(stream, 2)
    if version != 5 or 0 not in read_exact(stream, methods):
        raise RuntimeError("invalid SOCKS greeting")
    stream.sendall(b"\x05\x00")
    version, command, reserved, atyp = read_exact(stream, 4)
    if (version, reserved) != (5, 0):
        raise RuntimeError("invalid SOCKS request")
    return command, read_socks_address(stream, atyp)


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
            b"\xc6\x33\x64\x4d",
        ]
    )


def connect_mock(listener: socket.socket, resolver: tuple[str, int]) -> None:
    stream, _ = listener.accept()
    with stream:
        command, target = socks_handshake(stream)
        if command != 1 or target != resolver:
            raise RuntimeError(f"unexpected CONNECT target {target}")
        stream.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
        length = int.from_bytes(read_exact(stream, 2), "big")
        query = read_exact(stream, length)
        answer = dns_answer(query)
        stream.sendall(len(answer).to_bytes(2, "big") + answer)


def parse_udp_datagram(payload: bytes) -> tuple[tuple[str, int], bytes, bytes]:
    if payload[:3] != b"\x00\x00\x00":
        raise RuntimeError("invalid SOCKS UDP prefix")
    atyp = payload[3]
    if atyp == 1:
        address_end = 8
        host = socket.inet_ntop(socket.AF_INET, payload[4:address_end])
    elif atyp == 4:
        address_end = 20
        host = socket.inet_ntop(socket.AF_INET6, payload[4:address_end])
    elif atyp == 3:
        address_end = 5 + payload[4]
        host = payload[5:address_end].decode()
    else:
        raise RuntimeError(f"unsupported UDP address type {atyp}")
    port_end = address_end + 2
    port = int.from_bytes(payload[address_end:port_end], "big")
    return (host, port), payload[:port_end], payload[port_end:]


def associate_mock(
    listener: socket.socket,
    relay: socket.socket,
    resolver: tuple[str, int],
) -> None:
    stream, _ = listener.accept()
    with stream:
        command, _ = socks_handshake(stream)
        if command != 3:
            raise RuntimeError(f"unexpected SOCKS command {command}")
        relay_port = relay.getsockname()[1]
        stream.sendall(
            b"\x05\x00\x00\x01\x7f\x00\x00\x01" + relay_port.to_bytes(2, "big")
        )
        payload, peer = relay.recvfrom(65535)
        target, header, query = parse_udp_datagram(payload)
        if target != resolver:
            raise RuntimeError(f"unexpected UDP target {target}")
        relay.sendto(header + dns_answer(query), peer)


def capture_tcp(listener: socket.socket, stop: threading.Event, captures: list[str]) -> None:
    listener.settimeout(0.1)
    while not stop.is_set():
        try:
            stream, peer = listener.accept()
        except TimeoutError:
            continue
        captures.append(f"tcp:{peer[0]}:{peer[1]}")
        stream.close()


def capture_udp(sock: socket.socket, stop: threading.Event, captures: list[str]) -> None:
    sock.settimeout(0.1)
    while not stop.is_set():
        try:
            _, peer = sock.recvfrom(65535)
        except TimeoutError:
            continue
        captures.append(f"udp:{peer[0]}:{peer[1]}")


def run_mode(
    yayatht: Path,
    dns_client: Path,
    runtime: Path,
    resolver: tuple[str, int],
    mode: str,
) -> dict[str, object]:
    proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy.bind(("127.0.0.1", 0))
    proxy.listen()
    relay = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    relay.bind(("127.0.0.1", 0))
    mock_errors: list[str] = []

    def mock() -> None:
        try:
            if mode == "proxy-tcp":
                connect_mock(proxy, resolver)
            else:
                associate_mock(proxy, relay, resolver)
        except BaseException as error:
            mock_errors.append(str(error))

    server = threading.Thread(target=mock)
    server.start()
    name = f"dns-leak-{mode}-{os.getpid()}"
    result = subprocess.run(
        [
            str(yayatht),
            "run",
            "--socks5",
            f"127.0.0.1:{proxy.getsockname()[1]}",
            "--dns",
            mode,
            "--dns-upstream",
            f"{resolver[0]}:{resolver[1]}",
            "--no-ipv6",
            "--runtime-dir",
            str(runtime),
            "--name",
            name,
            "--",
            str(dns_client),
            "query",
            "192.0.2.1",
            f"{mode}.no-leak.test",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=15,
        check=False,
    )
    server.join(timeout=5)
    proxy.close()
    relay.close()
    if server.is_alive():
        raise RuntimeError(f"{mode} mock did not complete")
    if mock_errors:
        raise RuntimeError(f"{mode} mock failed: {mock_errors[0]}")
    if result.returncode != 0 or "id=ok" not in result.stdout:
        raise RuntimeError(
            f"{mode} DNS query failed ({result.returncode}): "
            f"{result.stdout.strip()} {result.stderr.strip()}"
        )
    return {"mode": mode, "stdout": result.stdout.strip()}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--yayatht", type=Path, default=Path("target/release/yayatht"))
    parser.add_argument(
        "--dns-client", type=Path, default=Path("target/release/dns-client")
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    yayatht = executable(args.yayatht)
    dns_client = executable(args.dns_client)

    sentinel_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sentinel_tcp.bind(("127.0.0.53", 0))
    sentinel_tcp.listen()
    resolver = ("127.0.0.53", sentinel_tcp.getsockname()[1])
    sentinel_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sentinel_udp.bind(resolver)
    stop = threading.Event()
    captures: list[str] = []
    capture_threads = [
        threading.Thread(target=capture_tcp, args=(sentinel_tcp, stop, captures)),
        threading.Thread(target=capture_udp, args=(sentinel_udp, stop, captures)),
    ]
    for thread in capture_threads:
        thread.start()

    try:
        with tempfile.TemporaryDirectory(prefix="yayatht-dns-leak-") as directory:
            runtime = Path(directory)
            os.chmod(runtime, 0o700)
            modes: list[dict[str, object]] = []
            for mode in ["proxy-tcp", "proxy-udp"]:
                try:
                    modes.append(run_mode(yayatht, dns_client, runtime, resolver, mode))
                except BaseException as error:
                    modes.append({"mode": mode, "error": str(error)})
        time.sleep(0.2)
    finally:
        stop.set()
        for thread in capture_threads:
            thread.join(timeout=1)
        sentinel_tcp.close()
        sentinel_udp.close()

    passed = not captures and all("error" not in mode for mode in modes)
    report = {
        "schema": 1,
        "capture": "TCP and UDP resolver socket sentinel",
        "resolver": f"{resolver[0]}:{resolver[1]}",
        "modes": modes,
        "direct_resolver_captures": captures,
        "verdict": "PASS" if passed else "FAIL",
    }
    serialized = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.write_text(serialized)
    print(serialized, end="")
    if not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
