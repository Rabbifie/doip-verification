#!/usr/bin/env python3
"""DoIP diagnostic transport test utility (Python standard library only).

The script exercises diagnostic-message ACK/NACK handling over TCP. It does not
execute UDS services. Specify the ECU address with --host; use --help to see
available test cases and options.
"""

from __future__ import annotations

import argparse
import socket
import struct
import sys
import time
from typing import Optional, Tuple

PROTOCOL_VERSION = 0x02
INVERSE_VERSION = 0xFD
DEFAULT_PORT = 13400
DEFAULT_TESTER_SA = 0x0E00
DEFAULT_ECU_SA = 0x1000

PT_ROUTING_ACTIVATION_REQUEST = 0x0005
PT_ROUTING_ACTIVATION_RESPONSE = 0x0006
PT_ALIVE_CHECK_REQUEST = 0x0007
PT_ALIVE_CHECK_RESPONSE = 0x0008
PT_DIAGNOSTIC_MESSAGE = 0x8001
PT_DIAGNOSTIC_POS_ACK = 0x8002
PT_DIAGNOSTIC_NEG_ACK = 0x8003

ACK_CODE_NAMES = {
    0x00: "ACK accepted",
}
NACK_CODE_NAMES = {
    0x02: "Invalid source address",
    0x03: "Unknown target address",
    0x04: "Diagnostic message too large",
    0x05: "Out of memory",
    0x06: "Target unreachable (version/profile dependent)",
    0x07: "Unknown network (version/profile dependent)",
    0x08: "Transport protocol error (version/profile dependent)",
}
RA_CODE_NAMES = {
    0x00: "Unknown source address",
    0x01: "All sockets registered and active",
    0x02: "Different source address already active",
    0x03: "Source address already registered on another socket",
    0x04: "Authentication missing",
    0x05: "Confirmation rejected",
    0x06: "Unsupported activation type",
    0x10: "Routing activation successful",
    0x11: "Routing activation pending / confirmation required",
}


class DoIPError(Exception):
    pass


class PeerClosed(DoIPError):
    pass


def parse_int(value: str) -> int:
    """Parse decimal or 0x-prefixed integer."""
    return int(value, 0)


def parse_hex_bytes(value: str) -> bytes:
    """Accept examples like '22 F1 90', '22:F1:90' or '22F190'."""
    cleaned = value.replace("0x", "").replace("0X", "")
    for separator in (" ", ":", ",", "-", "\t", "\n"):
        cleaned = cleaned.replace(separator, "")
    if len(cleaned) % 2:
        raise argparse.ArgumentTypeError("Hex data must contain an even number of digits")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"Invalid hex byte sequence: {value!r}") from exc


def make_message(payload_type: int, payload: bytes) -> bytes:
    if not (0 <= payload_type <= 0xFFFF):
        raise ValueError("payload type must fit in 16 bits")
    if len(payload) > 0xFFFFFFFF:
        raise ValueError("payload too large")
    return struct.pack(">BBHI", PROTOCOL_VERSION, INVERSE_VERSION, payload_type, len(payload)) + payload


def recv_exact(sock: socket.socket, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        try:
            part = sock.recv(length - len(chunks))
        except socket.timeout:
            raise
        if not part:
            raise PeerClosed(f"peer closed the TCP connection (received {len(chunks)}/{length} bytes)")
        chunks.extend(part)
    return bytes(chunks)


def recv_message(sock: socket.socket, max_payload: int = 1024 * 1024) -> Tuple[int, bytes, int, int]:
    header = recv_exact(sock, 8)
    version, inverse, payload_type, payload_length = struct.unpack(">BBHI", header)
    if inverse != (version ^ 0xFF):
        raise DoIPError(
            f"bad inverse version in ECU header: version=0x{version:02X}, inverse=0x{inverse:02X}"
        )
    if payload_length > max_payload:
        raise DoIPError(f"ECU announced unreasonable payload length {payload_length}")
    payload = recv_exact(sock, payload_length) if payload_length else b""
    return payload_type, payload, version, payload_length


def recv_message_handling_alive(
    sock: socket.socket,
    tester_sa: int,
    timeout: float,
) -> Tuple[int, bytes, int, int]:
    """Receive a message; answer server-initiated Alive Check if it arrives."""
    previous_timeout = sock.gettimeout()
    sock.settimeout(timeout)
    try:
        while True:
            payload_type, payload, version, payload_length = recv_message(sock)
            print(f"RX type=0x{payload_type:04X} payload_len={payload_length} data={payload.hex(' ').upper()}")
            if payload_type == PT_ALIVE_CHECK_REQUEST:
                if payload:
                    raise DoIPError("Alive Check Request should have an empty payload")
                sock.sendall(make_message(PT_ALIVE_CHECK_RESPONSE, struct.pack(">H", tester_sa)))
                print(f"TX Alive Check Response 0x0008 SA=0x{tester_sa:04X}")
                continue
            return payload_type, payload, version, payload_length
    finally:
        sock.settimeout(previous_timeout)


def connect_ecu(args: argparse.Namespace) -> socket.socket:
    print(f"Connecting to DoIP ECU {args.host}:{args.port} ...")
    sock = socket.create_connection((args.host, args.port), timeout=args.connect_timeout)
    sock.settimeout(args.timeout)
    print(f"TCP connected; local endpoint={sock.getsockname()}")
    return sock


def activate_routing(sock: socket.socket, tester_sa: int, expected_ecu_sa: int, args: argparse.Namespace) -> None:
    payload = struct.pack(">HB4s", tester_sa, 0x00, b"\x00\x00\x00\x00")
    request = make_message(PT_ROUTING_ACTIVATION_REQUEST, payload)
    print(f"TX Routing Activation Request 0x0005 SA=0x{tester_sa:04X} payload={payload.hex(' ').upper()}")
    sock.sendall(request)

    payload_type, response, _, _ = recv_message_handling_alive(sock, tester_sa, args.timeout)
    if payload_type != PT_ROUTING_ACTIVATION_RESPONSE:
        raise DoIPError(f"expected Routing Activation Response 0x0006, got 0x{payload_type:04X}")
    if len(response) < 5:
        raise DoIPError(f"Routing Activation Response too short: {len(response)} bytes")

    response_tester_sa, response_ecu_sa, response_code = struct.unpack(">HHB", response[:5])
    print(
        "Routing Activation Response: "
        f"code=0x{response_code:02X} ({RA_CODE_NAMES.get(response_code, 'unknown')}), "
        f"tester=0x{response_tester_sa:04X}, ecu=0x{response_ecu_sa:04X}"
    )
    if response_code != 0x10:
        raise DoIPError(f"Routing Activation did not succeed: 0x{response_code:02X}")
    if response_tester_sa != tester_sa:
        raise DoIPError(
            f"tester address mismatch: expected 0x{tester_sa:04X}, got 0x{response_tester_sa:04X}"
        )
    if response_ecu_sa != expected_ecu_sa:
        raise DoIPError(
            f"ECU address mismatch: expected 0x{expected_ecu_sa:04X}, got 0x{response_ecu_sa:04X}"
        )
    print("PASS: Routing Activation established")


def make_diagnostic_message(source_sa: int, target_sa: int, uds_payload: bytes) -> bytes:
    if len(uds_payload) == 0:
        raise ValueError("UDS payload must not be empty for this test")
    payload = struct.pack(">HH", source_sa, target_sa) + uds_payload
    return make_message(PT_DIAGNOSTIC_MESSAGE, payload)


def decode_ack(payload_type: int, payload: bytes) -> Tuple[Optional[int], Optional[int], Optional[int]]:
    if payload_type not in (PT_DIAGNOSTIC_POS_ACK, PT_DIAGNOSTIC_NEG_ACK):
        return None, None, None
    if len(payload) < 5:
        raise DoIPError(f"Diagnostic ACK/NACK payload too short: {len(payload)} bytes")
    source_sa, target_sa, code = struct.unpack(">HHB", payload[:5])
    return source_sa, target_sa, code


def report_diagnostic_response(
    payload_type: int,
    payload: bytes,
    expected_source: int,
    expected_target: int,
) -> bool:
    if payload_type not in (PT_DIAGNOSTIC_POS_ACK, PT_DIAGNOSTIC_NEG_ACK):
        print(f"FAIL: expected 0x8002 or 0x8003, got 0x{payload_type:04X}")
        return False

    source_sa, target_sa, code = decode_ack(payload_type, payload)
    assert source_sa is not None and target_sa is not None and code is not None
    print(
        f"DoIP {'ACK' if payload_type == PT_DIAGNOSTIC_POS_ACK else 'NACK'}: "
        f"SA=0x{source_sa:04X} TA=0x{target_sa:04X} code=0x{code:02X} "
        f"({ACK_CODE_NAMES.get(code, 'unknown') if payload_type == PT_DIAGNOSTIC_POS_ACK else NACK_CODE_NAMES.get(code, 'unknown')})"
    )
    if (source_sa, target_sa) != (expected_source, expected_target):
        print(
            "WARNING: ACK/NACK address reversal differs from expectation: "
            f"expected SA=0x{expected_source:04X} TA=0x{expected_target:04X}"
        )

    if payload_type == PT_DIAGNOSTIC_POS_ACK and code == 0x00:
        print("PASS: Diagnostic Message Positive ACK received (this does not mean the UDS service executed)")
        return True
    print("FAIL: ECU did not return a positive ACK with code 0x00")
    return False


def run_diagnostic_case(args: argparse.Namespace) -> int:
    tester_sa = args.tester_sa
    target_sa = args.target
    uds_payload = args.uds
    diagnostic_sa = args.diagnostic_sa if args.diagnostic_sa is not None else tester_sa

    with connect_ecu(args) as sock:
        activate_routing(sock, tester_sa, args.ecu_sa, args)

        frame = make_diagnostic_message(diagnostic_sa, target_sa, uds_payload)
        print(
            f"TX Diagnostic Message 0x8001: SA=0x{diagnostic_sa:04X} "
            f"TA=0x{target_sa:04X} UDS={uds_payload.hex(' ').upper()} "
            f"DoIP_payload_len={len(frame) - 8} total_len={len(frame)}"
        )

        if args.test == "fragmented":
            # Split the message across multiple TCP writes to test stream reassembly.
            chunks = [frame[:3], frame[3:8], frame[8:10], frame[10:12], frame[12:]]
            for index, chunk in enumerate(chunks, 1):
                if chunk:
                    sock.sendall(chunk)
                    print(f"TX fragment {index}/{len(chunks)}: {chunk.hex(' ').upper()}")
                    time.sleep(args.fragment_delay)
            response_type, response, _, _ = recv_message_handling_alive(sock, tester_sa, args.timeout)
            return 0 if report_diagnostic_response(response_type, response, target_sa, diagnostic_sa) else 1

        if args.test == "concat":
            second_uds = args.second_uds
            second_frame = make_diagnostic_message(diagnostic_sa, target_sa, second_uds)
            sock.sendall(frame + second_frame)
            print("TX two Diagnostic Messages in one send()")
            success_count = 0
            for index in range(2):
                response_type, response, _, _ = recv_message_handling_alive(sock, tester_sa, args.timeout)
                print(f"Response {index + 1}/2:")
                if report_diagnostic_response(response_type, response, target_sa, diagnostic_sa):
                    success_count += 1
            if success_count == 2:
                print("PASS: both concatenated messages received positive ACKs")
                return 0
            return 1

        if args.test == "oversized":
            # Test behavior when the diagnostic payload exceeds the configured limit.
            # Depending on the implementation profile, the ECU may return NACK 0x04
            # or close the connection in a controlled manner.
            oversized_uds = bytes([0xAA]) * args.oversize_uds_bytes
            frame = make_diagnostic_message(diagnostic_sa, target_sa, oversized_uds)
            print(
                f"TX oversized diagnostic: UDS_len={len(oversized_uds)}, "
                f"DoIP_payload_len={len(frame) - 8}"
            )
            sock.sendall(frame)
            try:
                response_type, response, _, _ = recv_message_handling_alive(sock, tester_sa, args.timeout)
                if response_type == PT_DIAGNOSTIC_NEG_ACK and len(response) >= 5 and response[4] == 0x04:
                    print("PASS: NACK 0x04 (Diagnostic Message Too Large)")
                    return 0
                print("RESULT: received a response; inspect whether it matches the firmware's specified size-limit behavior")
                return 2
            except (PeerClosed, ConnectionResetError, BrokenPipeError) as exc:
                print(f"PASS/REVIEW: ECU closed the connection for oversized input ({exc})")
                print("Verify from ECU logs or a packet capture that the connection was rejected cleanly.")
                return 0
            except socket.timeout:
                print("INCONCLUSIVE: no response/close observed before timeout")
                return 2

        # Normal positive test, invalid target, and wrong-source tests.
        sock.sendall(frame)
        try:
            response_type, response, _, _ = recv_message_handling_alive(sock, tester_sa, args.timeout)
        except (PeerClosed, ConnectionResetError) as exc:
            if args.test == "wrong-source":
                print(f"RESULT: ECU closed connection for mismatched source address: {exc}")
                print("Check UART/Wireshark and compare against the intended protocol behavior.")
                return 2
            raise

        if args.test == "positive":
            return 0 if report_diagnostic_response(response_type, response, target_sa, diagnostic_sa) else 1

        if args.test == "invalid-target":
            if response_type == PT_DIAGNOSTIC_NEG_ACK and len(response) >= 5 and response[4] == 0x03:
                print("PASS: NACK 0x03 (Unknown Target Address)")
                return 0
            print(
                f"FAIL/REVIEW: expected Diagnostic NACK 0x8003 code 0x03, "
                f"got type=0x{response_type:04X} payload={response.hex(' ').upper()}"
            )
            return 1

        if args.test == "wrong-source":
            if response_type == PT_DIAGNOSTIC_NEG_ACK and len(response) >= 5 and response[4] == 0x02:
                print("PASS: NACK 0x02 (Invalid Source Address)")
                return 0
            print(
                f"RESULT: expected NACK 0x02 or a specified controlled disconnect, "
                f"got type=0x{response_type:04X} payload={response.hex(' ').upper()}"
            )
            return 2

        raise DoIPError(f"unsupported diagnostic test mode: {args.test}")


def run_inactivity_test(args: argparse.Namespace) -> int:
    """Open TCP but deliberately do not send Routing Activation."""
    with connect_ecu(args) as sock:
        deadline = time.monotonic() + args.inactivity_wait
        print(
            f"No Routing Activation will be sent; waiting up to {args.inactivity_wait:.1f}s "
            "for server-side Initial Inactivity timeout..."
        )
        while time.monotonic() < deadline:
            sock.settimeout(min(0.5, max(0.05, deadline - time.monotonic())))
            try:
                data = sock.recv(1)
                if data == b"":
                    print("PASS: ECU closed the idle TCP connection")
                    return 0
                print(f"Received unexpected data while idle: {data.hex(' ').upper()}")
            except socket.timeout:
                continue
            except ConnectionResetError:
                print("PASS: ECU reset/closed the idle TCP connection")
                return 0
        print("FAIL: no TCP close/reset observed within the wait period")
        return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Test DoIP diagnostic-message ACK/NACK handling over TCP."
    )
    parser.add_argument("--host", required=True, help="ECU IPv4 address")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="DoIP TCP port (default: 13400)")
    parser.add_argument("--tester-sa", type=parse_int, default=DEFAULT_TESTER_SA, help="Tester logical address, e.g. 0x0E00")
    parser.add_argument("--ecu-sa", type=parse_int, default=DEFAULT_ECU_SA, help="Expected ECU logical address, e.g. 0x1000")
    parser.add_argument("--target", type=parse_int, default=DEFAULT_ECU_SA, help="Diagnostic target address, e.g. 0x1000")
    parser.add_argument("--diagnostic-sa", type=parse_int, default=None, help="Override SA in Diagnostic Message; used to test wrong-source")
    parser.add_argument("--uds", type=parse_hex_bytes, default=bytes.fromhex("22 F1 90"), help="UDS bytes in hex (default: '22 F1 90'); used as diagnostic payload only")
    parser.add_argument("--second-uds", type=parse_hex_bytes, default=bytes.fromhex("3E 00"), help="Second UDS payload for concat test (default: '3E 00')")
    parser.add_argument("--connect-timeout", type=float, default=5.0, help="TCP connect timeout, seconds")
    parser.add_argument("--timeout", type=float, default=3.0, help="Response timeout, seconds")
    parser.add_argument("--fragment-delay", type=float, default=0.05, help="Delay between TCP fragments, seconds")
    parser.add_argument("--oversize-uds-bytes", type=int, default=100, help="UDS bytes for oversized test (default: 100; DoIP payload=104 bytes)")
    parser.add_argument("--inactivity-wait", type=float, default=3.5, help="Wait time for Initial Inactivity test (default: 3.5 seconds)")
    parser.add_argument(
        "--test",
        choices=("positive", "fragmented", "invalid-target", "wrong-source", "oversized", "inactivity", "concat"),
        default="positive",
        help="Test case (default: positive)",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not (0 <= args.tester_sa <= 0xFFFF and 0 <= args.ecu_sa <= 0xFFFF and 0 <= args.target <= 0xFFFF):
        parser.error("logical addresses must be in the range 0x0000..0xFFFF")
    if args.diagnostic_sa is not None and not (0 <= args.diagnostic_sa <= 0xFFFF):
        parser.error("--diagnostic-sa must be in the range 0x0000..0xFFFF")
    if args.port < 1 or args.port > 65535:
        parser.error("--port must be in the range 1..65535")
    if args.timeout <= 0 or args.connect_timeout <= 0:
        parser.error("timeouts must be positive")
    if args.oversize_uds_bytes < 1 or args.oversize_uds_bytes > 65531:
        parser.error("--oversize-uds-bytes must be in the range 1..65531")

    print("DoIP diagnostic transport test")
    print(f"ECU={args.host}:{args.port}, tester SA=0x{args.tester_sa:04X}, ECU SA=0x{args.ecu_sa:04X}")
    print(f"Test={args.test}; UDS payload={args.uds.hex(' ').upper()}")
    print("Note: a positive DoIP ACK means transport acceptance only; it does not mean the UDS service succeeded.")
    print()

    try:
        if args.test == "inactivity":
            return run_inactivity_test(args)
        if args.test == "wrong-source" and args.diagnostic_sa is None:
            args.diagnostic_sa = (args.tester_sa + 1) & 0xFFFF
            print(f"Using mismatched Diagnostic SA=0x{args.diagnostic_sa:04X}; Routing Activation SA remains 0x{args.tester_sa:04X}")
        if args.test == "invalid-target" and args.target == args.ecu_sa:
            args.target = 0x1234
            print(f"Using unknown target TA=0x{args.target:04X}")
        return run_diagnostic_case(args)
    except (OSError, DoIPError, ValueError, struct.error) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
