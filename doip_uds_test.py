#!/usr/bin/env python3
"""DoIP and UDS integration test utility (Python standard library only).

The script sends selected UDS requests over a DoIP TCP connection and checks
both DoIP transport acknowledgements and UDS responses. No third-party packages
are required. Specify the ECU address with --host; use --help for options.
"""
from __future__ import annotations

import argparse
import socket
import struct
import sys
import time
from dataclasses import dataclass
from typing import Optional, Tuple

PROTOCOL_VERSION = 0x02
INVERSE_VERSION = 0xFD
PT_ROUTING_ACTIVATION_REQUEST = 0x0005
PT_ROUTING_ACTIVATION_RESPONSE = 0x0006
PT_ALIVE_CHECK_REQUEST = 0x0007
PT_ALIVE_CHECK_RESPONSE = 0x0008
PT_DIAGNOSTIC_MESSAGE = 0x8001
PT_DIAGNOSTIC_POS_ACK = 0x8002
PT_DIAGNOSTIC_NEG_ACK = 0x8003
DEFAULT_PORT = 13400
DEFAULT_TESTER_SA = 0x0E00
DEFAULT_ECU_SA = 0x1000
DEFAULT_VIN = "TEST1234567890123"  # Example test VIN; override with --vin when needed.
MAX_INBOUND_PAYLOAD = 1024 * 1024


class DoIPTestError(RuntimeError):
    pass


class PeerClosed(DoIPTestError):
    pass


def parse_int(text: str) -> int:
    return int(text, 0)


def make_doip(payload_type: int, payload: bytes, version: int = PROTOCOL_VERSION) -> bytes:
    if not 0 <= payload_type <= 0xFFFF:
        raise ValueError("Payload Type must fit in 16 bits")
    if len(payload) > 0xFFFFFFFF:
        raise ValueError("Payload too large")
    return struct.pack(">BBHI", version, version ^ 0xFF, payload_type, len(payload)) + payload


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise PeerClosed(f"ECU closed TCP connection (received {len(data)}/{size} bytes)")
        data.extend(chunk)
    return bytes(data)


def format_hex(data: bytes) -> str:
    return data.hex(" ").upper() if data else "<empty>"


@dataclass
class DoIPMessage:
    payload_type: int
    payload: bytes
    version: int


class DoIPConnection:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.sock: Optional[socket.socket] = None
        self.activated = False

    def __enter__(self) -> "DoIPConnection":
        print(f"Connecting to DoIP ECU {self.args.host}:{self.args.port} ...")
        self.sock = socket.create_connection(
            (self.args.host, self.args.port), timeout=self.args.connect_timeout
        )
        self.sock.settimeout(self.args.timeout)
        print(f"TCP connected; local endpoint={self.sock.getsockname()}")
        try:
            self.activate_routing()
        except Exception:
            self.sock.close()
            self.sock = None
            raise
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            finally:
                self.sock = None

    def send_message(self, payload_type: int, payload: bytes) -> None:
        if self.sock is None:
            raise DoIPTestError("TCP socket is not open")
        self.sock.sendall(make_doip(payload_type, payload, self.args.protocol_version))

    def recv_message(self) -> DoIPMessage:
        if self.sock is None:
            raise DoIPTestError("TCP socket is not open")
        header = recv_exact(self.sock, 8)
        version, inverse, payload_type, payload_length = struct.unpack(">BBHI", header)
        if inverse != (version ^ 0xFF):
            raise DoIPTestError(
                f"Bad inverse version in ECU header: version=0x{version:02X}, inverse=0x{inverse:02X}"
            )
        if payload_length > MAX_INBOUND_PAYLOAD:
            raise DoIPTestError(f"ECU announced unreasonable payload length {payload_length}")
        payload = recv_exact(self.sock, payload_length) if payload_length else b""
        print(
            f"RX DoIP type=0x{payload_type:04X} payload_len={payload_length} "
            f"data={format_hex(payload[:48])}"
            + (f" ... omitted={len(payload) - 48}" if len(payload) > 48 else "")
        )
        return DoIPMessage(payload_type, payload, version)

    def recv_non_alive(self) -> DoIPMessage:
        while True:
            msg = self.recv_message()
            if msg.payload_type == PT_ALIVE_CHECK_REQUEST:
                if msg.payload:
                    raise DoIPTestError("Alive Check Request must have an empty payload")
                self.send_message(
                    PT_ALIVE_CHECK_RESPONSE,
                    struct.pack(">H", self.args.tester_sa),
                )
                print(f"TX Alive Check Response 0x0008 SA=0x{self.args.tester_sa:04X}")
                continue
            return msg

    def activate_routing(self) -> None:
        payload = struct.pack(">HB4s", self.args.tester_sa, 0x00, b"\x00\x00\x00\x00")
        print(
            f"TX Routing Activation Request 0x0005 SA=0x{self.args.tester_sa:04X} "
            f"payload={format_hex(payload)}"
        )
        self.send_message(PT_ROUTING_ACTIVATION_REQUEST, payload)
        response = self.recv_non_alive()
        if response.payload_type != PT_ROUTING_ACTIVATION_RESPONSE:
            raise DoIPTestError(
                f"Expected 0x0006 Routing Activation Response, got 0x{response.payload_type:04X}"
            )
        if len(response.payload) < 5:
            raise DoIPTestError(f"Routing Activation Response too short: {len(response.payload)} bytes")
        tester_sa, ecu_sa, code = struct.unpack(">HHB", response.payload[:5])
        print(
            f"Routing Activation response=0x{code:02X}, "
            f"tester=0x{tester_sa:04X}, ECU=0x{ecu_sa:04X}"
        )
        if code != 0x10:
            raise DoIPTestError(f"Routing Activation failed with response code 0x{code:02X}")
        if tester_sa != self.args.tester_sa or ecu_sa != self.args.ecu_sa:
            raise DoIPTestError(
                f"Address mismatch in Routing Activation response: "
                f"tester=0x{tester_sa:04X}, ECU=0x{ecu_sa:04X}"
            )
        self.activated = True
        print("PASS: Routing Activation established")

    def request_uds(self, uds_request: bytes, label: str) -> bytes:
        if not self.activated:
            raise DoIPTestError("Routing Activation has not succeeded")
        if not uds_request:
            raise ValueError("UDS request cannot be empty")
        diagnostic_payload = struct.pack(">HH", self.args.tester_sa, self.args.ecu_sa) + uds_request
        frame = make_doip(PT_DIAGNOSTIC_MESSAGE, diagnostic_payload, self.args.protocol_version)
        print(
            f"\n[{label}] TX UDS request={format_hex(uds_request)}; "
            f"DoIP 0x8001 payload_len={len(diagnostic_payload)}"
        )
        assert self.sock is not None
        self.sock.sendall(frame)

        # The DoIP ACK/NACK confirms transport handling. UDS service result follows
        # as a separate 0x8001 message. Alive Check requests may occur between them.
        ack = self.recv_non_alive()
        if ack.payload_type not in (PT_DIAGNOSTIC_POS_ACK, PT_DIAGNOSTIC_NEG_ACK):
            raise DoIPTestError(
                f"Expected DoIP ACK/NACK after 0x8001, got type=0x{ack.payload_type:04X}"
            )
        if len(ack.payload) < 5:
            raise DoIPTestError(f"DoIP ACK/NACK payload too short: {len(ack.payload)} bytes")
        ack_sa, ack_ta, ack_code = struct.unpack(">HHB", ack.payload[:5])
        print(
            f"DoIP {'ACK' if ack.payload_type == PT_DIAGNOSTIC_POS_ACK else 'NACK'}: "
            f"SA=0x{ack_sa:04X} TA=0x{ack_ta:04X} code=0x{ack_code:02X}"
        )
        if ack.payload_type == PT_DIAGNOSTIC_NEG_ACK:
            raise DoIPTestError(f"ECU returned DoIP NACK 0x{ack_code:02X} for UDS request")
        if (ack_sa, ack_ta, ack_code) != (self.args.ecu_sa, self.args.tester_sa, 0x00):
            raise DoIPTestError(
                "Unexpected DoIP ACK fields; expected "
                f"SA=0x{self.args.ecu_sa:04X} TA=0x{self.args.tester_sa:04X} Code=0x00"
            )
        print("PASS: DoIP Positive ACK (transport acceptance only)")

        response = self.recv_non_alive()
        if response.payload_type != PT_DIAGNOSTIC_MESSAGE:
            raise DoIPTestError(
                f"Expected UDS response in DoIP 0x8001, got type=0x{response.payload_type:04X}"
            )
        if len(response.payload) < 5:
            raise DoIPTestError(f"DoIP diagnostic response too short: {len(response.payload)} bytes")
        source_sa, target_sa = struct.unpack(">HH", response.payload[:4])
        uds_response = response.payload[4:]
        print(
            f"UDS response addresses: SA=0x{source_sa:04X} TA=0x{target_sa:04X}; "
            f"PDU={format_hex(uds_response)}"
        )
        if (source_sa, target_sa) != (self.args.ecu_sa, self.args.tester_sa):
            raise DoIPTestError(
                f"Unexpected UDS response addresses: SA=0x{source_sa:04X}, TA=0x{target_sa:04X}"
            )
        return uds_response


def check_session_response(response: bytes, expected_session: int) -> None:
    if len(response) != 6 or response[0] != 0x50 or response[1] != expected_session:
        raise DoIPTestError(
            f"Expected UDS response 50 {expected_session:02X} <P2:2> <P2*:2>; got {format_hex(response)}"
        )
    p2_ms = int.from_bytes(response[2:4], "big")
    p2_star_10ms = int.from_bytes(response[4:6], "big")
    print(
        f"PASS: DiagnosticSessionControl session=0x{expected_session:02X}; "
        f"P2Server={p2_ms} ms, P2*Server={p2_star_10ms * 10} ms"
    )


def run_session(conn: DoIPConnection) -> None:
    response = conn.request_uds(b"\x10\x01", "Default Session (0x10 0x01)")
    check_session_response(response, 0x01)
    response = conn.request_uds(b"\x10\x03", "Extended Session (0x10 0x03)")
    check_session_response(response, 0x03)


def run_tester_present(conn: DoIPConnection) -> None:
    response = conn.request_uds(b"\x3E\x00", "TesterPresent (0x3E 0x00)")
    if response != b"\x7E\x00":
        raise DoIPTestError(f"Expected UDS 7E 00; got {format_hex(response)}")
    print("PASS: TesterPresent positive response 7E 00")


def run_vin(conn: DoIPConnection) -> None:
    response = conn.request_uds(b"\x22\xF1\x90", "ReadDataByIdentifier VIN (0x22 F1 90)")
    expected = b"\x62\xF1\x90" + conn.args.vin.encode("ascii")
    if len(conn.args.vin) != 17:
        raise DoIPTestError("Configured VIN must be exactly 17 ASCII characters")
    if response != expected:
        raise DoIPTestError(
            "VIN response mismatch. Expected " + format_hex(expected) + "; got " + format_hex(response)
        )
    returned_vin = response[3:].decode("ascii", errors="replace")
    print(f"PASS: VIN read successful: {returned_vin}")


def run_negative(conn: DoIPConnection) -> None:
    response = conn.request_uds(b"\x22\xF1\x91", "Unsupported DID (0x22 F1 91)")
    expected = b"\x7F\x22\x31"
    if response != expected:
        raise DoIPTestError(f"Expected UDS NRC 7F 22 31; got {format_hex(response)}")
    print("PASS: unsupported DID returned NRC 0x31")

    response = conn.request_uds(b"\x99", "Unsupported service (SID 0x99)")
    expected = b"\x7F\x99\x11"
    if response != expected:
        raise DoIPTestError(f"Expected UDS NRC 7F 99 11; got {format_hex(response)}")
    print("PASS: unsupported SID returned NRC 0x11")

    response = conn.request_uds(b"\x10", "Malformed DiagnosticSessionControl (0x10)")
    expected = b"\x7F\x10\x13"
    if response != expected:
        raise DoIPTestError(f"Expected UDS NRC 7F 10 13; got {format_hex(response)}")
    print("PASS: malformed session request returned NRC 0x13")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run selected UDS integration tests over DoIP TCP.")
    parser.add_argument("--host", required=True, help="ECU IPv4 address")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"DoIP TCP port (default {DEFAULT_PORT})")
    parser.add_argument("--tester-sa", type=parse_int, default=DEFAULT_TESTER_SA, help="Tester logical address, e.g. 0x0E00")
    parser.add_argument("--ecu-sa", type=parse_int, default=DEFAULT_ECU_SA, help="ECU logical address, e.g. 0x1000")
    parser.add_argument("--protocol-version", type=parse_int, default=PROTOCOL_VERSION, help="DoIP protocol version (default 0x02)")
    parser.add_argument("--connect-timeout", type=float, default=4.0, help="TCP connect timeout in seconds")
    parser.add_argument("--timeout", type=float, default=4.0, help="Receive timeout for each DoIP message in seconds")
    parser.add_argument("--vin", default=DEFAULT_VIN, help="Expected 17-character ASCII VIN")
    parser.add_argument(
        "--test",
        choices=("all", "session", "tester-present", "vin", "negative"),
        default="all",
        help="Test selection (default: all)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not 0 <= args.tester_sa <= 0xFFFF or not 0 <= args.ecu_sa <= 0xFFFF:
        print("ERROR: logical addresses must be between 0x0000 and 0xFFFF", file=sys.stderr)
        return 2
    try:
        vin_bytes = args.vin.encode("ascii")
    except UnicodeEncodeError:
        print("ERROR: VIN must contain ASCII characters only", file=sys.stderr)
        return 2
    if len(vin_bytes) != 17:
        print(f"ERROR: VIN must be 17 ASCII bytes; got {len(vin_bytes)}", file=sys.stderr)
        return 2

    print("DoIP and UDS integration test")
    print(f"ECU={args.host}:{args.port}, tester SA=0x{args.tester_sa:04X}, ECU SA=0x{args.ecu_sa:04X}")
    print(f"Test={args.test}; expected VIN={args.vin}")
    print("Important: DoIP 0x8002 is only a transport ACK; UDS success is checked from the later 0x8001 response.\n")

    start = time.monotonic()
    try:
        with DoIPConnection(args) as conn:
            if args.test in ("all", "session"):
                run_session(conn)
            if args.test in ("all", "tester-present"):
                run_tester_present(conn)
            if args.test in ("all", "vin"):
                run_vin(conn)
            if args.test in ("all", "negative"):
                run_negative(conn)
        elapsed = time.monotonic() - start
        print(f"\nPASS: selected Phase 7 test(s) completed in {elapsed:.2f}s")
        return 0
    except (DoIPTestError, PeerClosed, OSError, socket.timeout, struct.error) as exc:
        elapsed = time.monotonic() - start
        print(f"\nFAIL after {elapsed:.2f}s: {exc}", file=sys.stderr)
        print("Check the UART log and Wireshark filter: tcp.port == 13400", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
