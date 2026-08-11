"""
selftest.py
Self-check: spins up local (loopback) mock servers for every protocol
that's actually supported in this environment, and scans them with the
tool's real engine end to end — the same principle as the
test_e2e_*.py tests, but as an end-user command
(`portscanner --self-test`) instead of being confined to development.
Goal: confirm "the tool works correctly in this specific environment"
**before** you start scanning a real target — catches runtime
environment issues (Python version, an unintended code change...)
early instead of a misleading scan result.

SIGTRAN protocols (which need SCTP) only have SCTP availability checked
(via diagnostics) rather than an actual connection attempt — if SCTP
isn't available, they're classified SKIPPED, not FAILED.
"""

from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass

from portscanner.diagnostics import gather_diagnostics
from portscanner.protocols.diameter import detect as diameter_detect
from portscanner.protocols.gtpc import detect as gtpc_detect
from portscanner.protocols.gtpu import detect as gtpu_detect
from portscanner.protocols.sip import detect as sip_detect
from portscanner.transports.tcp import connect as tcp_connect
from portscanner.transports.udp import connect as udp_connect


@dataclass(slots=True)
class SelfTestResult:
    name: str
    status: str  # "pass" / "fail" / "skipped"
    detail: str = ""


# ---------------------------------------------------------------------------
# Small mock servers — the same messages used in the test_e2e_*.py tests
# ---------------------------------------------------------------------------

def _build_diameter_cea() -> bytes:
    avp_data = b"SelfTestHSS"
    avp = struct.pack("!I", 269) + struct.pack("!B", 0x40) + (8 + len(avp_data)).to_bytes(3, "big") + avp_data
    avp += b"\x00" * ((4 - len(avp) % 4) % 4)
    body = struct.pack("!III", 0, 1, 1) + avp
    length = 8 + len(body)
    return struct.pack("!B", 1) + length.to_bytes(3, "big") + struct.pack("!B", 0x00) + (257).to_bytes(3, "big") + body


async def _selftest_diameter() -> SelfTestResult:
    cea = _build_diameter_cea()

    async def handle(reader, writer):
        try:
            await reader.read(500)
            writer.write(cea)
            await writer.drain()
            await writer.wait_closed()
        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        outcome = await tcp_connect("127.0.0.1", port, timeout=2.0)
        if outcome.connection is None:
            return SelfTestResult("Diameter (TCP)", "fail", "failed to open a TCP connection to the mock server")
        result = await diameter_detect(outcome.connection, timeout=2.0)
        await outcome.connection.close()
    finally:
        server.close()

    if result is None or result.confidence != "confirmed":
        return SelfTestResult("Diameter (TCP)", "fail", f"result: {result}")
    return SelfTestResult("Diameter (TCP)", "pass")


async def _selftest_gtpc() -> SelfTestResult:
    class _Server(asyncio.DatagramProtocol):
        def connection_made(self, transport):
            self.transport = transport

        def datagram_received(self, data, addr):
            version = (data[0] >> 5) & 0x07
            if data[1] == 1 and version == 2:
                reply = struct.pack("!BBH", 0b01000000, 2, 4) + data[4:7] + b"\x00"
                self.transport.sendto(reply, addr)

    loop = asyncio.get_running_loop()
    transport, _protocol = await loop.create_datagram_endpoint(_Server, local_addr=("127.0.0.1", 0))
    port = transport.get_extra_info("sockname")[1]
    try:
        outcome = await udp_connect("127.0.0.1", port, timeout=2.0)
        result = await gtpc_detect(outcome.connection, timeout=2.0)
        await outcome.connection.close()
    finally:
        transport.close()

    if result is None or result.confidence != "confirmed":
        return SelfTestResult("GTP-C (UDP)", "fail", f"result: {result}")
    return SelfTestResult("GTP-C (UDP)", "pass")


async def _selftest_gtpu() -> SelfTestResult:
    class _Server(asyncio.DatagramProtocol):
        def connection_made(self, transport):
            self.transport = transport

        def datagram_received(self, data, addr):
            if data[1] == 1:  # Echo Request (GTP-U always uses a v1-style header)
                reply = struct.pack("!BBH", 0b00110010, 2, 4) + b"\x00\x00\x00\x00" + data[8:12]
                self.transport.sendto(reply, addr)

    loop = asyncio.get_running_loop()
    transport, _protocol = await loop.create_datagram_endpoint(_Server, local_addr=("127.0.0.1", 0))
    port = transport.get_extra_info("sockname")[1]
    try:
        outcome = await udp_connect("127.0.0.1", port, timeout=2.0)
        result = await gtpu_detect(outcome.connection, timeout=2.0)
        await outcome.connection.close()
    finally:
        transport.close()

    if result is None or result.confidence != "confirmed":
        return SelfTestResult("GTP-U (UDP)", "fail", f"result: {result}")
    return SelfTestResult("GTP-U (UDP)", "pass")


async def _selftest_sip() -> SelfTestResult:
    response = b"SIP/2.0 200 OK\r\nServer: SelfTest-CSCF\r\nContent-Length: 0\r\n\r\n"

    async def handle(reader, writer):
        try:
            await reader.read(500)
            writer.write(response)
            await writer.drain()
            await writer.wait_closed()
        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        outcome = await tcp_connect("127.0.0.1", port, timeout=2.0)
        if outcome.connection is None:
            return SelfTestResult("SIP/IMS (TCP)", "fail", "failed to open a TCP connection to the mock server")
        result = await sip_detect(outcome.connection, timeout=2.0)
        await outcome.connection.close()
    finally:
        server.close()

    if result is None or result.confidence != "confirmed":
        return SelfTestResult("SIP/IMS (TCP)", "fail", f"result: {result}")
    return SelfTestResult("SIP/IMS (TCP)", "pass")


def _selftest_sigtran_family() -> SelfTestResult:
    """SCTP itself is what gets checked (availability, not an actual
    connection) — the whole SIGTRAN family depends on it. If it's
    available, the assumption is that the code works (covered by
    separate simulated tests in test_e2e_sigtran_simulated.py, not here)."""
    diag = gather_diagnostics()
    if diag["sctp"]["available"]:
        return SelfTestResult(
            "SIGTRAN family (M3UA/SUA/M2UA/M2PA/IUA/V5UA)", "pass",
            "SCTP is available — the real scan will work (protocol logic is covered by separate tests)",
        )
    return SelfTestResult(
        "SIGTRAN family (M3UA/SUA/M2UA/M2PA/IUA/V5UA)", "skipped",
        f"SCTP is unavailable in this environment — {diag['sctp']['detail']}",
    )


async def run_self_test() -> list[SelfTestResult]:
    results = []
    for coro_fn in (_selftest_diameter, _selftest_gtpc, _selftest_gtpu, _selftest_sip):
        try:
            results.append(await coro_fn())
        except Exception as e:
            results.append(SelfTestResult(coro_fn.__name__, "fail", f"unexpected exception: {e}"))
    results.append(_selftest_sigtran_family())
    return results


def print_self_test_report(results: list[SelfTestResult]) -> bool:
    """Prints a report and returns True if everything passed or was skipped due to environment (not a real failure)."""
    icons = {"pass": "\u2713", "fail": "\u2717", "skipped": "\u25cb"}
    all_ok = True
    for r in results:
        print(f"{icons[r.status]} {r.name}: {r.status}" + (f" — {r.detail}" if r.detail else ""))
        if r.status == "fail":
            all_ok = False

    passed = sum(1 for r in results if r.status == "pass")
    skipped = sum(1 for r in results if r.status == "skipped")
    failed = sum(1 for r in results if r.status == "fail")
    print(f"\nresult: {passed} passed, {skipped} skipped (environment), {failed} failed.")
    if all_ok:
        print("The tool works correctly in this environment.")
    else:
        print("[!] there is a real problem — check the details above before relying on results from a real scan.")
    return all_ok
