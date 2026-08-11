"""
tests/test_e2e_diameter.py
**Real** end-to-end tests for Diameter — spins up an actual asyncio
server on loopback (127.0.0.1) and scans it with the tool's real
engine end to end (transports.tcp.connect + protocols.diameter.detect),
with no mocking of the transport layer at all. The difference from
test_protocols.py: there we test the byte-building/parsing functions
in isolation; here we test the full flow for real over an actual socket.
"""

import shutil
import struct
import subprocess

import pytest

from portscanner.protocols.diameter import detect as diameter_detect
from portscanner.transports.tcp import connect as tcp_connect

_HAS_OPENSSL = shutil.which("openssl") is not None


def _build_avp(code: int, data: bytes) -> bytes:
    length = 8 + len(data)
    out = struct.pack("!I", code) + struct.pack("!B", 0x40) + length.to_bytes(3, "big") + data
    return out + b"\x00" * ((4 - length % 4) % 4)


def _build_cea(product_name: bytes = b"E2ETestHSS", vendor_id: int | None = None,
               app_id: int | None = None, result_code: int | None = None) -> bytes:
    avps = _build_avp(269, product_name)
    if vendor_id is not None:
        avps += _build_avp(266, vendor_id.to_bytes(4, "big"))
    if app_id is not None:
        avps += _build_avp(258, app_id.to_bytes(4, "big"))
    if result_code is not None:
        avps += _build_avp(268, result_code.to_bytes(4, "big"))
    body = struct.pack("!III", 0, 1, 1) + avps
    length = 8 + len(body)
    header = struct.pack("!B", 1) + length.to_bytes(3, "big") + struct.pack("!B", 0x00) + (257).to_bytes(3, "big")
    return header + body


async def _start_diameter_server(port: int, cea_bytes: bytes):
    async def handle(reader, writer):
        try:
            await reader.read(500)  # wait for the incoming CER from the scanner
            writer.write(cea_bytes)
            await writer.drain()
            await writer.wait_closed()
        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            writer.close()

    return await __import__("asyncio").start_server(handle, "127.0.0.1", port)


@pytest.mark.asyncio
async def test_e2e_diameter_tcp_confirms_via_real_socket():
    """A real actual TCP connection (not a fake Connection) — CER is sent, CEA is read, and Diameter is confirmed."""
    cea = _build_cea(product_name=b"RealSocketHSS", vendor_id=193, app_id=16777251)  # Ericsson, S6a
    server = await _start_diameter_server(38680, cea)
    try:
        outcome = await tcp_connect("127.0.0.1", 38680, timeout=2.0)
        assert outcome.connection is not None
        result = await diameter_detect(outcome.connection, timeout=2.0)
        await outcome.connection.close()
    finally:
        server.close()

    assert result is not None
    assert result.confidence == "confirmed"
    assert "RealSocketHSS" in result.detail
    assert "Ericsson" in result.detail
    assert "S6a" in result.detail


@pytest.mark.asyncio
async def test_e2e_diameter_tcp_connection_refused_when_no_server():
    """Confirms that no server present really returns CLOSED (an actual RST), not an exception."""
    outcome = await tcp_connect("127.0.0.1", 38681, timeout=1.0)
    from portscanner.models import PortState
    assert outcome.state is PortState.CLOSED
    assert outcome.connection is None


@pytest.mark.skipif(not _HAS_OPENSSL, reason="openssl CLI is not available in this environment")
@pytest.mark.asyncio
async def test_e2e_diameter_tls_with_real_certificate(tmp_path):
    """Full Diameter/TLS: a real openssl certificate + a real TLS handshake + CER/CEA on top of it."""
    import asyncio
    import ssl

    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", str(key_path),
         "-out", str(cert_path), "-days", "1", "-nodes",
         "-subj", "/CN=e2e-hss.internal.test/O=E2ETelecom"],
        check=True, capture_output=True,
    )

    cea = _build_cea(product_name=b"TLSTestHSS")

    async def handle(reader, writer):
        try:
            await reader.read(500)
            writer.write(cea)
            await writer.drain()
            await writer.wait_closed()
        except (ConnectionResetError, BrokenPipeError, ssl.SSLError):
            pass
        finally:
            writer.close()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert_path), str(key_path))
    server = await asyncio.start_server(handle, "127.0.0.1", 38690, ssl=ctx)
    try:
        outcome = await tcp_connect("127.0.0.1", 38690, timeout=3.0, use_tls=True)
        assert outcome.connection is not None
        result = await diameter_detect(outcome.connection, timeout=2.0)
        await outcome.connection.close()
    finally:
        server.close()

    assert result is not None
    assert result.confidence == "confirmed"
    assert "TLSTestHSS" in result.detail
    # the real certificate info must have been read and shown in the detail
    assert "e2e-hss.internal.test" in result.detail
    assert "E2ETelecom" in result.detail


@pytest.mark.asyncio
async def test_e2e_diameter_dpr_rejection_is_likely():
    """A server rejects with a DPR instead of a CEA — must be classified likely, not confirmed and not None."""
    import asyncio

    def build_dpr():
        body = struct.pack("!III", 0, 1, 1)
        length = 8 + len(body)
        return struct.pack("!B", 1) + length.to_bytes(3, "big") + struct.pack("!B", 0x80) + (282).to_bytes(3, "big") + body

    async def handle(reader, writer):
        try:
            await reader.read(500)
            writer.write(build_dpr())
            await writer.drain()
            await writer.wait_closed()
        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 38682)
    try:
        outcome = await tcp_connect("127.0.0.1", 38682, timeout=2.0)
        assert outcome.connection is not None
        result = await diameter_detect(outcome.connection, timeout=2.0)
        await outcome.connection.close()
    finally:
        server.close()

    assert result is not None
    assert result.confidence == "likely"
