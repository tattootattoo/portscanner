"""
tests/test_e2e_sip.py
Real end-to-end tests for SIP/IMS — a real TCP server on loopback
replying with real SIP messages, the tool's real engine end to end.
"""

import asyncio

import pytest

from portscanner.protocols.sip import detect as sip_detect
from portscanner.transports.tcp import connect as tcp_connect


async def _start_sip_server(port: int, response: bytes):
    async def handle(reader, writer):
        try:
            await reader.read(500)  # wait for the incoming OPTIONS from the scanner
            writer.write(response)
            await writer.drain()
            await writer.wait_closed()
        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            writer.close()

    return await asyncio.start_server(handle, "127.0.0.1", port)


@pytest.mark.asyncio
async def test_e2e_sip_200_ok_confirmed_via_real_socket():
    response = (
        b"SIP/2.0 200 OK\r\n"
        b"Server: E2E-IMS-CSCF/1.0\r\n"
        b"Content-Length: 0\r\n\r\n"
    )
    server = await _start_sip_server(35060, response)
    try:
        outcome = await tcp_connect("127.0.0.1", 35060, timeout=2.0)
        assert outcome.connection is not None
        result = await sip_detect(outcome.connection, timeout=2.0)
        await outcome.connection.close()
    finally:
        server.close()

    assert result is not None
    assert result.confidence == "confirmed"
    assert "200" in result.detail
    assert "E2E-IMS-CSCF" in result.detail


@pytest.mark.asyncio
async def test_e2e_sip_max_forwards_rejection_still_confirmed():
    """A 483 Too Many Hops is expected due to the deliberate
    Max-Forwards:0 — must still be classified confirmed (SIP really
    was confirmed), not a scan failure."""
    response = b"SIP/2.0 483 Too Many Hops\r\nContent-Length: 0\r\n\r\n"
    server = await _start_sip_server(35061, response)
    try:
        outcome = await tcp_connect("127.0.0.1", 35061, timeout=2.0)
        assert outcome.connection is not None
        result = await sip_detect(outcome.connection, timeout=2.0)
        await outcome.connection.close()
    finally:
        server.close()

    assert result is not None
    assert result.confidence == "confirmed"
    assert "483" in result.detail


@pytest.mark.asyncio
async def test_e2e_sip_non_sip_server_returns_none():
    """A server replying with something that isn't SIP at all — must return None, not a false confirmation."""
    server = await _start_sip_server(35062, b"HTTP/1.1 200 OK\r\n\r\n")
    try:
        outcome = await tcp_connect("127.0.0.1", 35062, timeout=2.0)
        assert outcome.connection is not None
        result = await sip_detect(outcome.connection, timeout=2.0)
        await outcome.connection.close()
    finally:
        server.close()

    assert result is None
