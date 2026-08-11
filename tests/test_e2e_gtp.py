"""
tests/test_e2e_gtp.py
Real end-to-end tests for GTP-C and GTP-U — real UDP servers on
loopback, the tool's real engine end to end
(transports.udp + protocols.gtpc/gtpu).
"""

import asyncio
import struct

import pytest

from portscanner.protocols.gtpc import detect as gtpc_detect
from portscanner.protocols.gtpu import detect as gtpu_detect
from portscanner.transports.udp import connect as udp_connect


class _GTPv2EchoServer(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        version = (data[0] >> 5) & 0x07
        message_type = data[1]
        if message_type == 1:  # Echo Request
            if version == 2:
                reply = struct.pack("!BBH", 0b01000000, 2, 4) + data[4:7] + b"\x00"
            else:
                reply = struct.pack("!BBH", 0b00110010, 2, 4) + b"\x00\x00\x00\x00" + data[8:12]
            self.transport.sendto(reply, addr)


class _GTPv1OnlyEchoServer(asyncio.DatagramProtocol):
    """Replies only to v1 — simulates an older 2G/3G element that doesn't understand v2."""

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        version = (data[0] >> 5) & 0x07
        message_type = data[1]
        if message_type == 1 and version == 1:
            reply = struct.pack("!BBH", 0b00110010, 2, 4) + b"\x00\x00\x00\x00" + data[8:12]
            self.transport.sendto(reply, addr)


@pytest.mark.asyncio
async def test_e2e_gtpc_v2_confirmed_via_real_udp_socket():
    loop = asyncio.get_running_loop()
    transport, _protocol = await loop.create_datagram_endpoint(
        _GTPv2EchoServer, local_addr=("127.0.0.1", 32123)
    )
    try:
        outcome = await udp_connect("127.0.0.1", 32123, timeout=2.0)
        assert outcome.connection is not None
        result = await gtpc_detect(outcome.connection, timeout=2.0)
        await outcome.connection.close()
    finally:
        transport.close()

    assert result is not None
    assert result.confidence == "confirmed"
    assert "GTP-Cv2" in result.detail


@pytest.mark.asyncio
async def test_e2e_gtpc_falls_back_to_v1_with_legacy_element():
    """An element that only replies to v1 — the tool must detect it via a real fallback, not a mocked one."""
    loop = asyncio.get_running_loop()
    transport, _protocol = await loop.create_datagram_endpoint(
        _GTPv1OnlyEchoServer, local_addr=("127.0.0.1", 32124)
    )
    try:
        outcome = await udp_connect("127.0.0.1", 32124, timeout=2.0)
        assert outcome.connection is not None
        result = await gtpc_detect(outcome.connection, timeout=1.0)
        await outcome.connection.close()
    finally:
        transport.close()

    assert result is not None
    assert result.confidence == "confirmed"
    assert "GTP-Cv1" in result.detail


@pytest.mark.asyncio
async def test_e2e_gtpu_confirmed_via_real_udp_socket():
    loop = asyncio.get_running_loop()
    transport, _protocol = await loop.create_datagram_endpoint(
        _GTPv1OnlyEchoServer, local_addr=("127.0.0.1", 32152)
    )
    try:
        outcome = await udp_connect("127.0.0.1", 32152, timeout=2.0)
        assert outcome.connection is not None
        result = await gtpu_detect(outcome.connection, timeout=2.0)
        await outcome.connection.close()
    finally:
        transport.close()

    assert result is not None
    assert result.confidence == "confirmed"
    assert "GTP-Uv1" in result.detail


@pytest.mark.asyncio
async def test_e2e_gtp_no_response_returns_none():
    """No server at all on this port — must return None (not an exception) after the timeout."""
    outcome = await udp_connect("127.0.0.1", 32199, timeout=0.3)
    try:
        assert outcome.connection is not None
        result = await gtpc_detect(outcome.connection, timeout=0.3)
        assert result is None
    finally:
        await outcome.connection.close()
