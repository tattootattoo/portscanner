"""
tests/test_e2e_radius.py
A real end-to-end test for the RADIUS protocol — specifically to prove
that the plugin architecture (examples/example-protocol-plugin) doesn't
just "register" in the Registry, but that its detector actually works
correctly over a real UDP socket — without any actual pip install of
the plugin (we import the module directly from its path).
"""

import asyncio
import struct
import sys
from pathlib import Path

import pytest

from portscanner.transports.udp import connect as udp_connect

_PLUGIN_SRC = Path(__file__).parent.parent / "examples" / "example-protocol-plugin" / "src"
if str(_PLUGIN_SRC) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_SRC))

from radius_plugin.detector import detect as radius_detect  # noqa: E402


class _RadiusServer(asyncio.DatagramProtocol):
    def __init__(self, response_code: int):
        self.response_code = response_code

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        code, identifier, _length = struct.unpack("!BBH", data[:4])
        if code == 1:  # Access-Request
            reply = struct.pack("!BBH", self.response_code, identifier, 20) + b"\x00" * 16
            self.transport.sendto(reply, addr)


@pytest.mark.asyncio
async def test_e2e_radius_access_accept_via_real_udp_socket():
    loop = asyncio.get_running_loop()
    transport, _protocol = await loop.create_datagram_endpoint(
        lambda: _RadiusServer(response_code=2), local_addr=("127.0.0.1", 31812)  # Access-Accept
    )
    try:
        outcome = await udp_connect("127.0.0.1", 31812, timeout=2.0)
        assert outcome.connection is not None
        result = await radius_detect(outcome.connection, timeout=2.0)
        await outcome.connection.close()
    finally:
        transport.close()

    assert result is not None
    assert result.confidence == "likely"  # RADIUS doesn't verify the Response Authenticator
    assert "Access-Accept" in result.detail


@pytest.mark.asyncio
async def test_e2e_radius_access_reject_still_confirms_protocol():
    loop = asyncio.get_running_loop()
    transport, _protocol = await loop.create_datagram_endpoint(
        lambda: _RadiusServer(response_code=3), local_addr=("127.0.0.1", 31813)  # Access-Reject
    )
    try:
        outcome = await udp_connect("127.0.0.1", 31813, timeout=2.0)
        assert outcome.connection is not None
        result = await radius_detect(outcome.connection, timeout=2.0)
        await outcome.connection.close()
    finally:
        transport.close()

    assert result is not None
    assert "Access-Reject" in result.detail
