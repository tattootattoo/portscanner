"""
transports/udp.py
UDP is inherently connectionless, so "connecting" here just means
creating an endpoint bound to the destination (remote_addr) so we can
use the same send/recv interface as the other transports.

UDP support exists specifically for GTP-C (GPRS Tunneling Protocol -
Control Plane, 3GPP TS 29.060 for GTPv1 and TS 29.274 for GTPv2) — the
packet-network control protocol (2G/3G/4G) that runs exclusively over UDP.

No reply doesn't necessarily mean the port is closed (a firewall could
just be silently dropping the packet), so it's classified 'filtered' by
default unless an explicit reply or rejection arrives (an ICMP Port
Unreachable usually surfaces here as a ConnectionRefusedError).
"""

from __future__ import annotations

import asyncio
import time

from portscanner.models import PortState
from portscanner.transports.base import ConnectOutcome


class _UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.queue: asyncio.Queue[bytes] = asyncio.Queue()
        self.error: OSError | None = None

    def datagram_received(self, data: bytes, addr) -> None:
        self.queue.put_nowait(data)

    def error_received(self, exc: OSError) -> None:
        self.error = exc


class UDPConnection:
    __slots__ = ("_transport", "_protocol")

    def __init__(self, transport: asyncio.DatagramTransport, protocol: _UDPProtocol):
        self._transport = transport
        self._protocol = protocol

    async def send(self, data: bytes) -> None:
        self._transport.sendto(data)

    async def recv(self, max_bytes: int = 4096) -> bytes:
        if self._protocol.error:
            raise self._protocol.error
        return await self._protocol.queue.get()

    async def close(self) -> None:
        self._transport.close()


async def connect(host: str, port: int, timeout: float) -> ConnectOutcome:
    """
    "Connecting" over UDP here just opens a socket bound to the
    destination — the real state (open/filtered) is only determined
    later by the protocol detector itself (a GTP-C Echo, for instance)
    that sends an actual probe and waits for a reply. Here we report
    OPEN as soon as the socket binds successfully; it's the protocol
    detector that actually confirms whether anyone is listening. Note
    that this OPEN status is provisional and must not be treated as a
    final result on its own — see engine.py / cli.py, where UDP targets
    are always routed to the full protocol-identifying scan rather than
    being filtered out at this stage.
    """
    start = time.monotonic()
    loop = asyncio.get_running_loop()
    try:
        transport, protocol = await loop.create_datagram_endpoint(
            _UDPProtocol, remote_addr=(host, port)
        )
    except OSError as e:
        return ConnectOutcome(state=PortState.ERROR, error=str(e))

    latency = (time.monotonic() - start) * 1000
    return ConnectOutcome(
        state=PortState.OPEN, latency_ms=latency,
        connection=UDPConnection(transport, protocol),
    )
