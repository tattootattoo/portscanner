"""
transports/__init__.py
A single unified entry point for the transport layer: connect_for(transport, ...)
routes to the right implementation without the higher layers (engine)
needing to know each one's details.

TCP for Diameter, SCTP for the SIGTRAN family + Diameter, UDP for GTP-C
(the packet-network control protocol across every generation 2G/3G/4G).
"""

from __future__ import annotations

from portscanner.models import Transport
from portscanner.transports import tcp, udp, sctp
from portscanner.transports.base import ConnectOutcome

__all__ = ["connect_for", "ConnectOutcome"]


async def connect_for(
    transport: Transport,
    host: str,
    port: int,
    timeout: float,
    sctp_pool_size: int = 20,
    tls_ports: frozenset[int] = frozenset(),
) -> ConnectOutcome:
    if transport is Transport.TCP:
        return await tcp.connect(host, port, timeout, use_tls=port in tls_ports)
    if transport is Transport.UDP:
        return await udp.connect(host, port, timeout)
    if transport is Transport.SCTP:
        return await sctp.connect(host, port, timeout, pool_size=sctp_pool_size)
    raise ValueError(f"unsupported transport type: {transport}")
