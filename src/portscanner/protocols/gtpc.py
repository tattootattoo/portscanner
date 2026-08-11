"""
protocols/gtpc.py
GTP-C — GPRS Tunneling Protocol, Control Plane. The control protocol
for the packet network across every generation:
  - GTPv1-C (3GPP TS 29.060): used on the Gn/Gp interface between
    SGSN/GGSN (2G/3G).
  - GTPv2-C (3GPP TS 29.274): used on the S11/S5/S8/S10 interfaces in
    the EPC (4G), and some 5G-interworking interfaces (N26).

Both versions send their messages over UDP, and their standard IANA
port is the same (2123) — the version is determined by the Version
value in the header itself, not the port.

The detector here uses **Echo Request/Response** exclusively — the
lightest possible message in the protocol (a keepalive/ping
counterpart), explicitly defined by the standard for path-management
checks, and it never touches any subscriber data or an actual tunnel.
"""

from __future__ import annotations

import asyncio

from portscanner.models import Transport
from portscanner.protocols._gtp_common import (
    ECHO_SEQUENCE_NUMBER,
    build_echo_request_v1,
    build_echo_request_v2,
    classify_echo_response,
)
from portscanner.protocols.base import DetectionResult, register
from portscanner.transports.base import Connection

IANA_PORT = 2123


@register(name="GTP-C", transports=(Transport.UDP,), hint_ports=(IANA_PORT,))
async def detect(connection: Connection, timeout: float) -> DetectionResult | None:
    # try GTPv2-C first (the most common on modern 4G/5G-interworking networks)
    try:
        await connection.send(build_echo_request_v2())
        data = await asyncio.wait_for(connection.recv(4096), timeout=timeout)
    except (asyncio.TimeoutError, OSError, ConnectionError):
        data = b""

    result = classify_echo_response(data, 2, "GTP-C", "3GPP TS 29.274",
                                     expected_sequence=ECHO_SEQUENCE_NUMBER) if data else None
    if result:
        return result

    # no reply to v2 — try GTPv1-C (older 2G/3G elements might not understand v2)
    try:
        await connection.send(build_echo_request_v1())
        data = await asyncio.wait_for(connection.recv(4096), timeout=timeout)
    except (asyncio.TimeoutError, OSError, ConnectionError):
        return None

    return classify_echo_response(data, 1, "GTP-C", "3GPP TS 29.060",
                                   expected_sequence=ECHO_SEQUENCE_NUMBER) if data else None
