"""
protocols/gtpu.py
GTP-U — the user-plane data layer for the GTP protocol, across every
generation: Gn/Gp (2G/3G), S1-U/S5-U/S8-U (4G), and even N3/N9 in 5G
(which still use the same GTPv1-U header with extension headers for
QoS markers — GTP-U was never given a v2 version, see 3GPP TS 29.281).

Standard IANA port: 2152/udp. Exactly the same detector as GTP-C (Echo
Request/Response) — the lightest possible message, never touching any
actual data tunnel.
"""

from __future__ import annotations

import asyncio

from portscanner.models import Transport
from portscanner.protocols._gtp_common import (
    ECHO_SEQUENCE_NUMBER,
    build_echo_request_v1,
    classify_echo_response,
)
from portscanner.protocols.base import DetectionResult, register
from portscanner.transports.base import Connection

IANA_PORT = 2152


@register(name="GTP-U", transports=(Transport.UDP,), hint_ports=(IANA_PORT,))
async def detect(connection: Connection, timeout: float) -> DetectionResult | None:
    try:
        await connection.send(build_echo_request_v1())
        data = await asyncio.wait_for(connection.recv(4096), timeout=timeout)
    except (asyncio.TimeoutError, OSError, ConnectionError):
        return None

    return classify_echo_response(data, 1, "GTP-U", "3GPP TS 29.281",
                                   expected_sequence=ECHO_SEQUENCE_NUMBER) if data else None
