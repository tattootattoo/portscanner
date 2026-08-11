"""
protocols/m2pa.py
M2PA (MTP2 Peer-to-Peer Adaptation, RFC 4165) — emulates the MTP2 layer
directly between two peers (with no multi-homed ASP/AS concept like
M3UA/SUA/M2UA), so it doesn't use the shared ASPSM/ASP-UP messages in
`_sigtran_common.py`.

Uses the same Common Message Header (version+reserved+class+type+length)
but with its own Message Class (11 = M2PA Messages), and the basic
message is Link Status (type=2) instead of ASP-UP.

Note on accuracy: the status values for the Link State machine (RFC
4165 §5.1) are documented in the standard but less commonly seen in
practice than M3UA — if you run into unexpected behavior on a real
network, check RFC 4165 §5.1/§5.2 for the exact values. Still follows
the same principle as the rest of the SIGTRAN family: a valid Common
Header reply with class=11 (M2PA) = confirmed, or class=9 (MGMT/Error)
= likely.
"""

from __future__ import annotations

import asyncio
import struct

from portscanner.models import Transport
from portscanner.protocols._io import read_message
from portscanner.protocols.base import DetectionResult, register
from portscanner.transports.base import Connection

_M2PA_CLASS = 11
_LINK_STATUS_TYPE = 2
_STATUS_ALIGNMENT = 1  # start the alignment procedure — the natural first step of an MTP2 handshake

_CONFIRMED_CLASSES = {11}
_LIKELY_CLASSES = {9}  # MGMT/Error — a recognized SIGTRAN protocol that rejected the message

# IANA port (best-effort — same confidence level as M2UA/M3UA)
IANA_PORT = 3097


def _build_link_status() -> bytes:
    version, reserved = 1, 0
    header = struct.pack("!BBBB", version, reserved, _M2PA_CLASS, _LINK_STATUS_TYPE)
    status_field = struct.pack("!I", _STATUS_ALIGNMENT)
    length = 8 + len(status_field)
    return header + struct.pack("!I", length) + status_field


def _message_length(header: bytes) -> int | None:
    if len(header) < 8:
        return None
    return int.from_bytes(header[4:8], "big")


def _classify(data: bytes) -> str | None:
    if len(data) < 8:
        return None
    version, _reserved, msg_class, _msg_type = struct.unpack("!BBBB", data[:4])
    if version != 1:
        return None
    if msg_class in _CONFIRMED_CLASSES:
        return "confirmed"
    if msg_class in _LIKELY_CLASSES:
        return "likely"
    return None


@register(name="SIGTRAN/M2PA", transports=(Transport.SCTP,), hint_ports=(IANA_PORT,))
async def detect(connection: Connection, timeout: float) -> DetectionResult | None:
    try:
        await connection.send(_build_link_status())
        data = await read_message(connection, timeout, _message_length)
    except (asyncio.TimeoutError, OSError, ConnectionError, ValueError):
        return None

    confidence = _classify(data)
    if confidence is None:
        return None
    suffix = "" if confidence == "confirmed" else " (Error/MGMT reply — protocol confirmed but the request was rejected)"
    return DetectionResult(
        detail=f"M2PA (Link Status exchange, RFC 4165) — MTP2 peer-to-peer over SCTP{suffix}",
        confidence=confidence,
    )
