"""
protocols/_sigtran_common.py
M3UA (RFC 4666), SUA (RFC 3868), M2UA (RFC 3331), IUA (RFC 4233), and
V5UA (RFC 3807) all use the same "Common Message Header" and the same
ASP state-management messages (ASPSM class=3): ASP-UP (type=3) and the
ASP-UP-ACK reply (type=4). This file isn't a registered protocol on its
own — just shared construction/validation code imported by the other
SIGTRAN modules to avoid duplicating the same logic.

Reference for every message:
  Common Header: Version(1) + Reserved(1) + Message Class(1) +
                 Message Type(1) + Message Length(4, including the header)
"""

from __future__ import annotations

import asyncio
import struct

from portscanner.protocols._io import read_message
from portscanner.transports.base import Connection

_ASPSM_CLASS = 3
_ASP_UP_TYPE = 3

# ASPSM (state maintenance), ASPTM (traffic maintenance) — an explicit
# "successful" reply to ASP-UP (like ASP-UP-ACK) means a full confirmed match.
_CONFIRMED_CLASSES = {3, 4}
# MGMT (class=9): includes Error messages — meaning the other side does
# understand/speak the SIGTRAN protocol, but rejected the request
# (e.g. it needs a Routing Context registered beforehand). Still strong
# evidence, but not a full success — classified as likely.
_LIKELY_CLASSES = {9}


def build_aspup() -> bytes:
    """A basic ASP-UP message with no optional AVPs — enough to draw out a reply."""
    version, reserved = 1, 0
    header = struct.pack("!BBBB", version, reserved, _ASPSM_CLASS, _ASP_UP_TYPE)
    length = 8  # the header only, no body
    return header + struct.pack("!I", length)


def message_length(header: bytes) -> int | None:
    """Extracts the total message length from the Common Header (bytes 4-7)."""
    if len(header) < 8:
        return None
    return int.from_bytes(header[4:8], "big")


def classify_reply(data: bytes) -> str | None:
    """
    Classifies a valid Common Header reply as "confirmed" or "likely",
    or None if the header isn't valid at all (not SIGTRAN, or random data).
    The actual distinction between M3UA/SUA/M2UA is made per-module
    based on the port number that replied (hint_ports) — the header
    looks identical across all three.
    """
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


async def probe_adaptation_layer(connection: Connection, timeout: float) -> str | None:
    """
    The full shared sequence (send ASP-UP + robustly read the reply per
    its declared length + classify the reply) — imported directly by
    m3ua.py / sua.py / m2ua.py / iua.py / v5ua.py instead of each
    repeating the same logic. Returns "confirmed"/"likely"/None.
    """
    try:
        await connection.send(build_aspup())
        data = await read_message(connection, timeout, message_length)
    except (asyncio.TimeoutError, OSError, ConnectionError, ValueError):
        return None
    return classify_reply(data)


def format_detail(protocol_name: str, rfc: str, layer_desc: str, confidence: str) -> str:
    """
    Builds the detail string for an M3UA/SUA/M2UA/IUA/V5UA detector.

    Honesty note: classify_reply() only tells us the peer speaks *some*
    SIGTRAN ASPSM/ASPTM adaptation layer — the Common Message Header is
    byte-identical across M3UA/SUA/M2UA/IUA/V5UA (see this module's
    docstring), so the reply itself cannot distinguish which one it is.
    Each detector only gets tried because the port matched its
    hint_ports, so the specific protocol name in the result is an
    inference from the port number, not independent evidence from the
    reply. The detail text says so explicitly rather than implying the
    reply itself proves the specific protocol.
    """
    if confidence == "confirmed":
        note = (" — SIGTRAN adaptation-layer peer confirmed (ASP-UP/ACK); "
                 f"{protocol_name} specifically is inferred from the port scanned, "
                 "not distinguishable from other SIGTRAN family members by this reply alone")
    else:
        note = (" (Error/MGMT reply — the peer does speak a SIGTRAN adaptation-layer "
                 "protocol, but rejected the request; which family member is, again, "
                 "inferred from the port, not confirmed by this reply)")
    return f"{protocol_name} (ASP-UP exchange, RFC {rfc}) — {layer_desc} over SCTP{note}"
