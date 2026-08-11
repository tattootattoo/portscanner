"""
protocols/m2ua.py
M2UA (MTP2 User Adaptation, RFC 3331) — carries the MTP2 layer (the
lowest in SS7) over SCTP, used between a Signaling Gateway and a remote
MTP3. Standard IANA-registered port: 2904/sctp.
"""

from __future__ import annotations

from portscanner.models import Transport
from portscanner.protocols._sigtran_common import format_detail, probe_adaptation_layer
from portscanner.protocols.base import DetectionResult, register
from portscanner.transports.base import Connection

IANA_PORT = 2904


@register(name="SIGTRAN/M2UA", transports=(Transport.SCTP,), hint_ports=(IANA_PORT,))
async def detect(connection: Connection, timeout: float) -> DetectionResult | None:
    confidence = await probe_adaptation_layer(connection, timeout)
    if confidence is None:
        return None
    return DetectionResult(
        detail=format_detail("M2UA", "3331", "MTP2", confidence),
        confidence=confidence,
    )
