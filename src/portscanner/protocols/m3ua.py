"""
protocols/m3ua.py
M3UA (MTP3 User Adaptation, RFC 4666) — the most common member of the
SIGTRAN family, carries SS7 MTP3 messages (and therefore SCCP/TCAP on
top of it) over SCTP. Standard IANA-registered port: 2905/sctp.
"""

from __future__ import annotations

from portscanner.models import Transport
from portscanner.protocols._sigtran_common import format_detail, probe_adaptation_layer
from portscanner.protocols.base import DetectionResult, register
from portscanner.transports.base import Connection

IANA_PORT = 2905


@register(name="SIGTRAN/M3UA", transports=(Transport.SCTP,), hint_ports=(IANA_PORT,))
async def detect(connection: Connection, timeout: float) -> DetectionResult | None:
    confidence = await probe_adaptation_layer(connection, timeout)
    if confidence is None:
        return None
    return DetectionResult(
        detail=format_detail("M3UA", "4666", "MTP3", confidence),
        confidence=confidence,
    )
