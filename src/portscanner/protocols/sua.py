"""
protocols/sua.py
SUA (SCCP User Adaptation, RFC 3868) — carries SCCP messages directly
(without the MTP3 layer) over SCTP, typically used between an STP and
IP-based elements (like some SMS/USSD gateway implementations).
Standard IANA-registered port: 14001/sctp.
"""

from __future__ import annotations

from portscanner.models import Transport
from portscanner.protocols._sigtran_common import format_detail, probe_adaptation_layer
from portscanner.protocols.base import DetectionResult, register
from portscanner.transports.base import Connection

IANA_PORT = 14001


@register(name="SIGTRAN/SUA", transports=(Transport.SCTP,), hint_ports=(IANA_PORT,))
async def detect(connection: Connection, timeout: float) -> DetectionResult | None:
    confidence = await probe_adaptation_layer(connection, timeout)
    if confidence is None:
        return None
    return DetectionResult(
        detail=format_detail("SUA", "3868", "SCCP", confidence),
        confidence=confidence,
    )
