"""
protocols/iua.py
IUA (ISDN Q.921 User Adaptation, RFC 4233) — carries the Q.921 layer
(D-channel signaling on ISDN PRI/BRI lines) over SCTP, used on
PSTN<->VoIP gateways that still actually exist in some telecom
networks. Standard IANA-registered port: 9900/sctp.

Uses the same Common Header + ASPSM messages shared with the rest of
the SIGTRAN family (M3UA/SUA/M2UA) — see _sigtran_common.py.
"""

from __future__ import annotations

from portscanner.models import Transport
from portscanner.protocols._sigtran_common import format_detail, probe_adaptation_layer
from portscanner.protocols.base import DetectionResult, register
from portscanner.transports.base import Connection

IANA_PORT = 9900


@register(name="SIGTRAN/IUA", transports=(Transport.SCTP,), hint_ports=(IANA_PORT,))
async def detect(connection: Connection, timeout: float) -> DetectionResult | None:
    confidence = await probe_adaptation_layer(connection, timeout)
    if confidence is None:
        return None
    return DetectionResult(
        detail=format_detail("IUA", "4233", "ISDN Q.921", confidence),
        confidence=confidence,
    )
