"""
protocols/v5ua.py
V5UA (V5.2 User Adaptation, RFC 3807) — carries V5.2 interface
signaling (between a local exchange and an access node like a DSLAM)
over SCTP. A near-obsolete technology (the early-DSL era), but can
still turn up on older access networks.

Note on accuracy: the IANA port below (5675/sctp) is to the best of my
understanding of the registration, with lower confidence than the rest
of the SIGTRAN family (V5UA is less documented / less deployed in
practice than M3UA, for instance) — check the official IANA
registration if you run into unexpected behavior. Same principle as
the rest of the family: a valid Common Header reply with class=3/4 =
confirmed, or class=9 (MGMT/Error) = likely.
"""

from __future__ import annotations

from portscanner.models import Transport
from portscanner.protocols._sigtran_common import format_detail, probe_adaptation_layer
from portscanner.protocols.base import DetectionResult, register
from portscanner.transports.base import Connection

IANA_PORT = 5675


@register(name="SIGTRAN/V5UA", transports=(Transport.SCTP,), hint_ports=(IANA_PORT,))
async def detect(connection: Connection, timeout: float) -> DetectionResult | None:
    confidence = await probe_adaptation_layer(connection, timeout)
    if confidence is None:
        return None
    return DetectionResult(
        detail=format_detail("V5UA", "3807", "V5.2 access signaling", confidence),
        confidence=confidence,
    )
