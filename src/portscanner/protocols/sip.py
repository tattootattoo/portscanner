"""
protocols/sip.py
SIP (RFC 3261) — the call-control protocol for the IMS network
(Gm/Mw/Mg interfaces), the foundation of VoLTE, VoWiFi, and 5G Voice.
Standard IANA ports: 5060/tcp (sip) and 5061/tcp (sips, automatically
over TLS — added by default to tls_ports in the CLI).

The detector uses **OPTIONS** exclusively — a standard "capability
discovery" request per the spec (a ping counterpart), which doesn't
start or modify any actual call session. We also deliberately set
`Max-Forwards: 0`, so if there's an internal proxy receiving the
request, it should reply immediately (usually 483 Too Many Forwards)
instead of forwarding the request deeper into the IMS network —
minimizing the scan's footprint as much as possible, exactly the same
principle as the Echo Request in GTP-C/GTP-U.

Scope note: SIP is a general protocol, not exclusive to telecom (it's
also used in general-purpose VoIP systems) — it's included here
specifically as the official IMS signaling layer per 3GPP standards,
not as a "generic service" fingerprint.
"""

from __future__ import annotations

import asyncio
import uuid

from portscanner.models import Transport
from portscanner.protocols.base import DetectionResult, register
from portscanner.transports.base import Connection

IANA_PORT = 5060
IANA_TLS_PORT = 5061


def _build_options_request(host: str, port: int) -> bytes:
    call_id = uuid.uuid4().hex
    branch = "z9hG4bK" + uuid.uuid4().hex[:16]
    target = f"sip:probe@{host}:{port}"
    lines = [
        f"OPTIONS {target} SIP/2.0",
        f"Via: SIP/2.0/TCP {host}:{port};branch={branch}",
        "From: <sip:scanner@portscanner.local>;tag=" + uuid.uuid4().hex[:8],
        f"To: <{target}>",
        f"Call-ID: {call_id}",
        "CSeq: 1 OPTIONS",
        "Max-Forwards: 0",  # prevents the request from being forwarded deeper into the network — see docstring
        "Content-Length: 0",
        "", "",
    ]
    return "\r\n".join(lines).encode("ascii")


def _classify_response(data: bytes) -> DetectionResult | None:
    text = data.decode(errors="ignore")
    first_line = text.split("\r\n", 1)[0].strip()
    if not first_line.startswith("SIP/2.0 "):
        return None
    parts = first_line.split(" ", 2)
    status_code = parts[1] if len(parts) > 1 else "?"
    reason = parts[2] if len(parts) > 2 else ""
    server_header = ""
    for line in text.split("\r\n"):
        if line.lower().startswith("server:") or line.lower().startswith("user-agent:"):
            server_header = line.split(":", 1)[1].strip()
            break
    detail = f"SIP/IMS confirmed (OPTIONS ping, RFC 3261) — status={status_code} {reason}".strip()
    if server_header:
        detail += f" — server={server_header}"
    return DetectionResult(detail=detail, confidence="confirmed")


@register(name="SIP/IMS", transports=(Transport.TCP,), hint_ports=(IANA_PORT, IANA_TLS_PORT))
async def detect(connection: Connection, timeout: float) -> DetectionResult | None:
    # Use the actual scanned target for the Request-URI/Via if the
    # connection exposes it (TCPConnection always does); fall back to
    # the old placeholder only for a Connection implementation that
    # doesn't (e.g. a test double), so this never hard-fails.
    host = getattr(connection, "target_host", "") or "scanner.local"
    port = getattr(connection, "target_port", 0) or IANA_PORT
    try:
        await connection.send(_build_options_request(host, port))
        data = await asyncio.wait_for(connection.recv(4096), timeout=timeout)
    except (asyncio.TimeoutError, OSError, ConnectionError):
        return None
    return _classify_response(data)
