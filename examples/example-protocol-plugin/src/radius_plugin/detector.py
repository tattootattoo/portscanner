"""
radius_plugin/detector.py
A complete example of an external plugin adding the RADIUS protocol
(RFC 2865) — the predecessor of Diameter for AAA, still used on older
2G/3G equipment and some Wi-Fi/hotspot gateways. This file is *not*
part of the core portscanner package — simply installing it
(pip install -e .) is enough for RADIUS to automatically appear in the
detectors_for() list, with no changes to the core code.

The detector: a simple Access-Request (with no real User-Password, so
nothing sensitive is sent) checking whether the reply looks like a
structurally valid RADIUS message. We can't verify the Response
Authenticator (it needs a shared secret we don't have), so confidence
here is always "likely" even if the header is entirely correct — a
realistic classification instead of claiming 100% confirmation without
actual security verification.
"""

from __future__ import annotations

import asyncio
import os
import struct

from portscanner.models import Transport
from portscanner.protocols.base import DetectionResult, register
from portscanner.transports.base import Connection

IANA_AUTH_PORT = 1812
IANA_ACCT_PORT = 1813

_ACCESS_REQUEST = 1
_VALID_RESPONSE_CODES = {2, 3, 11}  # Access-Accept, Access-Reject, Access-Challenge


def _build_access_request() -> bytes:
    identifier = os.urandom(1)[0]
    authenticator = os.urandom(16)  # "Request Authenticator" — random per RFC 2865 §3

    username = b"portscanner-probe"
    attr_type_user_name = 1
    user_name_attr = struct.pack("!BB", attr_type_user_name, 2 + len(username)) + username

    length = 20 + len(user_name_attr)  # 20 = the fixed RADIUS header
    header = struct.pack("!BBH", _ACCESS_REQUEST, identifier, length) + authenticator
    return header + user_name_attr, identifier


def _classify_response(data: bytes, sent_identifier: int) -> DetectionResult | None:
    if len(data) < 20:
        return None
    code, identifier, length = struct.unpack("!BBH", data[:4])
    if code not in _VALID_RESPONSE_CODES:
        return None
    if identifier != sent_identifier:
        return None  # a reply to a different request, not to our probe
    if length > len(data) or length < 20:
        return None  # an unreasonable length — not actually valid RADIUS

    code_name = {2: "Access-Accept", 3: "Access-Reject", 11: "Access-Challenge"}[code]
    return DetectionResult(
        detail=f"RADIUS confirmed structurally (Access-Request probe, RFC 2865) — "
               f"response={code_name}. Note: the Response Authenticator was not "
               f"verified (needs a shared secret), so confidence stays 'likely' "
               f"even with a structurally valid reply.",
        confidence="likely",
    )


@register(name="RADIUS", transports=(Transport.UDP,), hint_ports=(IANA_AUTH_PORT, IANA_ACCT_PORT))
async def detect(connection: Connection, timeout: float) -> DetectionResult | None:
    request, identifier = _build_access_request()
    try:
        await connection.send(request)
        data = await asyncio.wait_for(connection.recv(4096), timeout=timeout)
    except (asyncio.TimeoutError, OSError, ConnectionError):
        return None
    return _classify_response(data, identifier)
