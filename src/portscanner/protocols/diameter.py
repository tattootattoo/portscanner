"""
protocols/diameter.py
Confirms the Diameter protocol (RFC 6733) via a standard CER/CEA
exchange, with deeper technical analysis than just "is the CEA reply
valid?":

  1. Parses the actual AVPs: Product-Name, Result-Code,
     Auth/Acct-Application-Id, Vendor-Specific-Application-Id to
     identify the interface type (Gx, Rx, S6a...).
  2. Vendor fingerprinting: extracts the actual Vendor-Id/
     Supported-Vendor-Id and maps them against the IANA Private
     Enterprise Numbers table, with a heuristic fallback based on the
     Product-Name text if the number isn't in the table.
  3. Confidence level: a successful CEA reply (Result-Code = 2xxx) =
     confirmed. An explicit Diameter-protocol reply that was rejected
     (a DPR, or a CEA with an error Result-Code) = likely — still
     strong evidence it's Diameter, just not a full success.
  4. If the connection came in over TLS (port 3869), adds a certificate
     summary (Subject/Issuer/validity) — useful for identifying the
     element without any actual decryption.

All of this is standard protocol analysis / publicly documented
information (3GPP/IANA), not an exploit or a way around any protection.
"""

from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass, field

from portscanner.models import Transport
from portscanner.protocols._io import read_message
from portscanner.protocols.base import DetectionResult, register
from portscanner.transports.base import Connection

_CER_COMMAND_CODE = 257
_DPR_COMMAND_CODE = 282  # Disconnect-Peer-Request — an explicit rejection of the connection

# standard AVP codes (RFC 6733 Base Protocol)
_AVP_ORIGIN_HOST = 264
_AVP_ORIGIN_REALM = 296
_AVP_RESULT_CODE = 268
_AVP_VENDOR_ID = 266
_AVP_PRODUCT_NAME = 269
_AVP_FIRMWARE_REVISION = 267
_AVP_INBAND_SECURITY_ID = 299
_AVP_AUTH_APPLICATION_ID = 258
_AVP_ACCT_APPLICATION_ID = 259
_AVP_VENDOR_SPECIFIC_APPLICATION_ID = 260
_AVP_SUPPORTED_VENDOR_ID = 265
_AVP_FLAG_VENDOR_SPECIFIC = 0x80

# standard Inband-Security-Id values (RFC 6733 §5.3.3)
_INBAND_SECURITY_LABELS = {0: "NO_INBAND_SECURITY", 1: "TLS"}

# known Application-Ids (RFC 6733/4006 + common 3GPP specifications).
# The list isn't exhaustive of every possible application; a number not
# listed here is shown as the raw number.
KNOWN_APPLICATION_IDS: dict[int, str] = {
    0: "Diameter Common Messages",
    1: "NASREQ (RFC 7155)",
    4: "Diameter Credit Control / Gy-Ro (RFC 4006)",
    16777216: "Cx/Dx — IMS HSS interface (3GPP TS 29.229)",
    16777217: "Sh — IMS HSS interface (3GPP TS 29.328/329)",
    16777236: "Rx — Policy/QoS interface (3GPP TS 29.214)",
    16777238: "Gx — PCEF/PCRF policy interface (3GPP TS 29.212)",
    16777251: "S6a/S6d — MME/SGSN-HSS interface (3GPP TS 29.272)",
    16777264: "S13/S13' — EIR interface (3GPP TS 29.272)",
    16777265: "SLg — MME-GMLC location interface (3GPP TS 29.172)",
    16777272: "S9 — Policy roaming interface (3GPP TS 29.215)",
    16777291: "Gxx — BBERF policy interface (3GPP TS 29.212)",
    16777303: "S6b — PDN-GW/3GPP AAA interface (3GPP TS 29.273)",
    16777309: "STa — non-3GPP access AAA interface (3GPP TS 29.273)",
    16777345: "SWx — 3GPP AAA/HSS interface (3GPP TS 29.273)",
}

# IANA Private Enterprise Numbers (PEN) table — a publicly documented
# sample of well-known telecom equipment vendors. Deliberately partial
# (best-effort) — full reference:
# https://www.iana.org/assignments/enterprise-numbers
KNOWN_VENDOR_IDS: dict[int, str] = {
    9: "Cisco Systems",
    42: "Sun Microsystems",
    111: "Oracle Corporation",
    193: "Ericsson",
    2011: "Huawei Technologies",
    2636: "Juniper Networks",
    10415: "3GPP",
}

# a heuristic fallback if Vendor-Id isn't in the table: a simple text
# match against Product-Name (freely set by the server itself, not an
# official PEN number).
_PRODUCT_NAME_VENDOR_HINTS: dict[str, str] = {
    "ericsson": "Ericsson", "huawei": "Huawei", "nokia": "Nokia",
    "oracle": "Oracle", "tekelec": "Oracle (Tekelec)", "cisco": "Cisco Systems",
    "juniper": "Juniper Networks", "mavenir": "Mavenir", "metaswitch": "Metaswitch",
    "freediameter": "FreeDiameter (open-source)", "open5gs": "Open5GS (open-source)",
}


@dataclass(slots=True)
class _DiameterInfo:
    product_name: str | None = None
    interfaces: list[str] = field(default_factory=list)
    vendor: str | None = None
    vendor_source: str = ""       # "Vendor-Id AVP" or "Product-Name heuristic"
    result_code: int | None = None
    origin_realm: str | None = None
    firmware_revision: int | None = None
    supports_inband_tls: bool | None = None  # from the Inband-Security-Id AVP
    tls_summary: str | None = None


def _build_cer() -> bytes:
    version = 1
    command_flags = 0x80  # Request bit
    application_id = 0    # Common Messages Application
    hop_by_hop = 0x00000001
    end_to_end = 0x00000001

    origin_host = b"scanner.local"
    avp_length = 8 + len(origin_host)
    padding = (4 - (avp_length % 4)) % 4
    avp = (
        struct.pack("!I", _AVP_ORIGIN_HOST)
        + struct.pack("!B", 0x40)  # Mandatory
        + avp_length.to_bytes(3, "big")
        + origin_host
        + b"\x00" * padding
    )

    body = struct.pack("!III", application_id, hop_by_hop, end_to_end) + avp
    msg_length = 8 + len(body)
    header = (
        struct.pack("!B", version)
        + msg_length.to_bytes(3, "big")
        + struct.pack("!B", command_flags)
        + _CER_COMMAND_CODE.to_bytes(3, "big")
    )
    return header + body


def _iter_avps(data: bytes):
    """Parses a sequence of consecutive AVPs. Silently skips any AVP with an unreasonable length."""
    i = 0
    n = len(data)
    while i + 8 <= n:
        avp_code = int.from_bytes(data[i:i + 4], "big")
        flags = data[i + 4]
        avp_length = int.from_bytes(data[i + 5:i + 8], "big")
        if avp_length < 8 or i + avp_length > n:
            break
        header_len = 8
        if flags & _AVP_FLAG_VENDOR_SPECIFIC:
            if avp_length < 12:
                break
            header_len = 12
        payload = data[i + header_len:i + avp_length]
        yield avp_code, payload
        padded_length = avp_length + ((4 - avp_length % 4) % 4)
        i += padded_length


def _describe_application_id(app_id: int) -> str:
    return KNOWN_APPLICATION_IDS.get(app_id, f"unknown Application-Id ({app_id})")


def _describe_vendor(vendor_id: int) -> str:
    return KNOWN_VENDOR_IDS.get(vendor_id, f"unknown Vendor-Id ({vendor_id})")


def _guess_vendor_from_product_name(product_name: str) -> str | None:
    lowered = product_name.lower()
    for needle, vendor in _PRODUCT_NAME_VENDOR_HINTS.items():
        if needle in lowered:
            return vendor
    return None


def _extract_info(body: bytes) -> _DiameterInfo:
    info = _DiameterInfo()
    for avp_code, payload in _iter_avps(body):
        if avp_code == _AVP_PRODUCT_NAME:
            info.product_name = payload.decode(errors="ignore").strip("\x00").strip()
        elif avp_code == _AVP_ORIGIN_REALM:
            info.origin_realm = payload.decode(errors="ignore").strip("\x00").strip()
        elif avp_code == _AVP_FIRMWARE_REVISION and len(payload) == 4:
            info.firmware_revision = int.from_bytes(payload, "big")
        elif avp_code == _AVP_INBAND_SECURITY_ID and len(payload) == 4:
            value = int.from_bytes(payload, "big")
            info.supports_inband_tls = (value == 1) or info.supports_inband_tls
        elif avp_code == _AVP_RESULT_CODE and len(payload) == 4:
            info.result_code = int.from_bytes(payload, "big")
        elif avp_code in (_AVP_VENDOR_ID, _AVP_SUPPORTED_VENDOR_ID) and len(payload) == 4 and info.vendor is None:
            vendor_id = int.from_bytes(payload, "big")
            info.vendor = _describe_vendor(vendor_id)
            info.vendor_source = "Vendor-Id AVP"
        elif avp_code in (_AVP_AUTH_APPLICATION_ID, _AVP_ACCT_APPLICATION_ID) and len(payload) == 4:
            app_id = int.from_bytes(payload, "big")
            if app_id != 0:
                info.interfaces.append(_describe_application_id(app_id))
        elif avp_code == _AVP_VENDOR_SPECIFIC_APPLICATION_ID:
            for code2, payload2 in _iter_avps(payload):
                if code2 in (_AVP_AUTH_APPLICATION_ID, _AVP_ACCT_APPLICATION_ID) and len(payload2) == 4:
                    app_id = int.from_bytes(payload2, "big")
                    info.interfaces.append(_describe_application_id(app_id))

    if info.vendor is None and info.product_name:
        guess = _guess_vendor_from_product_name(info.product_name)
        if guess:
            info.vendor = guess
            info.vendor_source = "Product-Name heuristic"

    return info


def _result_code_category(code: int) -> str:
    if 2000 <= code < 3000:
        return "success"
    if 3000 <= code < 4000:
        return "protocol error"
    if 4000 <= code < 5000:
        return "transient failure"
    if 5000 <= code < 6000:
        return "permanent failure"
    return "unknown"


def _parse_response(data: bytes) -> tuple[str | None, _DiameterInfo]:
    """
    Returns (confidence, info) where confidence is "confirmed"/"likely"/None.
    None = the reply isn't Diameter at all (invalid header).
    """
    if len(data) < 20:
        return None, _DiameterInfo()

    version = data[0]
    command_flags = data[4]
    command_code = int.from_bytes(data[5:8], "big")
    is_request = bool(command_flags & 0x80)

    if version != 1:
        return None, _DiameterInfo()

    body = data[20:]

    if command_code == _CER_COMMAND_CODE and not is_request:
        info = _extract_info(body)
        if info.result_code is None:
            # no Result-Code AVP in the reply (rare but allowed) — treat
            # it as a default success since it returned a
            # structurally-valid CEA.
            return "confirmed", info
        category = _result_code_category(info.result_code)
        confidence = "confirmed" if category == "success" else "likely"
        return confidence, info

    if command_code == _DPR_COMMAND_CODE and is_request:
        # the other side rejected the exchange entirely and asked to
        # disconnect — still definite evidence it's Diameter, just not
        # the expected success.
        info = _DiameterInfo()
        info.product_name = "(rejected the connection via DPR before completing CER/CEA)"
        return "likely", info

    # any other valid Diameter header (version=1) with an unexpected
    # command — still a strong indicator it's Diameter, but at a lower
    # confidence level.
    info = _DiameterInfo()
    info.product_name = f"(reply with an unexpected Diameter command: command-code={command_code})"
    return "likely", info


def _format_detail(info: _DiameterInfo) -> str:
    parts = ["Diameter"]
    if info.product_name:
        parts.append(f"product={info.product_name}")
    if info.vendor:
        parts.append(f"vendor={info.vendor} ({info.vendor_source})")
    if info.firmware_revision is not None:
        parts.append(f"firmware-revision={info.firmware_revision}")
    if info.origin_realm:
        parts.append(f"realm={info.origin_realm}")
    if info.supports_inband_tls is not None:
        parts.append(f"inband-TLS={'supported' if info.supports_inband_tls else 'not supported'}")
    if info.result_code is not None:
        parts.append(f"result-code={info.result_code} ({_result_code_category(info.result_code)})")
    if info.interfaces:
        seen: list[str] = []
        for item in info.interfaces:
            if item not in seen:
                seen.append(item)
        parts.append("interface=" + " | ".join(seen))
    if info.tls_summary:
        parts.append(f"tls=[{info.tls_summary}]")
    return " — ".join(parts)


def _diameter_length(header: bytes) -> int | None:
    if len(header) < 4:
        return None
    return int.from_bytes(header[1:4], "big")


def _tls_summary(connection: Connection) -> str | None:
    cert = getattr(connection, "tls_certificate", None)
    if not cert:
        return None
    bits = []
    if cert.get("subject"):
        bits.append(f"subject={cert['subject']}")
    if cert.get("issuer"):
        bits.append(f"issuer={cert['issuer']}")
    if cert.get("not_after"):
        bits.append(f"expires={cert['not_after']}")
    if cert.get("tls_version"):
        bits.append(f"tls={cert['tls_version']}")
    return ", ".join(bits) if bits else None


@register(name="Diameter", transports=(Transport.TCP, Transport.SCTP), hint_ports=(3868, 3869))
async def detect(connection: Connection, timeout: float) -> DetectionResult | None:
    try:
        await connection.send(_build_cer())
        data = await read_message(connection, timeout, _diameter_length, min_header_size=4)
    except (asyncio.TimeoutError, OSError, ConnectionError, ValueError):
        return None

    confidence, info = _parse_response(data)
    if confidence is None:
        return None

    info.tls_summary = _tls_summary(connection)
    return DetectionResult(detail=_format_detail(info), confidence=confidence)
