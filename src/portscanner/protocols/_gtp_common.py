"""
protocols/_gtp_common.py
GTP-C (Control Plane) and GTP-U (User Plane) use **exactly the same**
Echo Request/Response format (3GPP TS 29.281 §5.1: "the Echo
Request/Response messages support the same syntax for control-plane
and user-plane") — GTP-U was never given a "v2" version the way GTP-C
was, so its header is always in GTPv1 format even on 5G networks
(N3/N9 use the GTPv1-U header with extra extension headers for QoS
markers, not an entirely new header).

This file isn't a registered protocol on its own — it's shared
construction/classification code imported by gtpc.py and gtpu.py to
avoid duplicating the same logic.
"""

from __future__ import annotations

import struct

from portscanner.protocols.base import DetectionResult

ECHO_REQUEST = 1
ECHO_RESPONSE = 2
VERSION_NOT_SUPPORTED = 3

# The sequence number every Echo Request in this module sends — shared
# so callers can pass it to classify_echo_response() for correlation
# instead of duplicating the literal.
ECHO_SEQUENCE_NUMBER = 1


def build_echo_request_v2() -> bytes:
    """GTPv2 Echo Request (TS 29.274 §6.1): an 8-byte header with no IEs.
    Used only for GTP-C (GTP-U has no v2 version)."""
    flags = 0b010_0_0_000  # Version=2, P=0, T=0 (no TEID for Path Management messages)
    body = ECHO_SEQUENCE_NUMBER.to_bytes(3, "big") + b"\x00"  # + Spare
    header = struct.pack("!BBH", flags, ECHO_REQUEST, len(body))
    return header + body


def build_echo_request_v1() -> bytes:
    """
    GTPv1 Echo Request (TS 29.060 §7.2.1; TS 29.281 §5.1 for GTP-U) —
    a header with a TEID + Sequence Number. Exactly the same structure
    for both GTP-C and GTP-U.
    """
    # Version=1, PT=1(GTP not GTP'), Spare=0, E=0, S=1(sequence present), PN=0
    flags = 0b001_1_0_0_1_0
    teid = 0
    optional = ECHO_SEQUENCE_NUMBER.to_bytes(2, "big") + b"\x00\x00"  # + N-PDU + NextExtHeaderType
    header = struct.pack("!BBH", flags, ECHO_REQUEST, len(optional)) + struct.pack("!I", teid)
    return header + optional


def _extract_sequence(data: bytes, version: int, flags: int) -> int | None:
    """
    Locates and reads the Sequence Number field in a v1/v2 GTP header,
    given the header's own flags byte (not the flags we sent — the
    reply's layout is self-describing via its own S/T bit). Returns
    None if the field isn't present/parseable, in which case the
    caller falls back to the older type+version-only classification
    rather than rejecting the reply outright (some implementations
    are not fully spec-compliant here).
    """
    if version == 1:
        s_flag = bool(flags & 0x02)  # GTPv1 header: Version(3)|PT(1)|Spare(1)|E(1)|S(1)|PN(1)
        if not s_flag or len(data) < 10:
            return None
        return int.from_bytes(data[8:10], "big")  # after the 4-byte TEID
    if version == 2:
        t_flag = bool(flags & 0x08)  # GTPv2 header: Version(3)|P(1)|T(1)|Spare(3)
        seq_offset = 8 if t_flag else 4  # TEID (4 bytes) present only if T=1
        if len(data) < seq_offset + 3:
            return None
        return int.from_bytes(data[seq_offset:seq_offset + 3], "big")
    return None


def classify_echo_response(
    data: bytes, sent_version: int, protocol_label: str, standard_ref: str,
    expected_sequence: int | None = None,
) -> DetectionResult | None:
    if len(data) < 2:
        return None
    flags = data[0]
    version = (flags >> 5) & 0x07
    message_type = data[1]

    # Sequence-number correlation: UDP is connectionless, and while the
    # socket is OS-connected to the target address (see transports/udp.py,
    # which filters by peer address at the kernel level), that alone
    # doesn't confirm a given reply actually answers *our* Echo Request
    # rather than, say, a stale/delayed reply to an earlier probe on the
    # same 5-tuple (this file's own gtpc.py tries v2 then falls back to
    # v1 on the same socket). Checking the sequence number we sent
    # against the one in the reply closes that gap. If the reply's
    # header doesn't carry a parseable sequence field at all, we fall
    # back to the weaker type+version check rather than rejecting a
    # possibly-legitimate but less spec-strict implementation outright.
    if expected_sequence is not None:
        reply_sequence = _extract_sequence(data, version, flags)
        if reply_sequence is not None and reply_sequence != expected_sequence:
            return None

    if message_type == ECHO_RESPONSE and version == sent_version:
        return DetectionResult(
            detail=f"{protocol_label}v{sent_version} confirmed "
                   f"(Echo Request/Response, {standard_ref})",
            confidence="confirmed",
        )
    if message_type == ECHO_RESPONSE and version != sent_version:
        return DetectionResult(
            detail=f"{protocol_label} confirmed but with a different version (returned "
                   f"version={version} while we sent version={sent_version})",
            confidence="confirmed",
        )
    if message_type == VERSION_NOT_SUPPORTED:
        return DetectionResult(
            detail=f"{protocol_label} confirmed — the element returned Version Not "
                   f"Supported (it supports a different version than {sent_version})",
            confidence="likely",
        )
    return None
