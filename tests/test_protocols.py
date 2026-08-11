import struct

from portscanner.models import Transport
from portscanner.protocols import diameter, m2ua, m3ua, sua  # noqa: F401 (imported for the side effect — @register registration)
from portscanner.protocols._sigtran_common import build_aspup, classify_reply
from portscanner.protocols.base import detectors_for


# ---------------------------------------------------------------------------
# Diameter: message structure + AVP parsing
# ---------------------------------------------------------------------------

def test_build_cer_has_valid_diameter_header():
    msg = diameter._build_cer()
    version = msg[0]
    length = int.from_bytes(msg[1:4], "big")
    command_flags = msg[4]
    command_code = int.from_bytes(msg[5:8], "big")

    assert version == 1
    assert command_code == 257
    assert command_flags & 0x80
    assert length == len(msg)


def _build_avp(code: int, data: bytes, vendor_id: int | None = None) -> bytes:
    flags = 0x40 | (0x80 if vendor_id is not None else 0)
    header_len = 12 if vendor_id is not None else 8
    length = header_len + len(data)
    out = struct.pack("!I", code) + struct.pack("!B", flags) + length.to_bytes(3, "big")
    if vendor_id is not None:
        out += struct.pack("!I", vendor_id)
    out += data
    out += b"\x00" * ((4 - length % 4) % 4)
    return out


def _build_diameter_message(command_code: int, is_request: bool, avps: bytes = b"") -> bytes:
    app_id, hop, end = 0, 1, 1
    body = struct.pack("!III", app_id, hop, end) + avps
    length = 8 + len(body)
    flags = 0x80 if is_request else 0x00
    header = struct.pack("!B", 1) + length.to_bytes(3, "big") + \
              struct.pack("!B", flags) + command_code.to_bytes(3, "big")
    return header + body


def test_parse_response_accepts_synthetic_cea_without_result_code():
    cea = _build_diameter_message(257, is_request=False)
    confidence, info = diameter._parse_response(cea)
    assert confidence == "confirmed"
    assert info.interfaces == []


def test_parse_response_unexpected_command_is_likely_not_confirmed():
    # if the same CER comes back (an unexpected command for a reply) —
    # it's still an actually valid Diameter header, so it's classified
    # "likely" (neither None nor confirmed) via the catch-all.
    request = diameter._build_cer()
    confidence, _info = diameter._parse_response(request)
    assert confidence == "likely"


def test_parse_response_rejects_invalid_version():
    garbage = struct.pack("!B", 2) + (20).to_bytes(3, "big") + struct.pack("!B", 0) + \
              (257).to_bytes(3, "big") + struct.pack("!III", 0, 1, 1)
    confidence, _info = diameter._parse_response(garbage)
    assert confidence is None


def test_parse_response_extracts_product_name_and_interface():
    avps = _build_avp(269, b"TestHSS")
    avps += _build_avp(258, (16777251).to_bytes(4, "big"))  # S6a/S6d
    cea = _build_diameter_message(257, is_request=False, avps=avps)

    confidence, info = diameter._parse_response(cea)
    assert confidence == "confirmed"
    assert info.product_name == "TestHSS"
    assert any("S6a/S6d" in i for i in info.interfaces)


def test_parse_response_extracts_vendor_specific_application_id():
    inner = _build_avp(266, (10415).to_bytes(4, "big"))
    inner += _build_avp(258, (16777238).to_bytes(4, "big"))  # Gx
    avps = _build_avp(260, inner)
    cea = _build_diameter_message(257, is_request=False, avps=avps)

    confidence, info = diameter._parse_response(cea)
    assert confidence == "confirmed"
    assert any("Gx" in i for i in info.interfaces)


def test_parse_response_success_result_code_is_confirmed():
    avps = _build_avp(268, (2001).to_bytes(4, "big"))  # DIAMETER_SUCCESS
    cea = _build_diameter_message(257, is_request=False, avps=avps)
    confidence, info = diameter._parse_response(cea)
    assert confidence == "confirmed"
    assert info.result_code == 2001


def test_parse_response_error_result_code_is_likely():
    avps = _build_avp(268, (5012).to_bytes(4, "big"))  # DIAMETER_UNABLE_TO_COMPLY (permanent failure)
    cea = _build_diameter_message(257, is_request=False, avps=avps)
    confidence, info = diameter._parse_response(cea)
    assert confidence == "likely"
    assert info.result_code == 5012


def test_parse_response_dpr_is_likely():
    dpr = _build_diameter_message(282, is_request=True)  # Disconnect-Peer-Request
    confidence, info = diameter._parse_response(dpr)
    assert confidence == "likely"


# ---------------------------------------------------------------------------
# Vendor fingerprint
# ---------------------------------------------------------------------------

def test_vendor_from_known_vendor_id_avp():
    avps = _build_avp(266, (193).to_bytes(4, "big"))  # Ericsson PEN
    cea = _build_diameter_message(257, is_request=False, avps=avps)
    _confidence, info = diameter._parse_response(cea)
    assert info.vendor == "Ericsson"
    assert info.vendor_source == "Vendor-Id AVP"


def test_vendor_unknown_id_reports_raw_number():
    avps = _build_avp(266, (999999).to_bytes(4, "big"))
    cea = _build_diameter_message(257, is_request=False, avps=avps)
    _confidence, info = diameter._parse_response(cea)
    assert "999999" in info.vendor


def test_vendor_heuristic_fallback_from_product_name():
    avps = _build_avp(269, b"MyHuaweiHSS-v2")
    cea = _build_diameter_message(257, is_request=False, avps=avps)
    _confidence, info = diameter._parse_response(cea)
    assert info.vendor == "Huawei"
    assert info.vendor_source == "Product-Name heuristic"


def test_format_detail_includes_all_fields():
    info = diameter._DiameterInfo(
        product_name="TestPCRF", vendor="Ericsson", vendor_source="Vendor-Id AVP",
        result_code=2001, interfaces=["Gx — PCEF/PCRF policy interface (3GPP TS 29.212)"],
    )
    detail = diameter._format_detail(info)
    assert "TestPCRF" in detail
    assert "Ericsson" in detail
    assert "2001" in detail
    assert "Gx" in detail


# ---------------------------------------------------------------------------
# SIGTRAN family (M3UA / SUA / M2UA) — the same shared header
# ---------------------------------------------------------------------------

def test_build_aspup_is_valid_common_header():
    msg = build_aspup()
    version, reserved, msg_class, msg_type = struct.unpack("!BBBB", msg[:4])
    length = int.from_bytes(msg[4:8], "big")
    assert version == 1
    assert msg_class == 3
    assert msg_type == 3
    assert length == len(msg)


def test_classify_reply_ack_is_confirmed():
    reply = struct.pack("!BBBB", 1, 0, 4, 4) + struct.pack("!I", 8)  # ASPTM ack
    assert classify_reply(reply) == "confirmed"


def test_classify_reply_mgmt_error_is_likely():
    reply = struct.pack("!BBBB", 1, 0, 9, 0) + struct.pack("!I", 8)  # MGMT/Error
    assert classify_reply(reply) == "likely"


def test_classify_reply_rejects_garbage():
    assert classify_reply(b"\x00\x00\x00") is None
    assert classify_reply(struct.pack("!BBBB", 2, 0, 3, 3)) is None  # wrong version


# ---------------------------------------------------------------------------
# Registry: full specialization — no generic detectors, only signaling protocols
# ---------------------------------------------------------------------------

def test_no_generic_protocols_registered():
    """
    We check only the built-in protocols (source == 'builtin') — in
    isolation from any external plugins that might actually be
    installed in the same test-running environment (like the
    demonstration RADIUS plugin in examples/example-protocol-plugin),
    so the test doesn't become fragile depending on what's installed
    alongside the core package.
    """
    all_builtin_names = {
        d.name
        for d in detectors_for(Transport.TCP, 1) + detectors_for(Transport.SCTP, 1) + detectors_for(Transport.UDP, 1)
        if d.source == "builtin"
    }
    assert "generic-banner" not in all_builtin_names
    assert all_builtin_names == {
        "Diameter", "SIGTRAN/M3UA", "SIGTRAN/SUA", "SIGTRAN/M2UA",
        "SIGTRAN/M2PA", "SIGTRAN/IUA", "SIGTRAN/V5UA", "GTP-C", "GTP-U", "SIP/IMS",
    }


def test_diameter_available_on_tcp_and_sctp():
    tcp_names = [d.name for d in detectors_for(Transport.TCP, 3868)]
    sctp_names = [d.name for d in detectors_for(Transport.SCTP, 3868)]
    assert "Diameter" in tcp_names
    assert "Diameter" in sctp_names


def test_sigtran_family_only_on_sctp():
    tcp_names = [d.name for d in detectors_for(Transport.TCP, 2905)]
    assert "SIGTRAN/M3UA" not in tcp_names


def test_detectors_for_prioritizes_matching_hint_port():
    assert detectors_for(Transport.SCTP, 3868)[0].name == "Diameter"
    assert detectors_for(Transport.SCTP, 2905)[0].name == "SIGTRAN/M3UA"
    assert detectors_for(Transport.SCTP, 14001)[0].name == "SIGTRAN/SUA"
    assert detectors_for(Transport.SCTP, 2904)[0].name == "SIGTRAN/M2UA"
