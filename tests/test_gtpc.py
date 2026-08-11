import struct

from portscanner.protocols import _gtp_common as gtp
from portscanner.protocols import gtpc, gtpu


def test_build_echo_request_v2_structure():
    msg = gtp.build_echo_request_v2()
    version = (msg[0] >> 5) & 0x07
    message_type = msg[1]
    length = int.from_bytes(msg[2:4], "big")
    assert version == 2
    assert message_type == 1  # Echo Request
    assert length == len(msg) - 4  # the length doesn't include the first 4 header bytes


def test_build_echo_request_v1_structure():
    msg = gtp.build_echo_request_v1()
    version = (msg[0] >> 5) & 0x07
    message_type = msg[1]
    length = int.from_bytes(msg[2:4], "big")
    teid = int.from_bytes(msg[4:8], "big")
    assert version == 1
    assert message_type == 1
    assert teid == 0
    assert length == len(msg) - 8  # v1: length after the mandatory 8-byte header


def _build_response(version: int, message_type: int) -> bytes:
    flags = (version & 0x07) << 5
    return struct.pack("!BB", flags, message_type) + b"\x00\x00"


def test_classify_matching_version_echo_response_is_confirmed():
    reply = _build_response(version=2, message_type=gtp.ECHO_RESPONSE)
    result = gtp.classify_echo_response(reply, 2, "GTP-C", "TS 29.274")
    assert result is not None
    assert result.confidence == "confirmed"
    assert "GTP-C" in result.detail


def test_classify_mismatched_version_still_confirmed():
    reply = _build_response(version=1, message_type=gtp.ECHO_RESPONSE)
    result = gtp.classify_echo_response(reply, 2, "GTP-C", "TS 29.274")
    assert result is not None
    assert result.confidence == "confirmed"


def test_classify_version_not_supported_is_likely():
    reply = _build_response(version=1, message_type=gtp.VERSION_NOT_SUPPORTED)
    result = gtp.classify_echo_response(reply, 2, "GTP-C", "TS 29.274")
    assert result is not None
    assert result.confidence == "likely"


def test_classify_rejects_garbage():
    assert gtp.classify_echo_response(b"\x00", 2, "GTP-C", "TS 29.274") is None
    assert gtp.classify_echo_response(_build_response(2, 99), 2, "GTP-C", "TS 29.274") is None


def test_gtpc_registered_for_iana_port():
    assert gtpc.IANA_PORT == 2123


def test_gtpu_registered_for_iana_port():
    assert gtpu.IANA_PORT == 2152


def test_gtpu_uses_v1_header_only():
    # GTP-U has no v2 version — the module shouldn't export build_echo_request_v2
    assert not hasattr(gtpu, "build_echo_request_v2")
