import struct

from portscanner.protocols import gtpu
from portscanner.protocols._gtp_common import build_echo_request_v1, classify_echo_response


def test_gtpu_reuses_v1_echo_request():
    msg = build_echo_request_v1()
    version = (msg[0] >> 5) & 0x07
    message_type = msg[1]
    assert version == 1
    assert message_type == 1


def _build_response(version: int, message_type: int) -> bytes:
    flags = (version & 0x07) << 5
    return struct.pack("!BB", flags, message_type) + b"\x00\x00"


def test_classify_gtpu_echo_response_confirmed():
    reply = _build_response(version=1, message_type=2)
    result = classify_echo_response(reply, sent_version=1, protocol_label="GTP-U",
                                     standard_ref="3GPP TS 29.281")
    assert result is not None
    assert result.confidence == "confirmed"
    assert "GTP-U" in result.detail


def test_gtpu_detector_registered_for_udp_only():
    from portscanner.models import Transport
    from portscanner.protocols.base import detectors_for
    names = [d.name for d in detectors_for(Transport.UDP, gtpu.IANA_PORT)]
    assert "GTP-U" in names
    tcp_names = [d.name for d in detectors_for(Transport.TCP, gtpu.IANA_PORT)]
    assert "GTP-U" not in tcp_names
