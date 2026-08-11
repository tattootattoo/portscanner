import struct

from portscanner.protocols import v5ua
from portscanner.protocols._sigtran_common import build_aspup, classify_reply


def test_v5ua_iana_port():
    assert v5ua.IANA_PORT == 5675


def test_v5ua_uses_shared_aspup_message():
    msg = build_aspup()
    version, _reserved, msg_class, msg_type = struct.unpack("!BBBB", msg[:4])
    assert version == 1
    assert msg_class == 3
    assert msg_type == 3


def test_v5ua_classifies_ack_as_confirmed():
    reply = struct.pack("!BBBB", 1, 0, 3, 4) + struct.pack("!I", 8)
    assert classify_reply(reply) == "confirmed"


def test_v5ua_classifies_garbage_as_none():
    assert classify_reply(b"\x00\x00\x00") is None
