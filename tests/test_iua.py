import struct

from portscanner.protocols import iua
from portscanner.protocols._sigtran_common import build_aspup, classify_reply


def test_iua_iana_port():
    assert iua.IANA_PORT == 9900


def test_iua_uses_shared_aspup_message():
    """IUA uses exactly the same shared ASP-UP message as M3UA/SUA/M2UA."""
    msg = build_aspup()
    version, reserved, msg_class, msg_type = struct.unpack("!BBBB", msg[:4])
    assert version == 1
    assert msg_class == 3  # ASPSM
    assert msg_type == 3   # ASP Up


def test_iua_classifies_ack_as_confirmed():
    reply = struct.pack("!BBBB", 1, 0, 4, 4) + struct.pack("!I", 8)
    assert classify_reply(reply) == "confirmed"


def test_iua_classifies_mgmt_error_as_likely():
    reply = struct.pack("!BBBB", 1, 0, 9, 0) + struct.pack("!I", 8)
    assert classify_reply(reply) == "likely"
