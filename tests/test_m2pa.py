import struct

from portscanner.protocols import m2pa


def test_build_link_status_structure():
    msg = m2pa._build_link_status()
    version, reserved, msg_class, msg_type = struct.unpack("!BBBB", msg[:4])
    length = int.from_bytes(msg[4:8], "big")
    assert version == 1
    assert msg_class == 11
    assert msg_type == 2
    assert length == len(msg)


def test_classify_m2pa_class_is_confirmed():
    reply = struct.pack("!BBBB", 1, 0, 11, 1) + struct.pack("!I", 8)
    assert m2pa._classify(reply) == "confirmed"


def test_classify_mgmt_error_is_likely():
    reply = struct.pack("!BBBB", 1, 0, 9, 0) + struct.pack("!I", 8)
    assert m2pa._classify(reply) == "likely"


def test_classify_rejects_garbage():
    assert m2pa._classify(b"\x00\x00\x00") is None
    assert m2pa._classify(struct.pack("!BBBB", 2, 0, 11, 1)) is None  # wrong version
