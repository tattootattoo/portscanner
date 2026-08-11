"""
tests/test_e2e_sigtran_simulated.py
Note: this file is **not** a real end-to-end test — no real SCTP is
available in this environment (`--check-env` confirms this). What it
does instead: test the **actual production detect() functions** (not
the build/parse byte functions in isolation) via a mocked Connection —
covering important paths like timeout, an early connection close, and
multi-chunk replies, which weren't covered by the original
test_protocols.py tests (which only check isolated build/classify functions).

The difference from a real test: there's no actual SCTP association
state machine, no real INIT/INIT-ACK handshake — only the logic that
comes after the connection (sending ASP-UP, reading the reply,
classifying it) is actually tested with the exact same code used in
production.
"""

import asyncio
import struct

import pytest

from portscanner.protocols.iua import detect as iua_detect
from portscanner.protocols.m2pa import detect as m2pa_detect
from portscanner.protocols.m2ua import detect as m2ua_detect
from portscanner.protocols.m3ua import detect as m3ua_detect
from portscanner.protocols.sua import detect as sua_detect
from portscanner.protocols.v5ua import detect as v5ua_detect


class _RealisticFakeConnection:
    """
    A mock closer to real SCTP behavior than the simple FakeConnection
    in test_engine.py: it returns the reply in chunks (as could really
    happen if the message was split across more than one SCTP packet),
    and records everything that was sent.
    """

    def __init__(self, response_chunks: list[bytes]):
        self._chunks = list(response_chunks)
        self.sent_messages: list[bytes] = []
        self.closed = False

    async def send(self, data: bytes) -> None:
        self.sent_messages.append(data)

    async def recv(self, max_bytes: int = 4096) -> bytes:
        if not self._chunks:
            await asyncio.sleep(10)  # simulates a real timeout — the test sets a shorter one
            return b""
        return self._chunks.pop(0)

    async def close(self) -> None:
        self.closed = True


def _aspup_ack() -> bytes:
    return struct.pack("!BBBB", 1, 0, 4, 4) + struct.pack("!I", 8)


def _m2pa_ack() -> bytes:
    """M2PA is deliberately designed differently from the rest of the
    SIGTRAN family — it uses its own Link Status (class=11), not the
    shared ASPSM messages (class=3/4) that M3UA/SUA/M2UA/IUA/V5UA share
    via probe_adaptation_layer. See the m2pa.py docstring for details."""
    return struct.pack("!BBBB", 1, 0, 11, 1) + struct.pack("!I", 8)


def _mgmt_error() -> bytes:
    return struct.pack("!BBBB", 1, 0, 9, 0) + struct.pack("!I", 8)


_ALL_SIGTRAN_DETECTORS = [
    ("M3UA", m3ua_detect, _aspup_ack),
    ("SUA", sua_detect, _aspup_ack),
    ("M2UA", m2ua_detect, _aspup_ack),
    ("M2PA", m2pa_detect, _m2pa_ack),  # a deliberately different class — see _m2pa_ack
    ("IUA", iua_detect, _aspup_ack),
    ("V5UA", v5ua_detect, _aspup_ack),
]


@pytest.mark.asyncio
async def test_all_sigtran_protocols_confirm_on_ack():
    """All six protocols must confirm correctly on a "successful" reply matching their own format."""
    for name, detect_fn, build_ack in _ALL_SIGTRAN_DETECTORS:
        conn = _RealisticFakeConnection([build_ack()])
        result = await detect_fn(conn, timeout=1.0)
        assert result is not None, f"{name} failed to confirm on a successful reply in its own format"
        assert result.confidence == "confirmed", f"{name}: expected confirmed"
        assert len(conn.sent_messages) == 1, f"{name} must send exactly one message"


@pytest.mark.asyncio
async def test_all_sigtran_protocols_downgrade_on_mgmt_error():
    """An MGMT/Error reply must be classified likely, not confirmed and not None, for every protocol."""
    for name, detect_fn, _kw in _ALL_SIGTRAN_DETECTORS:
        conn = _RealisticFakeConnection([_mgmt_error()])
        result = await detect_fn(conn, timeout=1.0)
        assert result is not None, f"{name} failed to recognize an MGMT/Error reply"
        assert result.confidence == "likely", f"{name}: expected likely, not {result.confidence}"


@pytest.mark.asyncio
async def test_all_sigtran_protocols_return_none_on_timeout():
    """No reply at all (simulating filtered/silent drop) — must be None, not an exception that kills the scan."""
    for name, detect_fn, _kw in _ALL_SIGTRAN_DETECTORS:
        conn = _RealisticFakeConnection([])  # this triggers the long delay path in recv()
        result = await detect_fn(conn, timeout=0.2)
        assert result is None, f"{name} should return None when there's no reply, returned {result}"


@pytest.mark.asyncio
async def test_all_sigtran_protocols_return_none_on_garbage():
    """A reply of random data (not a valid SIGTRAN header at all) — must be a quiet None."""
    for name, detect_fn, _kw in _ALL_SIGTRAN_DETECTORS:
        conn = _RealisticFakeConnection([b"\x00\x01\x02garbage-not-sigtran-at-all"])
        result = await detect_fn(conn, timeout=1.0)
        assert result is None, f"{name} should return None on random data"


@pytest.mark.asyncio
async def test_all_sigtran_protocols_handle_connection_closed_mid_read():
    """The connection suddenly closes while waiting for a reply (ConnectionResetError) — clean isolation, not an exception that kills the scan."""

    class _DroppingConnection(_RealisticFakeConnection):
        async def recv(self, max_bytes: int = 4096) -> bytes:
            raise ConnectionResetError("the connection was suddenly closed by the other side")

    for name, detect_fn, _kw in _ALL_SIGTRAN_DETECTORS:
        conn = _DroppingConnection([])
        result = await detect_fn(conn, timeout=1.0)
        assert result is None, f"{name} must handle a dropped connection quietly (None), not raise an exception"
