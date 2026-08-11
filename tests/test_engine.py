"""
tests/test_engine.py
Tests for the project's core (engine.py) — by mocking the transport
layer (connect_for) and the protocol layer (detectors_for) instead of
a real network, so we can precisely control scenarios (repeated
refusal then success, an unexpected error, an ambiguous UDP reply...)
that are hard to reproduce on a real network.
"""

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from portscanner import engine
from portscanner.models import PortState, ScanConfig, Target, Transport
from portscanner.protocols.base import DetectionResult
from portscanner.transports.base import ConnectOutcome


class _FakeConnection:
    """A mock connection implementing the Connection interface (send/recv/close) with no real network."""

    def __init__(self):
        self.closed = False

    async def send(self, data: bytes) -> None:
        pass

    async def recv(self, max_bytes: int = 4096) -> bytes:
        return b""

    async def close(self) -> None:
        self.closed = True


def _target(host="10.0.0.1", port=3868, transport=Transport.TCP) -> Target:
    return Target(host=host, port=port, transport=transport)


def _config(**overrides) -> ScanConfig:
    base = dict(connect_timeout=1.0, probe_timeout=1.0, max_concurrency=10,
                identify_protocols=True, retries=0, retry_delay=0.0)
    base.update(overrides)
    return ScanConfig(**base)


# ---------------------------------------------------------------------------
# _scan_one: the basic case (open/closed) with no retry
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_scan_one_open_state_runs_identification():
    connection = _FakeConnection()
    outcome = ConnectOutcome(state=PortState.OPEN, connection=connection)
    fake_detector = type("D", (), {
        "name": "FakeProto",
        "detect": AsyncMock(return_value=DetectionResult(detail="matched", confidence="confirmed")),
    })()

    with patch("portscanner.engine.connect_for", new=AsyncMock(return_value=outcome)), \
         patch("portscanner.engine.protocols.detectors_for", return_value=[fake_detector]):
        sem = asyncio.Semaphore(5)
        result = await engine._scan_one(_target(), _config(), sem)

    assert result.state is PortState.OPEN
    assert result.protocol == "FakeProto"
    assert result.confidence == "confirmed"
    assert connection.closed is True  # the connection must always close after use


@pytest.mark.asyncio
async def test_scan_one_closed_state_skips_identification():
    outcome = ConnectOutcome(state=PortState.CLOSED, connection=None)
    detectors_mock = AsyncMock()

    with patch("portscanner.engine.connect_for", new=AsyncMock(return_value=outcome)), \
         patch("portscanner.engine.protocols.detectors_for") as detectors_for:
        sem = asyncio.Semaphore(5)
        result = await engine._scan_one(_target(), _config(), sem)

    assert result.state is PortState.CLOSED
    assert result.protocol is None
    detectors_for.assert_not_called()  # we must not try to identify a protocol for a closed port


@pytest.mark.asyncio
async def test_scan_one_no_identify_skips_protocol_detection_even_when_open():
    connection = _FakeConnection()
    outcome = ConnectOutcome(state=PortState.OPEN, connection=connection)

    with patch("portscanner.engine.connect_for", new=AsyncMock(return_value=outcome)), \
         patch("portscanner.engine.protocols.detectors_for") as detectors_for:
        sem = asyncio.Semaphore(5)
        result = await engine._scan_one(_target(), _config(identify_protocols=False), sem)

    assert result.state is PortState.OPEN
    assert result.protocol is None
    detectors_for.assert_not_called()


# ---------------------------------------------------------------------------
# retry logic — only for ambiguous states
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_scan_one_retries_filtered_then_succeeds():
    attempts = []

    async def fake_connect(transport, host, port, timeout, sctp_pool_size=20, tls_ports=frozenset()):
        attempts.append(1)
        if len(attempts) < 3:
            return ConnectOutcome(state=PortState.FILTERED)
        return ConnectOutcome(state=PortState.OPEN, connection=_FakeConnection())

    with patch("portscanner.engine.connect_for", new=fake_connect), \
         patch("portscanner.engine.protocols.detectors_for", return_value=[]):
        sem = asyncio.Semaphore(5)
        result = await engine._scan_one(_target(), _config(retries=5, retry_delay=0.0), sem)

    assert result.state is PortState.OPEN
    assert result.attempts == 3
    assert len(attempts) == 3  # it stopped retrying once it succeeded


@pytest.mark.asyncio
async def test_scan_one_stops_after_max_retries_when_still_failing():
    call_count = {"n": 0}

    async def always_error(*args, **kwargs):
        call_count["n"] += 1
        return ConnectOutcome(state=PortState.ERROR, error="always fails")

    with patch("portscanner.engine.connect_for", new=always_error):
        sem = asyncio.Semaphore(5)
        result = await engine._scan_one(_target(), _config(retries=2, retry_delay=0.0), sem)

    assert result.state is PortState.ERROR
    assert result.attempts == 3  # first attempt + 2 retries
    assert call_count["n"] == 3


@pytest.mark.asyncio
async def test_scan_one_does_not_retry_closed_state():
    call_count = {"n": 0}

    async def always_closed(*args, **kwargs):
        call_count["n"] += 1
        return ConnectOutcome(state=PortState.CLOSED)

    with patch("portscanner.engine.connect_for", new=always_closed):
        sem = asyncio.Semaphore(5)
        result = await engine._scan_one(_target(), _config(retries=5, retry_delay=0.0), sem)

    assert result.state is PortState.CLOSED
    assert result.attempts == 1  # CLOSED is not retryable — an explicit reply, not ambiguous
    assert call_count["n"] == 1


# ---------------------------------------------------------------------------
# isolating unexpected failures (a library bug, an unexpected exception...)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_scan_one_isolates_unexpected_exception():
    async def raises_unexpectedly(*args, **kwargs):
        raise RuntimeError("an unexpected bug somewhere")

    with patch("portscanner.engine.connect_for", new=raises_unexpectedly):
        sem = asyncio.Semaphore(5)
        result = await engine._scan_one(_target(), _config(retries=0), sem)

    assert result.state is PortState.ERROR
    assert "an unexpected bug" in result.error


@pytest.mark.asyncio
async def test_run_scan_isolates_one_bad_target_from_others():
    """A single target raising an unexpected exception must not prevent the other targets from succeeding."""

    async def fake_connect(transport, host, port, timeout, sctp_pool_size=20, tls_ports=frozenset()):
        if port == 666:
            raise RuntimeError("failure on the cursed port")
        return ConnectOutcome(state=PortState.CLOSED)

    targets = [_target(port=p) for p in (80, 443, 666, 8080)]
    with patch("portscanner.engine.connect_for", new=fake_connect):
        results = await engine.run_scan(targets, _config(identify_protocols=False))

    assert len(results) == 4  # every target returned a result, none broke the rest
    by_port = {r.port: r for r in results}
    assert by_port[666].state is PortState.ERROR
    assert by_port[80].state is PortState.CLOSED
    assert by_port[443].state is PortState.CLOSED
    assert by_port[8080].state is PortState.CLOSED


# ---------------------------------------------------------------------------
# ambiguous UDP logic: OPEN without protocol confirmation = filtered (not a misleading open)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_udp_open_without_protocol_confirmation_downgrades_to_filtered():
    connection = _FakeConnection()
    outcome = ConnectOutcome(state=PortState.OPEN, connection=connection)

    with patch("portscanner.engine.connect_for", new=AsyncMock(return_value=outcome)), \
         patch("portscanner.engine.protocols.detectors_for", return_value=[]):
        sem = asyncio.Semaphore(5)
        target = _target(transport=Transport.UDP, port=2123)
        result = await engine._scan_one(target, _config(), sem)

    assert result.state is PortState.FILTERED
    assert result.error is not None


@pytest.mark.asyncio
async def test_udp_open_with_protocol_confirmation_stays_open():
    connection = _FakeConnection()
    outcome = ConnectOutcome(state=PortState.OPEN, connection=connection)
    fake_detector = type("D", (), {
        "name": "GTP-C",
        "detect": AsyncMock(return_value=DetectionResult(detail="confirmed", confidence="confirmed")),
    })()

    with patch("portscanner.engine.connect_for", new=AsyncMock(return_value=outcome)), \
         patch("portscanner.engine.protocols.detectors_for", return_value=[fake_detector]):
        sem = asyncio.Semaphore(5)
        target = _target(transport=Transport.UDP, port=2123)
        result = await engine._scan_one(target, _config(), sem)

    assert result.state is PortState.OPEN
    assert result.protocol == "GTP-C"


@pytest.mark.asyncio
async def test_tcp_open_without_protocol_confirmation_stays_open():
    """The same scenario but for TCP — here OPEN is actually reliable (a
    real TCP connection succeeded) even if no protocol was confirmed,
    unlike UDP where it means something different."""
    connection = _FakeConnection()
    outcome = ConnectOutcome(state=PortState.OPEN, connection=connection)

    with patch("portscanner.engine.connect_for", new=AsyncMock(return_value=outcome)), \
         patch("portscanner.engine.protocols.detectors_for", return_value=[]):
        sem = asyncio.Semaphore(5)
        result = await engine._scan_one(_target(transport=Transport.TCP), _config(), sem)

    assert result.state is PortState.OPEN
    assert result.protocol is None


# ---------------------------------------------------------------------------
# iter_scan / run_scan: full coverage of every target
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_iter_scan_yields_result_for_every_target():
    async def fake_connect(*args, **kwargs):
        return ConnectOutcome(state=PortState.CLOSED)

    targets = [_target(port=p) for p in range(10)]
    with patch("portscanner.engine.connect_for", new=fake_connect):
        seen_ports = set()
        async for result in engine.iter_scan(targets, _config(identify_protocols=False)):
            seen_ports.add(result.port)

    assert seen_ports == set(range(10))


@pytest.mark.asyncio
async def test_run_scan_empty_targets_returns_empty_list():
    results = await engine.run_scan([], _config())
    assert results == []


# ---------------------------------------------------------------------------
# HostPacer: rate-limiting connections per host
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_host_pacer_delays_repeated_same_host_connections():
    pacer = engine.HostPacer(min_delay=0.1)
    loop = asyncio.get_running_loop()
    start = loop.time()
    await pacer.wait_turn("10.0.0.1")
    await pacer.wait_turn("10.0.0.1")
    elapsed = loop.time() - start
    assert elapsed >= 0.1


@pytest.mark.asyncio
async def test_host_pacer_does_not_delay_different_hosts():
    pacer = engine.HostPacer(min_delay=0.5)
    loop = asyncio.get_running_loop()
    start = loop.time()
    await asyncio.gather(*(pacer.wait_turn(f"10.0.0.{i}") for i in range(10)))
    elapsed = loop.time() - start
    assert elapsed < 0.1  # different addresses shouldn't be delayed at all


@pytest.mark.asyncio
async def test_host_pacer_disabled_when_min_delay_zero():
    pacer = engine.HostPacer(min_delay=0.0)
    loop = asyncio.get_running_loop()
    start = loop.time()
    for _ in range(5):
        await pacer.wait_turn("10.0.0.1")
    assert loop.time() - start < 0.05


# ---------------------------------------------------------------------------
# adaptive_iter_scan: concurrency adaptation + full coverage of every target
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_adaptive_iter_scan_covers_all_targets():
    from portscanner.adaptive import ConcurrencyController

    async def fake_connect(*args, **kwargs):
        return ConnectOutcome(state=PortState.CLOSED)

    targets = [_target(port=p) for p in range(25)]
    controller = ConcurrencyController(min_concurrency=2, max_concurrency=50, initial_concurrency=5)

    with patch("portscanner.engine.connect_for", new=fake_connect):
        seen = set()
        async for result in engine.adaptive_iter_scan(targets, _config(identify_protocols=False), controller):
            seen.add(result.port)

    assert seen == set(range(25))


@pytest.mark.asyncio
async def test_adaptive_iter_scan_decreases_concurrency_on_errors():
    from portscanner.adaptive import ConcurrencyController

    async def fake_connect(*args, **kwargs):
        return ConnectOutcome(state=PortState.ERROR, error="simulated congestion")

    targets = [_target(port=p) for p in range(20)]
    controller = ConcurrencyController(min_concurrency=2, max_concurrency=50, initial_concurrency=10)

    with patch("portscanner.engine.connect_for", new=fake_connect):
        async for _ in engine.adaptive_iter_scan(targets, _config(identify_protocols=False), controller):
            pass

    assert controller.current < 10  # every batch failed — concurrency must decrease
