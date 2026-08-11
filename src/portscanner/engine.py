"""
engine.py
The heart of the project: scans every Target asynchronously, with the
number of concurrent connections governed by a Semaphore
(max_concurrency) so we don't exhaust system resources (file
descriptors) when scanning large ranges. For each open port, it tries
the candidate protocol detectors in order until one confirms or they're
all exhausted.

Fault-tolerant: any unexpected exception on a single target is turned
into an ERROR result instead of breaking the whole asyncio.gather and
halting the entire scan.
"""

from __future__ import annotations

import asyncio
import logging

from portscanner import protocols
from portscanner.models import PortState, ScanConfig, ScanResult, Target, Transport
from portscanner.transports import connect_for

logger = logging.getLogger("portscanner.engine")

# States considered "retryable" (possibly transient: congestion, a
# dropped packet during the handshake...). CLOSED is not retryable
# because it's an explicit reply from the system (RST), not an
# ambiguous state.
_RETRYABLE_STATES = {PortState.FILTERED, PortState.ERROR}


class HostPacer:
    """
    Enforces a minimum interval between consecutive connections to the
    same host (across any ports) — prevents flooding a sensitive
    production element with a burst of connections all at once, even if
    overall concurrency is high. Has no effect on the speed of scanning
    different addresses — the limit only applies to repeated connections
    to the same address.
    """

    def __init__(self, min_delay: float):
        self.min_delay = min_delay
        self._locks: dict[str, asyncio.Lock] = {}
        self._last_attempt: dict[str, float] = {}

    async def wait_turn(self, host: str) -> None:
        if self.min_delay <= 0:
            return
        lock = self._locks.setdefault(host, asyncio.Lock())
        async with lock:
            loop = asyncio.get_running_loop()
            last = self._last_attempt.get(host)
            if last is not None:
                remaining = self.min_delay - (loop.time() - last)
                if remaining > 0:
                    await asyncio.sleep(remaining)
            self._last_attempt[host] = loop.time()


async def _scan_attempt(target: Target, config: ScanConfig) -> ScanResult:
    outcome = await connect_for(
        target.transport, target.host, target.port,
        config.connect_timeout, config.sctp_thread_pool_size, config.tls_ports,
    )

    result = ScanResult(
        target=target,
        state=outcome.state,
        latency_ms=outcome.latency_ms,
        port_hint=protocols.port_hint(target.port),
        error=outcome.error,
    )

    if outcome.state is not PortState.OPEN or not config.identify_protocols:
        if outcome.connection is not None:
            await outcome.connection.close()
        return result

    assert outcome.connection is not None
    try:
        candidates = protocols.detectors_for(target.transport, target.port)
        # Shared time budget for the whole identification step, not a
        # fresh config.probe_timeout per candidate detector. Previously
        # every applicable detector got its own full probe_timeout, so
        # an open port matching none of them (e.g. a non-telecom TCP
        # service) could wait probe_timeout * len(candidates) — up to
        # several detectors' worth of timeouts stacked serially on a
        # single connection. Splitting one shared deadline across the
        # remaining candidates keeps total identification latency close
        # to config.probe_timeout regardless of how many detectors apply.
        loop = asyncio.get_running_loop()
        deadline = loop.time() + config.probe_timeout
        for i, detector in enumerate(candidates):
            remaining = deadline - loop.time()
            if remaining <= 0:
                break
            detector_timeout = remaining / (len(candidates) - i)
            try:
                detected = await detector.detect(outcome.connection, detector_timeout)
            except Exception as e:  # isolate a single detector's failure from the rest of the scan
                logger.debug("detector %s failed on %s:%s — %s",
                             detector.name, target.host, target.port, e)
                continue
            if detected:
                result.protocol = detector.name
                result.confidence = detected.confidence
                result.detail = detected.detail
                break
    finally:
        await outcome.connection.close()

    if target.transport is Transport.UDP and result.protocol is None:
        # UDP is connectionless — a successful "connect" here only means
        # a local socket was created, not proof that anything on the
        # other side actually replied. Without an actual protocol
        # confirmation (an Echo reply, for instance), the real state is
        # ambiguous (open|filtered, exactly like standard UDP scanning
        # tools) — we classify it as filtered instead of misleadingly
        # reporting "open" for a port that may have nobody behind it at all.
        result.state = PortState.FILTERED
        result.error = result.error or "no protocol reply (ambiguous UDP state without an actual response)"

    return result


async def _scan_one(
    target: Target, config: ScanConfig, sem: asyncio.Semaphore, pacer: HostPacer | None = None,
) -> ScanResult:
    async with sem:
        last_result: ScanResult | None = None
        for attempt in range(1, config.retries + 2):  # first attempt + extra retries
            # Pacing applies to every attempt, including retries — not
            # just the first one. Previously wait_turn() was only
            # called once before this loop, so a retried target could
            # burst straight back at the host with none of the
            # min-delay-per-host protection applied to attempt 2, 3...
            # — defeating the whole point of pacing against a
            # sensitive live element whenever retries were configured.
            if pacer is not None:
                await pacer.wait_turn(target.host)
            try:
                result = await _scan_attempt(target, config)
            except Exception as e:
                # Blanket protection: any unexpected error (a library
                # bug, etc.) is turned into an ERROR result instead of
                # failing the entire asyncio.gather scan.
                logger.debug("scan attempt %d failed unexpectedly for %s:%s — %s",
                             attempt, target.host, target.port, e)
                result = ScanResult(
                    target=target, state=PortState.ERROR,
                    port_hint=protocols.port_hint(target.port), error=str(e),
                )

            result.attempts = attempt
            if result.state not in _RETRYABLE_STATES or attempt == config.retries + 1:
                return result
            last_result = result
            await asyncio.sleep(config.retry_delay)

        return last_result  # theoretically unreachable, but a safety net anyway


async def run_scan(targets: list[Target], config: ScanConfig) -> list[ScanResult]:
    """Runs the full scan and returns the results once they're all complete."""
    sem = asyncio.Semaphore(config.max_concurrency)
    pacer = HostPacer(config.min_delay_per_host) if config.min_delay_per_host > 0 else None
    tasks = [_scan_one(t, config, sem, pacer) for t in targets]
    return await asyncio.gather(*tasks)


async def iter_scan(targets: list[Target], config: ScanConfig):
    """
    Streaming version: yields each result as soon as it completes
    instead of waiting for everything — used to show a live progress
    bar while scanning large ranges (see cli.py).
    """
    sem = asyncio.Semaphore(config.max_concurrency)
    pacer = HostPacer(config.min_delay_per_host) if config.min_delay_per_host > 0 else None
    tasks = [asyncio.ensure_future(_scan_one(t, config, sem, pacer)) for t in targets]
    for coro in asyncio.as_completed(tasks):
        yield await coro


async def adaptive_iter_scan(targets: list[Target], config: ScanConfig, controller):
    """
    Like iter_scan, but concurrency isn't fixed — targets are scanned in
    batches, with each batch's size equal to controller.current at that
    moment. After each batch, the error rate (filtered+error) is fed
    back to the controller (see adaptive.ConcurrencyController), which
    decides whether to grow or shrink the next batch size based on the
    network's actual responsiveness — very useful for scanning huge
    target files (a large CIDR/hosts-file) without having to manually
    guess --concurrency.

    Note: each batch waits to fully finish before the next one starts
    (not true streaming across batches) — a simple tradeoff for keeping
    the adaptation logic simple; progress is still updated result by
    result within each batch.
    """
    i = 0
    n = len(targets)
    pacer = HostPacer(config.min_delay_per_host) if config.min_delay_per_host > 0 else None
    while i < n:
        batch = targets[i:i + controller.current]
        sem = asyncio.Semaphore(len(batch))
        results = await asyncio.gather(*(_scan_one(t, config, sem, pacer) for t in batch))

        error_count = sum(1 for r in results if r.state in _RETRYABLE_STATES)
        controller.observe(error_count / len(batch) if batch else 0.0)

        for r in results:
            yield r
        i += len(batch)


def run_shard_sync(
    shard: list[Target],
    fast_config: ScanConfig,
    deep_config: ScanConfig,
    use_two_phase: bool,
    adaptive_params: dict | None,
) -> list[ScanResult]:
    """
    A full synchronous wrapper (runs asyncio.run() internally) that
    scans a single shard of targets and returns every result as one
    list, only once the whole shard is done. Kept for callers that
    genuinely want the "one batch per shard" behavior (e.g. tests) —
    for the CLI's --workers path, prefer run_shard_streaming below,
    which reports each result to the caller as soon as it completes
    instead of holding the whole shard in memory until the end.
    """
    results: list[ScanResult] = []
    try:
        asyncio.run(_run_shard_inner(shard, fast_config, deep_config, use_two_phase, adaptive_params, results.append))
    finally:
        from portscanner.transports import sctp as sctp_transport
        sctp_transport.shutdown_executor()
    return results


async def _run_shard_inner(
    shard: list[Target],
    fast_config: ScanConfig,
    deep_config: ScanConfig,
    use_two_phase: bool,
    adaptive_params: dict | None,
    emit,
) -> None:
    """
    Shared core of the shard scan: runs the two-phase (or single-phase)
    logic and calls emit(result) as soon as each individual result
    completes — never builds up its own list. Both run_shard_sync
    (batches at the end via list.append) and run_shard_streaming
    (pushes to a cross-process queue immediately) are thin wrappers
    around this, so the actual scanning logic only lives in one place.
    """
    if not use_two_phase:
        async for result in iter_scan(shard, deep_config):
            emit(result)
        return

    # UDP has no handshake, so the "fast" connectivity check
    # (transports/udp.py: connect()) can only ever report OPEN — it
    # just means a local socket was created, not that anything
    # answered. Running those targets through the fast phase gives
    # zero filtering benefit and, worse, feeds every single UDP target
    # into the deep phase even when nothing is really open. So UDP
    # targets skip the fast phase entirely and go straight to a full
    # (protocol-identifying) scan, which is the only phase capable of
    # telling OPEN apart from FILTERED for UDP.
    fast_targets = [t for t in shard if t.transport is not Transport.UDP]
    udp_targets = [t for t in shard if t.transport is Transport.UDP]

    controller = None
    if adaptive_params is not None:
        from portscanner.adaptive import ConcurrencyController
        controller = ConcurrencyController(**adaptive_params)

    fast_iterator = (
        adaptive_iter_scan(fast_targets, fast_config, controller)
        if controller is not None
        else iter_scan(fast_targets, fast_config)
    )
    open_targets: list[Target] = list(udp_targets)
    async for result in fast_iterator:
        if result.state is PortState.OPEN:
            open_targets.append(result.target)
        else:
            emit(result)

    if open_targets:
        async for result in iter_scan(open_targets, deep_config):
            emit(result)


def run_shard_streaming(
    shard: list[Target],
    fast_config: ScanConfig,
    deep_config: ScanConfig,
    use_two_phase: bool,
    adaptive_params: dict | None,
    result_queue,
    shard_index: int,
) -> None:
    """
    Like run_shard_sync, but instead of returning a list at the very
    end, pushes each ScanResult onto result_queue (a
    multiprocessing.Queue) the moment it completes. This is the
    function actually used with --workers > 1 in cli.py: it means a
    worker process scanning a huge shard streams results to the main
    process (and from there straight to disk, e.g. ndjson) throughout
    the scan instead of holding the entire shard's results in memory
    and only handing them over once the whole shard finishes — the
    same result-by-result streaming guarantee single-process scans
    already have, now preserved across --workers too.

    Must be a top-level function (not a closure) so it can be pickled
    and handed to a separate process. Puts a ("__shard_done__",
    shard_index, count) sentinel once finished (success or error) so
    the main process knows this shard is complete without needing to
    join() before it can react to the last few results.
    """
    count = 0
    try:
        def _emit(result: ScanResult) -> None:
            nonlocal count
            count += 1
            result_queue.put(result)

        asyncio.run(_run_shard_inner(shard, fast_config, deep_config, use_two_phase, adaptive_params, _emit))
    except Exception as e:  # noqa: BLE001 - a shard-level failure must not hang the main process forever
        logger.exception("shard %d failed", shard_index)
        result_queue.put(("__shard_error__", shard_index, str(e)))
    finally:
        from portscanner.transports import sctp as sctp_transport
        sctp_transport.shutdown_executor()
        result_queue.put(("__shard_done__", shard_index, count))
