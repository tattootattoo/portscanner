"""
transports/sctp.py
asyncio has no built-in SCTP protocol support, but SCTP sockets are
still ordinary OS sockets under Linux (via lksctp) that the kernel
reports readiness for through the same epoll/select mechanism as TCP.
So instead of routing every SCTP operation through a bounded
ThreadPoolExecutor (the previous approach), we open the socket in
non-blocking mode and drive it with the event loop's own low-level
socket primitives (loop.sock_connect / sock_recv / sock_sendall) —
exactly like asyncio.open_connection does internally for TCP, just
without the StreamReader/StreamWriter wrapper (Python's transport
factories don't support IPPROTO_SCTP, so we talk to the raw socket
ourselves).

This removes the old, fixed thread-pool ceiling entirely: SCTP
concurrency is now governed by the same asyncio.Semaphore
(config.max_concurrency) as TCP and UDP, not by a separate, much
smaller thread count. A scan config that already works well for
TCP/UDP concurrency now scales the same way for SCTP, with no extra
tuning needed.
"""

from __future__ import annotations

import asyncio
import socket
import time

from portscanner.models import PortState
from portscanner.transports.base import ConnectOutcome

_SCTP_SUPPORTED = hasattr(socket, "IPPROTO_SCTP")


class SCTPConnection:
    __slots__ = ("_sock", "_loop")

    def __init__(self, sock: socket.socket, loop: asyncio.AbstractEventLoop):
        self._sock = sock
        self._loop = loop

    async def send(self, data: bytes) -> None:
        await self._loop.sock_sendall(self._sock, data)

    async def recv(self, max_bytes: int = 4096) -> bytes:
        return await self._loop.sock_recv(self._sock, max_bytes)

    async def close(self) -> None:
        self._sock.close()


async def connect(host: str, port: int, timeout: float, pool_size: int = 20) -> ConnectOutcome:
    """
    pool_size is accepted for backward compatibility with callers and
    the --sctp-pool-size CLI flag, but is no longer used: there is no
    thread pool anymore, so it has no effect on concurrency or
    behavior. See the module docstring.
    """
    if not _SCTP_SUPPORTED:
        return ConnectOutcome(
            state=PortState.ERROR,
            error="SCTP is not supported in this environment (requires lksctp-tools on Linux)",
        )

    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_SCTP)
    sock.setblocking(False)
    start = time.monotonic()
    try:
        await asyncio.wait_for(loop.sock_connect(sock, (host, port)), timeout=timeout)
        latency = (time.monotonic() - start) * 1000
        return ConnectOutcome(
            state=PortState.OPEN,
            latency_ms=latency,
            connection=SCTPConnection(sock, loop),
        )
    except asyncio.TimeoutError:
        sock.close()
        return ConnectOutcome(state=PortState.FILTERED, error="timeout")
    except ConnectionRefusedError:
        sock.close()
        return ConnectOutcome(state=PortState.CLOSED)
    except OSError as e:
        sock.close()
        return ConnectOutcome(state=PortState.ERROR, error=str(e))


def shutdown_executor() -> None:
    """
    Kept as a no-op for backward compatibility: engine.py calls this
    unconditionally after every scan (single-process and per worker
    process) to clean up SCTP resources. There is no executor anymore
    to shut down, since every SCTP socket now closes itself via
    SCTPConnection.close() right after use, same as TCP/UDP.
    """
    return None
