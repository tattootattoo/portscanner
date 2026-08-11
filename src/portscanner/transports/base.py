"""
transports/base.py
A unified interface (Protocol) for a connection, so the protocol
detection layer (protocols/*) can work the same way whether the
transport is TCP, UDP, or SCTP, without knowing the implementation
details underneath.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from portscanner.models import PortState


@runtime_checkable
class Connection(Protocol):
    """A live connection ready to send/receive bytes, regardless of transport type."""

    async def send(self, data: bytes) -> None: ...

    async def recv(self, max_bytes: int = 4096) -> bytes: ...

    async def close(self) -> None: ...


@dataclass(slots=True)
class ConnectOutcome:
    """The result of a connection attempt: either a ready connection, or a state explaining why it didn't open."""
    state: PortState
    latency_ms: float = 0.0
    connection: Connection | None = None
    error: str | None = None
