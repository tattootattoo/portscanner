"""
models.py
The core data models used across every layer of the project.
No networking logic lives here — just structure definitions (domain models).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Transport(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    SCTP = "sctp"


class PortState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class Target:
    """A single scan target: host + port + transport type."""
    host: str
    port: int
    transport: Transport


@dataclass(slots=True)
class ScanResult:
    """The result of scanning a single port, including protocol confirmation if any."""
    target: Target
    state: PortState
    latency_ms: float = 0.0
    port_hint: str = ""          # an unreliable initial guess based on the port number
    protocol: str | None = None  # the actually-confirmed protocol name (or None)
    confidence: str = ""         # "confirmed" (successful reply) or "likely" (an explicit reply that was rejected/errored)
    detail: str = ""             # extra detail (version, banner, failure reason...)
    error: str | None = None
    attempts: int = 1            # number of actual connection attempts (>1 if a retry was used)

    @property
    def host(self) -> str:
        return self.target.host

    @property
    def port(self) -> int:
        return self.target.port

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "transport": self.target.transport.value,
            "state": self.state.value,
            "latency_ms": round(self.latency_ms, 2),
            "port_hint": self.port_hint,
            "protocol": self.protocol,
            "confidence": self.confidence,
            "detail": self.detail,
            "error": self.error,
            "attempts": self.attempts,
        }


@dataclass(slots=True)
class ScanMetadata:
    """Metadata about a whole scan session — added to the JSON output so
    you can later tell when a scan happened, how long it took, and with
    what settings, instead of relying only on a raw list of results with
    no context."""
    tool_version: str
    started_at: str          # ISO 8601 UTC
    duration_seconds: float
    targets_scanned: int
    hosts: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    transports: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "tool_version": self.tool_version,
            "started_at": self.started_at,
            "duration_seconds": round(self.duration_seconds, 3),
            "targets_scanned": self.targets_scanned,
            "hosts": self.hosts,
            "ports": self.ports,
            "transports": self.transports,
        }


@dataclass(slots=True)
class ScanConfig:
    """All scan-session settings in one place — an alternative to passing 10 parameters to every function."""
    connect_timeout: float = 2.0
    probe_timeout: float = 2.0
    max_concurrency: int = 500
    identify_protocols: bool = True
    sctp_thread_pool_size: int = 20
    retries: int = 0            # extra attempts on filtered/error (0 = no retry)
    retry_delay: float = 0.3    # a short delay between attempts (seconds)
    # Ports scanned over TLS from the very first connection (Diameter/TLS, RFC 6733 §13).
    # The default 3869 is the IANA-standard port for Diameter/TLS.
    tls_ports: frozenset[int] = field(default_factory=lambda: frozenset({3869}))
    # Minimum time (seconds) between consecutive connections to the same host — 0 = no limit.
    # Useful for reducing impact on sensitive production elements during an authorized scan.
    min_delay_per_host: float = 0.0
