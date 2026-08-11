"""
protocols/base.py
A Registry pattern: every protocol registers itself via the @register
decorator, and the engine (engine.py) asks "which detectors are
candidates for this port/transport?" without knowing the details of any
specific protocol. Adding a new protocol = just a new file.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Awaitable, Callable

from portscanner.models import Transport
from portscanner.transports.base import Connection


@dataclass(frozen=True, slots=True)
class DetectionResult:
    """
    The result of a successful detection: details + confidence level.
      - "confirmed": a full, successful reply per the standard (a
        successful CEA, an ASP-UP-ACK).
      - "likely": an explicit reply in the same protocol but not the
        expected success case (e.g. Diameter rejected the connection
        with an error Result-Code, or returned a DPR instead of a CEA)
        — still strong evidence it's the same protocol, just not 100% certain.
    """
    detail: str
    confidence: str = "confirmed"


# The detection function: takes a live connection + a timeout, and
# returns a DetectionResult if a match was confirmed (at any confidence
# level), or None if there was no match at all.
DetectFn = Callable[[Connection, float], Awaitable[DetectionResult | None]]


@dataclass(frozen=True, slots=True)
class ProtocolDetector:
    name: str
    transports: tuple[Transport, ...]
    hint_ports: tuple[int, ...] = field(default_factory=tuple)
    detect: DetectFn = field(compare=False, default=None)  # type: ignore[assignment]
    source: str = "builtin"  # "builtin" or the external plugin module's name


_REGISTRY: list[ProtocolDetector] = []
_BUILTIN_MODULE_PREFIX = "portscanner.protocols."


def register(name: str, transports: tuple[Transport, ...], hint_ports: tuple[int, ...] = ()):
    """
    Decorator: registers the detection function as a new protocol
    detector. The source (builtin or an external package's name) is
    determined automatically from the function's own module — no need
    to pass it explicitly; registering from the core code vs. an
    external plugin differs only in the module name.
    """

    def decorator(func: DetectFn) -> DetectFn:
        module = getattr(func, "__module__", "") or ""
        source = "builtin" if module.startswith(_BUILTIN_MODULE_PREFIX) else module
        _REGISTRY.append(
            ProtocolDetector(
                name=name, transports=transports, hint_ports=hint_ports,
                detect=func, source=source,
            )
        )
        return func

    return decorator


def all_detectors() -> list[ProtocolDetector]:
    """Every registered detector regardless of transport/port — used for --list-protocols."""
    return list(_REGISTRY)


def detectors_for(transport: Transport, port: int) -> list[ProtocolDetector]:
    """
    Returns the detectors matching the transport type, in priority
    order: the detector matching the expected port number (hint_ports)
    is tried first (usually faster and more accurate), and the rest
    follow as a fallback — every detector here is a telecom signaling
    protocol (Diameter and the SIGTRAN family), there are no
    generic/negative detectors.
    """
    applicable = [d for d in _REGISTRY if transport in d.transports]
    applicable.sort(key=lambda d: 0 if port in d.hint_ports else 1)
    return applicable


# An unreliable initial guess based only on the port number (the
# standard IANA ports for the SIGTRAN family and Diameter) — used for
# display only, before actual confirmation via scanning
KNOWN_PORT_HINTS: dict[int, str] = {
    2123: "GTP-C (GTPv1/GTPv2)",
    2152: "GTP-U (all generations)",
    2904: "M2UA (SIGTRAN)",
    2905: "M3UA (SIGTRAN)",
    3097: "M2PA (SIGTRAN)",
    3868: "Diameter",
    3869: "Diameter/TLS",
    5060: "SIP/IMS",
    5061: "SIP/IMS-TLS",
    5675: "V5UA (SIGTRAN)",
    9900: "IUA (SIGTRAN)",
    14001: "SUA (SIGTRAN)",
}


def port_hint(port: int) -> str:
    return KNOWN_PORT_HINTS.get(port, "")
