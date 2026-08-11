"""
transports/tcp.py
TCP connectivity check via asyncio.open_connection — doesn't use a
thread per connection, so it can handle thousands of concurrent ports
with very little memory.

Also supports optional TLS wrapping (Diameter/TLS, RFC 6733 §13,
usually port 3869) — with no external library, using the standard ssl
module. Certificate verification (CA trust) is deliberately disabled
here: the goal is "discovery/fingerprinting" (the same way standard
fingerprinting tools inspect TLS certificates), not establishing a
trusted connection — and most internal core-network elements already
use self-signed certificates anyway. Certificate info
(Subject/Issuer/validity) is returned purely for identification purposes.
"""

from __future__ import annotations

import asyncio
import ssl
import time

from portscanner.models import PortState
from portscanner.transports._x509_lite import parse_certificate_fields
from portscanner.transports.base import ConnectOutcome


def _make_insecure_tls_context() -> ssl.SSLContext:
    """
    A TLS context for discovery purposes: accepts any certificate (much
    like `openssl s_client -connect ... -no-verify` or a standard
    fingerprinting scanner). Not used to transfer sensitive data or
    establish trust — only to open the channel and read the displayed
    certificate's information.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _extract_cert_summary(ssl_object: ssl.SSLObject | None) -> dict | None:
    if ssl_object is None:
        return None
    # With CERT_NONE, the normal getpeercert() always returns {}
    # (deliberate behavior in the standard ssl library that prevents
    # unverified data from being treated as trusted). The workaround: we
    # parse the raw DER bytes ourselves (always available regardless of
    # verify_mode) — see transports/_x509_lite.py.
    der = ssl_object.getpeercert(binary_form=True)
    if not der:
        return None
    fields = parse_certificate_fields(der)
    if fields is None:
        return None

    return {
        "subject": fields["subject"],
        "issuer": fields["issuer"],
        "not_before": fields["not_before"],
        "not_after": fields["not_after"],
        "tls_version": ssl_object.version() or "",
        "cipher": (ssl_object.cipher() or (None,))[0] or "",
    }


class TCPConnection:
    __slots__ = ("_reader", "_writer", "tls_certificate", "target_host", "target_port")

    def __init__(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
        tls_certificate: dict | None = None,
        target_host: str = "", target_port: int = 0,
    ):
        self._reader = reader
        self._writer = writer
        # duck-typed: protocols like diameter.py/sip.py optionally check
        # these fields (via getattr) if present, without breaking the
        # standard Connection interface. target_host/target_port let a
        # detector build a protocol message referencing the actual
        # scanned target (e.g. SIP's Request-URI/Via) instead of a
        # hardcoded placeholder.
        self.tls_certificate = tls_certificate
        self.target_host = target_host
        self.target_port = target_port

    async def send(self, data: bytes) -> None:
        self._writer.write(data)
        await self._writer.drain()

    async def recv(self, max_bytes: int = 4096) -> bytes:
        return await self._reader.read(max_bytes)

    async def close(self) -> None:
        self._writer.close()
        try:
            await self._writer.wait_closed()
        except Exception:
            pass  # the connection may already have dropped — not an error worth stopping the scan for


async def connect(host: str, port: int, timeout: float, use_tls: bool = False) -> ConnectOutcome:
    start = time.monotonic()
    ssl_context = _make_insecure_tls_context() if use_tls else None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ssl_context), timeout=timeout
        )
        latency = (time.monotonic() - start) * 1000
        cert_summary = None
        if use_tls:
            cert_summary = _extract_cert_summary(writer.get_extra_info("ssl_object"))
        return ConnectOutcome(
            state=PortState.OPEN,
            latency_ms=latency,
            connection=TCPConnection(reader, writer, tls_certificate=cert_summary,
                                      target_host=host, target_port=port),
        )
    except asyncio.TimeoutError:
        return ConnectOutcome(state=PortState.FILTERED, error="timeout")
    except ConnectionRefusedError:
        return ConnectOutcome(state=PortState.CLOSED)
    except ssl.SSLError as e:
        # the port really is open (TCP connected) but doesn't speak
        # valid TLS — we treat this as a clear ERROR instead of
        # classifying it CLOSED (which implies an explicit TCP refusal).
        return ConnectOutcome(state=PortState.ERROR, error=f"TLS handshake failed: {e}")
    except OSError as e:
        return ConnectOutcome(state=PortState.ERROR, error=str(e))
