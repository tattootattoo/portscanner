"""
protocols/_io.py
A shared helper: TCP doesn't guarantee a full message arrives in a
single recv() (a message can be split across more than one packet,
especially with lots of AVPs). This file reads until the full message
has arrived per the length declared in its header, instead of assuming
the first recv() is enough — an assumption that could silently fail on
real networks with fragmentation or congestion.
"""

from __future__ import annotations

import asyncio

from portscanner.transports.base import Connection


async def read_message(
    connection: Connection,
    timeout: float,
    length_from_header: "callable",
    min_header_size: int = 8,
    max_message_size: int = 65536,
) -> bytes:
    """
    Reads a full message via a repeated recv() loop, relying on the
    length_from_header(header_bytes) -> int|None function to return the
    declared total length as soon as the first min_header_size bytes
    arrive (or None if there still isn't enough data to read the length).

    Stops early if:
      - the overall timeout expires (asyncio.TimeoutError is raised).
      - the connection closes before the message is complete (returns
        whatever actually arrived).
      - the declared length is unreasonable (larger than
        max_message_size) — a guard against corrupted/malicious
        messages trying to make the scanner wait or allocate excessive memory.
    """
    buf = bytearray()
    declared_length: int | None = None

    async def _step() -> bool:
        nonlocal declared_length
        chunk = await connection.recv(4096)
        if not chunk:
            return False  # the connection closed
        buf.extend(chunk)
        if declared_length is None and len(buf) >= min_header_size:
            declared_length = length_from_header(bytes(buf[:min_header_size]))
            if declared_length is not None and declared_length > max_message_size:
                raise ValueError(
                    f"unreasonable declared message length ({declared_length} bytes) — rejected"
                )
        return True

    async def _loop() -> None:
        while True:
            if declared_length is not None and len(buf) >= declared_length:
                return
            if not await _step():
                return

    await asyncio.wait_for(_loop(), timeout=timeout)
    return bytes(buf)
