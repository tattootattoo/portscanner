"""
tests/test_e2e_discovery_pipeline.py
A real end-to-end test of the full combination: DNS discovery (with a
full mock of dnspython) -> automatic target construction -> the real
two-phase scan engine -> Diameter confirmation over a real TCP server
-> NDJSON output — all of it through the actual `cli.main()` (the same
function that runs when you type `portscanner` in a terminal), not
isolated internal functions.

Design note: `cli.main()` uses `asyncio.run()` internally, so it can't
be called from inside an async test function (an event-loop conflict).
That's why the mock Diameter server here is a plain (blocking) socket
on a separate thread, instead of asyncio.start_server — the client
side (cli.main itself) is already asyncio-based and doesn't care what
kind of server it's talking to.
"""

import io
import json
import socket
import struct
import sys
import threading
import time
import types
from contextlib import redirect_stdout

from portscanner.cli import main as cli_main


class _FakeNXDOMAIN(Exception):
    pass


class _FakeNoAnswer(Exception):
    pass


class _NaptrRdata:
    def __init__(self, service, flags, replacement):
        self.service = service
        self.flags = flags
        self.replacement = replacement + "."

    def __str__(self):
        return self.replacement


class _SrvRdata:
    def __init__(self, target, port, priority=10, weight=50):
        self.target = target + "."
        self.port = port
        self.priority = priority
        self.weight = weight

    def __str__(self):
        return self.target


class _FakeResolver:
    async def resolve(self, name, rtype):
        name = name.rstrip(".")
        if rtype == "NAPTR" and name == "epc.mnc001.mcc001.3gppnetwork.org":
            return [_NaptrRdata("AAA+D2T", "S", "_diameter._tcp.epc.mnc001.mcc001.3gppnetwork.org")]
        if rtype == "SRV" and name == "_diameter._tcp.epc.mnc001.mcc001.3gppnetwork.org":
            return [_SrvRdata("127.0.0.1", 33868)]
        raise _FakeNXDOMAIN(name)


def _install_fake_dnspython():
    dns_module = types.ModuleType("dns")
    resolver_module = types.ModuleType("dns.resolver")
    asyncresolver_module = types.ModuleType("dns.asyncresolver")
    resolver_module.NXDOMAIN = _FakeNXDOMAIN
    resolver_module.NoAnswer = _FakeNoAnswer
    asyncresolver_module.Resolver = lambda: _FakeResolver()
    dns_module.resolver = resolver_module
    dns_module.asyncresolver = asyncresolver_module
    sys.modules["dns"] = dns_module
    sys.modules["dns.resolver"] = resolver_module
    sys.modules["dns.asyncresolver"] = asyncresolver_module


def _uninstall_fake_dnspython():
    for name in ("dns", "dns.resolver", "dns.asyncresolver"):
        sys.modules.pop(name, None)


def _build_avp(code: int, data: bytes) -> bytes:
    length = 8 + len(data)
    out = struct.pack("!I", code) + struct.pack("!B", 0x40) + length.to_bytes(3, "big") + data
    return out + b"\x00" * ((4 - length % 4) % 4)


def _build_cea() -> bytes:
    avps = _build_avp(269, b"PipelineTestHSS")
    body = struct.pack("!III", 0, 1, 1) + avps
    length = 8 + len(body)
    return struct.pack("!B", 1) + length.to_bytes(3, "big") + struct.pack("!B", 0x00) + (257).to_bytes(3, "big") + body


def _run_blocking_diameter_server(port: int, response: bytes, stop_event: threading.Event) -> None:
    """A mock Diameter server — a plain blocking socket on a separate
    thread, to avoid an event-loop conflict with the asyncio.run()
    inside cli.main()."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(5)
    srv.settimeout(0.3)
    while not stop_event.is_set():
        try:
            conn, _addr = srv.accept()
        except socket.timeout:
            continue
        try:
            conn.recv(500)
            conn.sendall(response)
        except OSError:
            pass
        finally:
            conn.close()
    srv.close()


def test_full_pipeline_discover_realm_to_ndjson_via_real_cli_main():
    stop_event = threading.Event()
    server_thread = threading.Thread(
        target=_run_blocking_diameter_server, args=(33868, _build_cea(), stop_event), daemon=True,
    )
    server_thread.start()
    time.sleep(0.2)  # a brief delay to make sure the server has actually started listening

    _install_fake_dnspython()
    stdout_capture = io.StringIO()
    try:
        with redirect_stdout(stdout_capture):
            exit_code = cli_main([
                "--discover-realm", "epc.mnc001.mcc001.3gppnetwork.org",
                "--output", "ndjson", "--no-progress",
            ])
    finally:
        _uninstall_fake_dnspython()
        stop_event.set()
        server_thread.join(timeout=2)

    assert exit_code == 0

    lines = [line for line in stdout_capture.getvalue().split("\n") if line.strip()]
    parsed = [json.loads(line) for line in lines]

    types_seen = [p["type"] for p in parsed]
    assert types_seen[0] == "metadata"
    assert types_seen[-1] == "summary"

    result_lines = [p for p in parsed if p["type"] == "result"]
    assert len(result_lines) == 1
    assert result_lines[0]["host"] == "127.0.0.1"
    assert result_lines[0]["port"] == 33868
    assert result_lines[0]["protocol"] == "Diameter"
    assert "PipelineTestHSS" in result_lines[0]["detail"]

    summary = next(p for p in parsed if p["type"] == "summary")
    assert summary["open"] == 1
    assert summary["confirmed"] == 1


def test_full_pipeline_discover_realm_no_dnspython_fails_cleanly():
    """Without dnspython, the tool must return exit code 2 with a clear message, not a traceback."""
    _uninstall_fake_dnspython()  # make sure no mock version is left over from a previous test

    exit_code = cli_main(["--discover-realm", "some.realm.example.org", "--no-progress"])
    assert exit_code == 2
