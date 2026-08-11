"""
tests/test_discovery.py
Tests for the DNS discovery logic — with a full mock of the dnspython
interface (injected into sys.modules) so we can verify the tracing
logic (NAPTR -> SRV -> Target) is correct without a real network or
needing dnspython installed in this environment at all.
"""

import sys
import types

import pytest

from portscanner.models import Transport


# ---------------------------------------------------------------------------
# a full mock of the dnspython interface used (dns.asyncresolver + dns.resolver)
# ---------------------------------------------------------------------------

class _FakeNoAnswer(Exception):
    pass


class _FakeNXDOMAIN(Exception):
    pass


class _FakeNaptrRdata:
    def __init__(self, service: str, flags: str, replacement: str):
        self.service = service
        self.flags = flags
        self.replacement = replacement + "."

    def __str__(self):
        return self.replacement


class _FakeSrvRdata:
    def __init__(self, target: str, port: int, priority: int = 10, weight: int = 50):
        self.target = target + "."
        self.port = port
        self.priority = priority
        self.weight = weight

    def __str__(self):
        return self.target


class _FakeResolver:
    """Returns pre-configured replies from a dict instead of an actual DNS query."""

    def __init__(self, naptr_records: dict, srv_records: dict):
        self._naptr = naptr_records
        self._srv = srv_records

    async def resolve(self, name: str, rtype: str):
        name = name.rstrip(".")
        if rtype == "NAPTR":
            if name not in self._naptr:
                raise _FakeNXDOMAIN(name)
            records = self._naptr[name]
            if not records:
                raise _FakeNoAnswer(name)
            return records
        if rtype == "SRV":
            if name not in self._srv:
                raise _FakeNXDOMAIN(name)
            records = self._srv[name]
            if not records:
                raise _FakeNoAnswer(name)
            return records
        raise ValueError(f"record type not supported by the mock: {rtype}")


def _install_fake_dnspython(naptr_records: dict, srv_records: dict):
    """Injects mock dns/dns.resolver/dns.asyncresolver modules into
    sys.modules, so `import dns.asyncresolver` inside discovery.py
    finds them instead of trying to import the real library (not
    installed in this environment at all)."""
    dns_module = types.ModuleType("dns")
    resolver_module = types.ModuleType("dns.resolver")
    asyncresolver_module = types.ModuleType("dns.asyncresolver")

    resolver_module.NXDOMAIN = _FakeNXDOMAIN
    resolver_module.NoAnswer = _FakeNoAnswer
    asyncresolver_module.Resolver = lambda: _FakeResolver(naptr_records, srv_records)

    dns_module.resolver = resolver_module
    dns_module.asyncresolver = asyncresolver_module

    sys.modules["dns"] = dns_module
    sys.modules["dns.resolver"] = resolver_module
    sys.modules["dns.asyncresolver"] = asyncresolver_module


def _uninstall_fake_dnspython():
    for name in ("dns", "dns.resolver", "dns.asyncresolver"):
        sys.modules.pop(name, None)


# ---------------------------------------------------------------------------
# behavior when "dnspython is not installed"
# ---------------------------------------------------------------------------

def test_discovery_unavailable_without_dnspython():
    _uninstall_fake_dnspython()  # make sure no mock version is left over from a previous test
    from portscanner.discovery import DNSDiscoveryUnavailable, _require_dnspython

    with pytest.raises(DNSDiscoveryUnavailable):
        _require_dnspython()


# ---------------------------------------------------------------------------
# resolve_service_tags: converting alias/raw names
# ---------------------------------------------------------------------------

def test_resolve_service_tags_none_returns_all_known():
    from portscanner.discovery import KNOWN_NAPTR_SERVICES, resolve_service_tags
    tags = resolve_service_tags(None)
    assert len(tags) == len(KNOWN_NAPTR_SERVICES)


def test_resolve_service_tags_known_alias():
    from portscanner.discovery import resolve_service_tags
    assert resolve_service_tags(["generic-tcp"]) == ["AAA+D2T"]


def test_resolve_service_tags_raw_tag_passthrough():
    from portscanner.discovery import resolve_service_tags
    assert resolve_service_tags(["x-custom-tag"]) == ["x-custom-tag"]


# ---------------------------------------------------------------------------
# discover_naptr: full NAPTR -> SRV tracing (with a dnspython mock)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_discover_naptr_full_chain():
    naptr_records = {
        "epc.mnc001.mcc001.3gppnetwork.org": [
            _FakeNaptrRdata("AAA+D2T", "S", "_diameter._tcp.epc.mnc001.mcc001.3gppnetwork.org"),
        ],
    }
    srv_records = {
        "_diameter._tcp.epc.mnc001.mcc001.3gppnetwork.org": [
            _FakeSrvRdata("hss01.epc.mnc001.mcc001.3gppnetwork.org", 3868),
            _FakeSrvRdata("hss02.epc.mnc001.mcc001.3gppnetwork.org", 3868, priority=20),
        ],
    }
    _install_fake_dnspython(naptr_records, srv_records)
    try:
        from portscanner.discovery import discover_naptr
        elements = await discover_naptr("epc.mnc001.mcc001.3gppnetwork.org", ["AAA+D2T"])
    finally:
        _uninstall_fake_dnspython()

    assert len(elements) == 2
    hosts = {el.hostname for el in elements}
    assert hosts == {"hss01.epc.mnc001.mcc001.3gppnetwork.org", "hss02.epc.mnc001.mcc001.3gppnetwork.org"}
    assert all(el.port == 3868 for el in elements)
    assert all(el.naptr_service == "AAA+D2T" for el in elements)


@pytest.mark.asyncio
async def test_discover_naptr_filters_unmatched_service_tags():
    naptr_records = {
        "example.org": [
            _FakeNaptrRdata("AAA+D2T", "S", "_diameter._tcp.example.org"),
            _FakeNaptrRdata("x-something-else", "S", "_other._tcp.example.org"),
        ],
    }
    srv_records = {
        "_diameter._tcp.example.org": [_FakeSrvRdata("host1.example.org", 3868)],
    }
    _install_fake_dnspython(naptr_records, srv_records)
    try:
        from portscanner.discovery import discover_naptr
        elements = await discover_naptr("example.org", ["AAA+D2T"])  # only the requested type
    finally:
        _uninstall_fake_dnspython()

    assert len(elements) == 1
    assert elements[0].naptr_service == "AAA+D2T"


@pytest.mark.asyncio
async def test_discover_naptr_missing_realm_returns_empty():
    _install_fake_dnspython(naptr_records={}, srv_records={})
    try:
        from portscanner.discovery import discover_naptr
        elements = await discover_naptr("does-not-exist.example.org")
    finally:
        _uninstall_fake_dnspython()

    assert elements == []


@pytest.mark.asyncio
async def test_discover_naptr_missing_srv_skips_gracefully():
    naptr_records = {
        "example.org": [_FakeNaptrRdata("AAA+D2T", "S", "_diameter._tcp.example.org")],
    }
    _install_fake_dnspython(naptr_records, srv_records={})  # SRV deliberately missing
    try:
        from portscanner.discovery import discover_naptr
        elements = await discover_naptr("example.org", ["AAA+D2T"])
    finally:
        _uninstall_fake_dnspython()

    assert elements == []  # doesn't crash, just skips the missing element


# ---------------------------------------------------------------------------
# elements_to_targets: final conversion into Target objects
# ---------------------------------------------------------------------------

def test_elements_to_targets_maps_transport_from_service_tag():
    from portscanner.discovery import DiscoveredElement, elements_to_targets

    elements = [
        DiscoveredElement(naptr_service="AAA+D2T", hostname="a.example.org", port=3868, priority=10, weight=50),
        DiscoveredElement(naptr_service="AAA+D2S", hostname="b.example.org", port=3868, priority=10, weight=50),
        DiscoveredElement(naptr_service="x-3gpp-mme:x-s6a", hostname="c.example.org", port=3868, priority=10, weight=50),
    ]
    targets = elements_to_targets(elements)

    by_host = {t.host: t for t in targets}
    assert by_host["a.example.org"].transport is Transport.TCP
    assert by_host["b.example.org"].transport is Transport.SCTP
    assert by_host["c.example.org"].transport is Transport.SCTP  # s6a-mme is known in the table


def test_elements_to_targets_unknown_tag_defaults_to_tcp():
    from portscanner.discovery import DiscoveredElement, elements_to_targets

    elements = [DiscoveredElement(naptr_service="x-totally-unknown", hostname="x.example.org",
                                   port=1234, priority=10, weight=50)]
    targets = elements_to_targets(elements)
    assert targets[0].transport is Transport.TCP
