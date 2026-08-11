import pytest

from portscanner.models import Transport
from portscanner.targets import build_targets, expand_hosts, parse_ports


def test_parse_ports_single_and_range():
    assert parse_ports("80") == [80]
    assert parse_ports("1-5") == [1, 2, 3, 4, 5]


def test_parse_ports_mixed_and_dedup():
    assert parse_ports("22,80,80,100-102") == [22, 80, 100, 101, 102]


def test_parse_ports_invalid_range_raises():
    with pytest.raises(ValueError):
        parse_ports("100-1")  # start > end


def test_parse_ports_out_of_bounds_raises():
    with pytest.raises(ValueError):
        parse_ports("70000")


def test_build_targets_cartesian_product():
    targets = build_targets(["a", "b"], [80, 443], [Transport.TCP])
    assert len(targets) == 4
    assert {(t.host, t.port) for t in targets} == {
        ("a", 80), ("a", 443), ("b", 80), ("b", 443)
    }


# ---------------------------------------------------------------------------
# expand_hosts: CIDR / IP ranges / single addresses
# ---------------------------------------------------------------------------

def test_expand_hosts_plain_entries_passthrough():
    assert expand_hosts(["10.0.0.5", "hss01.example.com"]) == ["10.0.0.5", "hss01.example.com"]


def test_expand_hosts_cidr_small_network():
    # /30 has 4 addresses, 2 of them usable (host addresses)
    hosts = expand_hosts(["10.0.0.0/30"])
    assert hosts == ["10.0.0.1", "10.0.0.2"]


def test_expand_hosts_cidr_single_host_slash32():
    hosts = expand_hosts(["10.0.0.5/32"])
    assert hosts == ["10.0.0.5"]


def test_expand_hosts_ip_range():
    hosts = expand_hosts(["10.0.0.1-10.0.0.4"])
    assert hosts == ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]


def test_expand_hosts_dedup_preserves_order():
    hosts = expand_hosts(["10.0.0.1", "10.0.0.1", "10.0.0.2"])
    assert hosts == ["10.0.0.1", "10.0.0.2"]


def test_expand_hosts_mixed_specs():
    hosts = expand_hosts(["10.0.0.0/30", "hss01.example.com", "10.0.1.1-10.0.1.2"])
    assert hosts == ["10.0.0.1", "10.0.0.2", "hss01.example.com", "10.0.1.1", "10.0.1.2"]


def test_expand_hosts_respects_max_hosts():
    with pytest.raises(ValueError):
        expand_hosts(["10.0.0.0/24"], max_hosts=10)  # /24 = 254 usable addresses


def test_expand_hosts_domain_with_hyphen_not_treated_as_range():
    # a domain with an ordinary hyphen shouldn't be misinterpreted as an IP range
    hosts = expand_hosts(["my-host.example.com"])
    assert hosts == ["my-host.example.com"]
