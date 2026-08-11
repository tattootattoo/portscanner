"""
targets.py
Converts user input (text/files) into a list of Target objects ready to
scan. The parsing logic is isolated here so it's testable without any
network.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path

from portscanner.models import Target, Transport

# a default safety limit: prevents accidentally expanding a large CIDR
# (like a /8) into thousands/millions of addresses. Adjustable via
# --max-hosts on the CLI.
DEFAULT_MAX_HOSTS = 4096


def parse_ports(spec: str) -> list[int]:
    """
    Converts '80,443' or '1-1024' or '22,80,1000-2000' into a sorted,
    deduplicated list of port numbers. Raises ValueError with a clear
    message on an invalid format.
    """
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, _, end_s = part.partition("-")
            start, end = int(start_s), int(end_s)
            if not (0 <= start <= end <= 65535):
                raise ValueError(f"invalid port range: {part}")
            ports.update(range(start, end + 1))
        else:
            port = int(part)
            if not (0 <= port <= 65535):
                raise ValueError(f"invalid port number: {part}")
            ports.add(port)
    return sorted(ports)


def _expand_ip_range(spec: str) -> list[str]:
    """'10.0.0.1-10.0.0.20' -> a list of IPv4 addresses within the range (inclusive of both ends)."""
    start_s, _, end_s = spec.partition("-")
    start = ipaddress.ip_address(start_s.strip())
    end = ipaddress.ip_address(end_s.strip())
    if start.version != end.version:
        raise ValueError(f"mixed address family in range (IPv4/IPv6): {spec}")
    if int(end) < int(start):
        raise ValueError(f"invalid address range (end before start): {spec}")
    return [str(ipaddress.ip_address(i)) for i in range(int(start), int(end) + 1)]


def expand_hosts(specs: list[str], max_hosts: int = DEFAULT_MAX_HOSTS) -> list[str]:
    """
    Expands each entry in the address list according to its form:
      - CIDR:          '10.0.0.0/28'        -> every address in the network (excluding network/broadcast unless /31 or larger)
      - IP range:       '10.0.0.1-10.0.0.20' -> every address in the range, inclusive of both ends
      - single address/domain: 'hss01.example.com' or '10.0.0.5' -> added as-is

    Raises ValueError if the total output exceeds max_hosts (a guard
    against unintentionally scanning a huge network), and preserves
    order of appearance without duplicates.
    """
    expanded: list[str] = []
    seen: set[str] = set()

    def _add(host: str) -> None:
        if host not in seen:
            seen.add(host)
            expanded.append(host)

    for raw in specs:
        spec = raw.strip()
        if not spec:
            continue
        if "/" in spec:
            network = ipaddress.ip_network(spec, strict=False)
            hosts_iter = network.hosts() if network.num_addresses > 2 else [network.network_address]
            for addr in hosts_iter:
                _add(str(addr))
                if len(expanded) > max_hosts:
                    raise ValueError(
                        f"the number of addresses after expansion exceeded the maximum ({max_hosts}). "
                        f"Use --max-hosts to raise the limit, or narrow the '{spec}' range."
                    )
        elif "-" in spec and all(part.count(".") == 3 for part in spec.split("-", 1)):
            # distinguish an IP range ('a.b.c.d-a.b.c.d') from a domain name that just happens to contain a dash
            for addr in _expand_ip_range(spec):
                _add(addr)
                if len(expanded) > max_hosts:
                    raise ValueError(
                        f"the number of addresses after expansion exceeded the maximum ({max_hosts}). "
                        f"Use --max-hosts to raise the limit, or narrow the '{spec}' range."
                    )
        else:
            _add(spec)

    return expanded


def load_lines(path: str | Path) -> list[str]:
    """Reads a text file line by line, ignoring blank lines and comments (#)."""
    result = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                result.append(line)
    return result


def build_targets(
    hosts: list[str], ports: list[int], transports: list[Transport]
) -> list[Target]:
    """The cartesian product of the requested hosts / ports / transport types."""
    return [
        Target(host=h, port=p, transport=t)
        for h in hosts
        for p in ports
        for t in transports
    ]
