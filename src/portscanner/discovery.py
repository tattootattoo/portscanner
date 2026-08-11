"""
discovery.py
Automatic discovery of Diameter elements via DNS — the same official
mechanism real telecom-network elements use to find each other (3GPP TS
29.303, built on the general S-NAPTR framework for Diameter from RFC
6733 §5.2). Instead of specifying an IP manually, you give a realm name
(like "epc.mnc001.mcc001.3gppnetwork.org") and it:

    1) queries NAPTR for the realm, and filters the replies by "service
       tag" (e.g. "AAA+D2T" for generic Diameter over TCP, or
       "x-3gpp-mme:x-s6a" for the S6a interface specifically, per 3GPP).
    2) for each match, queries SRV on the "replacement" field to get the
       actual hostname + port.

This is an entirely ordinary DNS query (the same kind any network
tool/element would make) — not a hack or a way around any protection —
just aimed specifically at Diameter-protocol discovery.

Warning: needs dnspython (an optional dependency, not part of the base
install):
    pip install portscanner[dns]
This is deliberate so the core tool stays free of any mandatory external
dependency — DNS discovery is purely an optional extra feature.

Warning: the service-tag table below is best-effort per 3GPP TS 29.303
Table 5.2.1 — it doesn't cover every combination possible in the
standard. If you need an interface that isn't listed here, use
--naptr-service to specify the tag manually.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from portscanner.models import Target, Transport

logger = logging.getLogger("portscanner.discovery")

# easy alias -> (NAPTR service tag, expected transport type)
KNOWN_NAPTR_SERVICES: dict[str, tuple[str, Transport]] = {
    # the generic base for any Diameter element (RFC 6733 §5.2)
    "generic-tcp": ("AAA+D2T", Transport.TCP),
    "generic-sctp": ("AAA+D2S", Transport.SCTP),
    # specific 3GPP interfaces (best-effort — see TS 29.303 for the full exact values)
    "s6a-mme": ("x-3gpp-mme:x-s6a", Transport.SCTP),
    "s6a-hss": ("x-3gpp-hss:x-s6a", Transport.SCTP),
    "gx-pgw": ("x-3gpp-pgw:x-gx", Transport.TCP),
    "gx-pcrf": ("x-3gpp-pcrf:x-gx", Transport.TCP),
}

_TAG_TO_TRANSPORT: dict[str, Transport] = {
    tag: transport for tag, transport in KNOWN_NAPTR_SERVICES.values()
}


@dataclass(slots=True)
class DiscoveredElement:
    naptr_service: str
    hostname: str
    port: int
    priority: int
    weight: int


class DNSDiscoveryUnavailable(RuntimeError):
    """dnspython isn't installed — see the module docstring."""


def _require_dnspython() -> None:
    try:
        import dns.asyncresolver  # noqa: F401
        import dns.resolver  # noqa: F401
    except ImportError as e:
        raise DNSDiscoveryUnavailable(
            "DNS discovery requires dnspython (an optional dependency, not "
            "part of the base install): pip install portscanner[dns]"
        ) from e


def resolve_service_tags(names: list[str] | None) -> list[str]:
    """Converts aliases ('s6a-mme') or raw tags ('AAA+D2T') into a list
    of actual NAPTR tags ready to query. If None, returns every known tag."""
    if names is None:
        return [tag for tag, _t in KNOWN_NAPTR_SERVICES.values()]
    tags = []
    for name in names:
        if name in KNOWN_NAPTR_SERVICES:
            tags.append(KNOWN_NAPTR_SERVICES[name][0])
        else:
            tags.append(name)  # a raw tag passed directly (not in the table)
    return tags


async def discover_naptr(realm: str, service_tags: list[str] | None = None) -> list[DiscoveredElement]:
    """
    Returns every discovered element for a given realm, filtered by
    service_tags (or every known tag if None). Doesn't raise if the
    realm doesn't exist or there are no results — returns an empty list
    and logs a warning, so a single failed discovery doesn't stop the
    whole tool.
    """
    _require_dnspython()
    import dns.asyncresolver
    import dns.exception
    import dns.resolver

    tags = set(service_tags or [tag for tag, _t in KNOWN_NAPTR_SERVICES.values()])
    resolver = dns.asyncresolver.Resolver()
    elements: list[DiscoveredElement] = []

    try:
        naptr_answer = await resolver.resolve(realm, "NAPTR")
    except dns.resolver.NXDOMAIN:
        logger.warning("realm '%s' does not exist in DNS", realm)
        return []
    except dns.resolver.NoAnswer:
        logger.info("no NAPTR records for '%s'", realm)
        return []
    except dns.resolver.NoNameservers:
        logger.warning("no reachable/responsive DNS server for '%s' "
                        "(SERVFAIL or all nameservers refused/unreachable)", realm)
        return []
    except dns.exception.Timeout:
        logger.warning("DNS query for '%s' timed out", realm)
        return []
    except dns.exception.DNSException as e:
        # Catch-all for any other dnspython failure mode (malformed
        # response, etc.) so a DNS-layer problem never crashes the CLI
        # with a raw traceback — discovery failing is reported and
        # skipped, same as the specific cases above.
        logger.warning("DNS query for '%s' failed: %s", realm, e)
        return []

    for rdata in naptr_answer:
        service = rdata.service.decode() if isinstance(rdata.service, bytes) else str(rdata.service)
        if service not in tags:
            continue

        flags = rdata.flags.decode() if isinstance(rdata.flags, bytes) else str(rdata.flags)
        if flags.upper() != "S":
            # we only care about "S" replies (which redirect to an SRV
            # query) — the standard case for Diameter per RFC 6733/3958.
            # Other types (A/U) aren't supported yet.
            continue

        replacement = str(rdata.replacement).rstrip(".")
        try:
            srv_answer = await resolver.resolve(replacement, "SRV")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            logger.info("no SRV records for '%s' (from NAPTR service=%s)", replacement, service)
            continue
        except (dns.resolver.NoNameservers, dns.exception.Timeout) as e:
            logger.warning("DNS lookup for SRV '%s' failed: %s", replacement, e)
            continue
        except dns.exception.DNSException as e:
            logger.warning("DNS lookup for SRV '%s' failed: %s", replacement, e)
            continue

        for srv in srv_answer:
            elements.append(DiscoveredElement(
                naptr_service=service,
                hostname=str(srv.target).rstrip("."),
                port=int(srv.port),
                priority=int(srv.priority),
                weight=int(srv.weight),
            ))

    return elements


def elements_to_targets(elements: list[DiscoveredElement]) -> list[Target]:
    """
    Converts discovery results into Target objects ready to scan
    directly with the normal scan engine (engine.py) — with no special
    handling, discovery is just an alternative way to build the target
    list. Transport (TCP/SCTP) is determined by the service tag each
    element came from; an unknown tag defaults to TCP as a safe fallback.
    """
    return [
        Target(
            host=el.hostname, port=el.port,
            transport=_TAG_TO_TRANSPORT.get(el.naptr_service, Transport.TCP),
        )
        for el in elements
    ]
