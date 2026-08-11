"""
cli.py
Command-line interface: wires together all layers (targets -> engine ->
reporting) into one clear pipeline, with no networking logic of its own —
just orchestration. Supports:
  - single addresses / CIDR / ranges + address files
  - **two-phase scan (default)**: fast port-state discovery (short
    timeout + high concurrency) across all targets, followed by deep
    protocol confirmation (longer timeout for accuracy) only on the
    open ones — cuts scan time drastically on large ranges instead of
    forcing the same timeout on every target.
  - a live progress bar for each phase separately
  - automatic retry for ambiguous states (filtered/error)
  - clean Ctrl+C shutdown that still shows partial results instead of
    losing them
  - ready-made scan profiles via a TOML file (--profile)
  - --check-env: diagnose the runtime environment before scanning
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
import time
import tomllib
from datetime import datetime, timezone

from portscanner import __version__, engine
from portscanner.engine import iter_scan
from portscanner.models import PortState, ScanConfig, ScanMetadata, ScanResult, Target, Transport
from portscanner.reporting import (
    metadata_to_ndjson_line,
    print_table,
    protocol_breakdown,
    result_to_ndjson_line,
    summary_line,
    summary_to_ndjson_line,
    to_json,
    write_csv,
    write_json,
)
from portscanner.targets import DEFAULT_MAX_HOSTS, build_targets, expand_hosts, load_lines, parse_ports
from portscanner.transports import sctp as sctp_transport

# The "real" default for every option that can be customized via a TOML
# profile. argparse itself uses argparse.SUPPRESS for these options (see
# build_parser) so we can distinguish "the user didn't set a value" from
# "the user set the same value as the default" — the difference matters
# for precedence order: CLI > profile > here.
BUILTIN_DEFAULTS: dict[str, object] = {
    "ports": "2123,2152,2904,2905,3097,3868,3869,5060,5061,5675,9900,14001",
    "transport": "all",
    "tls_ports": "3869,5061",
    "connect_timeout": 2.0,
    "probe_timeout": 2.0,
    "concurrency": 500,
    "sctp_pool_size": 20,
    "retries": 0,
    "retry_delay": 0.3,
    "min_delay_per_host": 0.0,
    "max_hosts": DEFAULT_MAX_HOSTS,
    "output": "table",
    # Settings for the fast-discovery phase (phase 1 of the two-phase scan)
    "fast_timeout": 0.75,
    "fast_concurrency": 1000,     # used only with --no-adaptive (fixed concurrency)
    # Self-adapting concurrency (AIMD) for the discovery phase — on by default
    "adaptive_min_concurrency": 25,
    "adaptive_max_concurrency": 1500,
    "workers": 1,
}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="portscanner",
        description="A scanner specialized in telecom signaling protocols across "
                    "every generation (2G-5G): Diameter, the full SIGTRAN family "
                    "(M3UA/SUA/M2UA/M2PA/IUA/V5UA), GTP-C/GTP-U, and SIP/IMS — "
                    "confirmed through a real protocol exchange, not guessed "
                    "from the port number. Two-phase scan by default (fast "
                    "discovery, then deep confirmation) for higher speed on "
                    "large ranges.",
    )
    p.add_argument("--profile", help="TOML file with a ready-made scan configuration "
                                     "(see profiles/example.toml) — explicit CLI flags override it")
    p.add_argument("--check-env", action="store_true",
                    help="show runtime environment diagnostics (SCTP/TLS support, permissions) and exit")
    p.add_argument("--list-protocols", action="store_true",
                    help="list every registered detector (built-in + external plugins) and exit")
    p.add_argument("--self-test", action="store_true",
                    help="run a self-check (local mock servers for every protocol where possible) "
                         "to verify the tool works correctly in this environment before any real scan, then exit")
    p.add_argument("-V", "--version", action="version",
                    version=f"portscanner {__version__}")

    target_group = p.add_mutually_exclusive_group()
    target_group.add_argument(
        "--host", default=argparse.SUPPRESS,
        help="target(s) (comma-separated for more than one): a single IP, domain, "
             "CIDR ('10.0.0.0/28'), or range ('10.0.0.1-10.0.0.20') — "
             "example: '10.0.0.5,10.0.0.0/28,hss.example.com'",
    )
    target_group.add_argument(
        "--hosts-file", default=argparse.SUPPRESS,
        help="a file with one target per line — same formats "
             "supported by --host (IP/domain/CIDR/range)",
    )
    target_group.add_argument(
        "--discover-realm", default=argparse.SUPPRESS,
        help="auto-discover Diameter elements via DNS (3GPP TS 29.303, "
             "NAPTR/SRV) instead of specifying an IP manually — example: "
             "'epc.mnc001.mcc001.3gppnetwork.org'. Requires "
             "pip install portscanner[dns]. --ports is ignored here "
             "(ports come from the SRV records themselves).",
    )
    p.add_argument("--naptr-service", default=argparse.SUPPRESS,
                    help="NAPTR service tags to look for (comma-separated), aliases "
                         "from KNOWN_NAPTR_SERVICES or raw tags — default: all "
                         "known tags. Example: 'generic-tcp,s6a-mme'")
    p.add_argument("--max-hosts", type=int, default=argparse.SUPPRESS,
                    help=f"maximum number of addresses after expanding CIDR/ranges "
                         f"(default {DEFAULT_MAX_HOSTS}) — guards against accidentally scanning a huge network")

    p.add_argument(
        "--ports", default=argparse.SUPPRESS,
        help="defaults to the standard IANA ports for signaling protocols "
             "(GTP-C/GTP-U/M2UA/M3UA/IUA/V5UA/Diameter/SIP/SUA); accepts '80,443', '1-1024', or a mix",
    )
    p.add_argument("--ports-file", default=argparse.SUPPRESS, help="a file with one port per line")

    p.add_argument("--transport", choices=["tcp", "udp", "sctp", "all"], default=argparse.SUPPRESS,
                    help="SIGTRAN (M3UA/SUA/M2UA/M2PA/IUA/V5UA) only runs over SCTP; "
                         "Diameter/SIP run over TCP; GTP-C/GTP-U over UDP. "
                         "Default: all. ⚠️ A UDP scan with no real protocol reply "
                         "comes back as an ambiguous state (filtered).")
    p.add_argument("--tls-ports", default=argparse.SUPPRESS,
                    help="TCP ports scanned over TLS from the first connection (Diameter/TLS, SIPS); "
                         "'' to disable TLS entirely")

    p.add_argument("--connect-timeout", type=float, default=argparse.SUPPRESS,
                    help="connection timeout for the deep-confirmation phase (default 2.0s)")
    p.add_argument("--probe-timeout", type=float, default=argparse.SUPPRESS,
                    help="timeout waiting for a protocol reply in the deep-confirmation phase (default 2.0s)")
    p.add_argument("--concurrency", type=int, default=argparse.SUPPRESS,
                    help="max concurrency for the deep-confirmation phase (default 500)")
    p.add_argument("--sctp-pool-size", type=int, default=argparse.SUPPRESS,
                    help="deprecated, no longer used: SCTP now uses native async I/O "
                         "(the same --concurrency limit as TCP/UDP) instead of a thread pool. "
                         "Kept only so old commands/profiles don't break.")
    p.add_argument("--no-identify", action="store_true", default=argparse.SUPPRESS,
                    help="only check port state, without protocol confirmation (automatically disables the two-phase scan)")
    p.add_argument("--retries", type=int, default=argparse.SUPPRESS,
                    help="automatic retry for filtered/error states in the deep-confirmation phase (default 0)")
    p.add_argument("--retry-delay", type=float, default=argparse.SUPPRESS,
                    help="delay between retries in seconds (default 0.3)")
    p.add_argument("--min-delay-per-host", type=float, default=argparse.SUPPRESS,
                    help="minimum delay (seconds) between consecutive connections to the "
                         "same host across any ports — reduces impact on sensitive "
                         "production elements (default 0 = no limit). Does not affect "
                         "scan speed across different addresses.")

    p.add_argument("--no-two-phase", action="store_true", default=argparse.SUPPRESS,
                    help="disable the two-phase scan and run discovery/confirmation in a single "
                         "phase (simpler to debug, but usually slower on large ranges)")
    p.add_argument("--fast-timeout", type=float, default=argparse.SUPPRESS,
                    help="connection timeout for the fast-discovery phase (default 0.75s)")
    p.add_argument("--fast-concurrency", type=int, default=argparse.SUPPRESS,
                    help="fixed concurrency for the discovery phase (only with --no-adaptive)")
    p.add_argument("--no-adaptive", action="store_true", default=argparse.SUPPRESS,
                    help="disable self-adapting (AIMD) concurrency in the discovery phase, "
                         "and use a fixed --fast-concurrency instead")
    p.add_argument("--adaptive-min-concurrency", type=int, default=argparse.SUPPRESS,
                    help="lowest concurrency the auto-adapter will go down to (default 25)")
    p.add_argument("--adaptive-max-concurrency", type=int, default=argparse.SUPPRESS,
                    help="highest concurrency the auto-adapter will go up to (default 1500, "
                         "automatically capped by system limits — see --check-env)")
    p.add_argument("--workers", type=int, default=argparse.SUPPRESS,
                    help="number of processes to spread the scan across to use more than "
                         "one core (default 1 = single process, the usual behavior "
                         "with a detailed progress bar). More than 1 splits the targets "
                         "across separate processes — useful for very large ranges, but "
                         "progress updates at the whole-shard level rather than per target.")

    p.add_argument("--output", choices=["table", "json", "csv", "ndjson"], default=argparse.SUPPRESS,
                    help="ndjson = one independent JSON line per result as soon as it completes "
                         "(streaming), useful for feeding a live pipeline instead of waiting for the full scan")
    p.add_argument("--output-file", default=argparse.SUPPRESS, help="path to save results to (json/csv)")
    p.add_argument("--all-states", action="store_true", default=argparse.SUPPRESS,
                    help="show every state in the table, not just open")
    p.add_argument("--no-progress", action="store_true", default=argparse.SUPPRESS,
                    help="disable the live progress bar (useful when redirecting output to a file or CI)")
    p.add_argument("-v", "--verbose", action="store_true", default=argparse.SUPPRESS,
                    help="enable verbose logging")
    return p


def _load_profile(path: str) -> dict:
    with open(path, "rb") as f:
        data = tomllib.load(f)
    # Flat profile (all keys at one level) or nested under a [scan] table — both are supported
    return data.get("scan", data)


def _transports_from_arg(value: str) -> list[Transport]:
    if value == "all":
        return [Transport.TCP, Transport.UDP, Transport.SCTP]
    return [Transport(value)]


def _print_progress(label: str, done: int, total: int, open_count: int) -> None:
    """A simple progress bar with no external dependency — overwrites itself on the same line."""
    width = 30
    filled = int(width * done / total) if total else width
    bar = "#" * filled + "-" * (width - filled)
    sys.stderr.write(f"\r[{label}] [{bar}] {done}/{total} — open so far: {open_count}")
    sys.stderr.flush()
    if done == total:
        sys.stderr.write("\n")


async def _run_single_phase(
    targets: list[Target], config: ScanConfig, show_progress: bool,
    results_holder: list[ScanResult], on_result=None,
) -> None:
    """Single-phase scan/confirmation (the classic behavior, --no-two-phase)."""
    total = len(targets)
    open_count = 0
    async for result in iter_scan(targets, config):
        results_holder.append(result)
        if on_result is not None:
            on_result(result)
        if result.state is PortState.OPEN:
            open_count += 1
        if show_progress:
            _print_progress("scanning", len(results_holder), total, open_count)


async def _run_two_phase(
    targets: list[Target], fast_config: ScanConfig, deep_config: ScanConfig,
    show_progress: bool, results_holder: list[ScanResult], controller=None, on_result=None,
) -> None:
    """
    Phase 1 (fast_config): state discovery only (identify_protocols=False,
    guaranteed by the caller), with a short timeout across **all**
    non-UDP targets (see the UDP note below). If a controller
    (adaptive.ConcurrencyController) is passed, concurrency self-adapts
    batch by batch based on the actual error rate (see
    engine.adaptive_iter_scan) instead of a fixed concurrency
    (fast_config.max_concurrency is unused in that case). Non-open
    results (closed/filtered/error) are final right here.

    Phase 2 (deep_config): full protocol confirmation, with a longer
    timeout for accuracy, but only on the targets that came back open
    from phase 1 (plus every UDP target — see below) — usually a much
    smaller set, so the extra overhead (reopening the connection) is
    easily offset by the time saved on all the non-open targets.

    on_result (optional): a callback invoked as soon as any result
    completes (in either phase) — used for NDJSON streaming (see
    main()) without affecting the default behavior when None.
    """
    # UDP has no handshake, so the fast connectivity check (see
    # transports/udp.py: connect()) can only ever report OPEN — it just
    # means a local socket was created, not that anything answered.
    # Running UDP targets through the fast phase gives zero filtering
    # benefit and instead forces every single one into the deep phase
    # regardless of whether anything is really listening. So UDP
    # targets skip the fast phase entirely and are queued straight for
    # the deep (protocol-identifying) phase, which is the only phase
    # able to tell OPEN apart from FILTERED for UDP.
    fast_targets = [t for t in targets if t.transport is not Transport.UDP]
    udp_targets = [t for t in targets if t.transport is Transport.UDP]

    total = len(fast_targets)
    open_count = 0
    open_targets: list[Target] = list(udp_targets)
    done = 0

    fast_iterator = (
        engine.adaptive_iter_scan(fast_targets, fast_config, controller)
        if controller is not None
        else iter_scan(fast_targets, fast_config)
    )
    async for result in fast_iterator:
        done += 1
        if show_progress:
            label = f"fast discovery (concurrency={controller.current})" if controller else "fast discovery"
            _print_progress(label, done, total, open_count)
        if result.state is PortState.OPEN:
            open_count += 1
            open_targets.append(result.target)
        else:
            results_holder.append(result)
            if on_result is not None:
                on_result(result)

    if not open_targets:
        return

    deep_total = len(open_targets)
    deep_done = 0
    async for result in iter_scan(open_targets, deep_config):
        deep_done += 1
        results_holder.append(result)
        if on_result is not None:
            on_result(result)
        if show_progress:
            _print_progress("deep confirmation", deep_done, deep_total, deep_done)


def _print_protocol_list() -> None:
    from portscanner import protocols
    from portscanner.protocols.plugins import failed_plugins, loaded_plugins

    detectors = protocols.all_detectors()
    widths = [16, 10, 20, 30]
    header = "".join(c.ljust(w) for c, w in zip(("Protocol", "Transport", "Hint Ports", "Source"), widths))
    print(header)
    print("-" * len(header))
    for d in sorted(detectors, key=lambda x: x.name):
        transports_str = "/".join(t.value for t in d.transports)
        ports_str = ", ".join(str(p) for p in d.hint_ports) or "-"
        values = [d.name, transports_str, ports_str, d.source]
        print("".join(v.ljust(w) for v, w in zip(values, widths)))

    print(f"\nTotal: {len(detectors)} registered detectors "
          f"({sum(1 for d in detectors if d.source == 'builtin')} built-in, "
          f"{len(loaded_plugins)} from external plugins).")
    if failed_plugins:
        print("\n[!] plugins that failed to load (skipped, did not affect the rest):")
        for name, error in failed_plugins.items():
            print(f"    {name}: {error}")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.check_env:
        from portscanner.diagnostics import print_diagnostics
        print_diagnostics()
        return 0

    if args.list_protocols:
        _print_protocol_list()
        return 0

    if args.self_test:
        from portscanner.selftest import print_self_test_report, run_self_test
        results = asyncio.run(run_self_test())
        ok = print_self_test_report(results)
        return 0 if ok else 1

    logging.basicConfig(
        level=logging.DEBUG if getattr(args, "verbose", False) else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    # Precedence order: the profile fills gaps on top of BUILTIN_DEFAULTS,
    # and any explicit CLI flag (present in vars(args) thanks to
    # argparse.SUPPRESS) overrides both.
    merged: dict[str, object] = dict(BUILTIN_DEFAULTS)
    if args.profile:
        try:
            merged.update(_load_profile(args.profile))
        except (OSError, tomllib.TOMLDecodeError) as e:
            print(f"error reading profile '{args.profile}': {e}", file=sys.stderr)
            return 2
    explicit = {k: v for k, v in vars(args).items() if k not in ("profile", "check_env", "list_protocols", "self_test")}
    merged.update(explicit)

    host = merged.get("host")
    hosts_file = merged.get("hosts_file")
    discover_realm = merged.get("discover_realm")
    if not host and not hosts_file and not discover_realm:
        print("you must specify --host, --hosts-file, or --discover-realm "
              "(directly or via a TOML profile).", file=sys.stderr)
        return 2
    if sum(bool(x) for x in (host, hosts_file, discover_realm)) > 1:
        print("specify only one of --host, --hosts-file, or --discover-realm, not more than one.", file=sys.stderr)
        return 2

    if discover_realm:
        from portscanner.discovery import (
            DNSDiscoveryUnavailable, discover_naptr, elements_to_targets, resolve_service_tags,
        )

        naptr_service_spec = merged.get("naptr_service")
        service_names = [s.strip() for s in str(naptr_service_spec).split(",")] if naptr_service_spec else None
        service_tags = resolve_service_tags(service_names)
        print(f"[*] DNS lookup for '{discover_realm}' (tags: {', '.join(service_tags)}) ...",
              file=sys.stderr)
        try:
            elements = asyncio.run(discover_naptr(discover_realm, service_tags))
        except DNSDiscoveryUnavailable as e:
            print(f"error: {e}", file=sys.stderr)
            return 2

        if not elements:
            print(f"no Diameter element found for realm '{discover_realm}' "
                  f"(tags: {', '.join(service_tags)}).", file=sys.stderr)
            return 2
        for el in elements:
            print(f"[*] discovered: {el.hostname}:{el.port} (service={el.naptr_service}, "
                  f"priority={el.priority}, weight={el.weight})", file=sys.stderr)

        targets = elements_to_targets(elements)
        hosts = sorted({t.host for t in targets})
        ports = sorted({t.port for t in targets})
        transports = sorted({t.transport for t in targets}, key=lambda t: t.value)
    else:
        try:
            raw_hosts = [h.strip() for h in host.split(",") if h.strip()] if host else load_lines(hosts_file)
            hosts = expand_hosts(raw_hosts, max_hosts=int(merged["max_hosts"]))
            ports_file = merged.get("ports_file")
            ports = [int(p) for p in load_lines(ports_file)] if ports_file else parse_ports(str(merged["ports"]))
        except (ValueError, OSError) as e:
            print(f"input error: {e}", file=sys.stderr)
            return 2

        if not hosts:
            print("no targets to scan (address list is empty).", file=sys.stderr)
            return 2

        transports = _transports_from_arg(str(merged["transport"]))
        targets = build_targets(hosts, ports, transports)

    tls_ports_spec = str(merged["tls_ports"])
    try:
        tls_ports = frozenset(parse_ports(tls_ports_spec)) if tls_ports_spec.strip() else frozenset()
    except ValueError as e:
        print(f"invalid tls_ports format: {e}", file=sys.stderr)
        return 2

    identify_protocols = not bool(merged.get("no_identify", False))
    # The two-phase scan is meaningless if there's no protocol
    # confirmation at all (a single phase is then enough — it's the
    # "fast discovery" phase itself).
    use_two_phase = identify_protocols and not bool(merged.get("no_two_phase", False))
    use_adaptive = use_two_phase and not bool(merged.get("no_adaptive", False))

    # Cap every concurrency value to this environment's actual ulimit -n —
    # environments like GitHub Actions runners or constrained containers
    # can have a much lower limit than the defaults here.
    from portscanner.diagnostics import safe_max_concurrency

    concurrency, concurrency_warning = safe_max_concurrency(int(merged["concurrency"]))
    if concurrency_warning:
        print(f"[!] {concurrency_warning}", file=sys.stderr)

    # Centralized validation for every numeric setting that ScanConfig
    # and the engine assume is sane but nothing previously checked —
    # a negative value here used to reach asyncio.Semaphore or the
    # retry loop and crash with a raw traceback instead of a clean
    # "input error" message (e.g. --concurrency -5 raised
    # "ValueError: Semaphore initial value must be >= 0" from inside
    # engine.py, and --retries -3 made the retry loop's range() empty,
    # so _scan_one returned None and crashed reporting.py instead).
    workers = int(merged["workers"])
    validation_errors = []
    if concurrency < 1:
        validation_errors.append("--concurrency must be at least 1")
    if int(merged["retries"]) < 0:
        validation_errors.append("--retries cannot be negative")
    if float(merged["retry_delay"]) < 0:
        validation_errors.append("--retry-delay cannot be negative")
    if float(merged["connect_timeout"]) <= 0:
        validation_errors.append("--connect-timeout must be greater than 0")
    if float(merged["probe_timeout"]) <= 0:
        validation_errors.append("--probe-timeout must be greater than 0")
    if float(merged["min_delay_per_host"]) < 0:
        validation_errors.append("--min-delay-per-host cannot be negative")
    if int(merged["sctp_pool_size"]) < 1:
        validation_errors.append("--sctp-pool-size must be at least 1")
    if workers < 1:
        validation_errors.append("--workers must be at least 1")
    if validation_errors:
        for msg in validation_errors:
            print(f"input error: {msg}", file=sys.stderr)
        return 2

    deep_config = ScanConfig(
        connect_timeout=float(merged["connect_timeout"]),
        probe_timeout=float(merged["probe_timeout"]),
        max_concurrency=concurrency,
        identify_protocols=identify_protocols,
        sctp_thread_pool_size=int(merged["sctp_pool_size"]),
        retries=int(merged["retries"]),
        retry_delay=float(merged["retry_delay"]),
        tls_ports=tls_ports,
        min_delay_per_host=float(merged["min_delay_per_host"]),
    )

    no_progress = bool(merged.get("no_progress", False))
    all_states = bool(merged.get("all_states", False))
    show_progress = not no_progress and sys.stderr.isatty()
    results: list[ScanResult] = []
    scan_started_at = datetime.now(timezone.utc).isoformat()
    scan_start_monotonic = time.monotonic()

    output = str(merged["output"])
    output_file = merged.get("output_file")

    # NDJSON: we set up the sink and print an opening metadata line
    # **before** the scan even starts — the whole point is for the
    # consumer (another pipeline stage, jq...) to start receiving data
    # immediately instead of waiting for the entire scan, as json/csv do.
    ndjson_sink = None
    on_result = None
    if output == "ndjson":
        ndjson_sink = open(output_file, "w", encoding="utf-8") if output_file else sys.stdout
        opening_metadata = ScanMetadata(
            tool_version=__version__, started_at=scan_started_at, duration_seconds=0.0,
            targets_scanned=len(targets), hosts=hosts, ports=ports,
            transports=[t.value for t in transports],
        )
        print(metadata_to_ndjson_line(opening_metadata), file=ndjson_sink, flush=True)

        def on_result(result: ScanResult) -> None:  # noqa: F811
            print(result_to_ndjson_line(result), file=ndjson_sink, flush=True)

    # Build fast_config + adaptive_params once — needed whether we run as
    # a single process or distributed via --workers.
    fast_config = None
    adaptive_params: dict | None = None
    if use_two_phase:
        fast_max_concurrency, fast_warning = safe_max_concurrency(int(merged["fast_concurrency"]))
        if fast_warning and not use_adaptive:
            print(f"[!] {fast_warning}", file=sys.stderr)
        fast_config = ScanConfig(
            connect_timeout=float(merged["fast_timeout"]),
            probe_timeout=float(merged["fast_timeout"]),
            max_concurrency=fast_max_concurrency,
            identify_protocols=False,
            sctp_thread_pool_size=int(merged["sctp_pool_size"]),
            retries=0,  # the fast-discovery phase deliberately doesn't retry — speed is the priority here
            tls_ports=frozenset(),  # a TLS handshake isn't needed just to check port state
            min_delay_per_host=float(merged["min_delay_per_host"]),
        )
        if use_adaptive:
            adaptive_max, adaptive_warning = safe_max_concurrency(int(merged["adaptive_max_concurrency"]))
            if adaptive_warning:
                print(f"[!] {adaptive_warning}", file=sys.stderr)
            adaptive_min = int(merged["adaptive_min_concurrency"])
            adaptive_params = {
                "min_concurrency": min(adaptive_min, adaptive_max),
                "max_concurrency": adaptive_max,
                "initial_concurrency": min(fast_max_concurrency, adaptive_max),
            }

    mode_desc = "two-phase: fast discovery" + (" (self-adapting)" if use_adaptive else "") + " + deep confirmation" \
        if use_two_phase else "single-phase"
    if workers > 1:
        mode_desc += f" — distributed across {workers} processes"
    print(f"[*] scanning {len(hosts)} host(s) x {len(ports)} port(s) x {len(transports)} transport(s) "
          f"= {len(targets)} checks ({mode_desc}) ...", file=sys.stderr)

    try:
        if workers > 1:
            # Distributed scan: split the targets into 'workers' roughly
            # equal shards, each scanned in a separate Python process
            # (to use more than one core). Each worker streams results
            # back through a shared queue (engine.run_shard_streaming)
            # as soon as they complete, so on_result (ndjson) writes
            # to disk continuously across the whole run instead of in
            # one lump per shard — the results list is still built up
            # for the final table/json/csv path, but the on-disk
            # ndjson stream itself never waits on a full shard.
            import multiprocessing as mp

            shard_size = max(1, -(-len(targets) // workers))  # ceiling division
            shards = [targets[i:i + shard_size] for i in range(0, len(targets), shard_size)]
            print(f"[*] splitting into {len(shards)} shard(s) (~{shard_size} target(s) each) ...",
                  file=sys.stderr)

            ctx = mp.get_context("spawn")
            # Bounded so a slow consumer (disk I/O) applies backpressure
            # to the workers instead of an unbounded queue growing
            # without limit if disk writes fall behind scan speed.
            result_queue: mp.Queue = ctx.Queue(maxsize=10_000)
            processes = [
                ctx.Process(
                    target=engine.run_shard_streaming,
                    args=(shard, fast_config, deep_config, use_two_phase, adaptive_params, result_queue, i),
                    daemon=True,
                )
                for i, shard in enumerate(shards, 1)
            ]
            for p in processes:
                p.start()

            shard_counts: dict[int, int] = {}
            remaining_shards = len(shards)
            received = 0
            while remaining_shards > 0:
                item = result_queue.get()
                if isinstance(item, tuple) and item and item[0] == "__shard_done__":
                    _, shard_index, count = item
                    remaining_shards -= 1
                    print(f"[*] shard {shard_index}/{len(shards)} done "
                          f"({count} result(s))", file=sys.stderr)
                    continue
                if isinstance(item, tuple) and item and item[0] == "__shard_error__":
                    _, shard_index, error_msg = item
                    print(f"::warning::shard {shard_index}/{len(shards)} failed: {error_msg} "
                          f"(its results up to the failure are still included)", file=sys.stderr)
                    continue

                result = item
                received += 1
                results.append(result)
                if on_result is not None:
                    on_result(result)
                if show_progress and received % 200 == 0:
                    sys.stderr.write(f"\r[distributed scan] {received}/{len(targets)} results received "
                                      f"({len(shards) - remaining_shards}/{len(shards)} shards done)")
                    sys.stderr.flush()

            if show_progress:
                sys.stderr.write(f"\r[distributed scan] {received}/{len(targets)} results received "
                                  f"({len(shards)}/{len(shards)} shards done)\n")

            for p in processes:
                p.join(timeout=30)
                if p.is_alive():
                    print(f"::warning::a worker process did not exit cleanly after its shard "
                          f"finished — terminating it", file=sys.stderr)
                    p.terminate()
        elif use_two_phase:
            controller = None
            if adaptive_params is not None:
                from portscanner.adaptive import ConcurrencyController
                controller = ConcurrencyController(**adaptive_params)
            asyncio.run(_run_two_phase(
                targets, fast_config, deep_config, show_progress, results, controller, on_result
            ))
        else:
            asyncio.run(_run_single_phase(targets, deep_config, show_progress, results, on_result))
    except KeyboardInterrupt:
        print(f"\n[!] stopped manually (Ctrl+C) after {len(results)} result(s) — "
              f"showing partial results:", file=sys.stderr)
        if results and output != "ndjson":
            # In ndjson mode, results were already printed line by line as
            # they completed — no need (and no point) to show them again
            # as a table on top of a JSON stream on stdout.
            print_table(results, only_open=not all_states)
        if output == "ndjson" and output_file and ndjson_sink is not None:
            ndjson_sink.close()
        return 130
    finally:
        sctp_transport.shutdown_executor()

    print(f"[*] {summary_line(results)}", file=sys.stderr)
    breakdown = protocol_breakdown(results)
    if breakdown:
        print(f"[*] {breakdown}", file=sys.stderr)

    metadata = ScanMetadata(
        tool_version=__version__,
        started_at=scan_started_at,
        duration_seconds=time.monotonic() - scan_start_monotonic,
        targets_scanned=len(targets),
        hosts=hosts,
        ports=ports,
        transports=[t.value for t in transports],
    )

    if output == "table":
        print_table(results, only_open=not all_states)
    elif output == "json":
        if output_file:
            write_json(results, str(output_file), metadata)
            print(f"[*] saved to {output_file}", file=sys.stderr)
        else:
            print(to_json(results, metadata))
    elif output == "csv":
        out = str(output_file or "results.csv")
        write_csv(results, out)
        print(f"[*] saved to {out}", file=sys.stderr)
    elif output == "ndjson":
        # The results themselves were already printed as they completed
        # (on_result) — here we only print a final summary line with
        # accurate final statistics (the actual duration is now known),
        # and close the file if one was open.
        duration = time.monotonic() - scan_start_monotonic
        print(summary_to_ndjson_line(results, duration), file=ndjson_sink, flush=True)
        if output_file and ndjson_sink is not None:
            ndjson_sink.close()
            print(f"[*] saved to {output_file}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
