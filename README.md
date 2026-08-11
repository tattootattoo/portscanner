# Telecom Signaling Protocol Scanner

A CLI tool **specialized exclusively** in scanning and confirming
telecom signaling protocols across every generation (2G-5G), with a
lightweight asyncio architecture, smart two-phase scanning, and the
flexibility to run in any Linux environment (local, container, GitHub
Actions).

## Supported protocols

| Protocol | Standard | Transport | Role | Generation |
|---|---|---|---|---|
| **Diameter** | RFC 6733 | TCP / SCTP / **TLS** | AAA — the actual interface (Gx, Rx, S6a...) + vendor | 4G/5G/IMS |
| **M3UA** | RFC 4666 | SCTP | carries MTP3 (SS7) over IP | 2G-4G |
| **SUA** | RFC 3868 | SCTP | carries SCCP over IP | 2G-4G |
| **M2UA** | RFC 3331 | SCTP | carries MTP2 over IP | 2G-4G |
| **M2PA** | RFC 4165 | SCTP | peer-to-peer MTP2 emulation | 2G-4G |
| **IUA** | RFC 4233 | SCTP | carries ISDN Q.921 signaling (PSTN<->VoIP gateways) | 2G-3G legacy |
| **V5UA** | RFC 3807 | SCTP | carries V5.2 signaling (older DSL access network) | legacy |
| **GTP-C** | 3GPP TS 29.060 (v1) / 29.274 (v2) | UDP | packet-network control (Gn/Gp, S11/S5/S8) | 2G-5G-interworking |
| **GTP-U** | 3GPP TS 29.281 | UDP | user-plane data layer (GTP tunnel) | 2G-5G |
| **SIP/IMS** | RFC 3261 | TCP / **TLS (SIPS)** | VoLTE/VoWiFi/5G Voice call control | 4G/5G |

No generic fingerprinting (SSH/FTP/HTTP...) — every protocol here is
an official part of the 3GPP/IETF specifications for telecom networks.

**Only use this tool on systems you own or are officially authorized to scan.**

## Smart two-phase scanning (default)

Instead of forcing the same timeout on every target (whether it's open
or not), the tool automatically scans in two phases:

1. **Fast discovery**: high concurrency (1000 by default) + a short
   timeout (0.75s) across **every** target, with no protocol exchange
   at all — just determining the state.
2. **Deep confirmation**: only on the targets that came back open
   (usually a very small fraction of the total), with a longer timeout
   (2s) for full accuracy in identifying the protocol.

On a `/24` network (254 addresses) x 9 ports = 2286 targets, if only 3
are actually open, the old approach (single phase) waits out the full
timeout on all 2283 closed/filtered targets; with two phases, the long
wait only happens on the 3 that are open. Disable it with
`--no-two-phase` if you want simpler behavior for debugging.

```bash
portscanner --host 10.0.0.0/24 --fast-timeout 0.5 --fast-concurrency 2000
```

## Runtime environment flexibility

```bash
portscanner --check-env
```

Gives you an instant diagnosis: SCTP support, TLS, IPv6, root
privileges — before you start a real scan, so you know exactly what's
available in the environment you're running in (a local server, a
container, a CI runner...). The protocols that don't need SCTP
(Diameter/GTP-C/GTP-U/SIP) work in any ordinary Linux environment with
no extra setup.

### As a GitHub Actions step

```yaml
- uses: your-org/portscanner@main
  with:
    hosts-file: targets.txt
    transport: all
    extra-args: "--retries 1"
```

The action installs `lksctp-tools` and loads the SCTP kernel module by
default (`enable-sctp: true`), so SIGTRAN protocols are scanned for
real instead of returning ERROR — set `enable-sctp: false` to skip
this step if you only need tcp/udp. For large target lists, raise
`max-hosts` (default 20000) and `workers` (default 4, matches to the
runner's core count), and keep `output-format: ndjson` (the default)
so results stream to disk instead of being buffered as one JSON blob.

(See `action.yml`, `.github/workflows/example-monitor.yml.example` for
a small periodic-monitoring example, and
`.github/workflows/large-scale-scan.yml.example` +
`targets.txt.example` for a tens-of-thousands-of-targets setup — both
need a self-hosted runner if your targets are on a private network.)

### Real SCTP via Docker

```bash
docker compose run --rm portscanner portscanner --host 10.0.0.5 --transport sctp
```

## Technical highlights

- **asyncio instead of threads** — much lower memory usage.
- **A real plugin architecture**: any external package can add a new
  protocol via Python entry_points with no changes to any core code —
  see `examples/example-protocol-plugin/` (a complete working RADIUS example).
- **Self-adapting concurrency (AIMD)**: the fast-discovery phase
  automatically raises/lowers concurrency based on the actual error
  rate instead of guessing a fixed number — the same principle as TCP
  congestion control (`adaptive.py`).
- **Portability hardening across environments**: `--check-env` checks
  `ulimit -n` and suggests a safe max concurrency, and the tool
  automatically caps itself if the requested value exceeds the
  environment's limits (a GitHub Actions runner, a constrained
  container, a shared server...) instead of suddenly crashing with
  "Too many open files".
- **Real Diameter/TLS + SIPS**: a full TLS handshake + **a manual X.509
  DER parser with no external library**.
- **Vendor fingerprinting**: `Vendor-Id` mapped against the IANA
  Enterprise Numbers table.
- **Confidence level (`confirmed`/`likely`)**: distinguishes a
  successful reply from an explicit rejected one.
- **Robust message reading**: per the length declared in the header,
  resilient to TCP fragmentation.
- **Flexible addressing**: IP/domain/CIDR/range, with a `--max-hosts` safety cap.
- **TOML profiles**: precedence order explicit CLI > profile > default.
- **Smart retries + a progress bar per phase + clean Ctrl+C + comprehensive fault isolation**.
- **Distributed scanning (`--workers`)**: spreads targets across
  several processes to use more than one core on very large ranges.
- **Per-target rate limiting (`--min-delay-per-host`)**: prevents
  flooding a sensitive production element, without affecting the scan
  speed of other addresses.
- **JSON with full metadata**: scan time, duration, tool version, and
  the settings used — not just raw results.
- **Automatic DNS discovery** (`--discover-realm`, 3GPP TS 29.303):
  instead of manually specifying an IP, you give a realm name and it
  finds the actual Diameter elements via NAPTR/SRV — the same
  mechanism real network elements use. An optional dependency
  (`pip install portscanner[dns]`) — the core tool stays free of any
  mandatory dependency.
- **Streaming NDJSON output** (`--output ndjson`): one independent JSON
  line per result as soon as it completes (not waiting for the whole
  scan) — lets the tool feed a live pipeline
  (`| jq -c 'select(.state=="open")'`).
- **No mandatory external dependencies** — standard library only.

## Architecture

```
src/portscanner/
├── models.py              # Target, ScanResult, ScanMetadata, ScanConfig
├── targets.py               # port/address parsing + CIDR/ranges
├── diagnostics.py            # --check-env: runtime environment diagnosis + fd limits
├── selftest.py                 # --self-test: local mock servers to confirm the tool itself works
├── adaptive.py                # ConcurrencyController (AIMD) — pure logic
├── discovery.py                # DNS discovery (3GPP TS 29.303 NAPTR/SRV) — optional
├── transports/                # TCP(+TLS)/UDP/SCTP behind a unified Connection interface
│   ├── _x509_lite.py            # an X.509 DER parser with no external library
│   └── tcp.py, udp.py, sctp.py
├── protocols/                 # a Registry pattern — each protocol is its own file
│   ├── base.py                  # @register + DetectionResult + source tracking
│   ├── plugins.py                # discovers external plugins via entry_points
│   ├── _io.py, _sigtran_common.py, _gtp_common.py   # shared logic (DRY)
│   └── diameter.py, m3ua.py, sua.py, m2ua.py, m2pa.py,
│       gtpc.py, gtpu.py, sip.py
├── engine.py                  # Semaphore + retries + fault isolation + adaptive_iter_scan + HostPacer
├── reporting.py                # table/json/csv/ndjson + protocol breakdown
└── cli.py                       # argparse + two-phase scanning + TOML profiles + --list-protocols
tests/                        # 154+ tests (unit + real end-to-end with loopback servers)
profiles/                     # example TOML profiles
examples/example-protocol-plugin/   # a complete external plugin example (RADIUS)
Dockerfile, docker-compose.yml   # a real SCTP environment
action.yml                    # a ready-made composite GitHub Action
.github/workflows/ci.yml       # automatic pytest + ruff + mypy (3 Python versions)
```

**To add a new protocol to the core code**: create `protocols/xxx.py`
with a `detect()` function decorated with `@register(...)` that
returns `DetectionResult|None`, and import it in one line in
`protocols/__init__.py`.

**To add a protocol as an external plugin (without touching this
project at all)**: see `examples/example-protocol-plugin/README.md` —
the whole idea: a separate package whose `pyproject.toml` registers a
module under an entry_points group named `portscanner.protocols`, and
simply installing it (`pip install`) is enough.

## Installation and usage

```bash
pip install -e .
# or without installing:
PYTHONPATH=src python3 -m portscanner.cli --help
```

### Examples

```bash
# default scan: every standard signaling protocol, automatically two-phase
portscanner --host 10.0.0.5

# Diameter + interface/vendor identification (TLS automatic on 3869)
portscanner --host 10.0.0.5 --ports 3868,3869 --transport tcp

# GTP-C and GTP-U over UDP (every generation)
portscanner --host 10.0.0.5 --ports 2123,2152 --transport udp

# SIP/IMS (VoLTE signaling)
portscanner --host 10.0.0.5 --ports 5060,5061 --transport tcp

# the full SIGTRAN family over SCTP
portscanner --host 10.0.0.5 --ports 2904,2905,14001 --transport sctp

# a whole network via CIDR — automatic two-phase scanning saves a lot of time here
portscanner --host 10.0.0.0/24 --retries 1

# a ready-made TOML profile
portscanner --profile profiles/example.toml

# diagnose the environment before scanning (SCTP/TLS/IPv6 + open-file limit)
portscanner --check-env

# self-check: real local mock servers for every protocol, confirming the
# tool works correctly in this environment before any real target scan
portscanner --self-test

# list every registered protocol (built-in + external plugins)
portscanner --list-protocols

# scan a huge network with self-adapting concurrency (default) — adapts automatically
portscanner --hosts-file big-network.txt --adaptive-max-concurrency 3000

# distributed scan across several processes (using more than one core for very large ranges)
portscanner --host 10.0.0.0/16 --workers 4

# reduce impact on a sensitive production element (a minimum delay between connections to the same host)
portscanner --host 10.0.0.5 --min-delay-per-host 0.5

# disable auto-adaptation, use a fixed manual concurrency
portscanner --host 10.0.0.0/16 --no-adaptive --fast-concurrency 500

# disable two-phase scanning entirely (classic behavior, single phase)
portscanner --host 10.0.0.5 --no-two-phase

# multiple targets separated directly by commas
portscanner --host "10.0.0.5,10.0.0.0/28,hss.example.com"

# automatic DNS discovery (3GPP TS 29.303) instead of manually specifying an IP
pip install portscanner[dns]
portscanner --discover-realm "epc.mnc001.mcc001.3gppnetwork.org"

# discover specific service tags only (instead of every known tag)
portscanner --discover-realm "epc.mnc001.mcc001.3gppnetwork.org" --naptr-service generic-tcp,s6a-mme

# streaming NDJSON output — each result as soon as it completes, piped directly to jq
portscanner --host 10.0.0.0/24 --output ndjson --no-progress | jq -c 'select(.type=="result" and .state=="open")'

# show the tool's version
portscanner --version
```

### External plugin example

```bash
pip install -e examples/example-protocol-plugin   # adds RADIUS
portscanner --list-protocols                       # RADIUS will show up automatically
portscanner --host 10.0.0.5 --ports 1812,1813 --transport udp
```

### Exit codes

| Code | Meaning |
|---|---|
| 0 | scan completed successfully |
| 2 | input error |
| 130 | Ctrl+C — partial results are shown before exiting |

## Requirements

- Python 3.11+ (standard `tomllib`)
- SCTP requires `lksctp-tools` (or use the bundled Docker setup)
- DNS discovery (`--discover-realm`) requires `pip install portscanner[dns]` (optional)
- License: MIT (see `LICENSE`)

## Tests

```bash
pip install -e ".[dev]"
pytest tests/ -v          # 154+ tests
ruff check src tests
mypy src

# actually test the plugin architecture (optional)
pip install -e examples/example-protocol-plugin
portscanner --list-protocols   # RADIUS must show up with an external source
```

### Coverage levels (full transparency)

Not every protocol is tested at the same level — an important distinction to know:

| Level | Protocols | What it means |
|---|---|---|
| **real end-to-end** (`test_e2e_*.py`) | Diameter (TCP+TLS with a real openssl certificate), GTP-C (v1/v2+fallback), GTP-U, SIP, RADIUS | a real loopback server + the tool's full real engine, zero mocking of the transport layer |
| **mocked connection + DNS** | DNS discovery, the full DNS->NDJSON pipeline through `cli.main()` | dnspython fully mocked (no real DNS query), but the rest of the path (the engine, reporting) is 100% real |
| **`detect()` functions with a mocked Connection** (`test_e2e_sigtran_simulated.py`) | M3UA, SUA, M2UA, M2PA, IUA, V5UA (the full SIGTRAN family) | the actual production code is tested (not just isolated byte functions), but without a real SCTP socket — this environment has no SCTP support in the kernel at all (`--check-env` confirms this) |
| **isolated bytes only** | everything above also has more granular tests for the byte building/parsing itself (`test_protocols.py` and others) | verifies encoding accuracy in isolation from any I/O |

**A frank summary**: if you have an environment with real SCTP (the
bundled Docker setup, or a Linux server with `lksctp-tools`), run
`pytest` and try an actual scan — the SIGTRAN family has never seen a
real SCTP connection in this environment.

## Known limitations and technical transparency

- **M2PA**: the Link Status values are built on the best understanding
  of RFC 4165, less commonly seen in practice than M3UA — check RFC
  4165 §5 if you run into unexpected behavior.
- **V5UA**: the IANA port (5675) has lower confidence than the rest of
  the SIGTRAN family (a less documented / less practically deployed
  protocol) — check the IANA registration if you run into unexpected behavior.
- **SCTP multi-homing** (`SCTP_GET_PEER_ADDRS`): deliberately not
  implemented — the reply bytes vary in format depending on
  architecture/kernel, and there's no real SCTP environment here to
  verify against. Preferring transparency over shipping a guess that
  could be wrong.
- **SCCP/Global Title and MAP/CAP/INAP fingerprints**: deliberately not
  added — a principled decision, not a technical one: any interaction
  with them requires the tool to "act" as a real SS7 signaling point
  (Point Code), and the MAP operations themselves (location tracking,
  SMS interception) are, letter for letter, the same as documented SS7
  attack tools — entirely outside the scope of a fingerprinting tool,
  regardless of test-environment availability.
- **5G NGAP/N2** (gNB-AMF): not supported — uses complex ASN.1 PER
  encoding (3GPP TS 38.413); the risk of an inaccurate implementation
  without a real test environment currently outweighs the expected benefit.
- The `Application-Id`/`Vendor-Id` map in `diameter.py` is best-effort,
  extendable in one line.
- **DNS discovery**: the `KNOWN_NAPTR_SERVICES` table is best-effort
  per 3GPP TS 29.303 (not exhaustive of every combination) — use
  `--naptr-service` for a custom tag if you need an interface not in
  the table. Only supports NAPTR with flag="S" (redirects to SRV) —
  "A"/"U" types aren't supported currently.
- **NDJSON with `--workers`**: streaming happens at the whole-shard
  level (after each process finishes), not truly result by result, for
  the same reason the progress bar is limited in this mode (detailed
  cross-process tracking needs extra IPC).
- IPv6: TCP/UDP support it automatically, SCTP is currently IPv4 only.
- **Using it as a library**: `cli.main()` uses `asyncio.run()`
  internally, so it can't be called from inside an event loop that's
  already running (like other async code). This doesn't affect normal
  CLI usage (called from sync code), but it's a real constraint if
  someone wants to use portscanner as a library inside another asyncio
  application — use `engine.run_scan()`/`iter_scan()` directly in that case, instead of `cli.main()`.
