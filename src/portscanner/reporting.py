"""
reporting.py
Formats scan results into four output formats (table/json/csv/ndjson),
with no external dependencies (standard library only) to keep the
project lightweight.
"""

from __future__ import annotations

import csv
import json
from collections import Counter

from portscanner.models import PortState, ScanMetadata, ScanResult

_COLUMNS = ("Host", "Port", "Transport", "State", "Hint", "Protocol", "Confidence", "Detail")


def print_table(results: list[ScanResult], only_open: bool = True) -> None:
    rows = [r for r in results if not only_open or r.state is PortState.OPEN]
    rows.sort(key=lambda r: (r.host, r.port, r.target.transport.value))

    widths = [18, 7, 10, 10, 16, 16, 12, 40]
    header = "".join(c.ljust(w) for c, w in zip(_COLUMNS, widths))
    print(header)
    print("-" * len(header))
    for r in rows:
        values = [
            r.host, str(r.port), r.target.transport.value, r.state.value,
            r.port_hint, r.protocol or "-", r.confidence or "-", r.detail or "-",
        ]
        print("".join(v.ljust(w) for v, w in zip(values, widths)))


def to_json(results: list[ScanResult], metadata: ScanMetadata | None = None) -> str:
    payload: dict = {"results": [r.to_dict() for r in results]}
    if metadata is not None:
        payload = {"metadata": metadata.to_dict(), "results": payload["results"]}
    return json.dumps(payload, ensure_ascii=False, indent=2)


def write_json(results: list[ScanResult], path: str, metadata: ScanMetadata | None = None) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(to_json(results, metadata))


def write_csv(results: list[ScanResult], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(results[0].to_dict().keys()) if results else [])
        writer.writeheader()
        for r in results:
            writer.writerow(r.to_dict())


def summary_line(results: list[ScanResult]) -> str:
    open_count = sum(1 for r in results if r.state is PortState.OPEN)
    confirmed = sum(1 for r in results if r.protocol)
    return f"scanned {len(results)} target(s) — {open_count} open, {confirmed} protocol(s) confirmed."


def protocol_breakdown(results: list[ScanResult]) -> str:
    """The breakdown of confirmed protocols — useful for seeing the
    distribution of discovered elements (how many Diameter, how many
    M3UA...) at a glance instead of reading the whole table."""
    counts = Counter(r.protocol for r in results if r.protocol)
    if not counts:
        return ""
    parts = [f"{name}={count}" for name, count in sorted(counts.items(), key=lambda kv: -kv[1])]
    return "protocol breakdown: " + ", ".join(parts)


# ---------------------------------------------------------------------------
# NDJSON (Newline-Delimited JSON): one independent JSON line per result,
# instead of waiting for the whole scan before anything is printed —
# lets the tool feed a live pipeline (like
# `portscanner ... | jq -c 'select(.state=="open")'`). Each line has a
# "type" field marking its kind: "metadata" (opening line), "result" (a
# single result), or "summary" (closing line with final statistics).
# ---------------------------------------------------------------------------

def metadata_to_ndjson_line(metadata: ScanMetadata) -> str:
    return json.dumps({"type": "metadata", **metadata.to_dict()}, ensure_ascii=False)


def result_to_ndjson_line(result: ScanResult) -> str:
    return json.dumps({"type": "result", **result.to_dict()}, ensure_ascii=False)


def summary_to_ndjson_line(results: list[ScanResult], duration_seconds: float) -> str:
    open_count = sum(1 for r in results if r.state is PortState.OPEN)
    confirmed = sum(1 for r in results if r.protocol)
    payload = {
        "type": "summary",
        "total": len(results),
        "open": open_count,
        "confirmed": confirmed,
        "duration_seconds": round(duration_seconds, 3),
    }
    return json.dumps(payload, ensure_ascii=False)
