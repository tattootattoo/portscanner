#!/usr/bin/env python3
"""
split_targets.py — used only by .github/workflows/signaling-scan.yml.

Expands a hosts file (CIDR/range/single-host lines, same syntax the CLI
itself accepts) into a flat, ordered host list using the project's own
expand_hosts()/load_lines() — so chunking can never disagree with what
the scanner itself would have expanded — then writes it out as fixed-size
chunk files. Each chunk is later fed to the CLI as its own --hosts-file,
which is what gives the workflow a clean resume boundary: a chunk is
"done" once the scan step for it exits 0, nothing finer-grained than that.

Usage:
    python scripts/split_targets.py <hosts-file> <chunk-size> <max-hosts> <out-dir>

Writes <out-dir>/chunk_0000.txt, chunk_0001.txt, ... and prints the
total chunk count on stdout (nothing else), so the workflow can do:
    total=$(python scripts/split_targets.py targets.txt 200 50000 chunks)
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from portscanner.targets import expand_hosts, load_lines  # noqa: E402


def main() -> int:
    if len(sys.argv) != 5:
        print(__doc__, file=sys.stderr)
        return 2

    hosts_file, chunk_size_s, max_hosts_s, out_dir_s = sys.argv[1:5]
    chunk_size = int(chunk_size_s)
    max_hosts = int(max_hosts_s)
    out_dir = Path(out_dir_s)
    out_dir.mkdir(parents=True, exist_ok=True)

    specs = load_lines(hosts_file)
    hosts = expand_hosts(specs, max_hosts=max_hosts)

    if not hosts:
        print("0")
        return 0

    chunk_count = 0
    for i in range(0, len(hosts), chunk_size):
        chunk = hosts[i : i + chunk_size]
        chunk_path = out_dir / f"chunk_{chunk_count:04d}.txt"
        chunk_path.write_text("\n".join(chunk) + "\n", encoding="utf-8")
        chunk_count += 1

    print(chunk_count)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
