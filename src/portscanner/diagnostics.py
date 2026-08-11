"""
diagnostics.py
A quick diagnosis of the runtime environment — shows what's actually
available (SCTP, TLS, network permissions) before you start a real
scan. Especially useful when the tool runs in varied environments (a
Docker container, a GitHub Actions runner, a managed server...) where
what support is available isn't obvious up front.

Does not open any real network connection to an external target — it
only checks local system capabilities.
"""

from __future__ import annotations

import os
import platform
import socket
import sys


def _check_sctp() -> tuple[bool, str]:
    if not hasattr(socket, "IPPROTO_SCTP"):
        return False, "Python's socket module has no IPPROTO_SCTP (very rare on a modern Linux)"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_SCTP)
        s.close()
        return True, "available — an SCTP socket was created successfully"
    except OSError as e:
        return False, f"unavailable — {e} (needs lksctp-tools + the 'sctp' kernel module)"


def _check_tls() -> tuple[bool, str]:
    try:
        import ssl
        ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        return True, f"available — {ssl.OPENSSL_VERSION}"
    except Exception as e:
        return False, f"unavailable — {e}"


def _check_ipv6() -> tuple[bool, str]:
    if not socket.has_ipv6:
        return False, "the socket module was built without IPv6 support"
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.close()
        return True, "available"
    except OSError as e:
        return False, f"unavailable — {e}"


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _check_fd_limit() -> tuple[int, int]:
    """Returns (soft_limit, hard_limit) for the allowed number of file descriptors."""
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        return soft, hard
    except (ImportError, ValueError, OSError):
        # the resource module doesn't exist on Windows, for example — return a conservative value
        return 256, 256


def safe_max_concurrency(requested: int, reserve: int = 64) -> tuple[int, str | None]:
    """
    Caps the requested concurrency to this OS's actual limits
    (RLIMIT_NOFILE), leaving 'reserve' fds for the rest of the
    process's needs (open files, stdio, SCTP connections on separate
    threads...). This matters especially in constrained environments
    like some Docker containers or GitHub Actions runners that set
    ulimit -n to a low value (1024, say) — a higher concurrency than
    that causes a sudden "Too many open files" partway through the scan.

    Returns (the actual safe value, a warning message or None if no cap was applied).
    """
    soft_limit, _hard_limit = _check_fd_limit()
    safe_ceiling = max(1, soft_limit - reserve)
    if requested <= safe_ceiling:
        return requested, None
    warning = (
        f"the requested concurrency ({requested}) exceeds the safe limit for this environment "
        f"(ulimit -n={soft_limit}) — capped to {safe_ceiling}. "
        f"To raise the limit: `ulimit -n 65536` before running (if you have permission)."
    )
    return safe_ceiling, warning


def gather_diagnostics() -> dict[str, object]:
    sctp_ok, sctp_detail = _check_sctp()
    tls_ok, tls_detail = _check_tls()
    ipv6_ok, ipv6_detail = _check_ipv6()
    soft_fd, hard_fd = _check_fd_limit()
    return {
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
        "is_root": _is_root(),
        "sctp": {"available": sctp_ok, "detail": sctp_detail},
        "tls": {"available": tls_ok, "detail": tls_detail},
        "ipv6": {"available": ipv6_ok, "detail": ipv6_detail},
        "fd_limit": {"soft": soft_fd, "hard": hard_fd},
    }


def print_diagnostics() -> None:
    d = gather_diagnostics()
    print(f"Python: {d['python_version']}")
    print(f"System: {d['platform']}")
    print(f"Root privileges: {'yes' if d['is_root'] else 'no'}")
    fd = d["fd_limit"]
    print(f"Open file limit (ulimit -n): {fd['soft']} (hard max: {fd['hard']})")
    print()
    for name, label in (("sctp", "SCTP (M3UA/SUA/M2UA/M2PA)"), ("tls", "TLS (Diameter/TLS, SIPS)"),
                         ("ipv6", "IPv6")):
        info = d[name]
        status = "\u2713 available" if info["available"] else "\u2717 unavailable"
        print(f"{label}: {status}")
        print(f"    {info['detail']}")
    print()
    if not d["sctp"]["available"]:
        print("[!] SIGTRAN protocols (M3UA/SUA/M2UA/M2PA) will return ERROR for every scan.")
        print("    Fix: install lksctp-tools and load the module (`modprobe sctp`), or use")
        print("    the Docker setup bundled with the project (docker compose run --rm portscanner ...).")
        print("    The other protocols (Diameter/GTP-C/GTP-U/SIP) will work fine without SCTP.")
    safe_concurrency, warning = safe_max_concurrency(2000)
    print(f"\nSuggested safe max concurrency for this environment: {safe_concurrency}"
          f"{' (capped due to ulimit -n)' if warning else ''}")
    print("\nTo confirm that every protocol actually works in this environment (not just a "
          "capability check), try: portscanner --self-test")
