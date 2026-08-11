#!/bin/sh
# Tries to load the sctp module on the host kernel (if the container is
# running with enough privilege: --privileged or --cap-add=SYS_MODULE).
# If it fails, continues normally with a clear warning — the tool
# itself returns a clear ERROR for any SCTP scan if the module isn't
# loaded, so this isn't critical enough to stop startup.
if command -v modprobe >/dev/null 2>&1; then
    modprobe sctp 2>/dev/null || echo "[docker-entrypoint] warning: failed to load the sctp module — run the container with --privileged or --cap-add=SYS_MODULE, or make sure the host itself already has the module loaded." >&2
fi

if [ -f /proc/net/sctp/snmp ] || grep -qi sctp /proc/modules 2>/dev/null; then
    echo "[docker-entrypoint] SCTP support is available." >&2
else
    echo "[docker-entrypoint] SCTP support is unconfirmed — SCTP scans may return ERROR." >&2
fi

exec "$@"
