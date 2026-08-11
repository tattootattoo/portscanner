# Builds a runtime environment with real SCTP support (lksctp-tools +
# kernel module) — needs the container to run with enough privilege to
# load a kernel module (--privileged or --cap-add=NET_ADMIN depending
# on the Docker host distro, because socket.IPPROTO_SCTP needs the sctp
# module loaded on the host kernel itself, not just inside the container).
FROM python:3.12-slim

# lksctp-tools: user-space SCTP libraries and tools (needed for
# socket.IPPROTO_SCTP to work from Python). kmod for modprobe.
RUN apt-get update && apt-get install -y --no-install-recommends \
        lksctp-tools \
        libsctp-dev \
        kmod \
        iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY tests ./tests

RUN pip install --no-cache-dir -e ".[dev]"

# A simple entrypoint script: makes sure the sctp module is loaded (if
# permissions allow) before running any command — prints a clear
# warning instead of failing silently if it can't load it.
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["portscanner", "--help"]
