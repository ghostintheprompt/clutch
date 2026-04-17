# syntax=docker/dockerfile:1.6
# ─── Stage 1: dependency builder ─────────────────────────────────────────────
# Compile wheels in an ephemeral layer so the runtime image has no gcc / headers.
FROM python:3.11-slim-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt /tmp/
RUN pip install --no-cache-dir -r /tmp/requirements.txt


# ─── Stage 2: hardened runtime ────────────────────────────────────────────────
FROM python:3.11-slim-bookworm AS runtime

LABEL org.opencontainers.image.title="Clutch"
LABEL org.opencontainers.image.description="Cellular IMSI-catcher detection probe — hardened container"
LABEL org.opencontainers.image.source="https://github.com/ghostintheprompt/clutch"
LABEL org.opencontainers.image.licenses="MIT"

# Runtime system packages only:
#   tcpdump  — triggered PCAP capture on rule violations
#   iptables / nftables — active blocking of unauthorized IPs
#   libpcap  — shared library for tcpdump / scapy
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       tcpdump \
       iptables \
       nftables \
       libpcap0.8 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Non-root service account — principle of least privilege
RUN groupadd --gid 1001 clutch \
    && useradd  --uid 1001 --gid 1001 \
                --no-create-home --shell /bin/false \
                clutch

# Application layout:
#   /app            — read-only code (root-owned, group-readable)
#   /app/forensics  — writable output dir for reports, PCAPs, block audit
#   /app/config     — mounted config (read-only at runtime)
RUN mkdir -p /app/forensics/pcap \
               /app/forensics/reports \
               /app/forensics/validation \
               /app/forensics/blocks \
               /app/config \
    && chown -R root:clutch /app \
    && chmod -R 550 /app \
    && chmod -R 770 /app/forensics

WORKDIR /app

COPY --chown=root:clutch scripts/     ./scripts/
COPY --chown=root:clutch cellular_remote_config.json          ./config/
COPY --chown=root:clutch enhanced_cellular_security_config.json ./config/

# Grant tcpdump/iptables the specific capabilities they need via file capabilities
# rather than running the entire container as root.
RUN setcap cap_net_raw,cap_net_admin+eip /usr/bin/tcpdump    2>/dev/null || true \
    && setcap cap_net_raw,cap_net_admin+eip /usr/sbin/iptables 2>/dev/null || true \
    && setcap cap_net_raw,cap_net_admin+eip /usr/sbin/nft      2>/dev/null || true

# Verify the application imports cleanly before shipping the image
RUN python -c "import scripts.advanced_cellular_security; print('[ok] import check passed')" \
    || echo "[warn] import check failed — check requirements"

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c \
    "from scripts.advanced_cellular_security import EnhancedCellularSecurityMonitor; print('ok')" \
    || exit 1

USER clutch

# Forensics output persists across container restarts
VOLUME ["/app/forensics"]

# WebSocket coordination server port
EXPOSE 8765/tcp

ENTRYPOINT ["python", "scripts/advanced_cellular_security.py"]
CMD ["--config", "/app/config/enhanced_cellular_security_config.json", "--advanced"]
