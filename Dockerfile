# ── Hub Central Platform ──────────────────────────────────────────
# Multi-stage build — production-ready, non-root, TLS inside container

FROM python:3.12-slim AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.12-slim
LABEL org.opencontainers.image.title="Hub — Client-Sim Central Platform"
LABEL org.opencontainers.image.description="Multi-tenant island management platform"

WORKDIR /app

RUN addgroup --system hub && adduser --system --ingroup hub hub

COPY --from=builder /install /usr/local
COPY --chown=hub:hub . .

RUN mkdir -p /data && chown hub:hub /data
RUN chmod +x /app/start.sh

EXPOSE 8443

USER hub

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python3 -c "import urllib.request, ssl; ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE; urllib.request.urlopen('https://localhost:8443/api/health', context=ctx)" || exit 1

CMD ["/app/start.sh"]
