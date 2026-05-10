#!/bin/bash
set -e

PYTHON_BIN=${PYTHON_BIN:-python3}
DATA_DIR=${DATA_DIR:-/data}
HUB_PORT=${HUB_PORT:-8443}
CERT_PATH="${TLS_CERT_PATH:-${DATA_DIR}/tls/cert.pem}"
KEY_PATH="${TLS_KEY_PATH:-${DATA_DIR}/tls/key.pem}"

# Ensure data directories exist (important when ACI file share is mounted)
mkdir -p "${DATA_DIR}/tls" "${DATA_DIR}/pending" || true

# Generate self-signed cert if not present
if [ ! -f "$CERT_PATH" ] || [ ! -f "$KEY_PATH" ]; then
    echo "Generating self-signed TLS certificate..."
    "$PYTHON_BIN" -c "
from pathlib import Path
from app.tls import generate_self_signed
cert = Path('${CERT_PATH}')
key = Path('${KEY_PATH}')
cert.parent.mkdir(parents=True, exist_ok=True)
generate_self_signed(cert, key)
print('TLS certificate generated.')
" || { echo "ERROR: Failed to generate TLS certificate. Check that $DATA_DIR is writable."; exit 1; }
fi

exec "$PYTHON_BIN" -m uvicorn app.main:app \
    --host 0.0.0.0 \
    --port "$HUB_PORT" \
    --ssl-keyfile "$KEY_PATH" \
    --ssl-certfile "$CERT_PATH" \
    --proxy-headers \
    --forwarded-allow-ips "*"
