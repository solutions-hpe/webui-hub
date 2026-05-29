#!/bin/bash
set -e

PYTHON_BIN=${PYTHON_BIN:-python3}
export DATA_DIR=${DATA_DIR:-/data}
export HUB_PORT=${HUB_PORT:-8443}
CERT_PATH="${TLS_CERT_PATH:-${DATA_DIR}/tls/cert.pem}"
KEY_PATH="${TLS_KEY_PATH:-${DATA_DIR}/tls/key.pem}"
DEBUG_LOG="${DATA_DIR}/startup.log"

# Write all output to the file share so we can read it after crashes
exec > >(tee -a "$DEBUG_LOG") 2>&1

echo "[$(date -u)] === Hub container starting ==="
echo "[$(date -u)] DATA_DIR=$DATA_DIR HUB_PORT=$HUB_PORT"

# Ensure data directories exist (important when ACI file share is mounted)
echo "[$(date -u)] Creating data directories..."
mkdir -p "${DATA_DIR}/tls" "${DATA_DIR}/pending" || true
echo "[$(date -u)] Data directories ready."

# Generate self-signed cert if not present
if [ ! -f "$CERT_PATH" ] || [ ! -f "$KEY_PATH" ]; then
    echo "[$(date -u)] Generating self-signed TLS certificate..."
    "$PYTHON_BIN" -c "
from pathlib import Path
from app.tls import generate_self_signed
cert = Path('${CERT_PATH}')
key = Path('${KEY_PATH}')
cert.parent.mkdir(parents=True, exist_ok=True)
generate_self_signed(cert, key)
print('TLS certificate generated.')
" || { echo "[$(date -u)] ERROR: Failed to generate TLS certificate. Check that $DATA_DIR is writable."; exit 1; }
else
    echo "[$(date -u)] TLS certificate already exists — skipping generation."
fi

echo "[$(date -u)] Starting gunicorn (uvicorn workers) on port $HUB_PORT..."
# Single worker: FastAPI+uvicorn is async (I/O-bound), so one process with
# an async event loop handles all concurrent WebSocket connections via
# coroutines. Multiple workers cause concurrent writes to Azure Files SMB
# where fcntl.flock does NOT provide real mutual exclusion, leading to
# JSON corruption. Single worker means threading.Lock() in store.py works
# correctly across all requests with zero cross-process contention.
WORKERS=${UVICORN_WORKERS:-1}
echo "[$(date -u)] Worker count: $WORKERS"
exec "$PYTHON_BIN" -m gunicorn app.main:app \
    --workers "$WORKERS" \
    --worker-class uvicorn.workers.UvicornWorker \
    --bind "0.0.0.0:$HUB_PORT" \
    --keyfile "$KEY_PATH" \
    --certfile "$CERT_PATH" \
    --forwarded-allow-ips "*" \
    --timeout 120 \
    --graceful-timeout 30 \
    --keep-alive 5
