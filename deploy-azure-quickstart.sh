#!/usr/bin/env bash
# ── Hub — Azure One-Step Quickstart ───────────────────────────────
# Generates all secrets, deploys to Azure Container Instance, and
# prints the URL and credentials when done.
#
# Usage (from the webui-hub directory):
#   bash deploy-azure-quickstart.sh
#
# Optional overrides (set before running):
#   export ADMIN_PASSWORD=MySecurePass123
#   export RG=my-resource-group
#   export LOCATION=eastus

set -euo pipefail

# ── Prerequisite check ────────────────────────────────────────────
if ! command -v az &>/dev/null; then
    echo "❌ Azure CLI not found. Install from https://aka.ms/installazurecli"
    exit 1
fi
if ! command -v python3 &>/dev/null; then
    echo "❌ python3 not found."
    exit 1
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Hub — Azure Quickstart Deploy"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ── Generate secrets if not already set ───────────────────────────
if [ -z "${WEBUI_SECRET_KEY:-}" ]; then
    WEBUI_SECRET_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" 2>/dev/null \
        || python3 -c "import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())")
    echo "  ✔ Generated WEBUI_SECRET_KEY"
fi

if [ -z "${SECRET_KEY:-}" ]; then
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
    echo "  ✔ Generated SECRET_KEY"
fi

if [ -z "${ADMIN_PASSWORD:-}" ]; then
    ADMIN_PASSWORD=$(python3 -c "import secrets, string; print('Hub-' + secrets.token_urlsafe(12))")
    echo "  ✔ Generated ADMIN_PASSWORD: $ADMIN_PASSWORD"
    echo "     ⚠  Save this — it will not be shown again."
fi

export WEBUI_SECRET_KEY SECRET_KEY ADMIN_PASSWORD

echo ""

# ── Run main deploy script ────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bash "$SCRIPT_DIR/deploy-azure.sh"

echo ""
echo "  Secrets used (save these securely):"
echo "  ADMIN_PASSWORD   : $ADMIN_PASSWORD"
echo "  WEBUI_SECRET_KEY : $WEBUI_SECRET_KEY"
echo "  SECRET_KEY       : $SECRET_KEY"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
