#!/usr/bin/env bash
# ── Hub — Production Redeploy (CS resource group) ─────────────────
# Rebuilds the ACR image from current branch and redeploys the hub ACI.
#
# Usage:
#   bash redeploy-prod.sh
#
# Requires: .deploy-secrets-prod.env in the same directory, az CLI logged in.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECRETS_FILE="$SCRIPT_DIR/.deploy-secrets-prod.env"

RG="CS"
LOCATION="westus3"
CONTAINER_NAME="cs-hub"
ACR_NAME="cshubregistry"
ACR_SERVER="cshubregistry.azurecr.io"
IMAGE="hub:main"
STORAGE_ACCOUNT="cshubdata"
FILE_SHARE="hubdata"
HUB_PORT=8443

# ── Load secrets ──────────────────────────────────────────────────
if [ ! -f "$SECRETS_FILE" ]; then
    echo "❌ Missing $SECRETS_FILE"
    exit 1
fi
# shellcheck disable=SC1090
source "$SECRETS_FILE"
# Allow secrets file to override DNS_LABEL
DNS_LABEL="${DNS_LABEL:-cs-hub}"

for var in ADMIN_PASSWORD SECRET_KEY ENCRYPTION_KEY INSTALLER_API_KEY WEBUI_SECRET_KEY; do
    if [ -z "${!var:-}" ]; then
        echo "❌ $var not set in $SECRETS_FILE"
        exit 1
    fi
done

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Hub — Production Redeploy"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Resource Group : $RG"
echo "  Container      : $CONTAINER_NAME"
echo "  Image          : $ACR_SERVER/$IMAGE"
echo ""

# ── Prerequisite check ────────────────────────────────────────────
if ! command -v az &>/dev/null; then
    echo "❌ Azure CLI (az) not found."
    exit 1
fi

# ── Fetch credentials ─────────────────────────────────────────────
echo "▶ Fetching storage key..."
STORAGE_KEY=$(az storage account keys list \
    --account-name "$STORAGE_ACCOUNT" \
    --resource-group "$RG" \
    --query '[0].value' -o tsv)

if [ -z "$STORAGE_KEY" ]; then
    echo "❌ Failed to retrieve storage key for $STORAGE_ACCOUNT"
    exit 1
fi

echo "▶ Verifying Azure Files share '$FILE_SHARE'..."
SHARE_EXISTS=$(az storage share exists \
    --account-name "$STORAGE_ACCOUNT" \
    --account-key "$STORAGE_KEY" \
    --name "$FILE_SHARE" \
    --query 'exists' -o tsv)

if [ "$SHARE_EXISTS" != "true" ]; then
    echo "  Share not found — creating..."
    az storage share create \
        --name "$FILE_SHARE" \
        --account-name "$STORAGE_ACCOUNT" \
        --account-key "$STORAGE_KEY" \
        --output none
fi

echo "▶ Fetching ACR credentials..."
ACR_PWD=$(az acr credential show --name "$ACR_NAME" --query 'passwords[0].value' -o tsv)

# ── Stamp VERSION with git SHA so browsers cache-bust on each deploy ──
GIT_SHA=$(git -C "$SCRIPT_DIR" rev-parse --short HEAD 2>/dev/null || echo "dev")
echo "$GIT_SHA" > "$SCRIPT_DIR/VERSION"

# ── Build and push image ──────────────────────────────────────────
echo "▶ Building and pushing image to ACR..."
az acr build --registry "$ACR_NAME" --image "$IMAGE" "$SCRIPT_DIR" --output none
echo "  ✓ Image pushed: $ACR_SERVER/$IMAGE"

# ── Remove existing container (clean slate) ───────────────────────
EXISTING=$(az container show --name "$CONTAINER_NAME" --resource-group "$RG" \
    --query 'provisioningState' -o tsv 2>/dev/null || echo "none")

if [ "$EXISTING" != "none" ]; then
    echo "▶ Deleting existing container '$CONTAINER_NAME' (state: $EXISTING)..."
    az container delete --name "$CONTAINER_NAME" --resource-group "$RG" --yes --output none
    echo "  ✓ Deleted"
fi

# ── Deploy ────────────────────────────────────────────────────────
echo "▶ Creating container '$CONTAINER_NAME'..."
az container create \
    --name "$CONTAINER_NAME" \
    --resource-group "$RG" \
    --image "$ACR_SERVER/$IMAGE" \
    --registry-login-server "$ACR_SERVER" \
    --registry-username "$ACR_NAME" \
    --registry-password "$ACR_PWD" \
    --dns-name-label "$DNS_LABEL" \
    --ports "$HUB_PORT" \
    --protocol TCP \
    --cpu 1 \
    --memory 1.5 \
    --os-type Linux \
    --environment-variables \
        ADMIN_PASSWORD="$ADMIN_PASSWORD" \
        SECRET_KEY="$SECRET_KEY" \
        ENCRYPTION_KEY="$ENCRYPTION_KEY" \
        INSTALLER_API_KEY="$INSTALLER_API_KEY" \
        WEBUI_SECRET_KEY="$WEBUI_SECRET_KEY" \
        AZURE_STORAGE_ACCOUNT="$STORAGE_ACCOUNT" \
        AZURE_STORAGE_KEY="$STORAGE_KEY" \
        AZURE_CONTAINER="$FILE_SHARE" \
    --azure-file-volume-account-name "$STORAGE_ACCOUNT" \
    --azure-file-volume-account-key "$STORAGE_KEY" \
    --azure-file-volume-share-name "$FILE_SHARE" \
    --azure-file-volume-mount-path /data \
    --ip-address Public \
    --location "$LOCATION" \
    --restart-policy Always \
    --output none

# ── Get IP and FQDN ───────────────────────────────────────────────
HUB_IP=$(az container show \
    --name "$CONTAINER_NAME" \
    --resource-group "$RG" \
    --query 'ipAddress.ip' -o tsv)

HUB_FQDN=$(az container show \
    --name "$CONTAINER_NAME" \
    --resource-group "$RG" \
    --query 'ipAddress.fqdn' -o tsv)

# ── Verify mount succeeded ────────────────────────────────────────
echo "▶ Checking for volume mount errors..."
MOUNT_ERR=$(az container show --name "$CONTAINER_NAME" --resource-group "$RG" \
    --query "instanceView.events[?contains(message,'Failed') && contains(message,'Azure File Volume')].message" -o tsv 2>/dev/null || true)

if [ -n "$MOUNT_ERR" ]; then
    echo "❌ Azure File Volume mount error detected:"
    echo "   $MOUNT_ERR"
    echo ""
    echo "   Check storage key and share name, then re-run this script."
    exit 1
fi

# ── Poll health endpoint ──────────────────────────────────────────
echo "▶ Waiting for hub to respond at https://$HUB_IP:$HUB_PORT/api/health..."
for i in $(seq 1 24); do
    HEALTH=$(curl -sk --max-time 8 "https://$HUB_IP:$HUB_PORT/api/health" 2>/dev/null || true)
    if echo "$HEALTH" | grep -q '"status":"ok"'; then
        echo "  ✓ Hub is healthy"
        break
    fi
    if [ "$i" -eq 24 ]; then
        echo "❌ Hub did not respond after 120s. Check container logs:"
        echo "   az container logs --name $CONTAINER_NAME --resource-group $RG"
        exit 1
    fi
    printf "  [%02d/24] waiting...\r" "$i"
    sleep 5
done

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ✅ Hub redeployed successfully!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  URL  : https://$HUB_FQDN:$HUB_PORT"
echo "  IP   : $HUB_IP"
echo "  FQDN : $DNS_LABEL.$LOCATION.azurecontainer.io"
echo ""
echo "  ⚠  IP may have changed but FQDN stays stable — spoke config unchanged."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
