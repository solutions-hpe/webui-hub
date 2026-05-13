#!/usr/bin/env bash
# ── Hub — Azure Container Instance Deployment ─────────────────────
# Deploys the hub to Azure Container Instance with Azure File Share for persistence.
#
# Usage:
#   export WEBUI_SECRET_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
#   export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
#   export ENCRYPTION_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
#   export INSTALLER_API_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
#   export ADMIN_PASSWORD=your-secure-password
#   bash deploy-azure.sh
#
# Required env vars: WEBUI_SECRET_KEY, SECRET_KEY, ENCRYPTION_KEY, INSTALLER_API_KEY, ADMIN_PASSWORD
# Optional env vars: RG, LOCATION, ACR_NAME, CONTAINER_NAME, STORAGE_ACCOUNT, FILE_SHARE

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────
RG="${RG:-hub-rg}"
LOCATION="${LOCATION:-eastus}"
ACR_NAME="${ACR_NAME:-hubregistry$RANDOM}"
CONTAINER_NAME="${CONTAINER_NAME:-hub}"
STORAGE_ACCOUNT="${STORAGE_ACCOUNT:-hubstorage$RANDOM}"
FILE_SHARE="${FILE_SHARE:-hubdata}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
HUB_PORT="${HUB_PORT:-8443}"
DNS_LABEL="${DNS_LABEL:-hub-$RANDOM}"

# ── Validate required secrets ──────────────────────────────────────
if [ -z "${WEBUI_SECRET_KEY:-}" ]; then
    echo "❌ WEBUI_SECRET_KEY is required."
    echo "   Generate with: python3 -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
    exit 1
fi
if [ -z "${SECRET_KEY:-}" ]; then
    echo "❌ SECRET_KEY is required."
    echo "   Generate with: python3 -c \"import secrets; print(secrets.token_urlsafe(48))\""
    exit 1
fi
if [ -z "${ADMIN_PASSWORD:-}" ]; then
    echo "❌ ADMIN_PASSWORD is required."
    exit 1
fi
if [ -z "${ENCRYPTION_KEY:-}" ]; then
    echo "❌ ENCRYPTION_KEY is required."
    echo "   Generate with: python3 -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
    exit 1
fi
if [ -z "${INSTALLER_API_KEY:-}" ]; then
    echo "❌ INSTALLER_API_KEY is required."
    echo "   Generate with: python3 -c \"import secrets; print(secrets.token_urlsafe(32))\""
    exit 1
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Hub — Azure Container Instance Deploy"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Resource Group : $RG"
echo "  Location       : $LOCATION"
echo "  ACR            : $ACR_NAME"
echo "  Container      : $CONTAINER_NAME"
echo "  Storage        : $STORAGE_ACCOUNT / $FILE_SHARE"
echo "  DNS Label      : $DNS_LABEL"
echo ""

# ── Prerequisite check ────────────────────────────────────────────
if ! command -v az &>/dev/null; then
    echo "❌ Azure CLI (az) not found. Install from https://aka.ms/installazurecli"
    exit 1
fi

# ── Resource Group ────────────────────────────────────────────────
echo "▶ Creating resource group..."
az group create --name "$RG" --location "$LOCATION" --output none

# ── Container Registry ────────────────────────────────────────────
echo "▶ Creating container registry..."
az acr create --name "$ACR_NAME" --resource-group "$RG" --sku Basic --admin-enabled true --output none

echo "▶ Building and pushing image..."
az acr build --registry "$ACR_NAME" --image "hub:$IMAGE_TAG" . --output none

ACR_SERVER=$(az acr show --name "$ACR_NAME" --resource-group "$RG" --query loginServer -o tsv)
ACR_USER=$(az acr credential show --name "$ACR_NAME" --resource-group "$RG" --query username -o tsv)
ACR_PASS=$(az acr credential show --name "$ACR_NAME" --resource-group "$RG" --query 'passwords[0].value' -o tsv)

# ── Azure File Share (persistent /data) ───────────────────────────
echo "▶ Creating storage account and file share..."
az storage account create \
    --name "$STORAGE_ACCOUNT" \
    --resource-group "$RG" \
    --location "$LOCATION" \
    --sku Standard_LRS \
    --output none

STORAGE_KEY=$(az storage account keys list \
    --account-name "$STORAGE_ACCOUNT" \
    --resource-group "$RG" \
    --query '[0].value' -o tsv)

az storage share create \
    --name "$FILE_SHARE" \
    --account-name "$STORAGE_ACCOUNT" \
    --account-key "$STORAGE_KEY" \
    --output none

# ── Deploy ACI ────────────────────────────────────────────────────
echo "▶ Deploying Azure Container Instance..."
az container create \
    --resource-group "$RG" \
    --name "$CONTAINER_NAME" \
    --image "$ACR_SERVER/hub:$IMAGE_TAG" \
    --registry-login-server "$ACR_SERVER" \
    --registry-username "$ACR_USER" \
    --registry-password "$ACR_PASS" \
    --dns-name-label "$DNS_LABEL" \
    --ports "$HUB_PORT" \
    --protocol TCP \
    --os-type Linux \
    --cpu 1 \
    --memory 1.5 \
    --environment-variables \
        DATA_DIR=/data \
        ADMIN_PASSWORD="$ADMIN_PASSWORD" \
    --secure-environment-variables \
        WEBUI_SECRET_KEY="$WEBUI_SECRET_KEY" \
        SECRET_KEY="$SECRET_KEY" \
        ENCRYPTION_KEY="$ENCRYPTION_KEY" \
        INSTALLER_API_KEY="$INSTALLER_API_KEY" \
    --azure-file-volume-account-name "$STORAGE_ACCOUNT" \
    --azure-file-volume-account-key "$STORAGE_KEY" \
    --azure-file-volume-share-name "$FILE_SHARE" \
    --azure-file-volume-mount-path /data \
    --restart-policy Always \
    --output none

# ── Output ────────────────────────────────────────────────────────
FQDN=$(az container show \
    --resource-group "$RG" \
    --name "$CONTAINER_NAME" \
    --query ipAddress.fqdn -o tsv)

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ✅ Hub deployed successfully!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  URL      : https://$FQDN:$HUB_PORT"
echo "  Admin    : admin / [your ADMIN_PASSWORD]"
echo ""
echo "  ⚠  Self-signed TLS certificate — browsers will warn."
echo "     Accept the warning or add to trusted roots."
echo ""
echo "  Save these values securely:"
echo "  WEBUI_SECRET_KEY : [set from env]"
echo "  SECRET_KEY       : [set from env]"
echo "  ENCRYPTION_KEY   : [set from env]"
echo "  INSTALLER_API_KEY: [set from env]"
echo "  ACR_NAME         : $ACR_NAME"
echo "  STORAGE_ACCOUNT  : $STORAGE_ACCOUNT"
echo "  FILE_SHARE       : $FILE_SHARE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
