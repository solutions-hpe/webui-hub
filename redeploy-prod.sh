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

# ── Check for unpushed commits ────────────────────────────────────
echo "▶ Checking for unpushed commits..."
cd "$SCRIPT_DIR"

# Check main repo
MAIN_UNPUSHED=$(git log @{u}.. --oneline 2>/dev/null | wc -l | xargs)
if [ "$MAIN_UNPUSHED" -gt 0 ]; then
    echo "  ⚠  Main repo has $MAIN_UNPUSHED unpushed commit(s)"
    echo "  ▶  Pushing main repo to origin..."
    git push origin main || {
        echo "❌ Failed to push main repo"
        exit 1
    }
    echo "  ✓  Main repo pushed"
fi

# Check frontend submodule
if [ -d "$SCRIPT_DIR/frontend" ]; then
    cd "$SCRIPT_DIR/frontend"
    # Submodule may be in detached HEAD with no upstream — only check if upstream exists
    FRONTEND_UNPUSHED=0
    if git rev-parse @{u} &>/dev/null; then
        FRONTEND_UNPUSHED=$(git log @{u}.. --oneline | wc -l | xargs)
    fi
    if [ "$FRONTEND_UNPUSHED" -gt 0 ]; then
        echo "  ⚠  Frontend submodule has $FRONTEND_UNPUSHED unpushed commit(s)"
        echo "  ▶  Pushing frontend submodule to origin..."
        git push origin main || {
            echo "❌ Failed to push frontend submodule"
            exit 1
        }
        echo "  ✓  Frontend submodule pushed"
        
        # Update parent repo's submodule pointer and push
        cd "$SCRIPT_DIR"
        if git diff --quiet HEAD -- frontend; then
            echo "  ℹ  Parent repo submodule pointer already up to date"
        else
            echo "  ▶  Updating parent repo submodule pointer..."
            git add frontend
            git commit -m "Update frontend submodule pointer

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>" || true
            git push origin main || {
                echo "❌ Failed to push parent repo after submodule update"
                exit 1
            }
            echo "  ✓  Parent repo submodule pointer updated and pushed"
        fi
    fi
    cd "$SCRIPT_DIR"
fi

echo "  ✓  All commits pushed"

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

echo "▶ Checking hub.key on Azure Files share..."
KEY_FILE_EXISTS=$(az storage file exists \
    --share-name "$FILE_SHARE" \
    --path "hub.key" \
    --account-name "$STORAGE_ACCOUNT" \
    --account-key "$STORAGE_KEY" \
    --query 'exists' -o tsv 2>/dev/null || echo "unknown")
if [ "$KEY_FILE_EXISTS" = "true" ]; then
    echo "  ✓ hub.key exists — hub will manage its own key (not overwriting)"
else
    echo "  ℹ hub.key absent or check failed — hub will create it from WEBUI_SECRET_KEY on first startup"
    echo "  (Do NOT seed hub.key here: the hub writes its own key on first use to prevent mismatches)"
fi

echo "▶ Fetching ACR credentials..."
ACR_PWD=$(az acr credential show --name "$ACR_NAME" --query 'passwords[0].value' -o tsv)

# ── Import GitHub-built image from ghcr.io into ACR ──────────────
# GitHub Actions builds the image (correctly handling the cs-webui submodule)
# and pushes to ghcr.io on every push to main. We import that image into ACR
# rather than building locally — GitHub is the single source of truth for builds.
GHCR_IMAGE="ghcr.io/solutions-hpe/webui-hub:main"
GHCR_USER="solutions-hpe"
# Read GHCR_TOKEN from secrets file (must be a PAT with read:packages scope)
if [ -z "${GHCR_TOKEN:-}" ]; then
    echo "❌ GHCR_TOKEN not set in $SECRETS_FILE"
    exit 1
fi

echo "▶ Waiting for GitHub Actions build to complete..."
# Poll GHA workflow runs until the latest push to main has a completed run
REPO="solutions-hpe/webui-hub"
COMMIT_SHA=$(git -C "$SCRIPT_DIR" rev-parse HEAD)
for i in $(seq 1 30); do
    STATUS=$(curl -s \
        -H "Authorization: token $GHCR_TOKEN" \
        -H "Accept: application/vnd.github+json" \
        "https://api.github.com/repos/$REPO/actions/runs?branch=main&per_page=5" \
        | python3 -c "
import sys, json
data = json.load(sys.stdin)
runs = data.get('workflow_runs', [])
commit = '$COMMIT_SHA'
for r in runs:
    if r.get('head_sha', '').startswith(commit[:8]):
        print(r.get('conclusion') or r.get('status'))
        break
else:
    # No matching run found yet; check most recent
    if runs:
        r = runs[0]
        print(r.get('conclusion') or r.get('status'))
    else:
        print('pending')
" 2>/dev/null || echo "pending")
    if [ "$STATUS" = "success" ]; then
        echo "  ✓ GitHub Actions build completed"
        GHA_BUILD_OK=true
        break
    elif [ "$STATUS" = "failure" ] || [ "$STATUS" = "cancelled" ]; then
        echo "  ⚠ GitHub Actions build status: $STATUS — skipping ghcr.io import, using existing ACR image"
        GHA_BUILD_OK=false
        break
    fi
    echo "  ⏳ Build status: $STATUS (attempt $i/30)..."
    sleep 10
done

if [ "${GHA_BUILD_OK:-false}" = "true" ]; then
    echo "▶ Importing image from ghcr.io into ACR..."
    az acr import \
        --name "$ACR_NAME" \
        --source "$GHCR_IMAGE" \
        --image "$IMAGE" \
        --username "$GHCR_USER" \
        --password "$GHCR_TOKEN" \
        --force \
        --output none
    echo "  ✓ Image imported: $ACR_SERVER/$IMAGE"
else
    echo "▶ Using existing ACR image (ghcr.io import skipped due to build failure)"
fi

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
        DATA_DIR=/data \
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
