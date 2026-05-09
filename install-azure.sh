#!/usr/bin/env bash
set -euo pipefail

if ! command -v az >/dev/null 2>&1; then
  echo "Azure CLI (az) is required." >&2
  exit 1
fi

RG=${RG:-client-sim-central-rg}
LOCATION=${LOCATION:-eastus}
ACR_NAME=${ACR_NAME:-clientsimcentral$RANDOM}
APP_NAME=${APP_NAME:-client-sim-central}
CONTAINER_ENV_NAME=${CONTAINER_ENV_NAME:-client-sim-central-env}
PG_SERVER_NAME=${PG_SERVER_NAME:-clientsimpg$RANDOM}
PG_DB=${PG_DB:-csw}
PG_USER=${PG_USER:-cswadmin}
IMAGE_TAG=${IMAGE_TAG:-latest}
SECRET_KEY=${SECRET_KEY:-$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(48))
PY
)}
PG_PASSWORD=${PG_PASSWORD:-$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(24))
PY
)}

echo "Using resource group: $RG"
echo "Using location: $LOCATION"
echo "Using ACR: $ACR_NAME"
echo "Using Container App: $APP_NAME"
echo "Using PostgreSQL server: $PG_SERVER_NAME"

az group create --name "$RG" --location "$LOCATION"
az acr create --name "$ACR_NAME" --resource-group "$RG" --sku Basic --admin-enabled true
az acr build --registry "$ACR_NAME" --image "$APP_NAME:$IMAGE_TAG" .

az postgres flexible-server create \
  --resource-group "$RG" \
  --name "$PG_SERVER_NAME" \
  --location "$LOCATION" \
  --admin-user "$PG_USER" \
  --admin-password "$PG_PASSWORD" \
  --sku-name Standard_B1ms \
  --tier Burstable \
  --version 16 \
  --storage-size 32 \
  --yes

az postgres flexible-server db create --resource-group "$RG" --server-name "$PG_SERVER_NAME" --database-name "$PG_DB"
az postgres flexible-server firewall-rule create \
  --resource-group "$RG" \
  --name "$PG_SERVER_NAME" \
  --rule-name allow-azure-services \
  --start-ip-address 0.0.0.0 \
  --end-ip-address 0.0.0.0

az containerapp env create --name "$CONTAINER_ENV_NAME" --resource-group "$RG" --location "$LOCATION"

ACR_LOGIN_SERVER=$(az acr show --name "$ACR_NAME" --resource-group "$RG" --query loginServer --output tsv)
ACR_USERNAME=$(az acr credential show --name "$ACR_NAME" --resource-group "$RG" --query username --output tsv)
ACR_PASSWORD=$(az acr credential show --name "$ACR_NAME" --resource-group "$RG" --query passwords[0].value --output tsv)
DATABASE_URL="postgresql://${PG_USER}:${PG_PASSWORD}@${PG_SERVER_NAME}.postgres.database.azure.com:5432/${PG_DB}?sslmode=require"

az containerapp create \
  --name "$APP_NAME" \
  --resource-group "$RG" \
  --environment "$CONTAINER_ENV_NAME" \
  --image "$ACR_LOGIN_SERVER/$APP_NAME:$IMAGE_TAG" \
  --registry-server "$ACR_LOGIN_SERVER" \
  --registry-username "$ACR_USERNAME" \
  --registry-password "$ACR_PASSWORD" \
  --target-port 8000 \
  --ingress external \
  --env-vars DATABASE_URL="$DATABASE_URL" SECRET_KEY="$SECRET_KEY"

APP_FQDN=$(az containerapp show --name "$APP_NAME" --resource-group "$RG" --query properties.configuration.ingress.fqdn --output tsv)

echo
echo "Client-Sim Central deployed:"
echo "  URL: https://$APP_FQDN"
echo "  DATABASE_URL: $DATABASE_URL"
echo "  SECRET_KEY: $SECRET_KEY"
