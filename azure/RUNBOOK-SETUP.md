# Azure Automation Runbook Setup

## Overview

The `redeploy-runbook.ps1` script runs hourly in Azure Automation. It checks GitHub for new commits on the `lrb` branch — if a new commit exists since last deploy, it deletes and recreates the ACI container to pull the updated image.

**CI Pipeline flow:**
```
git push → GitHub Actions builds image → pushes to ghcr.io/solutions-hpe/webui-hub:lrb
                                             ↓ (within ~1 hour)
                            Azure Automation detects new SHA → redeploys ACI
```

---

## Authentication model

The runbook authenticates to Azure using a **Service Principal** stored as an Automation Credential asset named `AzureLogin`:

| Field | Value |
|-------|-------|
| Username | SP Application (client) ID — `07f16589-a3ac-4a85-9d9c-cecf10801f53` |
| Password | SP client secret |
| Tenant | `2e5cab22-02d0-4fe4-8ceb-f9faa02999c1` |

The SP (`cs-hub-automation-sp`) must have the **Contributor** role on resource group `LRB`.

---

## One-Time Setup

### 1. Create an Automation Account (if you don't have one)
```bash
az automation account create \
  --name cs-hub-automation \
  --resource-group LRB \
  --location westus3
```

### 2. Create the Service Principal

```bash
az ad sp create-for-rbac \
  --name cs-hub-automation-sp \
  --role Contributor \
  --scopes /subscriptions/<SUB_ID>/resourceGroups/LRB
```

Save the `appId` and `password` output — you will need them in step 3.

### 3. Create the AzureLogin Credential asset

In **Azure Portal → Automation Account → Credentials → Add a credential**:

| Field | Value |
|-------|-------|
| Name | `AzureLogin` |
| Username | SP `appId` from step 2 |
| Password | SP `password` from step 2 |

### 4. Create Automation Variables

> **Important:** Variables must be created with non-empty values. Creating a variable without a value and editing it later via CLI may leave the stored value empty, causing `ConvertTo-SecureString` errors at runtime. Use the Portal or the REST API method shown below to set values.

**Via Azure Portal** → Automation Account → Variables → Add variable:

| Name | Type | Encrypted | Value |
|------|------|-----------|-------|
| `LastDeployedSHA` | String | No | *(leave blank — runbook will fill this in)* |
| `HubAdminPassword` | String | Yes | your `ADMIN_PASSWORD` value |
| `HubWebuiSecretKey` | String | Yes | your `WEBUI_SECRET_KEY` value |
| `HubSecretKey` | String | Yes | your `SECRET_KEY` value |
| `StorageAccountKey` | String | Yes | Azure Storage Account key for `lrbcshub` |

**Via REST API** (use this if the Portal method doesn't work or you need to update values):

```bash
SUB="1480d28a-9917-4fdd-9ccc-96513a1c59f2"
BASE="https://management.azure.com/subscriptions/$SUB/resourceGroups/LRB/providers/Microsoft.Automation/automationAccounts/cs-hub-automation"
API="?api-version=2022-08-08"

set_var() {
  az rest --method PATCH \
    --url "${BASE}/variables/${1}${API}" \
    --body "{\"properties\":{\"value\":\"\\\"${2}\\\"\",\"isEncrypted\":true}}"
}

set_var "HubAdminPassword"  "your-admin-password"
set_var "HubWebuiSecretKey" "your-webui-secret-key"
set_var "HubSecretKey"      "your-secret-key"
set_var "StorageAccountKey" "$(az storage account keys list --account-name lrbcshub --resource-group LRB --query '[0].value' -o tsv)"
```

To get the storage key:
```bash
az storage account keys list \
  --account-name lrbcshub \
  --resource-group LRB \
  --query "[0].value" -o tsv
```

### 5. Import the Runbook

```bash
az automation runbook create \
  --automation-account-name cs-hub-automation \
  --resource-group LRB \
  --name redeploy-hub \
  --type PowerShell

az automation runbook replace-content \
  --automation-account-name cs-hub-automation \
  --resource-group LRB \
  --name redeploy-hub \
  --content @azure/redeploy-runbook.ps1

az automation runbook publish \
  --automation-account-name cs-hub-automation \
  --resource-group LRB \
  --name redeploy-hub
```

### 6. Create Hourly Schedule

```bash
az automation schedule create \
  --automation-account-name cs-hub-automation \
  --resource-group LRB \
  --name hourly \
  --frequency Hour \
  --interval 1

az automation job-schedule create \
  --automation-account-name cs-hub-automation \
  --resource-group LRB \
  --runbook-name redeploy-hub \
  --schedule-name hourly
```

---

## Updating the Runbook

If you change `redeploy-runbook.ps1`, push to GitHub and run:
```bash
az automation runbook replace-content \
  --automation-account-name cs-hub-automation \
  --resource-group LRB \
  --name redeploy-hub \
  --content @azure/redeploy-runbook.ps1

az automation runbook publish \
  --automation-account-name cs-hub-automation \
  --resource-group LRB \
  --name redeploy-hub
```

---

## Manual Trigger

> Note: `az automation variable set` is not available in all CLI versions. Use the REST API method below instead.

```bash
SUB="1480d28a-9917-4fdd-9ccc-96513a1c59f2"
BASE="https://management.azure.com/subscriptions/$SUB/resourceGroups/LRB/providers/Microsoft.Automation/automationAccounts/cs-hub-automation"

# Optional: clear last SHA to force redeploy regardless of commit
az rest --method PATCH \
  --url "${BASE}/variables/LastDeployedSHA?api-version=2022-08-08" \
  --body '{"properties":{"value":"\"\"","isEncrypted":false}}'

# Trigger the runbook
az rest --method PUT \
  --url "${BASE}/jobs/manual-trigger-$(date +%s)?api-version=2022-08-08" \
  --body '{"properties":{"runbook":{"name":"redeploy-hub"},"parameters":{},"runOn":""}}'
```

Check job status:
```bash
az automation job list \
  --resource-group LRB \
  --automation-account-name cs-hub-automation \
  --query "[0].{status:status, jobId:jobId}" -o table
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `AADSTS700016: Application not found` | `AzureLogin` credential has wrong username (e.g. a UPN instead of the SP `appId`) | Update the credential: Username = SP `appId` |
| `Please provide a valid tenant or a valid subscription` | SP has no role on the subscription/RG | Assign Contributor role to the SP on RG `LRB` |
| `Cannot bind argument to parameter 'String' because it is an empty string` | One or more Automation Variables has an empty value | Re-set all variables using the REST API method in step 4 |
| Job completes but container not redeployed | `LastDeployedSHA` matches latest GitHub commit | Clear `LastDeployedSHA` using the REST PATCH above, then retrigger |
