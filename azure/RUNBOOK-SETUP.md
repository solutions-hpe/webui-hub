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

## One-Time Setup

### 1. Create an Automation Account (if you don't have one)
```bash
az automation account create \
  --name cs-hub-automation \
  --resource-group LRB \
  --location westus3
```

### 2. Enable System-Assigned Managed Identity
```bash
az automation account update \
  --name cs-hub-automation \
  --resource-group LRB \
  --assign-identity
```

### 3. Grant Contributor access to the LRB resource group
```bash
# Get the Managed Identity principal ID
PRINCIPAL=$(az automation account show \
  --name cs-hub-automation \
  --resource-group LRB \
  --query identity.principalId -o tsv)

# Get your subscription ID
SUB=$(az account show --query id -o tsv)

az role assignment create \
  --assignee "$PRINCIPAL" \
  --role Contributor \
  --scope "/subscriptions/$SUB/resourceGroups/LRB"
```

### 4. Create Automation Variables

In Azure Portal → Automation Account → Variables:

| Name | Type | Encrypted | Value |
|------|------|-----------|-------|
| `LastDeployedSHA` | String | No | *(leave blank)* |
| `HubAdminPassword` | String | Yes | your admin password |
| `HubWebuiSecretKey` | String | Yes | your WEBUI_SECRET_KEY value |
| `HubSecretKey` | String | Yes | your SECRET_KEY value |
| `StorageAccountKey` | String | Yes | Azure Storage Account key for `lrbcshub` |

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
# Create schedule (starts next hour, repeats every hour)
az automation schedule create \
  --automation-account-name cs-hub-automation \
  --resource-group LRB \
  --name hourly \
  --frequency Hour \
  --interval 1

# Link schedule to runbook
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

## Manual Trigger

To force an immediate redeploy without waiting for the hourly schedule:
```bash
# Optional: clear last SHA to force redeploy regardless of commit
az automation variable set \
  --automation-account-name cs-hub-automation \
  --resource-group LRB \
  --name LastDeployedSHA \
  --value ""

# Start the runbook
az automation runbook start \
  --automation-account-name cs-hub-automation \
  --resource-group LRB \
  --name redeploy-hub
```
