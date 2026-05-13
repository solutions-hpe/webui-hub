<#
.SYNOPSIS
    Polls GitHub for a new image on the lrb branch and redeploys the ACI hub container if changed.

.DESCRIPTION
    Runs on a scheduled Azure Automation schedule (default: hourly, can be changed to nightly).
    Compares the latest commit SHA on the webui-hub lrb branch against the last
    deployed SHA (stored as an Automation Account Variable).
    If a new commit is detected, deletes and recreates the ACI container so it
    pulls the updated ghcr.io image.

.SETUP
    Azure Automation Account variables required (all Encrypted unless noted):
      LastDeployedSHA       (String, not encrypted) — initially blank
      HubAdminPassword      (String, encrypted)
      HubWebuiSecretKey     (String, encrypted)
      HubSecretKey          (String, encrypted)
      StorageAccountKey     (String, encrypted)

    The Automation Account must have a Credential asset named "AzureLogin":
      Username : Application (client) ID of the "cs-hub-automation-sp" service principal
                 (e.g. 07f16589-a3ac-4a85-9d9c-cecf10801f53)
      Password : Client secret generated for the service principal

    The service principal must have the "Contributor" role on the LRB resource group.
    Tenant ID is hardcoded below — update if it changes.
#>

$ErrorActionPreference = "Stop"

# ── Config ────────────────────────────────────────────────────────────────────
$GH_REPO        = "solutions-hpe/webui-hub"
$GH_BRANCH      = "lrb"
$IMAGE          = "ghcr.io/solutions-hpe/webui-hub:lrb"
$RG             = "LRB"
$CONTAINER_NAME = "cs-hub-lrb"
$LOCATION       = "westus3"
$DNS_LABEL      = "cs-hub-lrb"
$HUB_PORT       = 8443
$CPU            = 1.0
$MEMORY_GB      = 1.5
$STORAGE_ACCOUNT = "lrbcshub"
$FILE_SHARE      = "lrbhubdata"

# ── Authenticate via service principal ───────────────────────────────────────
# AzureLogin credential: Username = SP Application (client) ID, Password = client secret
Write-Output "Authenticating as service principal..."
$spCred    = Get-AutomationPSCredential -Name "AzureLogin"
$tenantId  = "2e5cab22-02d0-4fe4-8ceb-f9faa02999c1"
$appId     = $spCred.UserName
$appSecret = $spCred.GetNetworkCredential().Password | ConvertTo-SecureString -AsPlainText -Force
$psCred    = New-Object System.Management.Automation.PSCredential($appId, $appSecret)
Connect-AzAccount -ServicePrincipal -Credential $psCred -Tenant $tenantId | Out-Null
Set-AzContext -SubscriptionId "1480d28a-9917-4fdd-9ccc-96513a1c59f2" | Out-Null
Write-Output "Authenticated as SP: $appId"

# ── Check GitHub for latest commit SHA ───────────────────────────────────────
Write-Output "Checking GitHub branch: $GH_BRANCH..."
$apiUrl    = "https://api.github.com/repos/$GH_REPO/commits/$GH_BRANCH"
$response  = Invoke-RestMethod -Uri $apiUrl -Headers @{ "User-Agent" = "AzureAutomation" }
$latestSHA = $response.sha

$lastSHA = Get-AutomationVariable -Name "LastDeployedSHA" -ErrorAction SilentlyContinue
Write-Output "Latest SHA : $latestSHA"
Write-Output "Last deployed: $lastSHA"

if ($latestSHA -eq $lastSHA) {
    Write-Output "No new commits — skipping redeploy."
    exit 0
}

Write-Output "New commit detected — redeploying ACI container..."

# ── Read secrets from Automation Variables ────────────────────────────────────
$adminPassword   = Get-AutomationVariable -Name "HubAdminPassword"
$webuiSecretKey  = Get-AutomationVariable -Name "HubWebuiSecretKey"
$secretKey       = Get-AutomationVariable -Name "HubSecretKey"
$storageKey      = Get-AutomationVariable -Name "StorageAccountKey"

# ── Delete existing container ─────────────────────────────────────────────────
Write-Output "Deleting existing container: $CONTAINER_NAME..."
Remove-AzContainerGroup -ResourceGroupName $RG -Name $CONTAINER_NAME -ErrorAction SilentlyContinue
Start-Sleep -Seconds 10

# ── Recreate container with latest image ──────────────────────────────────────
Write-Output "Creating container with image: $IMAGE..."

$envVars = @(
    New-AzContainerInstanceEnvironmentVariableObject -Name "ADMIN_USERNAME"   -Value "admin"
    New-AzContainerInstanceEnvironmentVariableObject -Name "DATA_DIR"         -Value "/data"
    New-AzContainerInstanceEnvironmentVariableObject -Name "HUB_HOSTNAME"     -Value "cs-hub.lrbtechnologies.com"
    New-AzContainerInstanceEnvironmentVariableObject -Name "ADMIN_PASSWORD"   -SecureValue (ConvertTo-SecureString $adminPassword  -AsPlainText -Force)
    New-AzContainerInstanceEnvironmentVariableObject -Name "WEBUI_SECRET_KEY" -SecureValue (ConvertTo-SecureString $webuiSecretKey -AsPlainText -Force)
    New-AzContainerInstanceEnvironmentVariableObject -Name "SECRET_KEY"       -SecureValue (ConvertTo-SecureString $secretKey      -AsPlainText -Force)
)

$port = New-AzContainerInstancePortObject -Port $HUB_PORT -Protocol TCP

$volumeMount = New-AzContainerInstanceVolumeMountObject -Name "azurefile" -MountPath "/data"

$container = New-AzContainerInstanceObject `
    -Name $CONTAINER_NAME `
    -Image $IMAGE `
    -RequestCpu $CPU `
    -RequestMemoryInGb $MEMORY_GB `
    -Port @($port) `
    -EnvironmentVariable $envVars `
    -VolumeMount @($volumeMount)

$volume = New-AzContainerGroupVolumeObject `
    -Name "azurefile" `
    -AzureFileShareName $FILE_SHARE `
    -AzureFileStorageAccountName $STORAGE_ACCOUNT `
    -AzureFileStorageAccountKey (ConvertTo-SecureString $storageKey -AsPlainText -Force)

New-AzContainerGroup `
    -ResourceGroupName $RG `
    -Name $CONTAINER_NAME `
    -Location $LOCATION `
    -Container @($container) `
    -OsType Linux `
    -RestartPolicy Always `
    -IpAddressType Public `
    -IpAddressDnsNameLabel $DNS_LABEL `
    -Volume @($volume) | Out-Null

# ── Wait for container to become healthy ─────────────────────────────────────
Write-Output "Waiting for container to become healthy..."
$healthUrl  = "https://${DNS_LABEL}.westus3.azurecontainer.io:${HUB_PORT}/api/health"
$maxWait    = 600   # 10 minutes
$interval   = 20
$elapsed    = 0
$ready      = $false

while ($elapsed -lt $maxWait) {
    Start-Sleep -Seconds $interval
    $elapsed += $interval
    try {
        $resp = Invoke-RestMethod -Uri $healthUrl -SkipCertificateCheck -TimeoutSec 8 -ErrorAction Stop
        if ($resp.version) {
            Write-Output "✅ Container healthy after ${elapsed}s — version $($resp.version)"
            $ready = $true
            break
        }
    } catch { }
    Write-Output "   ${elapsed}s elapsed — not ready yet..."
}

if (-not $ready) {
    Write-Warning "⚠️  Container did not respond within ${maxWait}s — check ACI logs."
    # Still update SHA so we don't redeploy in a loop; operator should investigate.
}

# ── Update last deployed SHA ──────────────────────────────────────────────────
Set-AutomationVariable -Name "LastDeployedSHA" -Value $latestSHA
Write-Output "✅ Redeployed $CONTAINER_NAME with commit $latestSHA"
