# =============================================================================
# SecOps GitOps Lab — Setup Script
# Supports two deployment targets:
#   1. Local  — k3s via k3d inside Docker Desktop + WSL2
#   2. Cloud  — Azure AKS via Terraform
# =============================================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Colours ──────────────────────────────────────────────────────────────────
function Write-Header  { param($msg) Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-Step    { param($msg) Write-Host "  -> $msg" -ForegroundColor White }
function Write-Success { param($msg) Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Warn    { param($msg) Write-Host "  [WARN] $msg" -ForegroundColor Yellow }
function Write-Fail    { param($msg) Write-Host "  [FAIL] $msg" -ForegroundColor Red }
function Write-Info    { param($msg) Write-Host "  [INFO] $msg" -ForegroundColor DarkGray }

# ── Config ───────────────────────────────────────────────────────────────────
$CONFIG_FILE    = "$PSScriptRoot\..\config.yaml"
$MIN_KERNEL     = [Version]"5.8"
$NAMESPACE      = "secops-lab"
#$ARGOCD_VERSION = "5.51.6"   # Helm chart version
#$KYVERNO_VERSION= "3.1.4"
#$FALCO_VERSION  = "3.8.7"
#$ARGOCD_VERSION="7.6.12"     # Helm chart version
#$KYVERNO_VERSION="3.2.6"     # Helm chart version
#$FALCO_VERSION="4.10.0"      # Helm chart version


# ── Banner ───────────────────────────────────────────────────────────────────
Clear-Host
Write-Host @"

  ____            ___                  ____ _ _   ___
 / ___|  ___  ___/ _ \ _ __  ___     / ___(_) |_/ _ \ _ __  ___
 \___ \ / _ \/ __| | | | '_ \/ __|   | |  | | __| | | | '_ \/ __|
  ___) |  __/ (__| |_| | |_) \__ \   | |__| | |_| |_| | |_) \__ \
 |____/ \___|\___|\___/| .__/|___/    \____|_|\__|\___/| .__/|___/
                        |_|                              |_|
  SecOps GitOps Lab — Setup
"@ -ForegroundColor Cyan

Write-Host "  Interactive setup for local k3s or Azure AKS deployment.`n" -ForegroundColor DarkGray

# ── Target selection ─────────────────────────────────────────────────────────
Write-Header "Deployment Target"
Write-Host ""
Write-Host "  [1] Local   — k3s via k3d (Docker Desktop + WSL2, zero cost)" -ForegroundColor White
Write-Host "  [2] Cloud   — Azure AKS   (Terraform, ~`$8-10/mo with auto-stop)" -ForegroundColor White
Write-Host ""

do {
    $choice = Read-Host "  Select target [1/2]"
} while ($choice -notin @("1","2"))

$TARGET = if ($choice -eq "1") { "k3s" } else { "aks" }
Write-Success "Target selected: $TARGET"

# =============================================================================
# SHARED HELPERS
# =============================================================================

function Test-CommandExists {
    param($cmd)
    $null -ne (Get-Command $cmd -ErrorAction SilentlyContinue)
}

function Assert-CommandExists {
    param($cmd, $installHint)
    if (-not (Test-CommandExists $cmd)) {
        Write-Fail "$cmd not found. $installHint"
        exit 1
    }
    Write-Success "$cmd found"
}

function Invoke-Helm {
    param([string[]]$Arguments)
    & helm @Arguments
    if ($LASTEXITCODE -ne 0) { throw "helm command failed: helm $($Arguments -join ' ')" }
}

function Invoke-Kubectl {
    param([string[]]$Arguments)
    & kubectl @Arguments
    if ($LASTEXITCODE -ne 0) { throw "kubectl command failed: kubectl $($Arguments -join ' ')" }
}

# =============================================================================
# LOCAL PATH — k3s via k3d
# =============================================================================

function Install-LocalCluster {

    Write-Header "Checking Local Prerequisites"

    # 1. Docker Desktop
    Write-Step "Checking Docker Desktop..."
    Assert-CommandExists "docker" "Install Docker Desktop from https://www.docker.com/products/docker-desktop"
    $dockerRunning = docker info 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "Docker Desktop is installed but not running. Please start it and re-run."
        exit 1
    }
    Write-Success "Docker Desktop running"

    # 2. WSL2
    Write-Step "Checking WSL2..."
    $wslOutput = wsl --status 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "WSL2 not found. Enable it with: wsl --install"
        exit 1
    }
    Write-Success "WSL2 available"

    # 3. WSL2 kernel version (required for Falco eBPF)
    Write-Step "Checking WSL2 kernel version (need $MIN_KERNEL+ for Falco eBPF)..."
    $kernelRaw = wsl -- uname -r 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "Could not read WSL2 kernel version. Ensure a Linux distro is installed: wsl --install -d Ubuntu"
        exit 1
    }

    # Parse kernel version — strip anything after - (e.g. 5.15.90.1-microsoft-standard)
    $kernelClean = ($kernelRaw -split "-")[0].Trim()
    # Pad to 3 parts if needed
    $parts = $kernelClean -split "\."
    while ($parts.Count -lt 3) { $parts += "0" }
    $kernelVersion = [Version]($parts[0..2] -join ".")

    if ($kernelVersion -lt $MIN_KERNEL) {
        Write-Warn "WSL2 kernel $kernelVersion is below required $MIN_KERNEL"
        Write-Step "Updating WSL2 kernel — running: wsl --update"
        wsl --update
        Write-Warn "Please restart WSL2 and re-run this script: wsl --shutdown"
        exit 1
    }
    Write-Success "WSL2 kernel $kernelVersion >= $MIN_KERNEL"

    # 4. k3d
    Write-Step "Checking k3d..."
    if (-not (Test-CommandExists "k3d")) {
        Write-Warn "k3d not found — installing via winget..."
        winget install -e --id k3d.k3d --silent
        if ($LASTEXITCODE -ne 0) {
            Write-Fail "k3d install failed. Install manually: https://k3d.io/#installation"
            exit 1
        }
        # Refresh PATH
        $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH","Machine") + ";" +
                    [System.Environment]::GetEnvironmentVariable("PATH","User")
    }
    Write-Success "k3d available: $(k3d version)"

    # 5. kubectl
    Write-Step "Checking kubectl..."
    if (-not (Test-CommandExists "kubectl")) {
        Write-Warn "kubectl not found. installing via winget..."
        winget install -e --id Kubernetes.kubectl --silent
        if ($LASTEXITCODE -ne 0) {
            Write-Fail "kubectl install failed. Install manually: https://kubernetes.io/docs/tasks/tools/"
            exit 1
        }
        $env:PATH = @(
                    [System.Environment]::GetEnvironmentVariable("PATH","Machine")
                    [System.Environment]::GetEnvironmentVariable("PATH","User")
                    ) -join ";"
    }
    Write-Success "kubectl available: $(kubectl version --client 2>&1)"

    # 6. Helm
    Write-Step "Checking helm..."
    if (-not (Test-CommandExists "helm")) {
        Write-Warn "helm not found — installing via winget..."
        winget install -e --id Helm.Helm --silent
        if ($LASTEXITCODE -ne 0) {
            Write-Fail "helm install failed. Install manually: https://helm.sh/docs/intro/install/"
            exit 1
        }
        $env:PATH = @(
                    [System.Environment]::GetEnvironmentVariable("PATH","Machine")
                    [System.Environment]::GetEnvironmentVariable("PATH","User")
                    ) -join ";"
    }
    Write-Success "helm available: $(helm version --short)"

    # ── Create k3s cluster ────────────────────────────────────────────────────
    Write-Header "Creating k3s Cluster"

    $clusterExists = k3d cluster list --no-headers 2>&1 | Select-String "secops-lab"
    if ($clusterExists) {
        Write-Warn "Cluster 'secops-lab' already exists"
        $rebuild = Read-Host "  Delete and recreate? [y/N]"
        if ($rebuild -eq "y") {
            Write-Step "Deleting existing cluster..."
            k3d cluster delete secops-lab
        } else {
            Write-Info "Using existing cluster"
        }
    }

    if (-not (k3d cluster list --no-headers 2>&1 | Select-String "secops-lab")) {
        Write-Step "Creating k3s cluster (2 nodes)..."
        k3d cluster create secops-lab `
            --agents 2 `
            --port "30080:80@loadbalancer" `
            --port "30443:443@loadbalancer" `
            --k3s-arg "--disable=traefik@server:0" `
            --wait
        if ($LASTEXITCODE -ne 0) {
            Write-Fail "k3s cluster creation failed"
            exit 1
        }
        Write-Success "k3s cluster created"
    }

    # ── kubectl context ───────────────────────────────────────────────────────
    Write-Step "Switching kubectl context to k3d-secops-lab..."
    kubectl config use-context k3d-secops-lab
    Write-Success "kubectl context: k3d-secops-lab"

    # ── Update config.yaml ────────────────────────────────────────────────────
    Update-ConfigTarget "k3s"

    # ── Install platform components ───────────────────────────────────────────
    Install-PlatformComponents -target "k3s"
}

# =============================================================================
# CLOUD PATH — Azure AKS via Terraform
# =============================================================================

function Install-CloudCluster {

    Write-Header "Checking Cloud Prerequisites"

    # 1. Azure CLI
    Write-Step "Checking Azure CLI..."
    Assert-CommandExists "az" "Install from: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"
    Write-Success "Azure CLI: $(az version --query '\"azure-cli\"' -o tsv)"

    # 2. az login check
    Write-Step "Checking Azure login..."
    $account = az account show 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Warn "Not logged in to Azure — running az login..."
        az login
        if ($LASTEXITCODE -ne 0) {
            Write-Fail "Azure login failed"
            exit 1
        }
    }
    $subName = az account show --query name -o tsv
    Write-Success "Logged in — subscription: $subName"

    # 3. Terraform
    Write-Step "Checking Terraform..."
    if (-not (Test-CommandExists "terraform")) {
        Write-Warn "Terraform not found — installing via winget..."
        winget install -e --id Hashicorp.Terraform --silent
        if ($LASTEXITCODE -ne 0) {
            Write-Fail "Terraform install failed. Install manually: https://developer.hashicorp.com/terraform/install"
            exit 1
        }
        $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH","Machine") + ";" +
                    [System.Environment]::GetEnvironmentVariable("PATH","User")
    }
    Write-Success "Terraform: $(terraform version -json | ConvertFrom-Json | Select-Object -ExpandProperty terraform_version)"

    # 4. kubectl + helm
    Assert-CommandExists "kubectl" "Install from: https://kubernetes.io/docs/tasks/tools/"
    Assert-CommandExists "helm"    "Install from: https://helm.sh/docs/intro/install/"

    # ── Terraform apply ───────────────────────────────────────────────────────
    Write-Header "Provisioning AKS Cluster via Terraform"

    $tfDir = "$PSScriptRoot\terraform"
    Push-Location $tfDir

    Write-Step "terraform init..."
    terraform init
    if ($LASTEXITCODE -ne 0) { Write-Fail "terraform init failed"; exit 1 }

    Write-Step "terraform plan..."
    terraform plan -out=tfplan
    if ($LASTEXITCODE -ne 0) { Write-Fail "terraform plan failed"; exit 1 }

    Write-Host ""
    $apply = Read-Host "  Apply the plan? [y/N]"
    if ($apply -ne "y") {
        Write-Warn "Aborted — no changes made"
        Pop-Location
        exit 0
    }

    Write-Step "terraform apply..."
    terraform apply tfplan
    if ($LASTEXITCODE -ne 0) { Write-Fail "terraform apply failed"; exit 1 }

    Pop-Location

    # ── Get AKS credentials ───────────────────────────────────────────────────
    Write-Step "Getting AKS credentials..."
    $rgName      = terraform -chdir="$tfDir" output -raw resource_group_name
    $clusterName = terraform -chdir="$tfDir" output -raw cluster_name
    az aks get-credentials --resource-group $rgName --name $clusterName --overwrite-existing
    Write-Success "kubectl context set to: $clusterName"

    # ── Configure auto-stop schedule ─────────────────────────────────────────
    Write-Header "Configuring AKS Auto-Stop Schedule"
    Install-AutoStopSchedule -resourceGroup $rgName -clusterName $clusterName

    # ── Update config.yaml ────────────────────────────────────────────────────
    Update-ConfigTarget "aks"

    # ── Install platform components ───────────────────────────────────────────
    Install-PlatformComponents -target "aks"
}

# =============================================================================
# AUTO-STOP SCHEDULE (AKS only)
# =============================================================================

function Install-AutoStopSchedule {
    param($resourceGroup, $clusterName)

    Write-Step "Reading auto_stop schedule from config.yaml..."
    # Simple YAML read — extracts timezone only for az cli (schedule managed via Azure Automation)
    $configContent = Get-Content $CONFIG_FILE -Raw

    # Extract timezone
    if ($configContent -match "timezone:\s*'([^']+)'") {
        $timezone = $Matches[1]
    } else {
        $timezone = "UTC"
        Write-Warn "No timezone found in config.yaml — defaulting to UTC"
    }

    Write-Info "Schedule timezone: $timezone"
    Write-Info "Schedule: Mon-Fri 08:00-19:00 (from config.yaml)"
    Write-Info "Weekends: cluster left in current state"

    # Create Azure Automation Account for stop/start schedule
    Write-Step "Creating Azure Automation Account..."
    $automationAccount = "secops-lab-automation"

    az automation account create `
        --name $automationAccount `
        --resource-group $resourceGroup `
        --location (az group show --name $resourceGroup --query location -o tsv) `
        --output none 2>&1 | Out-Null

    # Create stop runbook
    Write-Step "Creating stop runbook..."
    $stopScript = @"
Connect-AzAccount -Identity
Stop-AzAksCluster -ResourceGroupName '$resourceGroup' -Name '$clusterName'
"@
    $stopScript | Set-Content "$env:TEMP\aks-stop.ps1"

    az automation runbook create `
        --automation-account-name $automationAccount `
        --resource-group $resourceGroup `
        --name "Stop-AKSCluster" `
        --type PowerShell `
        --output none 2>&1 | Out-Null

    az automation runbook replace-content `
        --automation-account-name $automationAccount `
        --resource-group $resourceGroup `
        --name "Stop-AKSCluster" `
        --content "$env:TEMP\aks-stop.ps1" `
        --output none 2>&1 | Out-Null

    az automation runbook publish `
        --automation-account-name $automationAccount `
        --resource-group $resourceGroup `
        --name "Stop-AKSCluster" `
        --output none 2>&1 | Out-Null

    # Create start runbook (same pattern)
    Write-Step "Creating start runbook..."
    $startScript = @"
Connect-AzAccount -Identity
Start-AzAksCluster -ResourceGroupName '$resourceGroup' -Name '$clusterName'
"@
    $startScript | Set-Content "$env:TEMP\aks-start.ps1"

    az automation runbook create `
        --automation-account-name $automationAccount `
        --resource-group $resourceGroup `
        --name "Start-AKSCluster" `
        --type PowerShell `
        --output none 2>&1 | Out-Null

    az automation runbook replace-content `
        --automation-account-name $automationAccount `
        --resource-group $resourceGroup `
        --name "Start-AKSCluster" `
        --content "$env:TEMP\aks-start.ps1" `
        --output none 2>&1 | Out-Null

    az automation runbook publish `
        --automation-account-name $automationAccount `
        --resource-group $resourceGroup `
        --name "Start-AKSCluster" `
        --output none 2>&1 | Out-Null

    # Weekday schedules (Mon-Fri)
    # Stop at 19:00, Start at 08:00
    $days = @("Monday","Tuesday","Wednesday","Thursday","Friday")

    foreach ($day in $days) {
        $stopScheduleName  = "Stop-$day"
        $startScheduleName = "Start-$day"

        az automation schedule create `
            --automation-account-name $automationAccount `
            --resource-group $resourceGroup `
            --name $stopScheduleName `
            --frequency Week `
            --interval 1 `
            --start-time "$(Get-Date -Format 'yyyy-MM-dd')T19:00:00" `
            --time-zone $timezone `
            --week-days $day `
            --output none 2>&1 | Out-Null

        az automation schedule create `
            --automation-account-name $automationAccount `
            --resource-group $resourceGroup `
            --name $startScheduleName `
            --frequency Week `
            --interval 1 `
            --start-time "$(Get-Date -Format 'yyyy-MM-dd')T08:00:00" `
            --time-zone $timezone `
            --week-days $day `
            --output none 2>&1 | Out-Null

        # Link schedules to runbooks
        az automation job-schedule create `
            --automation-account-name $automationAccount `
            --resource-group $resourceGroup `
            --runbook-name "Stop-AKSCluster" `
            --schedule-name $stopScheduleName `
            --output none 2>&1 | Out-Null

        az automation job-schedule create `
            --automation-account-name $automationAccount `
            --resource-group $resourceGroup `
            --runbook-name "Start-AKSCluster" `
            --schedule-name $startScheduleName `
            --output none 2>&1 | Out-Null
    }

    Write-Success "Auto-stop schedule configured (Mon-Fri 08:00-19:00 $timezone)"
    Write-Info "Manual override: az aks start --resource-group $resourceGroup --name $clusterName"
    Write-Info "Manual override: az aks stop  --resource-group $resourceGroup --name $clusterName"
}

# =============================================================================
# SHARED — Install platform components (both paths)
# =============================================================================

function Install-PlatformComponents {
    param($target)

    Write-Header "Creating Namespace"
    kubectl create namespace $NAMESPACE --dry-run=client -o yaml | kubectl apply -f -
    Write-Success "Namespace: $NAMESPACE"

    # ── ArgoCD ────────────────────────────────────────────────────────────────
    Write-Header "Installing ArgoCD"
    Write-Step "Adding Helm repo..."
    helm repo add argo https://argoproj.github.io/argo-helm --force-update | Out-Null
    helm repo update | Out-Null

    Write-Step "Installing ArgoCD (trimmed — no Dex, no ApplicationSet)..."
    Invoke-Helm @(
        "upgrade", "--install", "argocd", "argo/argo-cd",
        "--namespace", "argocd",
        "--create-namespace",
        #"--version", $ARGOCD_VERSION,
        "--set", "dex.enabled=false",
        "--set", "applicationSet.enabled=false",
        "--set", "configs.params.server\.insecure=true",
        "--wait",
        "--timeout", "5m"
    )
    Write-Success "ArgoCD installed"

    Write-Step "Retrieving ArgoCD initial admin password..."
    $argoPass = kubectl -n argocd get secret argocd-initial-admin-secret `
        -o jsonpath="{.data.password}" | `
        ForEach-Object { [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($_)) }
    Write-Success "ArgoCD admin password: $argoPass"
    Write-Info "Save this — it will not be shown again"

    # ── ArgoCD API Token (permanent) ─────────────────────────────────────────
    Write-Header "Configuring ArgoCD API Access"

    # Step 1 — add secops-backend account
    Write-Step "Adding secops-backend account to ArgoCD..."
    $cmPatch = [System.IO.Path]::GetTempFileName() + ".json"
    '{"data":{"accounts.secops-backend":"apiKey"}}' | Set-Content $cmPatch -Encoding ascii
    kubectl patch configmap argocd-cm -n argocd --type=merge --patch-file $cmPatch
    Remove-Item $cmPatch

    # Step 2 — set permissions (get + sync required for watchdog/reset)
    Write-Step "Setting permissions for secops-backend..."
    $rbacPatch = [System.IO.Path]::GetTempFileName() + ".json"
    '{"data":{"policy.csv":"p, secops-backend, applications, get, */*, allow\np, secops-backend, applications, sync, */*, allow\n"}}' | Set-Content $rbacPatch -Encoding ascii
    kubectl patch configmap argocd-rbac-cm -n argocd --type=merge --patch-file $rbacPatch
    Remove-Item $rbacPatch

    # Step 3 — wait for ArgoCD to pick up config
    Write-Step "Waiting for ArgoCD to reload config..."
    Start-Sleep -Seconds 10

    # Step 4 — get admin session token
    Write-Step "Getting ArgoCD admin session token..."
    $adminToken = (Invoke-RestMethod `
        -Uri "http://localhost:8080/api/v1/session" `
        -Method POST `
        -ContentType "application/json" `
        -Body "{`"username`":`"admin`",`"password`":`"$argoPass`"}").token

    # Step 5 — generate permanent token for secops-backend
    Write-Step "Generating permanent API token for secops-backend..."
    $apiToken = (Invoke-RestMethod `
        -Uri "http://localhost:8080/api/v1/account/secops-backend/token" `
        -Method POST `
        -Headers @{Authorization="Bearer $adminToken"} `
        -ContentType "application/json" `
        -Body "{}").token

    # Step 6 — store as Kubernetes secret
    Write-Step "Storing ArgoCD API token as Kubernetes secret..."
    kubectl create secret generic argocd-api-token `
        --from-literal=token=$apiToken `
        -n $NAMESPACE `
        --dry-run=client -o yaml | kubectl apply -f -

    # Step 7 — inject into backend deployment
    Write-Step "Injecting ArgoCD token into backend deployment..."
    kubectl set env deployment/secops-backend `
        -n $NAMESPACE `
        ARGOCD_TOKEN=$apiToken

    Write-Success "ArgoCD API token configured — permanent, no expiry"

    # ── Kyverno ───────────────────────────────────────────────────────────────
    Write-Header "Installing Kyverno"
    Write-Step "Adding Helm repo..."
    helm repo add kyverno https://kyverno.github.io/kyverno --force-update | Out-Null
    helm repo update | Out-Null

    Write-Step "Installing Kyverno (1 replicas)..."
    Invoke-Helm @(
        "upgrade", "--install", "kyverno", "kyverno/kyverno",
        "--namespace", "kyverno",
        "--create-namespace",
        #"--version", $KYVERNO_VERSION,
        "--set", "replicaCount=1",
        "--set", "admissionController.replicas=1",
        "--wait",
        "--timeout", "5m"
    )
    Write-Success "Kyverno installed (1 replicas)"

    # ── Falco ─────────────────────────────────────────────────────────────────
    Write-Header "Installing Falco"
    Write-Step "Adding Helm repo..."
    helm repo add falcosecurity https://falcosecurity.github.io/charts --force-update | Out-Null
    helm repo update | Out-Null

    Write-Step "Installing Falco (eBPF driver)..."
    Invoke-Helm @(
        "upgrade", "--install", "falco", "falcosecurity/falco",
        "--namespace", "falco",
        "--create-namespace",
        #"--version", $FALCO_VERSION,
        #"--set", "driver.kind=ebpf",
        #"--set", "driver.kind=modern-ebpf",
        "--set", "driver.kind=auto",
        "--set", "falcosidekick.enabled=true",
        "--set", "falcosidekick.config.webhook.address=http://secops-backend.$NAMESPACE.svc.cluster.local:3000/events/falco",
        "--set", "falcosidekick.config.webhook.checkcert=false",
        "--wait",
        "--timeout", "5m"
    )
    Write-Success "Falco installed (eBPF + Sidekick webhook configured)"

    # ── Apply GitOps manifests ────────────────────────────────────────────────
    Write-Header "Applying GitOps Base Manifests"
    Write-Step "Applying Kyverno policies..."
    Invoke-Kubectl @("apply", "-f", "$PSScriptRoot\..\gitops\policies\", "-n", $NAMESPACE)
    Write-Step "Applying base workloads..."
    Invoke-Kubectl @("apply", "-f", "$PSScriptRoot\..\gitops\base\", "-n", $NAMESPACE)
    Write-Step "Registering ArgoCD applications..."
    Invoke-Kubectl @("apply", "-f", "$PSScriptRoot\..\gitops\apps\", "-n", "argocd")
    Write-Success "GitOps manifests applied"

   # ── Summary ───────────────────────────────────────────────────────────────
    Write-Header "Setup Complete"
 
    if ($target -eq "k3s") {
        $frontendUrl = "http://localhost:30080"
    } else {
        Write-Step "Getting frontend IP (may take 1-2 min for LoadBalancer)..."
        $ip = ""
        $attempts = 0
        while (-not $ip -and $attempts -lt 12) {
            Start-Sleep -Seconds 10
            $ip = kubectl get svc secops-frontend -n $NAMESPACE `
                -o jsonpath="{.status.loadBalancer.ingress[0].ip}" 2>$null
            $attempts++
        }
        $frontendUrl = if ($ip) { "http://$ip" } else { "http://<pending — check: kubectl get svc -n $NAMESPACE>" }
    }
 
    # ── Start ArgoCD port-forward in background ───────────────────────────────
    Write-Header "Starting ArgoCD Port-Forward"
    Write-Step "Starting ArgoCD port-forward on http://localhost:8080 ..."
 
    $portForwardJob = Start-Job -ScriptBlock {
        kubectl port-forward svc/argocd-server -n argocd 8080:80
    }
 
    Start-Sleep -Seconds 3
 
    if ($portForwardJob.State -eq "Running") {
        Write-Success "ArgoCD port-forward running (Job ID: $($portForwardJob.Id))"
    } else {
        Write-Warn "Port-forward may have failed — run manually:"
        Write-Info "kubectl port-forward svc/argocd-server -n argocd 8080:80"
    }
 
    Write-Host ""
    Write-Host "  +-------------------------------------------------+" -ForegroundColor Cyan
    Write-Host "  |  SecOps GitOps Lab is ready                     |" -ForegroundColor Cyan
    Write-Host "  |                                                 |" -ForegroundColor Cyan
    Write-Host "  |  Demo UI:   $frontendUrl" -ForegroundColor White
    Write-Host "  |  ArgoCD:    http://localhost:8080               |" -ForegroundColor White
    Write-Host "  |  ArgoCD user: admin" -ForegroundColor White
    Write-Host "  |  ArgoCD pw: $argoPass" -ForegroundColor White
    Write-Host "  |                                                 |" -ForegroundColor Cyan
    Write-Host "  |  Next: generate your first token                |" -ForegroundColor DarkGray
    Write-Host "  |  Admin UI -> /admin -> Generate                 |" -ForegroundColor DarkGray
    Write-Host "  |                                                 |" -ForegroundColor Cyan
    Write-Host "  |  Note: ArgoCD port-forward (Job $($portForwardJob.Id)) stops  |" -ForegroundColor DarkGray
    Write-Host "  |  when this terminal closes. To restart:        |" -ForegroundColor DarkGray
    Write-Host "  |  kubectl port-forward svc/argocd-server \`      |" -ForegroundColor DarkGray
    Write-Host "  |    -n argocd 8080:80                           |" -ForegroundColor DarkGray
    Write-Host "  +-------------------------------------------------+" -ForegroundColor Cyan
    Write-Host ""
}
# =============================================================================
# HELPERS
# =============================================================================

function Update-ConfigTarget {
    param($target)
    Write-Step "Updating config.yaml target to '$target'..."
    $content = Get-Content $CONFIG_FILE -Raw
    $content = $content -replace "target: '[^']*'", "target: '$target'"
    Set-Content $CONFIG_FILE $content
    Write-Success "config.yaml updated — cluster.target: $target"
}

# =============================================================================
# ENTRY POINT
# =============================================================================

if ($TARGET -eq "k3s") {
    Install-LocalCluster
} else {
    Install-CloudCluster
}
