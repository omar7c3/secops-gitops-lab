# =============================================================================
# SecOps GitOps Lab — AKS Cluster
# =============================================================================

terraform {
  required_version = ">= 1.8.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.75.0"
    }
  }
}


provider "azurerm" {
  features {}
}

# ── Resource Group ────────────────────────────────────────────────────────────
resource "azurerm_resource_group" "lab" {
  name     = var.resource_group_name
  location = var.location

  tags = {
    project     = "secops-gitops-lab"
    environment = "demo"
    managed_by  = "terraform"
  }
}

# ── AKS Cluster ───────────────────────────────────────────────────────────────
resource "azurerm_kubernetes_cluster" "lab" {
  name                = var.cluster_name
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  dns_prefix          = var.cluster_name
  kubernetes_version  = var.kubernetes_version

  # ── Default node pool — 2x B2s ─────────────────────────────────────────────
  default_node_pool {
    name                = "default"
    node_count          = 2
    vm_size             = var.vmss_sku
    os_disk_size_gb     = 30
    type                = "VirtualMachineScaleSets"

    # Required for Falco eBPF — ensures OS is up to date
    os_sku = "Ubuntu"
  }

  # ── Identity ────────────────────────────────────────────────────────────────
  identity {
    type = "SystemAssigned"
  }

  # ── Network ─────────────────────────────────────────────────────────────────
  network_profile {
    network_plugin    = "azure"
    network_policy    = "calico"   # Required for NetworkPolicy enforcement
    load_balancer_sku = "standard"
  }

  # ── RBAC ────────────────────────────────────────────────────────────────────
  local_account_disabled = false

  role_based_access_control_enabled = true

  # ── Maintenance window — align with auto-stop schedule ──────────────────────
  maintenance_window {
    allowed {
      day   = "Saturday"
      hours = [2, 3, 4]
    }
  }

  tags = {
    project     = "secops-gitops-lab"
    environment = "demo"
    managed_by  = "terraform"
  }
}

 # ── Automation Account ─────────────────────────────────────────────────────
resource "azurerm_automation_account" "main" {
  name                = "secops-lab-automation"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  sku_name            = "Basic"
  identity {
    type = "SystemAssigned"
  }
}
resource "azurerm_role_assignment" "aks_automation" {
  scope                = azurerm_kubernetes_cluster.lab.id
  role_definition_name = "Contributor"
  principal_id         = azurerm_automation_account.main.identity[0].principal_id
}



 # ── Runbooks ───────────────────────────────────────────────────────────────
resource "azurerm_automation_runbook" "start" {
  name                    = "Start-AKSCluster"
  location                = azurerm_resource_group.lab.location
  resource_group_name     = azurerm_resource_group.lab.name
  automation_account_name = azurerm_automation_account.main.name
  log_verbose             = true
  log_progress            = true
  runbook_type            = "PowerShell"
  content                 = local.start_script
}

resource "azurerm_automation_runbook" "stop" {
  name                    = "Stop-AKSCluster"
  location                = azurerm_resource_group.lab.location
  resource_group_name     = azurerm_resource_group.lab.name
  automation_account_name = azurerm_automation_account.main.name
  log_verbose             = true
  log_progress            = true
  runbook_type            = "PowerShell"
  content                 = local.stop_script
}

# ── Schedules ───────────────────────────────────────────────────────────────
# START schedules
resource "azurerm_automation_schedule" "start" {
  for_each = {
    for s in local.schedule : join("-", s.days) => s
    if s.start != null && local.autostop_enabled
  }

  name                    = "Start-${each.key}"
  resource_group_name     = azurerm_resource_group.lab.name
  automation_account_name = azurerm_automation_account.main.name
  frequency               = "Week"
  interval                = 1
  timezone                = local.timezone
  week_days               = each.value.days
# start_time              = "${formatdate("YYYY-MM-DD", timestamp())}T${each.value.start}:00Z"
  start_time              = formatdate("YYYY-MM-DD'T'hh:mm:ss'Z'", timeadd(timestamp(), "30m"))
  lifecycle {
    ignore_changes = [
      start_time
    ]
  }
}

# STOP schedules
resource "azurerm_automation_schedule" "stop" {
  for_each = {
    for s in local.schedule : join("-", s.days) => s
    if s.stop != null && local.autostop_enabled
  }

  name                    = "Stop-${each.key}"
  resource_group_name     = azurerm_resource_group.lab.name
  automation_account_name = azurerm_automation_account.main.name
  frequency               = "Week"
  interval                = 1
  timezone                = local.timezone
  week_days               = each.value.days
# start_time              = "${formatdate("YYYY-MM-DD", timestamp())}T${each.value.stop}:00Z"
  start_time              = formatdate("YYYY-MM-DD'T'hh:mm:ss'Z'", timeadd(timestamp(), "30m"))
  lifecycle {
    ignore_changes = [
      start_time
    ]
  }
}

# ── Job Schedules (link runbooks to schedules) ───────────────────────────────────────────────────────────────

resource "azurerm_automation_job_schedule" "start" {
  for_each = azurerm_automation_schedule.start

  resource_group_name     = azurerm_resource_group.lab.name
  automation_account_name = azurerm_automation_account.main.name
  schedule_name           = each.value.name
  runbook_name            = azurerm_automation_runbook.start.name
}

resource "azurerm_automation_job_schedule" "stop" {
  for_each = azurerm_automation_schedule.stop

  resource_group_name     = azurerm_resource_group.lab.name
  automation_account_name = azurerm_automation_account.main.name
  schedule_name           = each.value.name
  runbook_name            = azurerm_automation_runbook.stop.name
}
