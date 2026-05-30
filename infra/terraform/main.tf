# =============================================================================
# SecOps GitOps Lab — AKS Cluster
# =============================================================================

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.90"
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
    vm_size             = "Standard_B2s"
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
