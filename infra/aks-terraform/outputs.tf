# =============================================================================
# SecOps GitOps Lab — Terraform Outputs
# Used by setup.ps1 to retrieve cluster details after apply
# =============================================================================

output "resource_group_name" {
  description = "Resource group name — used by setup.ps1 for az aks get-credentials"
  value       = azurerm_resource_group.lab.name
}

output "cluster_name" {
  description = "AKS cluster name — used by setup.ps1 for az aks get-credentials"
  value       = azurerm_kubernetes_cluster.lab.name
}

output "kube_config" {
  description = "Raw kubeconfig — use setup.ps1 to configure kubectl context"
  value       = azurerm_kubernetes_cluster.lab.kube_config_raw
  sensitive   = true
}

output "node_resource_group" {
  description = "Auto-generated resource group for AKS node VMs"
  value       = azurerm_kubernetes_cluster.lab.node_resource_group
}
