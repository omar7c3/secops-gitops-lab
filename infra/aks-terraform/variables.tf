# =============================================================================
# SecOps GitOps Lab — Terraform Variables
# =============================================================================

variable "resource_group_name" {
  description = "Azure resource group name"
  type        = string
  default     = "rg-eastus-secops-gitops-lab"
}

variable "location" {
  description = "Azure region — pick one close to you"
  type        = string
  default     = "eastus"
}

variable "cluster_name" {
  description = "AKS cluster name"
  type        = string
  default     = "aks-secops-gitops-lab"
}

variable "kubernetes_version" {
  description = "Kubernetes version — keep current for Falco eBPF compatibility"
  type        = string
  default     = "1.35.3"
}

variable "vmss_sku" {
  description = "Azure VMSS that will power the AKS cluster"
  type        = string
  default     = "Standard_B2ps_v2"
}
