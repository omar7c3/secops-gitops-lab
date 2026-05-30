# =============================================================================
# SecOps GitOps Lab — Terraform Variables
# =============================================================================

variable "resource_group_name" {
  description = "Azure resource group name"
  type        = string
  default     = "secops-gitops-lab-rg"
}

variable "location" {
  description = "Azure region — pick one close to you"
  type        = string
  default     = "eastus"
}

variable "cluster_name" {
  description = "AKS cluster name"
  type        = string
  default     = "secops-gitops-lab"
}

variable "kubernetes_version" {
  description = "Kubernetes version — keep current for Falco eBPF compatibility"
  type        = string
  default     = "1.29"
}
