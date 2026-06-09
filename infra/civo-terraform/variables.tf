# =============================================================================
# SecOps GitOps Lab — Terraform Variables (Civo)
# =============================================================================

variable "civo_token" {
  description = "Civo API token — set via TF_VAR_civo_token or a .tfvars file (never commit)"
  type        = string
  sensitive   = true
}

variable "region" {
  description = "Civo region: NYC1, LON1, FRA1, PHX1"
  type        = string
  default     = "NYC1"
}

variable "cni" {
  description = "Cluster CNI: flannel or cilium"
  type        = string
  default     = "cilium"
}

variable "cluster_name" {
  description = "Civo cluster name"
  type        = string
  default     = "civo-secops-gitops-lab"
}

variable "node_size" {
  description = <<-EOT
    Civo node size slug.
      g4s.kube.small  = 1 vCPU / 2 GB  / 30 GB  (~$11/mo)
      g4s.kube.medium = 2 vCPU / 4 GB  / 50 GB  (~$22/mo)  ← default
      g4s.kube.large  = 4 vCPU / 8 GB  / 50 GB  (~$44/mo)  ← closer to Basv2 RAM
    Run `civo sizes ls` to see the full list.
  EOT
  type        = string
  default     = "g4s.kube.medium"
}

variable "node_count" {
  description = "Number of worker nodes"
  type        = number
  default     = 1
}
