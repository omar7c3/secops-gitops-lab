# =============================================================================
# SecOps GitOps Lab — Terraform Outputs (Civo)
# =============================================================================

output "cluster_name" {
  description = "Civo cluster name — use with: civo kubernetes config <name> --save"
  value       = civo_kubernetes_cluster.lab.name
}

output "region" {
  description = "Civo region the cluster is deployed in"
  value       = civo_kubernetes_cluster.lab.region
}

output "api_endpoint" {
  description = "Kubernetes API server endpoint"
  value       = civo_kubernetes_cluster.lab.api_endpoint
}

output "master_ip" {
  description = "Node IP — point your DNS A record here"
  value       = civo_kubernetes_cluster.lab.master_ip
}

output "kube_config" {
  description = "Raw kubeconfig — use: civo kubernetes config <name> --save --merge"
  value       = civo_kubernetes_cluster.lab.kubeconfig
  sensitive   = true
}

output "dns_entry" {
  description = "Civo-assigned DNS entry for the cluster"
  value       = civo_kubernetes_cluster.lab.dns_entry
}
