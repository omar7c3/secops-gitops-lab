# =============================================================================
# SecOps GitOps Lab — Civo Kubernetes Cluster
# Converted from AKS — no resource groups, no automation accounts.
# Auto-stop is handled by civo CLI scripts invoked via null_resource local-exec.
# =============================================================================

terraform {
  required_version = ">= 1.8.0"

  required_providers {
    civo = {
      source  = "civo/civo"
      version = "~> 1.1.0"
    }
  }
}

provider "civo" {
  region = var.region
}

# ── Network ───────────────────────────────────────────────────────────────────
resource "civo_network" "lab" {
  label = "${var.cluster_name}-network"
}

# ── Firewall ──────────────────────────────────────────────────────────────────
resource "civo_firewall" "lab" {
  name                 = "${var.cluster_name}-firewall"
  network_id           = civo_network.lab.id
  create_default_rules = false  # we define only what we need

  # HTTPS — web interface
  ingress_rule {
    label      = "https"
    protocol   = "tcp"
    port_range = "443"
    cidr       = ["0.0.0.0/0"]
    action     = "allow"
  }

  # HTTP — redirect to HTTPS (optional but useful for cert-manager challenges)
  ingress_rule {
    label      = "http"
    protocol   = "tcp"
    port_range = "80"
    cidr       = ["0.0.0.0/0"]
    action     = "allow"
  }

  # kubectl access — restrict to your own IP in production
  ingress_rule {
    label      = "kubernetes-api"
    protocol   = "tcp"
    port_range = "6443"
    cidr       = ["0.0.0.0/0"]
    action     = "allow"
  }
}

# ── Kubernetes Cluster ────────────────────────────────────────────────────────
resource "civo_kubernetes_cluster" "lab" {
  name        = var.cluster_name
  network_id  = civo_network.lab.id
  firewall_id = civo_firewall.lab.id
  cni         = var.cni 

  # Closest equivalent to Standard_B2ps_v2 (2 vCPU / 8 GB) on Civo.
  # g4s.kube.medium = 2 vCPU / 4 GB / 50 GB (~$11/mo)
  # g4s.kube.large  = 4 vCPU / 8 GB / 50 GB (~$20/mo) — closer RAM match
  # Switch to g4s.kube.large if your workload needs the RAM.
  pools {
    size       = var.node_size
    node_count = var.node_count
    labels = {
      project     = "secops-gitops-lab"
      environment = "demo"
      managed_by  = "terraform"
    }
  }

  # Write kubeconfig locally after apply
  write_kubeconfig = true

  # Built-in apps — metrics-server is enough for a dev cluster.
  # Add "cert-manager" here if you want Civo to manage the install.
  applications = "metrics-server"
}

# ── Auto-stop (delete) / Auto-start (recreate) via Civo CLI ──────────────────
# Civo has no "pause" API. The equivalent of AKS Stop/Start is delete + recreate,
# which is safe because kubeconfig and DNS update automatically on recreate.
#
# This block renders cron-ready shell scripts you can drop into a scheduler
# (crontab, GitHub Actions scheduled workflow, etc.).
# They are NOT executed by Terraform itself — just written to disk.
resource "local_file" "stop_script" {
  count    = local.autostop_enabled ? 1 : 0
  filename = "${path.module}/scripts/stop-cluster.sh"
  content  = local.stop_script
}

resource "local_file" "start_script" {
  count    = local.autostop_enabled ? 1 : 0
  filename = "${path.module}/scripts/start-cluster.sh"
  content  = local.start_script
}
