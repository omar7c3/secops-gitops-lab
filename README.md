# SecOps GitOps Lab

An interactive demo environment showing real Kubernetes attack scenarios
and how GitOps-driven security controls detect, block, and recover from them.
Built as a portfolio project for cloud/infra/infosec/DevOps leadership roles.

## What It Demonstrates

| Skill | Evidence |
|---|---|
| Cloud / Infrastructure | Terraform, AKS, cost optimization, auto-stop scheduling |
| GitOps / DevOps | ArgoCD drift detection, reconciliation, Git as single source of truth |
| Information Security | Falco runtime detection, Kyverno admission policies, real attack scenarios |
| Networking | NetworkPolicy enforcement, lateral movement demonstration |
| Architecture Leadership | ADRs, scoped design decisions, dual deployment path |
| Product Thinking | Token-gated demo, interactive scenario modes, session management |

---

## The Scenarios

### Scenario 1 — Privilege Escalation via Service Account Abuse

A pod with an over-permissioned `cluster-admin` service account steals
its own token and uses it to delete admission controls, suspend GitOps,
create a privileged pod, and gain root on the node.

**With Controls:** `automountServiceAccountToken: false` — no token to steal.
Attack stopped at step 1.

**Allow Attack:** Pod does everything itself. Cluster stays compromised
until visitor manually clicks **Restore Protection**. Dwell time shown.
Then proof — same attack, blocked.

### Scenario 2 — Lateral Movement via NetworkPolicy Bypass

A pod with narrowly scoped NetworkPolicy admin rights steals its token
and deletes the deny-all NetworkPolicy. Unlike Scenario 1 it cannot
suspend ArgoCD — the window is bounded by GitOps reconciliation (~30s).

**With Controls:** Kyverno blocks the deletion at admission. Window: 0 seconds.

**Allow Attack:** Window opens, internal services probed, ArgoCD
auto-recovers in ~30 seconds. Then proof — blocked at admission.

---

## Quick Start

### Local (k3s — zero cost)

Requirements: Windows + Docker Desktop + WSL2 (Ubuntu, kernel 5.8+)

```powershell
git clone https://github.com/omar7c3/secops-gitops-lab.git
cd secops-gitops-lab
.\infra\setup.ps1
# Select: [1] Local
```

### Cloud (AKS — ~$8-10/mo with auto-stop)

Requirements: Azure CLI + Terraform + kubectl + helm

```powershell
.\infra\setup.ps1
# Select: [2] Cloud
```

---

## Architecture

```
Single AKS cluster (2x B2s) or local k3s
│
├── ArgoCD          — GitOps engine, drift detection, reconciliation
├── Kyverno (x2)    — Admission policy enforcement
├── Falco           — Runtime threat detection (eBPF, DaemonSet)
├── Backend         — Token gate + event store + scenario orchestration + watchdog
├── Frontend        — Vue 3 demo UI (3-panel layout + timeline bar)
├── Target App      — Vulnerable workload scenarios run against
└── Postgres        — Demo database for Scenario 2
```

## Access

The demo is token-gated. Request a token from the owner.

Admin UI: `/admin` — requires admin password.

---

## Repository Structure

```
secops-gitops-lab/
├── infra/
│   ├── setup.ps1              # Interactive setup — cloud or local
│   ├── terraform/             # AKS provisioning
│   └── local/                 # k3s local setup helpers
├── gitops/
│   ├── apps/                  # ArgoCD Application manifests
│   ├── policies/              # Kyverno admission policies
│   └── base/                  # All Kubernetes workload manifests
├── scenarios/
│   ├── 01-privilege-escalation/
│   └── 02-networkpolicy-bypass/
├── backend/                   # Node.js — token + event + scenario API
├── frontend/                  # Vue 3 — demo UI
├── target-app/                # Vulnerable workload
├── docs/adrs/                 # Architecture Decision Records
└── config.yaml                # All tuneable parameters
```

## Config

All tuneable parameters live in `config.yaml` at the repo root.
No code changes needed to adjust session duration, auto-stop schedule,
watchdog behavior, or user-facing messages.

## Cost

| Mode | Est. Monthly |
|---|---|
| AKS always-on | ~$50/mo |
| AKS with auto-stop (Mon-Fri 8am-7pm) | ~$8-10/mo |
| Local k3s | $0 |
