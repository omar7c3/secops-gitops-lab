# SecOps GitOps Lab

An interactive demo environment showing real Kubernetes attack scenarios and how GitOps-driven security controls detect, block, and recover from them. Built as a portfolio project for cloud, infra, infosec, and DevOps leadership roles.

Live at [secops-demo.omar7c3.win](https://secops-demo.omar7c3.win/) — you'll need a token to get in, with an admin interface at [secops-demo.omar7c3.win/admin](https://secops-demo.omar7c3.win/admin). Runs weekdays only, 8AM–5PM ET, on an automated cluster lifecycle to keep costs to ~$6–7/mo. Scheduling is handled via Azure Logic App due to GitHub Actions cron reliability limitations — the native cron config remains in the workflow for reference.

To try the demo, request a token via [LinkedIn](https://www.linkedin.com/in/omar-al-abayechi) or use the shared token `DEMO-ZGQ2-5MXU`. Note that only one active session is permitted at a time.

---

## What It Demonstrates

| Skill | Evidence |
|---|---|
| Cloud / Infrastructure | Terraform, AKS, Civo, cost optimisation. Civo has no native auto-stop, so a GitHub Actions workflow was engineered to fill the gap: scheduled cluster create/destroy, state management via Azure Storage backend, kubeconfig lifecycle, SQLite backup/restore, Cloudflare DNS updates, and PVC cleanup to unblock network deletion |
| Automation & Scripting | GitHub Actions workflows for full cluster lifecycle management, PowerShell setup scripts for local and cloud deployment paths, bash attack/proof scripts executed via kubectl exec |
| Software Engineering | Node.js/Express backend, Vue 3 frontend, SQLite persistence, JWT session management, real-time event feed, ArgoCD API integration, Falco webhook receiver |
| GitOps / DevOps | ArgoCD drift detection, reconciliation, Git as single source of truth |
| Information Security | Falco runtime detection, Kyverno admission policies, real attack chains |
| Networking | NetworkPolicy enforcement, lateral movement demonstration |
| Architecture Leadership | Scoped design decisions, dual deployment path (local and cloud) |
| Product Thinking | Token-gated demo, interactive scenario modes, session management |

---

## The Scenarios

Each scenario runs in two modes: **With Controls** (defences active) and **Allow Attack** (controlled misconfiguration to show the full blast radius). A proof phase runs after every attack to confirm the controls are restored.

### Scenario 1 — Privilege Escalation

A pod with an over-permissioned `cluster-admin` service account reads its mounted token and uses it to delete Kyverno admission policies, suspend ArgoCD sync, create a privileged pod with the node filesystem mounted, and read cluster certificates.

| Mode | What happens |
|---|---|
| **With Controls** | `automountServiceAccountToken: false` means no token is mounted, so the attack stops at step 1 |
| **Allow Attack** | The full attack chain runs. The cluster stays compromised until the visitor clicks **Restore Protection**. Dwell time is tracked. A proof phase follows showing the same attack blocked. |

**Controls in play:** `automountServiceAccountToken: false` · Kyverno `no-privileged-containers` · Kyverno `no-hostpath-mount` · ArgoCD self-heal

### Scenario 2 — Lateral Movement via NetworkPolicy Bypass

A pod with narrowly scoped NetworkPolicy admin rights reads its token and deletes the `deny-all` NetworkPolicy. Unlike Scenario 1, it cannot suspend ArgoCD, so the lateral movement window is bounded by GitOps reconciliation (around 30 seconds).

| Mode | What happens |
|---|---|
| **With Controls** | Kyverno `protect-networkpolicies` blocks the deletion at admission. Window: 0 seconds. |
| **Allow Attack** | `protect-networkpolicies` is removed, the window opens, and internal services are probed. ArgoCD auto-recovers in about 30 seconds. A proof phase follows showing the attack blocked at admission. |

**Controls in play:** Kyverno `protect-networkpolicies` · ArgoCD auto-reconcile · `deny-all` NetworkPolicy

---

## Quick Start

### Local (k3d — zero cost)

Requirements: Windows · Docker Desktop · WSL2 (Ubuntu, kernel 5.8+)

```powershell
git clone https://github.com/omar7c3/secops-gitops-lab.git
cd secops-gitops-lab
.\infra\setup.ps1
# Select: [1] Local — k3s via k3d (Docker Desktop + WSL2, zero cost)
```

Setup installs k3d, deploys ArgoCD, Kyverno, Falco, and the full application stack. Takes around 5 minutes. The UI is at `http://localhost:30080`.

### Cloud (AKS — ~$14–15/mo with auto-stop)

Requirements: Azure CLI · Terraform · kubectl · helm

```powershell
.\infra\setup.ps1
# Select: [2] Cloud — Azure AKS (Terraform, ~$14-15/mo with auto-stop)
```

### Cloud (Civo — ~$6–7/mo with engineered auto-stop, down from $22/mo 24/7)

Two options here.

**Option 1 — via setup script**

Requirements: Civo CLI · Terraform · kubectl · helm

```powershell
.\infra\setup.ps1
# Select: [3] Cloud — Civo Kubernetes (Terraform, ~$6-7/mo · engineered auto-stop — no native equivalent)
```

**Option 2 — fully managed via GitHub Actions**

Just configure the repository secrets below and the workflows handle everything automatically: cluster provisioning, platform install, database backup/restore, DNS updates, and scheduled shutdown.

| Secret | Description |
|---|---|
| `AZURE_CLIENT_ID` | Entra ID client ID used for OIDC authentication |
| `AZURE_SUBSCRIPTION_ID` | Azure subscription ID that hosts the resources |
| `AZURE_TENANT_ID` | Entra ID tenant ID |
| `STORAGE_ACCOUNT_NAME` | Azure storage account used as backend for cluster state, DB backups, kubeconfig, etc. |
| `CONTAINER_NAME` | The blob container within the storage account |
| `CF_ZONE_ID` | Cloudflare zone ID |
| `CF_RECORD_NAME` | Cloudflare DNS record name used as the frontend URL |
| `CF_RECORD_ID` | Cloudflare DNS record ID, updated on every cluster creation |
| `CF_TOKEN` | Cloudflare API token used to automate DNS record updates |
| `CIVO_TOKEN` | Civo API token used to manage the cluster lifecycle |
| `ADMIN_PASSWORD` | Password for the admin portal |
| `JWT_SECRET` | Secret used to issue and verify user tokens |

---

## Architecture

```
Single AKS cluster (2x Standard_B2s nodes) or local k3d (2 agents + server)
│
├── ArgoCD          — GitOps engine (trimmed, no Dex, no ApplicationSet)
│   ├── secops-lab              app — workloads, NetworkPolicies
│   └── secops-lab-policies     app — Kyverno ClusterPolicies
│
├── Kyverno (1 replica)  — Admission policy enforcement
│   ├── disallow-automount-sa-token   — blocks token mounts without documented need
│   ├── no-privileged-containers      — blocks privileged: true
│   ├── no-hostpath-mount             — blocks hostPath volumes
│   ├── protect-networkpolicies       — blocks NetworkPolicy deletion
│   └── require-resource-limits       — enforces CPU/memory limits
│
├── Falco (eBPF DaemonSet)  — Runtime threat detection
│
├── Backend (Node.js/Express + SQLite)
│   ├── Token gate + JWT session management
│   ├── Event feed (polled by frontend every 2s)
│   ├── Scenario orchestration (kubectl cp + exec into target-app)
│   ├── ArgoCD state poller
│   ├── Falco Sidekick webhook receiver
│   └── Watchdog — resets cluster when dirty with no active session
│
├── Frontend (Vue 3 + Pinia + Tailwind CSS, served by nginx)
│   ├── Token gate (visitor login)
│   ├── Demo UI — 3-panel layout: Attack Feed · System State · Impact
│   ├── Timeline bar
│   └── Admin dashboard
│
├── Target App (bitnami/kubectl)  — Workload scenarios run against
│   ├── Default: minimal-sa, automountServiceAccountToken: false
│   ├── Scenario 1 Allow Attack: over-privileged-sa (cluster-admin)
│   └── Scenario 2: network-tooling-sa (NetworkPolicy admin)
│
└── Postgres  — Demo database used in Scenario 2 lateral movement probes
```

---

## Access

The demo is token-gated. Visitors need a token issued by the admin.

- **Visitor UI:** `http://<host>/` — enter a token to start a 30-minute session
- **Admin UI:** `http://<host>/admin` — password-protected dashboard for token management, session release, and force cluster reset
- Only one active session is permitted at a time, across all tokens

---

## Repository Structure

```
secops-gitops-lab/
├── .github/
│   └── workflows/
│       ├── civo-infrastructure-schedule.yml  # Scheduled cluster lifecycle — create at 8AM, destroy at 5PM ET (weekdays)
│       └── civo-platform-bootstrap.yml       # Post-create — installs platform stack, restores DB, updates DNS
├── infra/
│   ├── setup.ps1                             # Interactive setup — local or cloud
│   ├── aks-terraform/                        # AKS provisioning (modules: cluster, networking)
│   └── civo-terraform/                       # Civo provisioning (modules: cluster, networking)
├── gitops/
│   ├── apps/                                 # ArgoCD Application manifests
│   ├── policies/                             # Kyverno ClusterPolicy definitions
│   └── base/                                 # All Kubernetes manifests (deployments, services,
│                                             # NetworkPolicies, RBAC, ConfigMaps, PVCs)
├── backend/
│   ├── Dockerfile                            # Build context is backend/ (scenarios/ lives here too)
│   ├── scenarios/
│   │   ├── 01-privilege-escalation/
│   │   │   ├── attack.sh                     # Runs inside target-app pod via kubectl exec
│   │   │   └── proof.sh                      # Re-runs attack after reconciliation to prove controls hold
│   │   └── 02-networkpolicy-bypass/
│   │       ├── attack.sh
│   │       └── proof.sh
│   └── src/
│       ├── index.js                          # Express app — route registration
│       ├── db.js                             # SQLite init (sessions, tokens, events, audit log)
│       ├── watchdog.js                       # Cluster dirty-check and auto-reset
│       └── routes/
│           ├── token-public.js               # POST /token/validate
│           ├── token-admin.js                # Token generate / revoke (admin JWT)
│           ├── sessions.js                   # Session end / status
│           ├── events.js                     # GET /events/feed + POST /internal webhook
│           ├── scenarios.js                  # Scenario run / restore / proof / reset
│           ├── argocd.js                     # ArgoCD state poller
│           ├── admin.js                      # Admin dashboard + force reset
│           ├── k8s-client.js                 # kubectl-based K8s operations
│           └── falco-webhook.js              # Falco Sidekick alert receiver
├── frontend/
│   └── src/
│       ├── views/
│       │   ├── TokenGate.vue
│       │   ├── DemoView.vue                  # 3-panel demo UI
│       │   └── AdminView.vue
│       ├── components/
│       │   ├── ModeModal.vue                 # Scenario context + mode selection
│       │   ├── TimelineBar.vue
│       │   └── StolenDataPanel.vue
│       └── stores/
│           ├── session.js                    # Pinia session store + axios 401 interceptor
│           └── scenario.js                   # Pinia scenario store + polling
└── config.yaml                               # All tuneable parameters (session duration,
                                              # watchdog, messages, reconcile timeouts)
```

---

## Config

All tuneable parameters live in `config.yaml` at the repo root and are mounted into the backend pod via a ConfigMap. No code changes are needed to adjust session duration, watchdog behaviour, reconcile timeouts, or user-facing messages.

```yaml
session:
  duration_minutes: 30
  max_concurrent: 1          # One active session at a time, globally
scenario:
  proof_delay_seconds: 5
  reconcile_timeout_seconds: 120
watchdog:
  enabled: true
  interval_seconds: 60       # Resets cluster when dirty with no active session
```

---

## How Attack Scripts Work

Scripts live in `backend/scenarios/` and are baked into the backend Docker image. When a scenario runs, the backend:

1. Patches the `target-app` deployment to swap the service account (Allow Attack mode)
2. Waits for the new pod to reach `Running` state (handles rollout timing)
3. `kubectl cp`s the script into the pod's `/tmp` directory
4. `kubectl exec`s it — the script runs inside the pod using the mounted SA token
5. Each step emits a structured event via `POST /internal` to the backend
6. The frontend polls `/events/feed` every 2s and renders events in the Attack Feed panel

In controlled mode (With Controls), the pod has no token so the script exits at step 1 and auto-triggers the proof phase. For Allow Attack in Scenario 1, state transitions to `waiting` and the visitor manually triggers restore. For Scenario 2, ArgoCD auto-recovers and proof runs automatically after the reconcile window closes.

---

## Cost

| Mode | Est. Monthly |
|---|---|
| AKS always-on | ~$50/mo |
| AKS with auto-stop (Mon–Fri 8AM–5PM) | ~$14–15/mo |
| Civo always-on | ~$22/mo |
| Civo with auto-stop (Mon–Fri 8AM–5PM) | ~$6–7/mo |
| Local k3d | $0 |
