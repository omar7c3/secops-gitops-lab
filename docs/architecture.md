# Architecture

## Overview

Single Kubernetes cluster running all components. Two deployment targets
(AKS cloud, k3s local) with identical behavior — only the frontend
service type differs (LoadBalancer vs NodePort).

## Component Responsibilities

| Component | Role | Pods |
|---|---|---|
| ArgoCD | GitOps engine — drift detection + reconciliation | 4 (trimmed: no Dex, no ApplicationSet) |
| Kyverno | Admission webhook — blocks policy violations at API level | 2 (basic resilience) |
| Falco | DaemonSet — runtime syscall monitoring via eBPF | 1 per node |
| Backend | Token gate + event store + scenario orchestration + watchdog | 1 |
| Frontend | Vue 3 demo UI | 1 |
| Target App | Vulnerable workload — exec target for attack scripts | 1 |
| Postgres | Demo database for Scenario 2 | 1 |

**Total: ~11 pods**

## Falco vs Kyverno

| | Falco | Kyverno |
|---|---|---|
| When | Runtime — after the fact | Admission — before it happens |
| What | Running pods, syscalls | API requests to Kubernetes |
| How it stops things | It doesn't — detects and alerts | Blocks the request at admission |
| Analogy | Security camera | Bouncer |

## Attack Flow

### Scenario 1 (Allow Attack)

```
Backend swaps SA → over-privileged-sa
  Pod reads cluster-admin token
  Pod deletes Kyverno policies
  Pod suspends ArgoCD
  Pod creates privileged pod
  Pod mounts hostPath: /
  Pod chroots → root on node
  [WAITING — visitor must restore]
  Visitor clicks Restore Protection
  Backend resumes ArgoCD sync
  ArgoCD reconciles all drift
  Proof phase — attack blocked
```

### Scenario 2 (Allow Attack)

```
Backend deletes Kyverno protect-networkpolicies
Backend swaps SA → network-tooling-sa
  Pod reads network-tooling-sa token
  Pod deletes NetworkPolicy deny-all
  Pod tries to suspend ArgoCD → DENIED (wrong namespace)
  ~30s lateral movement window
  ArgoCD auto-reconciles (no suspension possible)
  Window closes
  Proof phase — blocked at admission
```

## Watchdog

Runs every 60 seconds inside the backend pod. Checks:
1. Is cluster state different from Git (dirty)?
2. Is there no active session (or session expired/ended)?

If both true → resumes ArgoCD sync + triggers reconcile.
Never resets while a session is active, even if idle.

## Secret Handling Reference

| Level | Pattern | Safe? |
|---|---|---|
| 4 — Worst | Plain text in manifest | Never |
| 3 — Bad | secretRef as env var | No |
| 2 — Better | Mounted as file | Acceptable |
| 1 — Best | External store (Vault/Key Vault) | Yes |
