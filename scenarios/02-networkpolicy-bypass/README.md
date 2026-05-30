# Scenario 2 — Lateral Movement via NetworkPolicy Bypass

## What This Demonstrates

A pod with a narrowly scoped but over-permissioned service account
(`network-tooling-sa` with NetworkPolicy admin rights) can delete the
namespace deny-all NetworkPolicy, opening a lateral movement window.

Unlike Scenario 1, the attacker **cannot suspend ArgoCD** — the window
is bounded by GitOps reconciliation time (~30 seconds).

## The Misconfiguration

| Misconfiguration | Real World Equivalent |
|---|---|
| `network-tooling-sa` has `delete` on `networkpolicies` | CNI helper / monitoring pod given management rights instead of read-only |
| `automountServiceAccountToken: true` | Token accessible to any process in the container |

## Key Contrast With Scenario 1

| | Scenario 1 | Scenario 2 |
|---|---|---|
| SA permissions | `cluster-admin` — everything | NetworkPolicy admin only |
| Can suspend ArgoCD? | Yes — window is indefinite | No — window is ~30 seconds |
| Recovery | Manual — visitor must act | Automatic — ArgoCD reconciles |
| Lesson | cluster-admin = permanent breach | Narrow permissions = bounded blast radius |

## Attack Chain

```
exec into pod
  → read network-tooling-sa token
  → delete NetworkPolicy deny-all   (Kyverno blocks WITH controls)
  → try to suspend ArgoCD           (access denied — wrong namespace)
  → probe internal services during ~30s window
  → ArgoCD reconciles — NetworkPolicy restored
```

## Files

| File | Purpose |
|---|---|
| `attack.sh` | Steals token, deletes NetworkPolicy, probes internal services |
| `proof.sh` | Re-runs attack — Kyverno blocks at admission |
| `expected.yaml` | Desired state — deny-all NetworkPolicy + protect-networkpolicies policy |
