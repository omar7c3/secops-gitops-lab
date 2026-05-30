# Scenario 1 — Privilege Escalation via Service Account Abuse

## What This Demonstrates

A pod with an over-permissioned service account (`cluster-admin`) and
`automountServiceAccountToken: true` can steal its own token and use it
to own the entire cluster — deleting admission controls, suspending GitOps,
and gaining root on the node.

## The Misconfigurations

| Misconfiguration | Real World Equivalent |
|---|---|
| `automountServiceAccountToken: true` | App that doesn't need K8s API access but has it |
| SA bound to `cluster-admin` | Legacy app migrated to K8s with admin rights never revoked |

## Attack Chain

```
exec into pod
  → read /var/run/secrets/.../token        (cluster-admin token)
  → delete Kyverno no-privileged-containers
  → delete Kyverno no-hostpath-mount
  → suspend ArgoCD sync
  → create privileged pod with hostPath: /
  → exec into privileged pod
  → chroot /host → root on node
  → read cluster certs, kubelet config, all pod secrets
```

## With Controls vs Allow Attack

| Mode | What happens |
|---|---|
| With Controls | `automountServiceAccountToken: false` — no token to steal, attack stops at step 1 |
| Allow Attack | Backend swaps SA to `over-privileged-sa`, pod does everything itself |

## Recovery

**Allow Attack mode requires manual recovery** — visitor must click
"Restore Protection" in the UI. This is intentional: cluster-admin
credential theft has no automatic recovery. The dwell time counter
shows how long the cluster was compromised.

After manual restore:
1. Backend resumes ArgoCD sync
2. ArgoCD deletes `privileged-attack-pod`
3. ArgoCD deletes `cluster-admin` SA binding
4. ArgoCD restores both Kyverno policies
5. ArgoCD swaps SA back to `minimal-sa`

## Files

| File | Purpose |
|---|---|
| `attack.sh` | Runs inside target-app pod — steals token and executes full chain |
| `proof.sh` | Re-runs attack after reconcile — proves controls hold |
| `expected.yaml` | Desired state used by backend to verify reconciliation |
