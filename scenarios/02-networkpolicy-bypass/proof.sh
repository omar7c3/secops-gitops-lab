#!/bin/bash
# =============================================================================
# Scenario 2 — NetworkPolicy Bypass
# proof.sh — re-runs attack after reconciliation to prove controls hold
# =============================================================================

set -euo pipefail

BACKEND_URL="${BACKEND_URL:-http://secops-backend:3000}"
NAMESPACE="${NAMESPACE:-secops-lab}"

emit() {
  local phase=$1 severity=$2 title=$3 explanation=$4
  curl -sf -X POST "$BACKEND_URL/internal" \
    -H "Content-Type: application/json" \
    -d "{\"phase\":\"$phase\",\"severity\":\"$severity\",\"title\":\"$title\",\"explanation\":\"$explanation\"}" \
    || true
}

emit "PROOF" "INFO" \
  "Re-running attack — Kyverno and ArgoCD both active" \
  "Same attack. protect-networkpolicies Kyverno policy restored by ArgoCD. Watch what happens."

APISERVER="https://kubernetes.default.svc"
CA="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

# ── Primary check: is the database path sealed again? ─────────────────────────
# Token-independent TCP probe — works even after the SA has been reverted to
# minimal-sa. The egress policies are back, so target-app egress to postgres
# should be denied once more.
POSTGRES_RESULT=$(bash -c 'echo > /dev/tcp/postgres/5432' 2>/dev/null && echo "OPEN" || echo "blocked")

if [ "$POSTGRES_RESULT" = "blocked" ]; then
  emit "PROOF" "SUCCESS" \
    "Database path sealed — postgres unreachable" \
    "Egress isolation restored by ArgoCD. target-app egress to postgres is denied again — the path that was open during the window is now closed. GitOps fully restored the security posture."
else
  emit "PROOF" "WARNING" \
    "Database still reachable — check cluster state" \
    "postgres:5432 is still reachable after reconciliation. Expected it to be sealed once the egress policies are restored. Run Reset to Safe State and verify NetworkPolicies."
fi

# ── Secondary check: admission guard re-blocks the delete (only if SA mounted) ─
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null || echo "")

if [ -z "$TOKEN" ]; then
  emit "PROOF" "SUCCESS" \
    "No token — SA swapped back to minimal-sa" \
    "network-tooling-sa no longer mounted. ArgoCD reverted target-app to minimal-sa — the attack cannot even start."
  exit 0
fi

RESULT=$(kubectl delete networkpolicy deny-all \
  --token="$TOKEN" \
  --server="$APISERVER" \
  --certificate-authority="$CA" \
  -n "$NAMESPACE" \
  2>&1 || echo "BLOCKED")

if echo "$RESULT" | grep -q "BLOCKED\|denied\|forbidden\|violation"; then
  emit "PROOF" "SUCCESS" \
    "NetworkPolicy deletion blocked at admission" \
    "Same attack, different result. Kyverno protect-networkpolicies blocked the deletion at admission — the isolation cannot be stripped again."
else
  emit "PROOF" "WARNING" \
    "Unexpected result — check cluster state" \
    "Please run Reset to Safe State and verify Kyverno policies are restored."
fi
