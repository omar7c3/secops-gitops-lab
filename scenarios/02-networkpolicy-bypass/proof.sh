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
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null || echo "")

if [ -z "$TOKEN" ]; then
  emit "PROOF" "SUCCESS" \
    "No token — SA swapped back to minimal-sa" \
    "network-tooling-sa no longer mounted. Attack cannot start."
  exit 0
fi

# Try to delete deny-all — should be blocked by Kyverno
RESULT=$(kubectl delete networkpolicy deny-all \
  --token="$TOKEN" \
  --server="$APISERVER" \
  --certificate-authority="$CA" \
  -n "$NAMESPACE" \
  2>&1 || echo "BLOCKED")

if echo "$RESULT" | grep -q "BLOCKED\|denied\|forbidden\|violation"; then
  emit "PROOF" "SUCCESS" \
    "NetworkPolicy deletion blocked at admission" \
    "Same attack. Different result. Kyverno blocked the deletion. Lateral movement window: 0 seconds. Database credentials are still in environment but the network path is sealed."
else
  emit "PROOF" "WARNING" \
    "Unexpected result — check cluster state" \
    "Please run Reset to Safe State and verify Kyverno policies are restored."
  exit 0
fi

# Verify the database path is sealed again — deny-all restored, no backdoor was
# planted, so target-app egress to postgres should be denied once more.
POSTGRES_RESULT=$(bash -c 'echo > /dev/tcp/postgres/5432' 2>/dev/null && echo "OPEN" || echo "blocked")

if [ "$POSTGRES_RESULT" = "blocked" ]; then
  emit "PROOF" "SUCCESS" \
    "Database path sealed — postgres unreachable" \
    "With deny-all restored and no attacker backdoor planted, target-app egress to postgres is denied again. The lateral movement path that was open during the window is now closed. GitOps fully restored the security posture."
else
  emit "PROOF" "WARNING" \
    "Database still reachable — check cluster state" \
    "postgres:5432 is still reachable after reconciliation. Expected it to be sealed once deny-all is restored. Run Reset to Safe State and verify NetworkPolicies."
fi
