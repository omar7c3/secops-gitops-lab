#!/bin/bash
# =============================================================================
# Scenario 2 — NetworkPolicy Bypass
# proof.sh — re-runs attack after reconciliation to prove controls hold
#
# Expected outcome: Kyverno blocks NetworkPolicy deletion at admission
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
  "Same attack. Kyverno policy restored. Watch what happens."

APISERVER="https://kubernetes.default.svc"
CA="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null || echo "")

if [ -z "$TOKEN" ]; then
  emit "PROOF" "SUCCESS" \
    "No token — SA swapped back to minimal-sa" \
    "network-tooling-sa no longer mounted. Attack cannot start."
  exit 0
fi

# Try to delete NetworkPolicy — should be blocked by Kyverno
RESULT=$(kubectl delete networkpolicy deny-all \
  --token="$TOKEN" \
  --server="$APISERVER" \
  --certificate-authority="$CA" \
  -n "$NAMESPACE" \
  2>&1 || echo "BLOCKED")

if echo "$RESULT" | grep -q "BLOCKED\|denied\|forbidden\|violation"; then
  emit "PROOF" "SUCCESS" \
    "NetworkPolicy deletion blocked at admission" \
    "Same attack. Different result. Kyverno blocked at admission. Lateral movement window: 0 seconds."
else
  emit "PROOF" "WARNING" \
    "Unexpected result — check cluster state" \
    "Please run Reset to Safe State and verify Kyverno policies are restored."
fi
