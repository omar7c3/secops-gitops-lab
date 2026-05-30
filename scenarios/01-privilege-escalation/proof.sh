#!/bin/bash
# =============================================================================
# Scenario 1 — Privilege Escalation
# proof.sh — re-runs the attack after reconciliation to prove controls hold
#
# Expected outcome: blocked at Step 1 (no token mounted)
# =============================================================================

set -euo pipefail

BACKEND_URL="${BACKEND_URL:-http://secops-backend:3000}"

emit() {
  local phase=$1 severity=$2 title=$3 explanation=$4
  curl -sf -X POST "$BACKEND_URL/internal" \
    -H "Content-Type: application/json" \
    -d "{\"phase\":\"$phase\",\"severity\":\"$severity\",\"title\":\"$title\",\"explanation\":\"$explanation\"}" \
    || true
}

emit "PROOF" "INFO" \
  "Re-running same attack to prove controls hold" \
  "Same attack.sh. Same commands. Controls are now restored. Watch what happens."

# Step 1 — check for token
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null || echo "")

if [ -z "$TOKEN" ]; then
  emit "PROOF" "SUCCESS" \
    "No token found — attack blocked at step 1" \
    "automountServiceAccountToken is false. Same attack. Different result. GitOps restored the security posture completely."
  exit 0
fi

# If token somehow exists — try to create privileged pod (should be blocked by Kyverno)
emit "PROOF" "WARNING" \
  "Token found — attempting privileged pod creation" \
  "Token still present but Kyverno should block privileged pod creation."

RESULT=$(kubectl apply -f - \
  --token="$TOKEN" \
  --server="https://kubernetes.default.svc" \
  --certificate-authority="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt" \
  2>&1 <<'EOF' || true
apiVersion: v1
kind: Pod
metadata:
  name: proof-attack-pod
  namespace: secops-lab
spec:
  containers:
    - name: attacker
      image: alpine:latest
      command: ["sleep", "60"]
      securityContext:
        privileged: true
      resources:
        limits:
          cpu: "100m"
          memory: "128Mi"
  restartPolicy: Never
EOF
)

if echo "$RESULT" | grep -q "denied\|blocked\|violation"; then
  emit "PROOF" "SUCCESS" \
    "Privileged pod blocked by Kyverno" \
    "Same attack. Different result. Kyverno admission policy is restored and blocking the attack."
else
  emit "PROOF" "WARNING" \
    "Unexpected result during proof phase" \
    "Please check cluster state and run Reset to Safe State."
fi
