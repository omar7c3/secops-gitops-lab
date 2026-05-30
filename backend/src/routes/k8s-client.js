// =============================================================================
// Kubernetes Client Helper
// Wraps @kubernetes/client-node for common operations
// Used by scenario orchestration and watchdog
// =============================================================================

'use strict'

const k8s = require('@kubernetes/client-node')

const kc = new k8s.KubeConfig()

// Load in-cluster config when running inside Kubernetes
// Falls back to local kubeconfig for development
try {
  kc.loadFromCluster()
  console.log('[k8s] loaded in-cluster config')
} catch {
  kc.loadFromDefault()
  console.log('[k8s] loaded local kubeconfig')
}

const appsApi    = kc.makeApiClient(k8s.AppsV1Api)
const coreApi    = kc.makeApiClient(k8s.CoreV1Api)
const customApi  = kc.makeApiClient(k8s.CustomObjectsApi)

const NAMESPACE = process.env.NAMESPACE || 'secops-lab'

// ── Swap service account on target-app deployment ─────────────────────────────
async function swapServiceAccount(deploymentName, saName, mountToken) {
  const patch = {
    spec: {
      template: {
        spec: {
          serviceAccountName:           saName,
          automountServiceAccountToken: mountToken
        }
      }
    }
  }

  await appsApi.patchNamespacedDeployment(
    deploymentName,
    NAMESPACE,
    patch,
    undefined, undefined, undefined, undefined,
    { headers: { 'Content-Type': 'application/merge-patch+json' } }
  )

  console.log(`[k8s] swapped SA on ${deploymentName} -> ${saName} (mount: ${mountToken})`)
}

// ── Delete a Kyverno ClusterPolicy ────────────────────────────────────────────
async function deleteKyvernoPolicy(policyName) {
  try {
    await customApi.deleteClusterCustomObject(
      'kyverno.io', 'v1', 'clusterpolicies', policyName
    )
    console.log(`[k8s] deleted Kyverno policy: ${policyName}`)
  } catch (err) {
    if (err.statusCode === 404) {
      console.log(`[k8s] policy ${policyName} already gone`)
    } else {
      throw err
    }
  }
}

// ── Suspend ArgoCD sync for an application ────────────────────────────────────
async function suspendArgoCDSync(appName) {
  const patch = { spec: { syncPolicy: { automated: null } } }
  await customApi.patchNamespacedCustomObject(
    'argoproj.io', 'v1alpha1', 'argocd', 'applications', appName,
    patch,
    undefined, undefined, undefined,
    { headers: { 'Content-Type': 'application/merge-patch+json' } }
  )
  console.log(`[k8s] suspended ArgoCD sync: ${appName}`)
}

// ── Resume ArgoCD sync for an application ────────────────────────────────────
async function resumeArgoCDSync(appName) {
  const patch = {
    spec: {
      syncPolicy: {
        automated: { prune: true, selfHeal: true }
      }
    }
  }
  await customApi.patchNamespacedCustomObject(
    'argoproj.io', 'v1alpha1', 'argocd', 'applications', appName,
    patch,
    undefined, undefined, undefined,
    { headers: { 'Content-Type': 'application/merge-patch+json' } }
  )
  console.log(`[k8s] resumed ArgoCD sync: ${appName}`)
}

// ── Trigger ArgoCD hard sync ──────────────────────────────────────────────────
async function syncArgoCD(appName) {
  await customApi.patchNamespacedCustomObject(
    'argoproj.io', 'v1alpha1', 'argocd', 'applications', appName,
    { operation: { sync: { force: true } } },
    undefined, undefined, undefined,
    { headers: { 'Content-Type': 'application/merge-patch+json' } }
  )
  console.log(`[k8s] triggered ArgoCD sync: ${appName}`)
}

// ── Check if cluster state matches Git (dirty check) ─────────────────────────
async function isClusterDirty() {
  try {
    const apps = await Promise.all([
      customApi.getNamespacedCustomObject(
        'argoproj.io', 'v1alpha1', 'argocd', 'applications', 'secops-lab'
      ),
      customApi.getNamespacedCustomObject(
        'argoproj.io', 'v1alpha1', 'argocd', 'applications', 'secops-lab-policies'
      )
    ])

    return apps.some(app => {
      const syncStatus = app.body?.status?.sync?.status
      return syncStatus && syncStatus !== 'Synced'
    })
  } catch (err) {
    console.error('[k8s] dirty check error:', err.message)
    return false
  }
}

// ── Check if ArgoCD sync is suspended ────────────────────────────────────────
async function isArgoCDSuspended(appName) {
  try {
    const app = await customApi.getNamespacedCustomObject(
      'argoproj.io', 'v1alpha1', 'argocd', 'applications', appName
    )
    return !app.body?.spec?.syncPolicy?.automated
  } catch {
    return false
  }
}

module.exports = {
  swapServiceAccount,
  deleteKyvernoPolicy,
  suspendArgoCDSync,
  resumeArgoCDSync,
  syncArgoCD,
  isClusterDirty,
  isArgoCDSuspended
}
