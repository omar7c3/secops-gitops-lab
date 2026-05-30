// =============================================================================
// Kubernetes Client Helper
// Wraps @kubernetes/client-node for common operations
// Used by scenario orchestration and watchdog
//
// NOTE: ArgoCD Application is namespace-scoped (lives in argocd namespace).
// @kubernetes/client-node v1.x uses param objects, not positional args.
// =============================================================================

'use strict'

const http  = require('http')
const https = require('https')
const k8s   = require('@kubernetes/client-node')

const kc = new k8s.KubeConfig()

try {
  kc.loadFromCluster()
  console.log('[k8s] loaded in-cluster config')
} catch {
  kc.loadFromDefault()
  console.log('[k8s] loaded local kubeconfig')
}

const appsApi   = kc.makeApiClient(k8s.AppsV1Api)
const customApi = kc.makeApiClient(k8s.CustomObjectsApi)

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

  await appsApi.patchNamespacedDeployment({
    name:      deploymentName,
    namespace: NAMESPACE,
    body:      patch
  }, { headers: { 'Content-Type': 'application/merge-patch+json' } })

  console.log(`[k8s] swapped SA on ${deploymentName} -> ${saName} (mount: ${mountToken})`)
}

// ── Delete a Kyverno ClusterPolicy ────────────────────────────────────────────
async function deleteKyvernoPolicy(policyName) {
  try {
    await customApi.deleteClusterCustomObject({
      group:   'kyverno.io',
      version: 'v1',
      plural:  'clusterpolicies',
      name:    policyName
    })
    console.log(`[k8s] deleted Kyverno policy: ${policyName}`)
  } catch (err) {
    if (err.statusCode === 404) {
      console.log(`[k8s] policy ${policyName} already gone`)
    } else {
      throw err
    }
  }
}

// ArgoCD Applications are namespace-scoped — they live in the argocd namespace
const ARGOCD_PARAMS = { group: 'argoproj.io', version: 'v1alpha1', namespace: 'argocd', plural: 'applications' }
const MERGE_PATCH   = { headers: { 'Content-Type': 'application/merge-patch+json' } }

// ── Suspend ArgoCD sync ────────────────────────────────────────────────────────
async function suspendArgoCDSync(appName) {
  await customApi.patchNamespacedCustomObject({
    ...ARGOCD_PARAMS,
    name: appName,
    body: { spec: { syncPolicy: { automated: null } } }
  }, MERGE_PATCH)
  console.log(`[k8s] suspended ArgoCD sync: ${appName}`)
}

// ── Resume ArgoCD sync ────────────────────────────────────────────────────────
async function resumeArgoCDSync(appName) {
  await customApi.patchNamespacedCustomObject({
    ...ARGOCD_PARAMS,
    name: appName,
    body: { spec: { syncPolicy: { automated: { prune: true, selfHeal: true } } } }
  }, MERGE_PATCH)
  console.log(`[k8s] resumed ArgoCD sync: ${appName}`)
}

// ── Trigger ArgoCD hard sync via ArgoCD REST API ──────────────────────────────
function syncArgoCD(appName) {
  const server   = process.env.ARGOCD_SERVER || 'argocd-server.argocd.svc.cluster.local'
  const port     = parseInt(process.env.ARGOCD_PORT || '80', 10)
  const token    = process.env.ARGOCD_TOKEN || ''
  const body     = JSON.stringify({ prune: true, strategy: { hook: {} } })
  const protocol = port === 443 ? https : http

  return new Promise((resolve, reject) => {
    const req = protocol.request({
      hostname: server,
      port,
      path:     `/api/v1/applications/${appName}/sync`,
      method:   'POST',
      headers: {
        'Content-Type':   'application/json',
        'Content-Length': Buffer.byteLength(body),
        ...(token ? { Authorization: `Bearer ${token}` } : {})
      }
    }, (res) => {
      let data = ''
      res.on('data', c => { data += c })
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          console.log(`[k8s] triggered ArgoCD sync: ${appName}`)
          resolve()
        } else {
          reject(new Error(`HTTP-Code: ${res.statusCode} Body: ${data.slice(0, 200)}`))
        }
      })
    })
    req.on('error', reject)
    req.setTimeout(5000, () => { req.destroy(); reject(new Error('ArgoCD sync request timeout')) })
    req.write(body)
    req.end()
  })
}

// ── Check if cluster state differs from Git (dirty check) ────────────────────
async function isClusterDirty() {
  try {
    const apps = await Promise.all([
      customApi.getNamespacedCustomObject({ ...ARGOCD_PARAMS, name: 'secops-lab' }),
      customApi.getNamespacedCustomObject({ ...ARGOCD_PARAMS, name: 'secops-lab-policies' })
    ])

    return apps.some(app => {
      const syncStatus = app?.status?.sync?.status
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
    const app = await customApi.getNamespacedCustomObject({ ...ARGOCD_PARAMS, name: appName })
    return !app?.spec?.syncPolicy?.automated
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
