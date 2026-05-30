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

const customApi = kc.makeApiClient(k8s.CustomObjectsApi)

const NAMESPACE = process.env.NAMESPACE || 'secops-lab'

// ── Swap service account on target-app deployment ─────────────────────────────
// Uses kubectl patch — the k8s client typed API defaults to wrong Content-Type.
// When mounting a token, adds secops-lab/needs-api-access: "true" to satisfy
// the disallow-automount-sa-token Kyverno policy exception. ArgoCD removes it
// on reconcile.
function swapServiceAccount(deploymentName, saName, mountToken) {
  const patch = JSON.stringify({
    spec: {
      template: {
        metadata: {
          labels: { 'secops-lab/needs-api-access': mountToken ? 'true' : null }
        },
        spec: {
          serviceAccountName:           saName,
          automountServiceAccountToken: mountToken
        }
      }
    }
  })

  return new Promise((resolve, reject) => {
    const { exec } = require('child_process')
    exec(
      `kubectl patch deployment ${deploymentName} -n ${NAMESPACE} --type=merge -p '${patch}'`,
      (err) => {
        if (err) return reject(err)
        console.log(`[k8s] swapped SA on ${deploymentName} -> ${saName} (mount: ${mountToken})`)
        resolve()
      }
    )
  })
}

// ── kubectl patch helper — bypasses Content-Type bug in k8s client v1.4 ──────
function kubectlPatch(resource, namespace, patchJson) {
  const { exec } = require('child_process')
  return new Promise((resolve, reject) => {
    exec(
      `kubectl patch ${resource} -n ${namespace} --type=merge -p '${patchJson}'`,
      (err, stdout, stderr) => {
        if (err) return reject(new Error(stderr || err.message))
        resolve(stdout.trim())
      }
    )
  })
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

// ── Suspend ArgoCD sync ────────────────────────────────────────────────────────
function suspendArgoCDSync(appName) {
  return kubectlPatch(`application/${appName}`, 'argocd',
    '{"spec":{"syncPolicy":{"automated":null}}}')
    .then(() => console.log(`[k8s] suspended ArgoCD sync: ${appName}`))
}

// ── Resume ArgoCD sync ────────────────────────────────────────────────────────
function resumeArgoCDSync(appName) {
  return kubectlPatch(`application/${appName}`, 'argocd',
    '{"spec":{"syncPolicy":{"automated":{"prune":true,"selfHeal":true}}}}')
    .then(() => console.log(`[k8s] resumed ArgoCD sync: ${appName}`))
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
