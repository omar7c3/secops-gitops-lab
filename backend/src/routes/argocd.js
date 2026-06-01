// =============================================================================
// Route — /argocd
// Polls ArgoCD API for drift/sync state — fed to frontend System State panel
// =============================================================================

'use strict'

const express = require('express')
const https   = require('https')
const http    = require('http')
const router  = express.Router()

const ARGOCD_SERVER  = process.env.ARGOCD_SERVER  || 'argocd-server.argocd.svc.cluster.local'
const ARGOCD_TOKEN   = process.env.ARGOCD_TOKEN   || ''
const ARGOCD_PORT    = process.env.ARGOCD_PORT    || '80'

// GET /argocd/state — polled by frontend every 2s
router.get('/state', async (req, res) => {
  try {
    const apps = await Promise.all([
      getArgoCDApp('secops-lab'),
      getArgoCDApp('secops-lab-policies')
    ])

    const state = apps.map(app => ({
      name:         app.metadata?.name,
      syncStatus:   app.status?.sync?.status,      // Synced | OutOfSync
      healthStatus: app.status?.health?.status,    // Healthy | Degraded | Progressing
      suspended:    app.spec?.syncPolicy?.automated === null || !app.spec?.syncPolicy?.automated,
      resources:    (app.status?.resources || [])
        // Hide the postgres-seed PostSync hook Job — it re-runs and self-deletes
        // on every ArgoCD sync (which scenarios trigger), so it blinks in/out of
        // the panel as noise rather than meaningful drift.
        .filter(r => !(r.kind === 'Job' && r.name === 'postgres-seed'))
        .map(r => ({
          kind:      r.kind,
          name:      r.name,
          namespace: r.namespace,
          status:    r.status,
          health:    r.health?.status
        }))
    }))

    return res.json({ apps: state, timestamp: Date.now() })
  } catch (err) {
    console.error('[argocd] state fetch error:', err.message)
    return res.status(503).json({ error: 'ArgoCD unavailable', message: err.message })
  }
})

// ── ArgoCD API helper ─────────────────────────────────────────────────────────
function getArgoCDApp(appName) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: ARGOCD_SERVER,
      port:     ARGOCD_PORT,
      path:     `/api/v1/applications/${appName}`,
      method:   'GET',
      headers:  ARGOCD_TOKEN ? { Authorization: `Bearer ${ARGOCD_TOKEN}` } : {}
    }

    const protocol = ARGOCD_PORT === '443' ? https : http
    const req = protocol.request(options, (res) => {
      let data = ''
      res.on('data', chunk => { data += chunk })
      res.on('end', () => {
        try { resolve(JSON.parse(data)) }
        catch (e) { reject(new Error(`Invalid JSON from ArgoCD: ${data.slice(0, 100)}`)) }
      })
    })

    req.on('error', reject)
    req.setTimeout(5000, () => { req.destroy(); reject(new Error('ArgoCD request timeout')) })
    req.end()
  })
}

module.exports = router
