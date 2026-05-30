// =============================================================================
// Routes — /scenario
// JWT-authenticated — scenario orchestration
// =============================================================================

'use strict'

const express  = require('express')
const { exec } = require('child_process')
const path     = require('path')
const { getDb } = require('../db')
const k8s      = require('./k8s-client')

const router = express.Router()

const SCENARIOS_DIR = path.resolve(__dirname, '../../../scenarios')

// ── POST /scenario/run ────────────────────────────────────────────────────────
router.post('/run', async (req, res) => {
  const { scenario, mode } = req.body
  // scenario: 'privilege-escalation' | 'network-policy-bypass'
  // mode:     'controlled' | 'uncontrolled'

  if (!scenario || !mode) {
    return res.status(400).json({ error: 'scenario and mode required' })
  }

  const db     = getDb()
  const state  = db.prepare('SELECT * FROM scenario_state WHERE id = 1').get()

  if (state.status !== 'idle') {
    return res.status(409).json({
      error: 'scenario_running',
      message: 'A scenario is already running. Reset to Safe State first.'
    })
  }

  const now = Math.floor(Date.now() / 1000)

  // ── Allow Attack setup ──────────────────────────────────────────────────────
  if (mode === 'uncontrolled') {
    if (scenario === 'privilege-escalation') {
      // Swap SA to over-privileged-sa
      await k8s.swapServiceAccount('target-app', 'over-privileged-sa', true)
      emitEvent(req.user.sessionId, 'SETUP', 'WARNING', scenario,
        'Swapping service account to over-privileged-sa',
        'Backend patches target-app deployment. This mimics a common misconfiguration — an app given more Kubernetes API access than it needs. automountServiceAccountToken is now true.')
    }

    if (scenario === 'network-policy-bypass') {
      // Delete Kyverno protect-networkpolicies policy
      await k8s.deleteKyvernoPolicy('protect-networkpolicies')
      emitEvent(req.user.sessionId, 'SETUP', 'WARNING', scenario,
        'Backend deleting Kyverno policy: protect-networkpolicies',
        'Backend removes the one Kyverno policy protecting NetworkPolicy resources. Pod will now be able to delete it using the network-tooling-sa token.')

      // Swap SA to network-tooling-sa
      await k8s.swapServiceAccount('target-app', 'network-tooling-sa', true)
      emitEvent(req.user.sessionId, 'SETUP', 'WARNING', scenario,
        'Swapping SA to network-tooling-sa',
        'Backend patches target-app to mount network-tooling-sa. This SA has NetworkPolicy delete rights but cannot touch ArgoCD.')
    }
  }

  // Update state machine
  db.prepare(`
    UPDATE scenario_state SET
      status = 'attacking',
      scenario = ?,
      mode = ?,
      session_id = ?,
      attack_started_at = ?,
      argocd_suspended = 0,
      kyverno_deleted = 0
    WHERE id = 1
  `).run(scenario, mode, req.user.sessionId, now)

  // Log to audit
  db.prepare(`
    INSERT INTO audit_log (session_id, token_id, event_type, detail)
    VALUES (?, ?, 'SCENARIO_RUN', ?)
  `).run(req.user.sessionId, req.user.tokenId,
    JSON.stringify({ scenario, mode }))

  // Run attack script inside target-app pod
  const scriptPath = path.join(SCENARIOS_DIR, `0${scenario === 'privilege-escalation' ? 1 : 2}-${scenario}`, 'attack.sh')

  const namespace = global.CONFIG.cluster.namespace
  const cmd = `kubectl exec target-app -n ${namespace} -- bash ${scriptPath}`

  exec(cmd, { timeout: 120000 }, (err, stdout, stderr) => {
    if (err) console.error('[scenario] attack.sh error:', err.message)
    if (stderr) console.error('[scenario] attack.sh stderr:', stderr)
    console.log('[scenario] attack.sh stdout:', stdout)
  })

  return res.json({ started: true, scenario, mode })
})

// ── POST /scenario/restore ────────────────────────────────────────────────────
// Scenario 1 only — visitor manually restores after Allow Attack
router.post('/restore', async (req, res) => {
  const db    = getDb()
  const state = db.prepare('SELECT * FROM scenario_state WHERE id = 1').get()
  const now   = Math.floor(Date.now() / 1000)

  if (state.status !== 'waiting') {
    return res.status(409).json({ error: 'not in waiting state' })
  }

  // Calculate dwell time
  const dwellSeconds = state.compromised_at ? now - state.compromised_at : 0

  db.prepare(`
    UPDATE scenario_state SET
      status = 'reconciling',
      restored_at = ?,
      dwell_time_seconds = ?
    WHERE id = 1
  `).run(now, dwellSeconds)

  emitEvent(req.user.sessionId, 'RESTORE', 'INFO', state.scenario,
    'Visitor triggered manual protection restore',
    `Backend resumes ArgoCD sync. Recording total dwell time — ${Math.floor(dwellSeconds / 60)}m ${dwellSeconds % 60}s.`)

  // Resume ArgoCD sync
  await k8s.resumeArgoCDSync('secops-lab')
  await k8s.resumeArgoCDSync('secops-lab-policies')

  emitEvent(req.user.sessionId, 'RESTORE', 'INFO', state.scenario,
    'ArgoCD sync resumed',
    'GitOps is active again. ArgoCD will now detect and reconcile all drift introduced during the attack.')

  emitEvent(req.user.sessionId, 'RESTORE', 'WARNING', state.scenario,
    `Dwell time: ${Math.floor(dwellSeconds / 60)}m ${dwellSeconds % 60}s`,
    `Cluster was fully compromised for this duration. In a real incident this window represents maximum attacker access time — certificate theft, data exfiltration, and backdoor installation could all occur in this window.`)

  return res.json({ restored: true, dwellSeconds })
})

// ── POST /scenario/proof ──────────────────────────────────────────────────────
router.post('/proof', async (req, res) => {
  const db    = getDb()
  const state = db.prepare('SELECT * FROM scenario_state WHERE id = 1').get()

  if (!state.scenario) {
    return res.status(409).json({ error: 'no scenario to prove' })
  }

  db.prepare(`UPDATE scenario_state SET status = 'proof' WHERE id = 1`).run()

  const namespace  = global.CONFIG.cluster.namespace
  const scriptNum  = state.scenario === 'privilege-escalation' ? '01' : '02'
  const scriptPath = path.join(SCENARIOS_DIR, `${scriptNum}-${state.scenario}`, 'proof.sh')
  const cmd        = `kubectl exec target-app -n ${namespace} -- bash ${scriptPath}`

  // Wait for proof_delay_seconds before running
  const delayMs = (global.CONFIG.scenario.proof_delay_seconds || 5) * 1000
  setTimeout(() => {
    exec(cmd, { timeout: 60000 }, (err, stdout, stderr) => {
      if (err) console.error('[proof] error:', err.message)
      db.prepare(`UPDATE scenario_state SET status = 'complete' WHERE id = 1`).run()
    })
  }, delayMs)

  return res.json({ started: true })
})

// ── POST /scenario/reset ──────────────────────────────────────────────────────
router.post('/reset', async (req, res) => {
  const db  = getDb()
  const now = Math.floor(Date.now() / 1000)

  // Resume ArgoCD sync if suspended
  await k8s.resumeArgoCDSync('secops-lab').catch(() => {})
  await k8s.resumeArgoCDSync('secops-lab-policies').catch(() => {})

  // Trigger ArgoCD hard sync
  await k8s.syncArgoCD('secops-lab').catch(() => {})
  await k8s.syncArgoCD('secops-lab-policies').catch(() => {})

  // Clear event feed for this session
  const state = db.prepare('SELECT * FROM scenario_state WHERE id = 1').get()
  if (state.session_id) {
    db.prepare(`DELETE FROM events WHERE session_id = ?`).run(state.session_id)
  }

  // Reset state machine
  db.prepare(`
    UPDATE scenario_state SET
      status = 'idle', scenario = NULL, mode = NULL, session_id = NULL,
      argocd_suspended = 0, kyverno_deleted = 0,
      attack_started_at = NULL, compromised_at = NULL,
      restored_at = NULL, dwell_time_seconds = NULL,
      window_started_at = NULL, window_ended_at = NULL
    WHERE id = 1
  `).run()

  return res.json({ reset: true })
})

// ── GET /scenario/state ───────────────────────────────────────────────────────
router.get('/state', (req, res) => {
  const state = getDb().prepare('SELECT * FROM scenario_state WHERE id = 1').get()
  const now   = Math.floor(Date.now() / 1000)

  // Add live dwell time if currently compromised
  if (state.status === 'waiting' && state.compromised_at) {
    state.current_dwell_seconds = now - state.compromised_at
  }

  // Add live window duration for Scenario 2
  if (state.window_started_at && !state.window_ended_at) {
    state.current_window_seconds = now - state.window_started_at
  }

  return res.json(state)
})

// ── Helper — emit event to DB ─────────────────────────────────────────────────
function emitEvent(sessionId, phase, severity, scenario, title, explanation) {
  getDb().prepare(`
    INSERT INTO events (session_id, phase, severity, title, explanation, scenario)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(sessionId, phase, severity, title, explanation, scenario)
}

module.exports = router
