// =============================================================================
// Routes — /admin
// Master password protected — admin UI only
// =============================================================================

'use strict'

const express   = require('express')
const { getDb } = require('../db')
const k8s       = require('./k8s-client')
const router    = express.Router()

// GET /admin/dashboard — all data for admin UI
router.get('/dashboard', (req, res) => {
  const db  = getDb()
  const now = Math.floor(Date.now() / 1000)

  const tokens = db.prepare(`
    SELECT t.*,
      (SELECT COUNT(*) FROM sessions s WHERE s.token_id = t.id) as session_count,
      (SELECT MAX(started_at) FROM sessions s WHERE s.token_id = t.id) as last_used
    FROM tokens t
    ORDER BY t.created_at DESC
  `).all()

  const activeSessions = db.prepare(`
    SELECT s.*, t.label
    FROM sessions s
    JOIN tokens t ON t.id = s.token_id
    WHERE s.ended_at IS NULL AND s.expires_at > ?
    ORDER BY s.started_at DESC
  `).all(now)

  const blockedAttempts = db.prepare(`
    SELECT * FROM audit_log
    WHERE event_type = 'ACCESS_DENIED'
    ORDER BY created_at DESC
    LIMIT 50
  `).all()

  const failedAdminAttempts = db.prepare(`
    SELECT * FROM audit_log
    WHERE event_type = 'ADMIN_ACCESS_DENIED'
    ORDER BY created_at DESC
    LIMIT 50
  `).all()

  const scenarioState = db.prepare('SELECT * FROM scenario_state WHERE id = 1').get()

  return res.json({ tokens, activeSessions, blockedAttempts, failedAdminAttempts, scenarioState })
})

// POST /admin/session/release — force release a session
router.post('/session/release', (req, res) => {
  const { sessionId } = req.body
  if (!sessionId) return res.status(400).json({ error: 'sessionId required' })

  const db  = getDb()
  const now = Math.floor(Date.now() / 1000)

  db.prepare(`
    UPDATE sessions SET ended_at = ?, end_reason = 'admin_force_released'
    WHERE id = ? AND ended_at IS NULL
  `).run(now, sessionId)

  db.prepare(`
    INSERT INTO audit_log (session_id, event_type, detail)
    VALUES (?, 'SESSION_END', ?)
  `).run(sessionId, JSON.stringify({ reason: 'admin_force_released' }))

  return res.json({ released: sessionId })
})

// POST /admin/cluster/reset — hard reset from admin UI
router.post('/cluster/reset', async (req, res) => {
  const db = getDb()

  await k8s.resumeArgoCDSync('secops-lab').catch(() => {})
  await k8s.resumeArgoCDSync('secops-lab-policies').catch(() => {})
  await k8s.syncArgoCD('secops-lab').catch(() => {})
  await k8s.syncArgoCD('secops-lab-policies').catch(() => {})

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

module.exports = router
