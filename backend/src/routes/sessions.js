// =============================================================================
// Routes — /session
// JWT-authenticated — called by frontend
// =============================================================================

'use strict'

const express = require('express')
const { getDb } = require('../db')
const router = express.Router()

// ── POST /session/end ─────────────────────────────────────────────────────────
// Visitor clicks "End Session" button
router.post('/end', (req, res) => {
  const { sessionId } = req.user
  const db = getDb()

  db.prepare(`
    UPDATE sessions
    SET ended_at = ?, end_reason = 'user_ended'
    WHERE id = ? AND ended_at IS NULL
  `).run(Math.floor(Date.now() / 1000), sessionId)

  db.prepare(`
    INSERT INTO audit_log (session_id, token_id, event_type, detail)
    VALUES (?, ?, 'SESSION_END', ?)
  `).run(sessionId, req.user.tokenId, JSON.stringify({ reason: 'user_ended' }))

  // Signal watchdog that session ended — it will check if cluster is dirty
  // and reset if needed
  db.prepare(`
    UPDATE scenario_state SET status = 'idle' WHERE id = 1 AND status = 'idle'
  `).run()

  return res.json({ ended: true, sessionId })
})

// ── GET /session/status ───────────────────────────────────────────────────────
router.get('/status', (req, res) => {
  const { sessionId } = req.user
  const db = getDb()
  const config = global.CONFIG

  const session = db.prepare(`
    SELECT * FROM sessions WHERE id = ?
  `).get(sessionId)

  if (!session) return res.status(404).json({ error: 'session not found' })

  const now       = Math.floor(Date.now() / 1000)
  const remaining = Math.max(0, session.expires_at - now)

  // Update last_seen
  db.prepare(`UPDATE sessions SET last_seen_at = ? WHERE id = ?`)
    .run(now, sessionId)

  return res.json({
    sessionId,
    expiresAt: session.expires_at,
    remainingSeconds: remaining,
    durationMinutes: config.session.duration_minutes
  })
})

module.exports = router
