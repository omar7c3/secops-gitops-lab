// =============================================================================
// Routes — /token admin operations (admin JWT required)
// generate, sessions, usage, revoke
// =============================================================================

'use strict'

const express   = require('express')
const { getDb } = require('../db')
const router    = express.Router()

// ── POST /token/generate ──────────────────────────────────────────────────────
router.post('/generate', (req, res) => {
  const { label, expiryDays } = req.body
  const config = global.CONFIG

  if (!label) return res.status(400).json({ error: 'label required' })

  const days      = expiryDays || config.token.default_expiry_days || 7
  const expiresAt = Math.floor(Date.now() / 1000) + days * 86400

  // Generate token ID matching DEMO-XXXX-XXXX format
  const chars   = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
  const segment = (n) => Array.from({ length: n }, () =>
    chars[Math.floor(Math.random() * chars.length)]).join('')
  const tokenId = `DEMO-${segment(4)}-${segment(4)}`

  getDb().prepare(`
    INSERT INTO tokens (id, label, expires_at) VALUES (?, ?, ?)
  `).run(tokenId, label, expiresAt)

  return res.status(201).json({ token: tokenId, label, expiresAt, expiryDays: days })
})

// ── GET /token/sessions ───────────────────────────────────────────────────────
router.get('/sessions', (req, res) => {
  const db  = getDb()
  const now = Math.floor(Date.now() / 1000)

  const active = db.prepare(`
    SELECT s.*, t.label
    FROM sessions s
    JOIN tokens t ON t.id = s.token_id
    WHERE s.ended_at IS NULL AND s.expires_at > ?
    ORDER BY s.started_at DESC
  `).all(now)

  const blocked = db.prepare(`
    SELECT * FROM audit_log
    WHERE event_type = 'ACCESS_DENIED'
    ORDER BY created_at DESC
    LIMIT 50
  `).all()

  return res.json({ active, blocked })
})

// ── GET /token/usage ──────────────────────────────────────────────────────────
router.get('/usage', (req, res) => {
  const rows = getDb().prepare(`
    SELECT a.*, t.label
    FROM audit_log a
    LEFT JOIN tokens t ON t.id = a.token_id
    ORDER BY a.created_at DESC
    LIMIT 200
  `).all()

  return res.json({ log: rows })
})

// ── DELETE /token/revoke ──────────────────────────────────────────────────────
router.delete('/revoke', (req, res) => {
  const { tokenId } = req.body
  if (!tokenId) return res.status(400).json({ error: 'tokenId required' })

  const db = getDb()
  db.prepare(`UPDATE tokens SET revoked = 1 WHERE id = ?`).run(tokenId)

  db.prepare(`
    UPDATE sessions SET ended_at = ?, end_reason = 'admin_revoked'
    WHERE token_id = ? AND ended_at IS NULL
  `).run(Math.floor(Date.now() / 1000), tokenId)

  return res.json({ revoked: tokenId })
})

module.exports = router
