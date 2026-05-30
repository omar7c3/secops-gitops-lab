// =============================================================================
// Routes — /token/validate (public)
// Called by frontend token gate — no auth required
// =============================================================================

'use strict'

const express = require('express')
const jwt     = require('jsonwebtoken')
const { v4: uuidv4 } = require('uuid')
const { getDb }      = require('../db')

const router     = express.Router()
const JWT_SECRET = process.env.JWT_SECRET
const JWT_EXPIRES = '2h'

// ── POST /token/validate ──────────────────────────────────────────────────────
router.post('/validate', (req, res) => {
  const { token: tokenValue } = req.body
  const ip        = req.ip
  const userAgent = req.headers['user-agent'] || ''

  if (!tokenValue) {
    return res.status(400).json({ error: 'token required' })
  }

  const db     = getDb()
  const config = global.CONFIG

  // Find token
  const token = db.prepare(`
    SELECT * FROM tokens WHERE id = ? AND revoked = 0
  `).get(tokenValue)

  if (!token) {
    db.prepare(`
      INSERT INTO audit_log (token_id, event_type, ip, user_agent, detail)
      VALUES (?, 'ACCESS_DENIED', ?, ?, ?)
    `).run(tokenValue, ip, userAgent, JSON.stringify({ reason: 'token_invalid' }))

    return res.status(401).json({
      error: 'invalid',
      message: config.messages.token_invalid
    })
  }

  // Check expiry
  if (Date.now() / 1000 > token.expires_at) {
    db.prepare(`
      INSERT INTO audit_log (token_id, event_type, ip, user_agent, detail)
      VALUES (?, 'ACCESS_DENIED', ?, ?, ?)
    `).run(token.id, ip, userAgent, JSON.stringify({ reason: 'token_expired' }))

    return res.status(401).json({
      error: 'expired',
      message: config.messages.session_expired
    })
  }

  // Check for active session on this token
  const activeSession = db.prepare(`
    SELECT * FROM sessions
    WHERE token_id = ?
      AND ended_at IS NULL
      AND expires_at > ?
  `).get(token.id, Math.floor(Date.now() / 1000))

  if (activeSession) {
    db.prepare(`
      INSERT INTO audit_log (token_id, session_id, event_type, ip, user_agent, detail)
      VALUES (?, ?, 'ACCESS_DENIED', ?, ?, ?)
    `).run(token.id, activeSession.id, ip, userAgent,
      JSON.stringify({ reason: 'session_active', active_session_ip: activeSession.ip }))

    return res.status(409).json({
      error: 'session_active',
      message: config.messages.session_in_use
    })
  }

  // Create new session
  const sessionId   = uuidv4()
  const durationSec = (config.session.duration_minutes || 30) * 60
  const expiresAt   = Math.floor(Date.now() / 1000) + durationSec

  db.prepare(`
    INSERT INTO sessions (id, token_id, expires_at, ip, user_agent)
    VALUES (?, ?, ?, ?, ?)
  `).run(sessionId, token.id, expiresAt, ip, userAgent)

  db.prepare(`
    INSERT INTO audit_log (token_id, session_id, event_type, ip, user_agent, detail)
    VALUES (?, ?, 'SESSION_START', ?, ?, ?)
  `).run(token.id, sessionId, ip, userAgent, JSON.stringify({ label: token.label }))

  // Issue JWT
  const jwtToken = jwt.sign(
    { sessionId, tokenId: token.id, label: token.label },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES }
  )

  return res.json({
    jwt: jwtToken,
    sessionId,
    expiresAt,
    label: token.label,
    durationMinutes: config.session.duration_minutes
  })
})

module.exports = router
