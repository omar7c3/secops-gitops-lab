// =============================================================================
// Middleware — JWT auth for visitor routes
// =============================================================================

'use strict'

const jwt = require('jsonwebtoken')
const { getDb } = require('../db')

const JWT_SECRET = process.env.JWT_SECRET || 'change-me-in-production'

function authMiddleware(req, res, next) {
  const header = req.headers.authorization || ''
  const token  = header.startsWith('Bearer ') ? header.slice(7) : null

  if (!token) {
    return res.status(401).json({ error: 'authorization required' })
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET)
    const db      = getDb()

    // Verify session still active
    const session = db.prepare(`
      SELECT * FROM sessions
      WHERE id = ? AND ended_at IS NULL AND expires_at > ?
    `).get(payload.sessionId, Math.floor(Date.now() / 1000))

    if (!session) {
      return res.status(401).json({
        error: 'session_expired',
        message: global.CONFIG?.messages?.session_expired || 'Session expired.'
      })
    }

    req.user = payload
    next()
  } catch (err) {
    return res.status(401).json({ error: 'invalid token' })
  }
}

module.exports = { authMiddleware }
