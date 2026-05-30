// =============================================================================
// Middleware — Admin password + JWT session for admin routes
// =============================================================================

'use strict'

const jwt       = require('jsonwebtoken')
const { getDb } = require('../db')

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD
const JWT_SECRET     = process.env.JWT_SECRET

if (!ADMIN_PASSWORD) {
  console.error('[fatal] ADMIN_PASSWORD env var is not set — refusing to start')
  process.exit(1)
}

// Admin JWT expiry — default 1 hour, overridable via config
const ADMIN_SESSION_HOURS = global.CONFIG?.admin?.session_hours || 1

// ── POST /admin/auth ──────────────────────────────────────────────────────────
// Exchanges admin password for a short-lived JWT
// Called by AdminView.vue on login
function adminAuthHandler(req, res) {
  const { password } = req.body

  if (!password || password !== ADMIN_PASSWORD) {
    try {
      getDb().prepare(`
        INSERT INTO audit_log (event_type, ip, user_agent, detail)
        VALUES ('ADMIN_ACCESS_DENIED', ?, ?, ?)
      `).run(
        req.ip,
        req.headers['user-agent'] || '',
        JSON.stringify({ path: '/admin/auth', reason: 'wrong_password' })
      )
    } catch (err) {
      console.error('[admin] failed to log denied attempt:', err.message)
    }

    return res.status(401).json({ error: 'invalid password' })
  }

  const token = jwt.sign(
    { role: 'admin' },
    JWT_SECRET,
    { expiresIn: `${ADMIN_SESSION_HOURS}h` }
  )

  const expiresIn = ADMIN_SESSION_HOURS * 3600

  return res.json({ token, expiresIn })
}

// ── adminMiddleware ───────────────────────────────────────────────────────────
// Accepts admin JWT (issued by adminAuthHandler)
// Applied to all /admin and /watchdog routes
function adminMiddleware(req, res, next) {
  const header = req.headers.authorization || ''
  const token  = header.startsWith('Bearer ') ? header.slice(7) : null

  if (!token) {
    logDenied(req, 'no_token')
    return res.status(401).json({ error: 'admin authorization required' })
  }

  // Verify JWT
  try {
    const payload = jwt.verify(token, JWT_SECRET)
    if (payload.role !== 'admin') throw new Error('not admin')
    return next()
  } catch (err) {
    logDenied(req, 'invalid_jwt')
    return res.status(401).json({ error: 'admin authorization required' })
  }
}

function logDenied(req, reason) {
  try {
    getDb().prepare(`
      INSERT INTO audit_log (event_type, ip, user_agent, detail)
      VALUES ('ADMIN_ACCESS_DENIED', ?, ?, ?)
    `).run(
      req.ip,
      req.headers['user-agent'] || '',
      JSON.stringify({ path: req.path, reason })
    )
  } catch (err) {
    console.error('[admin] failed to log denied attempt:', err.message)
  }
}

module.exports = { adminMiddleware, adminAuthHandler }
