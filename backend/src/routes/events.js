// =============================================================================
// Routes — /events (JWT auth) + /events/internal (cluster-only)
// =============================================================================

'use strict'

const express   = require('express')
const { getDb } = require('../db')

// ── JWT-authenticated event feed ──────────────────────────────────────────────
const router = express.Router()

// GET /events/feed — polled by frontend every 2s
router.get('/feed', (req, res) => {
  const { sessionId } = req.user
  const since = parseInt(req.query.since || '0', 10)

  const events = getDb().prepare(`
    SELECT * FROM events
    WHERE session_id = ? AND id > ?
    ORDER BY id ASC
    LIMIT 100
  `).all(sessionId, since)

  const lastId = events.length > 0 ? events[events.length - 1].id : since

  return res.json({ events, lastId })
})

module.exports = { eventsRouter: router }

// =============================================================================
// Internal webhook routes — called from inside the cluster only
// No JWT auth — cluster network boundary is the security control
// =============================================================================

const internalRouter = express.Router()

// POST /events/internal — called by attack.sh at each step
internalRouter.post('/', (req, res) => {
  console.log('[internal] content-type:', req.headers['content-type'])
  console.log('[internal] body:', JSON.stringify(req.body))

  const { phase, severity, title, explanation, scenario } = req.body

  // Validate required fields before touching DB
  if (!phase || !severity || !title || !explanation) {
    return res.status(400).json({ error: 'phase, severity, title, explanation required' })
  }

  const db = getDb()

  // Get current active session
  const state = db.prepare('SELECT * FROM scenario_state WHERE id = 1').get()

  if (!state || !state.session_id) {
    return res.status(200).json({ skipped: true, reason: 'no active session' })
  }

  // If phase is WAITING — update state machine to waiting + record compromised_at
  if (phase === 'WAITING') {
    db.prepare(`
      UPDATE scenario_state SET
        status = 'waiting',
        compromised_at = ?
      WHERE id = 1
    `).run(Math.floor(Date.now() / 1000))
  }

  db.prepare(`
    INSERT INTO events (session_id, phase, severity, title, explanation, scenario)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(state.session_id, phase, severity, title, explanation, scenario || state.scenario)

  return res.status(201).json({ ok: true })
})

// POST /events/stolen-data — attack.sh sends stolen data for impact panel
internalRouter.post('/stolen-data', (req, res) => {
  const { scenario, data } = req.body
  const db    = getDb()
  const state = db.prepare('SELECT * FROM scenario_state WHERE id = 1').get()

  if (!state || !state.session_id) return res.status(200).json({ skipped: true })

  db.prepare(`
    INSERT INTO events (session_id, phase, severity, title, explanation, scenario)
    VALUES (?, 'IMPACT', 'CRITICAL', 'Stolen data sample', ?, ?)
  `).run(state.session_id, JSON.stringify({ type: 'stolen_data', data }), scenario)

  return res.status(201).json({ ok: true })
})

// POST /events/probe-results — Scenario 2 internal service probe results
internalRouter.post('/probe-results', (req, res) => {
  const { scenario, results } = req.body
  const db    = getDb()
  const state = db.prepare('SELECT * FROM scenario_state WHERE id = 1').get()

  if (!state || !state.session_id) return res.status(200).json({ skipped: true })

  db.prepare(`
    INSERT INTO events (session_id, phase, severity, title, explanation, scenario)
    VALUES (?, 'IMPACT', 'CRITICAL', 'Internal service probe results', ?, ?)
  `).run(state.session_id,
    JSON.stringify({ type: 'probe_results', results }),
    scenario)

  return res.status(201).json({ ok: true })
})

// POST /events/window-start — Scenario 2 lateral movement window opened
internalRouter.post('/window-start', (req, res) => {
  const { started_at } = req.body
  getDb().prepare(`
    UPDATE scenario_state SET window_started_at = ? WHERE id = 1
  `).run(started_at)
  return res.status(201).json({ ok: true })
})

module.exports.eventsInternalRouter = internalRouter
