// =============================================================================
// SecOps GitOps Lab — Backend
// Token gate + event feed + scenario orchestration + watchdog
// =============================================================================

'use strict'

const express  = require('express')
const cors     = require('cors')
const helmet   = require('helmet')
const path     = require('path')
const fs       = require('fs')
const yaml     = require('js-yaml')

const { initDb }          = require('./db')
const tokenRoutes          = require('./routes/token-public')
const tokenAdminRoutes     = require('./routes/token-admin')
const sessionRoutes        = require('./routes/sessions')
const { eventsRouter, eventsInternalRouter } = require('./routes/events')
const scenarioRoutes       = require('./routes/scenarios')
const watchdogRoutes       = require('./routes/watchdog')
const adminRoutes          = require('./routes/admin')
const { startWatchdog }    = require('./watchdog')
const { authMiddleware }   = require('./middleware/auth')
const { adminMiddleware, adminAuthHandler } = require('./middleware/admin')

// ── Load config ──────────────────────────────────────────────────────────────
const CONFIG_PATH = path.resolve(__dirname, '../../config.yaml')
const config = yaml.load(fs.readFileSync(CONFIG_PATH, 'utf8'))

global.CONFIG = config

// ── Init ─────────────────────────────────────────────────────────────────────
const app  = express()
const PORT = process.env.PORT || 3000

initDb()

app.use(helmet())
app.use(cors())
app.use(express.json())

// ── Health check (no auth) ────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ status: 'ok', target: config.cluster.target }))

// ── Public routes (no auth) ───────────────────────────────────────────────────
app.use('/token', tokenRoutes)          // validate only

// ── Visitor routes (JWT auth) ─────────────────────────────────────────────────
app.use('/session',  authMiddleware, sessionRoutes)
app.use('/events',   authMiddleware, eventsRouter)
app.use('/scenario', authMiddleware, scenarioRoutes)
app.use('/argocd',   authMiddleware, require('./routes/argocd'))

// ── Admin auth (public — exchanges password for JWT) ──────────────────────────
app.post('/admin/auth', adminAuthHandler)

// ── Admin routes (JWT auth) ───────────────────────────────────────────────────
app.use('/token',    adminMiddleware, tokenAdminRoutes)  // generate, revoke, sessions, usage
app.use('/admin',    adminMiddleware, adminRoutes)
app.use('/watchdog', adminMiddleware, watchdogRoutes)

// ── Internal routes (cluster-only, no external auth) ─────────────────────────
// Called by attack.sh and Falco Sidekick webhook from inside the cluster
app.use('/events/internal',     eventsInternalRouter)
app.use('/events/falco',        require('./routes/falco-webhook'))

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`[backend] listening on :${PORT}`)
  console.log(`[backend] cluster target: ${config.cluster.target}`)
  console.log(`[backend] namespace: ${config.cluster.namespace}`)

  if (config.watchdog.enabled) {
    startWatchdog(config)
    console.log(`[watchdog] started — interval: ${config.watchdog.interval_seconds}s`)
  }
})

module.exports = app
