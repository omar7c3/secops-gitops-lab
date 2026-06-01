// =============================================================================
// Watchdog
// Runs on an interval — checks cluster state and resets if safe to do so
//
// Reset conditions (ALL must be true):
//   1. Cluster state differs from Git (dirty)
//   2. ONE of: no session, session expired, user ended, admin released
//
// NEVER resets if session is active — even if idle
// =============================================================================

'use strict'

const { getDb }  = require('./db')
const k8s        = require('./routes/k8s-client')
const { resetCluster } = require('./cluster-reset')

let watchdogTimer = null
let lastCheck     = null
let lastReset     = null
let checksRun     = 0

function startWatchdog(config) {
  const intervalMs = (config.watchdog.interval_seconds || 60) * 1000

  watchdogTimer = setInterval(async () => {
    await runWatchdogCheck()
  }, intervalMs)

  // Run once immediately on start
  setTimeout(runWatchdogCheck, 5000)
}

async function runWatchdogCheck() {
  checksRun++
  lastCheck = new Date().toISOString()

  const db    = getDb()
  const now   = Math.floor(Date.now() / 1000)
  const state = db.prepare('SELECT * FROM scenario_state WHERE id = 1').get()

  // ── Check 1: Is there an active session? ─────────────────────────────────
  const activeSession = db.prepare(`
    SELECT * FROM sessions
    WHERE ended_at IS NULL AND expires_at > ?
  `).get(now)

  if (activeSession) {
    // Active session — NEVER reset regardless of cluster state
    return
  }

  // ── Check 2: Is cluster dirty? ────────────────────────────────────────────
  const dirty = await k8s.isClusterDirty().catch(() => false)

  if (!dirty) return  // Clean — nothing to do

  // ── Check 3: Is it safe to reset? ────────────────────────────────────────
  // No active session + dirty cluster = safe to reset
  // Determine why there is no session (for logging)
  const lastSession = db.prepare(`
    SELECT * FROM sessions ORDER BY started_at DESC LIMIT 1
  `).get()

  const reason = lastSession?.end_reason || 'no_active_session'

  console.log(`[watchdog] dirty cluster detected, no active session (${reason}) — resetting`)

  // Shared cleanup — resync + delete untracked artifacts + clear events + reset
  // state (see cluster-reset.js). Keeps the watchdog in lock-step with the
  // manual reset paths.
  await resetCluster().catch(err => console.error('[watchdog] reset error:', err.message))

  lastReset = new Date().toISOString()
  console.log(`[watchdog] reset complete at ${lastReset}`)
}

function stopWatchdog() {
  if (watchdogTimer) {
    clearInterval(watchdogTimer)
    watchdogTimer = null
  }
}

function getWatchdogStatus() {
  return { lastCheck, lastReset, checksRun, running: !!watchdogTimer }
}

module.exports = { startWatchdog, stopWatchdog, getWatchdogStatus }
