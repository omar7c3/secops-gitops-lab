// =============================================================================
// Database — SQLite via better-sqlite3
// Single file DB — simple, zero config, persists across pod restarts
// via a mounted volume (see backend deployment manifest)
// =============================================================================

'use strict'

const Database = require('better-sqlite3')
const path     = require('path')

const DB_PATH = process.env.DB_PATH || path.resolve(__dirname, '../../data/secops-lab.db')

let db

function initDb() {
  const dir = path.dirname(DB_PATH)
  const fs  = require('fs')
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true })

  db = new Database(DB_PATH)
  db.pragma('journal_mode = WAL')   // Better concurrent read performance
  db.pragma('foreign_keys = ON')

  // ── Tokens ──────────────────────────────────────────────────────────────────
  db.exec(`
    CREATE TABLE IF NOT EXISTS tokens (
      id          TEXT PRIMARY KEY,
      label       TEXT NOT NULL,
      expires_at  INTEGER NOT NULL,
      created_at  INTEGER NOT NULL DEFAULT (unixepoch()),
      revoked     INTEGER NOT NULL DEFAULT 0
    )
  `)

  // ── Sessions ────────────────────────────────────────────────────────────────
  db.exec(`
    CREATE TABLE IF NOT EXISTS sessions (
      id           TEXT PRIMARY KEY,
      token_id     TEXT NOT NULL REFERENCES tokens(id),
      started_at   INTEGER NOT NULL DEFAULT (unixepoch()),
      expires_at   INTEGER NOT NULL,
      ended_at     INTEGER,
      end_reason   TEXT,        -- 'expired' | 'user_ended' | 'admin_released' | 'grace_expired'
      ip           TEXT,
      user_agent   TEXT,
      last_seen_at INTEGER NOT NULL DEFAULT (unixepoch())
    )
  `)

  // ── Audit log ───────────────────────────────────────────────────────────────
  db.exec(`
    CREATE TABLE IF NOT EXISTS audit_log (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      token_id   TEXT,
      session_id TEXT,
      event_type TEXT NOT NULL,  -- SESSION_START | ACCESS_DENIED | SESSION_END | SCENARIO_RUN | etc
      ip         TEXT,
      user_agent TEXT,
      detail     TEXT,           -- JSON — reason, scenario, mode, dwell_time, etc
      created_at INTEGER NOT NULL DEFAULT (unixepoch())
    )
  `)

  // ── Event feed ──────────────────────────────────────────────────────────────
  db.exec(`
    CREATE TABLE IF NOT EXISTS events (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id  TEXT,
      phase       TEXT NOT NULL,     -- SETUP | ATTACK | DETECT | IMPACT | RECONCILE | PROOF | RESTORE | WAITING
      severity    TEXT NOT NULL,     -- INFO | WARNING | CRITICAL | SUCCESS
      title       TEXT NOT NULL,
      explanation TEXT NOT NULL,
      scenario    TEXT,              -- 'privilege-escalation' | 'network-policy-bypass'
      created_at  INTEGER NOT NULL DEFAULT (unixepoch())
    )
  `)

  // ── Scenario state ──────────────────────────────────────────────────────────
  db.exec(`
    CREATE TABLE IF NOT EXISTS scenario_state (
      id                  INTEGER PRIMARY KEY CHECK (id = 1),
      status              TEXT NOT NULL DEFAULT 'idle',
      -- idle | attacking | waiting | reconciling | proof | complete
      scenario            TEXT,
      mode                TEXT,      -- 'controlled' | 'uncontrolled'
      session_id          TEXT,
      argocd_suspended    INTEGER NOT NULL DEFAULT 0,
      kyverno_deleted     INTEGER NOT NULL DEFAULT 0,
      attack_started_at   INTEGER,
      compromised_at      INTEGER,   -- when WAITING state began (dwell time start)
      restored_at         INTEGER,   -- when visitor clicked Restore Protection
      dwell_time_seconds  INTEGER,   -- compromised_at to verified reconciliation (frozen when cluster clean)
      window_started_at   INTEGER,   -- Scenario 2 lateral movement window start
      window_ended_at     INTEGER    -- Scenario 2 window end (ArgoCD reconciled)
    )
  `)

  // Insert default scenario state row
  db.exec(`
    INSERT OR IGNORE INTO scenario_state (id, status) VALUES (1, 'idle')
  `)

  console.log(`[db] initialized at ${DB_PATH}`)
  return db
}

function getDb() {
  if (!db) throw new Error('DB not initialized — call initDb() first')
  return db
}

module.exports = { initDb, getDb }
