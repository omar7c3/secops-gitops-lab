// =============================================================================
// Route — /events/falco
// Receives alerts from Falco Sidekick webhook
// Translates Falco alert format into our event feed format
// =============================================================================

'use strict'

const express   = require('express')
const { getDb } = require('../db')
const router    = express.Router()

// Falco rule name → human readable narration
const FALCO_NARRATIONS = {
  'Terminal shell in container': {
    title: 'Falco: exec into container detected',
    explanation: 'Falco detected an interactive shell opened inside a running container. Any exec access to a production pod is suspicious and should be investigated.'
  },
  'Launch Privileged Container': {
    title: 'Falco: Privileged container started',
    explanation: 'Falco detected a container started with privileged: true via kernel syscall monitoring. Alert fired — but the damage is already done. Detection without prevention is too late at this stage.'
  },
  'Container escape attempt': {
    title: 'Falco: Container escape attempt detected',
    explanation: 'Falco sees the chroot syscall. Alert fired. Both alerts would page your on-call team but the attacker already has node access.'
  },
  'K8s NetworkPolicy Deleted': {
    title: 'Falco: NetworkPolicy deleted',
    explanation: 'Falco detected the deletion via Kubernetes audit log integration. Alert fired immediately — lateral movement is now possible until ArgoCD reconciles.'
  },
  'K8s ClusterRoleBinding Created': {
    title: 'Falco: Unexpected ClusterRoleBinding created',
    explanation: 'Falco detected a new ClusterRoleBinding — a common indicator of privilege escalation. The attacker is attempting to grant themselves elevated cluster permissions.'
  }
}

// POST /events/falco — called by Falco Sidekick
router.post('/', (req, res) => {
  const alert = req.body
  const db    = getDb()

  // Falco Sidekick format: { rule, priority, output, time, ... }
  const ruleName = alert.rule || alert.Rule || 'Unknown Falco Rule'
  const priority = (alert.priority || alert.Priority || 'WARNING').toUpperCase()

  const narration = FALCO_NARRATIONS[ruleName] || {
    title: `Falco: ${ruleName}`,
    explanation: alert.output || alert.Output || 'Falco alert fired — check Falco logs for details.'
  }

  const severity = priority === 'CRITICAL' || priority === 'EMERGENCY' ? 'CRITICAL' : 'WARNING'

  // Get current active session
  const state = db.prepare('SELECT * FROM scenario_state WHERE id = 1').get()

  if (state && state.session_id) {
    db.prepare(`
      INSERT INTO events (session_id, phase, severity, title, explanation, scenario)
      VALUES (?, 'DETECT', ?, ?, ?, ?)
    `).run(state.session_id, severity, narration.title, narration.explanation, state.scenario)
  }

  console.log(`[falco] alert: ${ruleName} (${priority})`)
  return res.status(200).json({ ok: true })
})

module.exports = router
