// =============================================================================
// Shared cluster cleanup
// Single source of truth for bringing the cluster + scenario state back to a
// clean baseline. Used by /scenario/reset, /admin/cluster/reset, /session/end,
// and the watchdog so the reset logic can't drift between them.
//
// Resync alone is NOT enough: attacker-created resources (privileged-attack-pod,
// attacker-postgres-exfil) are not in Git, so ArgoCD won't prune them — they
// must be deleted explicitly.
// =============================================================================

'use strict'

const { exec }  = require('child_process')
const { getDb } = require('./db')
const k8s       = require('./routes/k8s-client')

// opts.actor  — who triggered it ('user' | 'admin' | 'watchdog' | 'system')
// opts.reason — short reason string for the audit trail
async function resetCluster({ clearEvents = true, actor = 'system', reason = null } = {}) {
  const db        = getDb()
  const namespace = global.CONFIG.cluster.namespace

  // Capture the session before we null it — used for event cleanup + audit.
  const state     = db.prepare('SELECT session_id FROM scenario_state WHERE id = 1').get()
  const sessionId = state && state.session_id ? state.session_id : null

  // 1. Resume + hard-sync both apps → restore all Git-managed drift
  //    (deny-all, Kyverno policies, target-app service account).
  await k8s.resumeArgoCDSync('secops-lab').catch(() => {})
  await k8s.resumeArgoCDSync('secops-lab-policies').catch(() => {})
  await k8s.syncArgoCD('secops-lab').catch(() => {})
  await k8s.syncArgoCD('secops-lab-policies').catch(() => {})

  // 2. Delete attacker-created artifacts ArgoCD won't prune (not in Git).
  exec(`kubectl delete pod privileged-attack-pod -n ${namespace} --ignore-not-found`, () => {})
  exec(`kubectl delete networkpolicy attacker-postgres-exfil -n ${namespace} --ignore-not-found`, () => {})

  // 3. Clear the event feed for the active/last session.
  if (clearEvents && sessionId) {
    db.prepare('DELETE FROM events WHERE session_id = ?').run(sessionId)
  }

  // 4. Reset the scenario state machine.
  db.prepare(`
    UPDATE scenario_state SET
      status = 'idle', scenario = NULL, mode = NULL, session_id = NULL,
      argocd_suspended = 0, kyverno_deleted = 0,
      attack_started_at = NULL, compromised_at = NULL,
      restored_at = NULL, dwell_time_seconds = NULL,
      window_started_at = NULL, window_ended_at = NULL
    WHERE id = 1
  `).run()

  // 5. Audit the reset (every path — user, admin, watchdog).
  db.prepare(`
    INSERT INTO audit_log (session_id, event_type, detail)
    VALUES (?, 'CLUSTER_RESET', ?)
  `).run(sessionId, JSON.stringify({ actor, reason }))
}

module.exports = { resetCluster }
