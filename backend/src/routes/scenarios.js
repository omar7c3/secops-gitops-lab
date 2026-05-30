// =============================================================================
// Routes — /scenario
// JWT-authenticated — scenario orchestration
// =============================================================================

'use strict'

const express  = require('express')
const { exec } = require('child_process')
const path     = require('path')
const { getDb } = require('../db')
const k8s      = require('./k8s-client')

const router = express.Router()

const SCENARIOS_DIR = path.resolve(__dirname, '../../scenarios')

// ── POST /scenario/run ────────────────────────────────────────────────────────
router.post('/run', async (req, res) => {
  const { scenario, mode } = req.body
  // scenario: 'privilege-escalation' | 'network-policy-bypass'
  // mode:     'controlled' | 'uncontrolled'

  if (!scenario || !mode) {
    return res.status(400).json({ error: 'scenario and mode required' })
  }

  const db     = getDb()
  const state  = db.prepare('SELECT * FROM scenario_state WHERE id = 1').get()

  if (state.status !== 'idle') {
    return res.status(409).json({
      error: 'scenario_running',
      message: 'A scenario is already running. Reset to Safe State first.'
    })
  }

  const now = Math.floor(Date.now() / 1000)

  // ── Setup — differs by scenario and mode ────────────────────────────────────
  if (scenario === 'privilege-escalation' && mode === 'uncontrolled') {
    await k8s.swapServiceAccount('target-app', 'over-privileged-sa', true)
    emitEvent(req.user.sessionId, 'SETUP', 'WARNING', scenario,
      'Swapping service account to over-privileged-sa',
      'Backend patches target-app deployment. This mimics a common misconfiguration — an app given more Kubernetes API access than it needs. automountServiceAccountToken is now true.')
  }

  if (scenario === 'network-policy-bypass') {
    if (mode === 'controlled') {
      emitEvent(req.user.sessionId, 'SETUP', 'INFO', scenario,
        'Mounting network-tooling-sa — Kyverno guard remains active',
        'SA gives NetworkPolicy delete rights, but protect-networkpolicies Kyverno policy is still running. Watch what happens at admission.')
    }
    // Both modes: swap SA so attack.sh has a token to work with
    // For uncontrolled: deleteKyvernoPolicy happens AFTER pod rollout (see below)
    // to avoid ArgoCD self-heal restoring the policy before the attack runs
    await k8s.swapServiceAccount('target-app', 'network-tooling-sa', true)
    emitEvent(req.user.sessionId, 'SETUP', 'WARNING', scenario,
      'Swapping SA to network-tooling-sa',
      'Backend patches target-app to mount network-tooling-sa. This SA has NetworkPolicy delete rights but cannot touch ArgoCD.')
  }

  // Update state machine
  db.prepare(`
    UPDATE scenario_state SET
      status = 'attacking',
      scenario = ?,
      mode = ?,
      session_id = ?,
      attack_started_at = ?,
      argocd_suspended = 0,
      kyverno_deleted = 0
    WHERE id = 1
  `).run(scenario, mode, req.user.sessionId, now)

  // Log to audit
  db.prepare(`
    INSERT INTO audit_log (session_id, token_id, event_type, detail)
    VALUES (?, ?, 'SCENARIO_RUN', ?)
  `).run(req.user.sessionId, req.user.tokenId,
    JSON.stringify({ scenario, mode }))

  // Run attack script inside target-app pod
  // Script content is read from backend filesystem and piped to target-app
  // target-app does not have the script files — backend does
  const scriptPath = path.join(SCENARIOS_DIR, `0${scenario === 'privilege-escalation' ? 1 : 2}-${scenario}`, 'attack.sh')
  const namespace  = global.CONFIG.cluster.namespace

  // SA swap triggers a rollout — wait for a Running pod before proceeding
  waitForRunningPod(namespace, 'target-app', 60000)
    .then(async pod => {
      // S2 uncontrolled: delete Kyverno guard HERE, immediately before the attack,
      // so ArgoCD self-heal has no time to restore it before attack.sh runs
      if (scenario === 'network-policy-bypass' && mode === 'uncontrolled') {
        await k8s.deleteKyvernoPolicy('protect-networkpolicies').catch(() => {})
        emitEvent(req.user.sessionId, 'SETUP', 'WARNING', scenario,
          'Backend deleting Kyverno policy: protect-networkpolicies',
          'Backend removes the Kyverno policy protecting NetworkPolicy resources. Pod will now be able to delete it using the network-tooling-sa token.')
      }

      const copyCmd = `kubectl cp ${scriptPath} ${namespace}/${pod}:/tmp/attack.sh`
      exec(copyCmd, (cpErr) => {
        if (cpErr) {
          console.error('[scenario] failed to copy attack.sh:', cpErr.message)
          return
        }
        const execCmd = `kubectl exec ${pod} -n ${namespace} -- bash /tmp/attack.sh`
        exec(execCmd, { timeout: 120000 }, (execErr, stdout, stderr) => {
          if (execErr) console.error('[scenario] attack.sh error:', execErr.message)
          if (stderr)  console.error('[scenario] attack.sh stderr:', stderr)
          if (stdout)  console.log('[scenario] attack.sh stdout:', stdout)

          // If attack exited without reaching the WAITING phase (controlled mode,
          // or scenario 2 where there is no manual restore step), auto-run proof.
          // Scenario 1 uncontrolled sets status='waiting' via the WAITING event —
          // that path waits for the visitor to click Restore Protection instead.
          const st = getDb().prepare('SELECT status FROM scenario_state WHERE id = 1').get()
          if (st && st.status === 'attacking') {
            if (mode === 'uncontrolled') {
              // Scenario 2 uncontrolled: give ArgoCD time to reconcile before proof
              const proofDelay = (scenario === 'network-policy-bypass')
                ? (global.CONFIG.scenario.reconcile_timeout_seconds || 60) * 1000
                : (global.CONFIG.scenario.proof_delay_seconds || 5) * 1000
              console.log(`[scenario] attack exited — auto-proof in ${proofDelay / 1000}s`)
              setTimeout(() => execProofScript(namespace, scenario, getDb()), proofDelay)
            } else {
              // Controlled mode: attack being blocked IS the demonstration — no proof needed
              getDb().prepare(`UPDATE scenario_state SET status = 'complete' WHERE id = 1`).run()
              console.log('[scenario] controlled mode complete — no proof phase')
            }
          }
        })
      })
    })
    .catch(err => console.error('[scenario] timed out waiting for target-app pod:', err.message))

  return res.json({ started: true, scenario, mode })
})

// ── POST /scenario/restore ────────────────────────────────────────────────────
// Scenario 1 only — visitor manually restores after Allow Attack
router.post('/restore', async (req, res) => {
  const db    = getDb()
  const state = db.prepare('SELECT * FROM scenario_state WHERE id = 1').get()
  const now   = Math.floor(Date.now() / 1000)

  if (state.status !== 'waiting') {
    return res.status(409).json({ error: 'not in waiting state' })
  }

  // Calculate dwell time
  const dwellSeconds = state.compromised_at ? now - state.compromised_at : 0

  db.prepare(`
    UPDATE scenario_state SET
      status = 'reconciling',
      restored_at = ?,
      dwell_time_seconds = ?
    WHERE id = 1
  `).run(now, dwellSeconds)

  emitEvent(req.user.sessionId, 'RESTORE', 'INFO', state.scenario,
    'Visitor triggered manual protection restore',
    `Backend resumes ArgoCD sync. Recording total dwell time — ${Math.floor(dwellSeconds / 60)}m ${dwellSeconds % 60}s.`)

  // Resume ArgoCD sync
  await k8s.resumeArgoCDSync('secops-lab')
  await k8s.resumeArgoCDSync('secops-lab-policies')

  emitEvent(req.user.sessionId, 'RESTORE', 'INFO', state.scenario,
    'ArgoCD sync resumed',
    'GitOps is active again. ArgoCD will now detect and reconcile all drift introduced during the attack.')

  emitEvent(req.user.sessionId, 'RESTORE', 'WARNING', state.scenario,
    `Dwell time: ${Math.floor(dwellSeconds / 60)}m ${dwellSeconds % 60}s`,
    `Cluster was fully compromised for this duration. In a real incident this window represents maximum attacker access time — certificate theft, data exfiltration, and backdoor installation could all occur in this window.`)

  return res.json({ restored: true, dwellSeconds })
})

// ── POST /scenario/proof ──────────────────────────────────────────────────────
router.post('/proof', async (req, res) => {
  const db    = getDb()
  const state = db.prepare('SELECT * FROM scenario_state WHERE id = 1').get()

  if (!state.scenario) {
    return res.status(409).json({ error: 'no scenario to prove' })
  }

  const namespace = global.CONFIG.cluster.namespace
  const delayMs   = (global.CONFIG.scenario.proof_delay_seconds || 5) * 1000

  setTimeout(() => execProofScript(namespace, state.scenario, db), delayMs)

  return res.json({ started: true })
})

// ── POST /scenario/reset ──────────────────────────────────────────────────────
router.post('/reset', async (req, res) => {
  const db  = getDb()
  const now = Math.floor(Date.now() / 1000)

  // Resume ArgoCD sync if suspended
  await k8s.resumeArgoCDSync('secops-lab').catch(() => {})
  await k8s.resumeArgoCDSync('secops-lab-policies').catch(() => {})

  // Trigger ArgoCD hard sync
  await k8s.syncArgoCD('secops-lab').catch(() => {})
  await k8s.syncArgoCD('secops-lab-policies').catch(() => {})

  // Delete attack artifact pods that ArgoCD won't prune (not in Git)
  const namespace = global.CONFIG.cluster.namespace
  exec(`kubectl delete pod privileged-attack-pod -n ${namespace} --ignore-not-found`, () => {})

  // Clear event feed for this session
  const state = db.prepare('SELECT * FROM scenario_state WHERE id = 1').get()
  if (state.session_id) {
    db.prepare(`DELETE FROM events WHERE session_id = ?`).run(state.session_id)
  }

  // Reset state machine
  db.prepare(`
    UPDATE scenario_state SET
      status = 'idle', scenario = NULL, mode = NULL, session_id = NULL,
      argocd_suspended = 0, kyverno_deleted = 0,
      attack_started_at = NULL, compromised_at = NULL,
      restored_at = NULL, dwell_time_seconds = NULL,
      window_started_at = NULL, window_ended_at = NULL
    WHERE id = 1
  `).run()

  return res.json({ reset: true })
})

// ── GET /scenario/state ───────────────────────────────────────────────────────
router.get('/state', (req, res) => {
  const state = getDb().prepare('SELECT * FROM scenario_state WHERE id = 1').get()
  const now   = Math.floor(Date.now() / 1000)

  // Add live dwell time if currently compromised
  if (state.status === 'waiting' && state.compromised_at) {
    state.current_dwell_seconds = now - state.compromised_at
  }

  // Add live window duration for Scenario 2
  if (state.window_started_at && !state.window_ended_at) {
    state.current_window_seconds = now - state.window_started_at
  }

  return res.json(state)
})

// ── Helper — copy and run proof.sh inside target-app, set state to complete ───
function execProofScript(namespace, scenario, db) {
  const scriptNum  = scenario === 'privilege-escalation' ? '01' : '02'
  const scriptPath = path.join(SCENARIOS_DIR, `${scriptNum}-${scenario}`, 'proof.sh')

  db.prepare(`UPDATE scenario_state SET status = 'proof' WHERE id = 1`).run()

  waitForRunningPod(namespace, 'target-app', 60000)
    .then(pod => {
      exec(`kubectl cp ${scriptPath} ${namespace}/${pod}:/tmp/proof.sh`, (cpErr) => {
        if (cpErr) {
          console.error('[proof] failed to copy proof.sh:', cpErr.message)
          db.prepare(`UPDATE scenario_state SET status = 'complete' WHERE id = 1`).run()
          return
        }
        exec(`kubectl exec ${pod} -n ${namespace} -- bash /tmp/proof.sh`,
          { timeout: 60000 }, (execErr, stdout, stderr) => {
            if (execErr) console.error('[proof] error:', execErr.message)
            if (stdout)  console.log('[proof] stdout:', stdout)
            db.prepare(`UPDATE scenario_state SET status = 'complete' WHERE id = 1`).run()
          })
      })
    })
    .catch(err => {
      console.error('[proof] timed out waiting for target-app pod:', err.message)
      db.prepare(`UPDATE scenario_state SET status = 'complete' WHERE id = 1`).run()
    })
}

// ── Helper — wait for a Running pod matching label ────────────────────────────
// SA swap triggers a rollout; poll until a Ready pod exists or timeout
function waitForRunningPod(namespace, appLabel, timeoutMs = 60000) {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + timeoutMs
    const cmd = `kubectl get pod -n ${namespace} -l app=${appLabel} --field-selector=status.phase=Running -o jsonpath="{.items[0].metadata.name}"`

    const poll = () => {
      exec(cmd, (err, stdout) => {
        const name = stdout?.trim()
        if (!err && name) return resolve(name)
        if (Date.now() >= deadline) return reject(new Error(`no Running pod for app=${appLabel} after ${timeoutMs}ms`))
        setTimeout(poll, 3000)
      })
    }
    poll()
  })
}

// ── Helper — emit event to DB ─────────────────────────────────────────────────
function emitEvent(sessionId, phase, severity, scenario, title, explanation) {
  getDb().prepare(`
    INSERT INTO events (session_id, phase, severity, title, explanation, scenario)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(sessionId, phase, severity, title, explanation, scenario)
}

module.exports = router
