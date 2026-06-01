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
  const SCENARIO_DIRS = {
    'privilege-escalation':  '01-privilege-escalation',
    'network-policy-bypass': '02-networkpolicy-bypass'
  }
  const scriptPath = path.join(SCENARIOS_DIR, SCENARIO_DIRS[scenario], 'attack.sh')
  const namespace  = global.CONFIG.cluster.namespace

  // SA swap triggers a rollout — wait for a Running pod before proceeding
  waitForRunningPod(namespace, 'target-app', 60000)
    .then(async pod => {
      // S2 uncontrolled: suspend secops-lab-policies ArgoCD app FIRST so ArgoCD
      // cannot restore protect-networkpolicies via self-heal (it re-creates in <3s).
      // secops-lab app stays active — it will auto-reconcile deny-all (~30s).
      if (scenario === 'network-policy-bypass' && mode === 'uncontrolled') {
        await k8s.suspendArgoCDSync('secops-lab-policies').catch(() => {})
        await k8s.deleteKyvernoPolicy('protect-networkpolicies').catch(() => {})
        emitEvent(req.user.sessionId, 'SETUP', 'WARNING', scenario,
          'Backend deleting Kyverno policy: protect-networkpolicies',
          'Backend suspends the policies ArgoCD app and removes protect-networkpolicies. The pod can now delete the deny-all NetworkPolicy — but cannot suspend ArgoCD secops-lab, so that app will auto-reconcile the deletion.')
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
            if (mode === 'uncontrolled' && scenario === 'network-policy-bypass') {
              // Restore the admission guard promptly (resume + hard-sync) so proof
              // can show the re-attack blocked, then poll for deny-all to be
              // reconciled back — stamping window_ended at the real close moment.
              k8s.resumeArgoCDSync('secops-lab-policies').catch(() => {})
              k8s.syncArgoCD('secops-lab-policies').catch(() => {})
              waitForWindowClose(req.user.sessionId, namespace)
            } else if (mode === 'uncontrolled') {
              const proofDelay = (global.CONFIG.scenario.proof_delay_seconds || 5) * 1000
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

  // Enter reconciling. Dwell time is NOT frozen here — it keeps counting until
  // the cluster is verified back to desired state (see waitForReconcile below).
  // restored_at records the button-click moment for reference only.
  db.prepare(`
    UPDATE scenario_state SET
      status = 'reconciling',
      restored_at = ?
    WHERE id = 1
  `).run(now)

  emitEvent(req.user.sessionId, 'RESTORE', 'INFO', state.scenario,
    'Visitor triggered manual protection restore',
    'SOC response started. Backend removes attacker-created resources and resumes ArgoCD sync. Dwell time keeps counting until the cluster is verified back to desired state.')

  // SOC response — delete the attacker-created privileged pod.
  // ArgoCD will not prune it (created out-of-band via the API, no Git tracking
  // label), so the incident responder deletes it directly as containment.
  const namespace = global.CONFIG.cluster.namespace
  exec(`kubectl delete pod privileged-attack-pod -n ${namespace} --ignore-not-found`, () => {})
  emitEvent(req.user.sessionId, 'RESTORE', 'INFO', state.scenario,
    'SOC response — deleting attacker-created privileged pod',
    'Incident response removes privileged-attack-pod (privileged: true, node root filesystem mounted at /host). ArgoCD cannot prune it because the attacker created it directly, not through Git — so the SOC deletes it as part of containment.')

  // Resume ArgoCD sync, then trigger a hard sync. Resume alone only re-enables
  // self-heal on ArgoCD's next ~3min resync cycle; the explicit sync reverts the
  // drift (policies, SA swap) now so recovery is prompt.
  await k8s.resumeArgoCDSync('secops-lab')
  await k8s.resumeArgoCDSync('secops-lab-policies')
  await k8s.syncArgoCD('secops-lab').catch(() => {})
  await k8s.syncArgoCD('secops-lab-policies').catch(() => {})

  emitEvent(req.user.sessionId, 'RESTORE', 'INFO', state.scenario,
    'ArgoCD sync resumed',
    'GitOps is active again. ArgoCD will now detect and reconcile all drift introduced during the attack — restoring Kyverno policies and swapping the service account back to minimal-sa.')

  // Freeze dwell time only once the cluster is actually reconciled.
  waitForReconcile(req.user.sessionId, state.scenario, state.compromised_at)

  return res.json({ restored: true })
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

  // Resume ArgoCD sync if suspended (both apps — S2 suspends secops-lab-policies)
  await k8s.resumeArgoCDSync('secops-lab').catch(() => {})
  await k8s.resumeArgoCDSync('secops-lab-policies').catch(() => {})
  await k8s.resumeArgoCDSync('secops-lab-policies').catch(() => {})

  // Trigger ArgoCD hard sync
  await k8s.syncArgoCD('secops-lab').catch(() => {})
  await k8s.syncArgoCD('secops-lab-policies').catch(() => {})

  // Delete attack artifacts ArgoCD won't prune (not in Git)
  const namespace = global.CONFIG.cluster.namespace
  exec(`kubectl delete pod privileged-attack-pod -n ${namespace} --ignore-not-found`, () => {})
  exec(`kubectl delete networkpolicy attacker-postgres-exfil -n ${namespace} --ignore-not-found`, () => {})

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

  // Live dwell time while compromised AND through reconciliation — until the
  // cluster is verified clean and dwell_time_seconds is frozen.
  if (state.compromised_at && state.dwell_time_seconds == null) {
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
  const SCENARIO_DIRS = {
    'privilege-escalation':  '01-privilege-escalation',
    'network-policy-bypass': '02-networkpolicy-bypass'
  }
  const scriptPath = path.join(SCENARIOS_DIR, SCENARIO_DIRS[scenario], 'proof.sh')

  db.prepare(`UPDATE scenario_state SET status = 'proof' WHERE id = 1`).run()

  waitForRunningPod(namespace, 'target-app', 60000)
    .then(pod => {
      exec(`kubectl cp ${scriptPath} ${namespace}/${pod}:/tmp/proof.sh`, (cpErr) => {
        if (cpErr) {
          console.error('[proof] failed to copy proof.sh:', cpErr.message)
          const now2 = Math.floor(Date.now() / 1000)
          db.prepare(`UPDATE scenario_state SET status = 'complete', window_ended_at = COALESCE(window_ended_at, CASE WHEN window_started_at IS NOT NULL THEN ? ELSE NULL END) WHERE id = 1`).run(now2)
          return
        }
        exec(`kubectl exec ${pod} -n ${namespace} -- bash /tmp/proof.sh`,
          { timeout: 60000 }, (execErr, stdout, stderr) => {
            if (execErr) console.error('[proof] error:', execErr.message)
            if (stdout)  console.log('[proof] stdout:', stdout)
            const now2 = Math.floor(Date.now() / 1000)
            db.prepare(`UPDATE scenario_state SET status = 'complete', window_ended_at = COALESCE(window_ended_at, CASE WHEN window_started_at IS NOT NULL THEN ? ELSE NULL END) WHERE id = 1`).run(now2)
          })
      })
    })
    .catch(err => {
      console.error('[proof] timed out waiting for target-app pod:', err.message)
      const now2 = Math.floor(Date.now() / 1000)
      db.prepare(`UPDATE scenario_state SET status = 'complete', window_ended_at = COALESCE(window_ended_at, CASE WHEN window_started_at IS NOT NULL THEN ? ELSE NULL END) WHERE id = 1`).run(now2)
    })
}

// ── Helper — wait for deployment rollout then return the new Running pod ──────
// Uses kubectl rollout status to wait for the new RS to become available,
// avoiding the race where the OLD pod is still Running right after a SA swap.
function waitForRunningPod(namespace, appLabel, timeoutMs = 60000) {
  return new Promise((resolve, reject) => {
    const timeoutSec = Math.floor(timeoutMs / 1000)
    const rolloutCmd = `kubectl rollout status deployment/${appLabel} -n ${namespace} --timeout=${timeoutSec}s`

    exec(rolloutCmd, { timeout: timeoutMs + 5000 }, (err) => {
      if (err) return reject(new Error(`rollout did not complete for ${appLabel}: ${err.message}`))

      // Pick the NEWEST Running pod. Right after a SA swap the old pod is still
      // in Running/Terminating phase, and an unordered items[0] can select it —
      // running attack.sh in the pre-swap pod (no token mounted), which surfaces
      // as a false "No token found". Sort by creationTimestamp and take the last.
      const getCmd = `kubectl get pod -n ${namespace} -l app=${appLabel} --field-selector=status.phase=Running --sort-by=.metadata.creationTimestamp -o name`
      exec(getCmd, (err2, stdout) => {
        const names  = (stdout || '').trim().split('\n').map(s => s.trim()).filter(Boolean)
        const newest = names.length ? names[names.length - 1].replace(/^pod\//, '') : ''
        if (!err2 && newest) return resolve(newest)
        reject(new Error(`no Running pod found for app=${appLabel} after rollout`))
      })
    })
  })
}

// ── Helper — poll until ArgoCD reconciles, then freeze dwell time ─────────────
// Dwell time represents the true attacker-access window: from compromise until
// the cluster is verified back to desired state — NOT the button-click moment.
function waitForReconcile(sessionId, scenario, compromisedAt, attempt = 0) {
  const INTERVAL_MS  = 3000
  const MAX_ATTEMPTS = Math.ceil((global.CONFIG.scenario.reconcile_timeout_seconds || 120) / (INTERVAL_MS / 1000))

  setTimeout(async () => {
    const db    = getDb()
    const state = db.prepare('SELECT status, dwell_time_seconds FROM scenario_state WHERE id = 1').get()

    // Aborted (reset), already finalized, or no longer in a recovery state — stop
    if (!state || state.dwell_time_seconds != null ||
        !['reconciling', 'proof', 'complete'].includes(state.status)) {
      return
    }

    const reconciled = await k8s.isS1Reconciled().catch(() => false)
    const now        = Math.floor(Date.now() / 1000)

    if (reconciled) {
      const dwell = compromisedAt ? now - compromisedAt : 0
      db.prepare(`UPDATE scenario_state SET dwell_time_seconds = ? WHERE id = 1`).run(dwell)
      emitEvent(sessionId, 'RECONCILE', 'SUCCESS', scenario,
        `Cluster reconciled to desired state — dwell time ${Math.floor(dwell / 60)}m ${dwell % 60}s`,
        'ArgoCD has restored all drift: Kyverno admission policies re-created and the service account swapped back to minimal-sa. The attacker-created pod was removed by the SOC. Dwell time stops here — this is the true attacker-access window.')
      // Reconciled — NOW run proof to demonstrate controls hold, then complete.
      // Chaining proof after reconciliation (instead of a fixed frontend timer)
      // keeps the run button disabled until every event has fired.
      execProofScript(global.CONFIG.cluster.namespace, scenario, db)
      return
    }

    if (attempt >= MAX_ATTEMPTS) {
      const dwell = compromisedAt ? now - compromisedAt : 0
      db.prepare(`UPDATE scenario_state SET dwell_time_seconds = ?, status = 'complete' WHERE id = 1`).run(dwell)
      emitEvent(sessionId, 'RECONCILE', 'WARNING', scenario,
        `Reconciliation not confirmed — dwell time capped at ${Math.floor(dwell / 60)}m ${dwell % 60}s`,
        'Desired state was not reached within the timeout (a Kyverno policy, the target-app service account, or the attacker pod did not return to baseline). Dwell time has been frozen at the cap — check ArgoCD application health.')
      return
    }

    waitForReconcile(sessionId, scenario, compromisedAt, attempt + 1)
  }, INTERVAL_MS)
}

// ── Helper — S2: close the lateral-movement window on real reconciliation ─────
// The attacker plants no backdoor, so the path closes when ArgoCD (secops-lab,
// never suspended) restores deny-all. Stamp window_ended at that moment, then —
// once protect-networkpolicies is also back — run proof to show the re-attack
// is blocked. Falls back to a timeout cap.
function waitForWindowClose(sessionId, namespace, attempt = 0) {
  const INTERVAL_MS  = 3000
  const MAX_ATTEMPTS = Math.ceil((global.CONFIG.scenario.reconcile_timeout_seconds || 120) / (INTERVAL_MS / 1000))

  setTimeout(async () => {
    const db    = getDb()
    const state = db.prepare('SELECT status, window_started_at, window_ended_at FROM scenario_state WHERE id = 1').get()

    // Aborted (reset) — stop polling
    if (!state || state.status === 'idle') return

    const now         = Math.floor(Date.now() / 1000)
    const denyAllBack = await k8s.resourceExists(`networkpolicy deny-all -n ${namespace}`).catch(() => false)

    // Stamp the window close the moment deny-all is reconciled back
    if (denyAllBack && state.window_ended_at == null) {
      const windowSecs = state.window_started_at ? now - state.window_started_at : 0
      db.prepare(`UPDATE scenario_state SET window_ended_at = ? WHERE id = 1`).run(now)
      emitEvent(sessionId, 'RECONCILE', 'SUCCESS', 'network-policy-bypass',
        `deny-all restored — lateral movement window closed (${windowSecs}s)`,
        'ArgoCD reconciled the deleted deny-all NetworkPolicy back to desired state. Namespace isolation is re-established and the attacker path to postgres is sealed. No backdoor was planted, so nothing persists.')
    }

    // Once the admission guard is also restored, prove the re-attack is blocked.
    const guardBack = await k8s.resourceExists(`clusterpolicy protect-networkpolicies`).catch(() => false)
    if ((denyAllBack || state.window_ended_at != null) && guardBack) {
      execProofScript(namespace, 'network-policy-bypass', getDb())
      return
    }

    if (attempt >= MAX_ATTEMPTS) {
      if (state.window_ended_at == null) {
        const windowSecs = state.window_started_at ? now - state.window_started_at : 0
        db.prepare(`UPDATE scenario_state SET window_ended_at = ? WHERE id = 1`).run(now)
        emitEvent(sessionId, 'RECONCILE', 'WARNING', 'network-policy-bypass',
          `Window close not confirmed — capped at ${windowSecs}s`,
          'deny-all was not observed restored within the timeout. Check ArgoCD secops-lab application health.')
      }
      execProofScript(namespace, 'network-policy-bypass', getDb())
      return
    }

    waitForWindowClose(sessionId, namespace, attempt + 1)
  }, INTERVAL_MS)
}

// ── Helper — emit event to DB ─────────────────────────────────────────────────
function emitEvent(sessionId, phase, severity, scenario, title, explanation) {
  getDb().prepare(`
    INSERT INTO events (session_id, phase, severity, title, explanation, scenario)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(sessionId, phase, severity, title, explanation, scenario)
}

module.exports = router
