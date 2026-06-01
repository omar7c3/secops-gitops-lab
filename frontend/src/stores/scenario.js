// =============================================================================
// Pinia Store — Scenario
// Manages scenario state, events, ArgoCD state, and polling
// =============================================================================

import { defineStore }  from 'pinia'
import { ref, computed } from 'vue'
import axios            from 'axios'

export const useScenarioStore = defineStore('scenario', () => {
  // ── State ──────────────────────────────────────────────────────────────────
  const events        = ref([])
  const lastEventId   = ref(0)
  const scenarioState = ref({ status: 'idle' })
  const argocdState   = ref({ apps: [] })
  const dwellSeconds  = ref(0)
  const windowSeconds = ref(0)

  let pollTimer  = null
  let dwellTimer = null

  // ── Computed ───────────────────────────────────────────────────────────────
  const isCompromised = computed(() =>
    scenarioState.value.status === 'waiting')

  const isAttacking = computed(() =>
    scenarioState.value.status === 'attacking')

  const isReconciling = computed(() =>
    scenarioState.value.status === 'reconciling')

  const isIdle = computed(() =>
    scenarioState.value.status === 'idle')

  const isComplete = computed(() =>
    scenarioState.value.status === 'complete')

  // An Allow Attack (uncontrolled) run mutated the cluster — force an explicit
  // Reset to Safe State before another scenario can run, so results don't mix.
  const needsReset = computed(() =>
    scenarioState.value.status === 'complete' &&
    scenarioState.value.mode === 'uncontrolled')

  // ── Security posture — live control status derived from events ────────────
  const securityPosture = computed(() => {
    const sc  = scenarioState.value.scenario
    const st  = scenarioState.value.status
    const evts = events.value

    if (!sc) return null

    const has = (phase, fragment) => evts.some(e =>
      e.phase === phase && e.title?.toLowerCase().includes(fragment.toLowerCase()))

    const status = (compromised, recovered) => {
      if (!compromised) return 'active'
      if (recovered)   return 'restored'
      if (st === 'reconciling' || st === 'proof') return 'restoring'
      return 'compromised'
    }

    if (sc === 'privilege-escalation') {
      const tokenCompromised  = has('SETUP', 'over-privileged-sa')
      const kyv1Compromised   = has('ATTACK', 'no-privileged-containers')
      const kyv2Compromised   = has('ATTACK', 'no-hostpath-mount')
      const argoCompromised   = has('ATTACK', 'argocd') || has('ATTACK', 'gitops')
      const recovered         = has('RESTORE', 'argocd sync resumed') || st === 'complete'

      return [
        {
          label:       'automountServiceAccountToken: false',
          description: 'No token mounted in pod — nothing for an attacker to steal',
          status:      status(tokenCompromised, recovered),
          restoredBy:  'ArgoCD — target-app deployment'
        },
        {
          label:       'Kyverno: no-privileged-containers',
          description: 'Blocks privileged: true pod creation at admission',
          status:      status(kyv1Compromised, recovered),
          restoredBy:  'ArgoCD — secops-lab-policies app'
        },
        {
          label:       'Kyverno: no-hostpath-mount',
          description: 'Blocks hostPath volume mounts — prevents node filesystem access',
          status:      status(kyv2Compromised, recovered),
          restoredBy:  'ArgoCD — secops-lab-policies app'
        },
        {
          label:       'ArgoCD sync',
          description: 'Automatically reconciles cluster state back to Git on drift',
          status:      status(argoCompromised, recovered),
          restoredBy:  'Manual — Restore Protection button'
        }
      ]
    }

    if (sc === 'network-policy-bypass') {
      const kyvernoRemoved   = has('SETUP', 'protect-networkpolicies')          // backend removed guard (allow attack)
      const kyvernoBlocked   = has('DETECT', 'kyverno')                         // with controls: delete blocked at admission
      const denyAllDeleted   = has('ATTACK', 'creating egress policy')          // allow attack opened the DB path (deny-all already deleted)
      const denyAllRestored  = has('RECONCILE', 'window closed') || st === 'complete'
      const recovered        = st === 'complete' || has('PROOF', '')

      return [
        {
          label:       'Kyverno: protect-networkpolicies',
          description: 'Blocks NetworkPolicy deletion at admission',
          status:      kyvernoBlocked ? 'active' : status(kyvernoRemoved, recovered),
          restoredBy:  'ArgoCD — secops-lab-policies app'
        },
        {
          label:       'NetworkPolicy: deny-all',
          description: 'Default-deny all ingress and egress in the namespace',
          status:      status(denyAllDeleted, denyAllRestored),
          restoredBy:  'ArgoCD auto-reconcile (~30s)'
        },
        {
          label:       'ArgoCD auto-reconcile',
          description: 'Detects and restores deleted NetworkPolicies automatically',
          status:      'active',
          note:        'network-tooling-sa has no rights to the argocd namespace — attacker cannot suspend this'
        }
      ]
    }

    return null
  })

  const timelineEvents = computed(() => {
    // Group events by phase for timeline bar
    const phases = ['SETUP','ATTACK','DETECT','IMPACT','WAITING','RESTORE','RECONCILE','PROOF']
    return phases
      .map(phase => events.value.find(e => e.phase === phase))
      .filter(Boolean)
  })

  // ── Actions ────────────────────────────────────────────────────────────────
  function startPolling() {
    if (pollTimer) return
    pollTimer = setInterval(async () => {
      await Promise.all([fetchEvents(), fetchState(), fetchArgoCD()])
    }, 2000)
  }

  function stopPolling() {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null }
    if (dwellTimer) { clearInterval(dwellTimer); dwellTimer = null }
  }

  async function fetchEvents() {
    try {
      const res = await axios.get(`/api/events/feed?since=${lastEventId.value}`)
      if (res.data.events.length) {
        events.value.push(...res.data.events)
        lastEventId.value = res.data.lastId
      }
    } catch { /* session may have expired */ }
  }

  async function fetchState() {
    try {
      const res = await axios.get('/api/scenario/state')
      scenarioState.value = res.data

      // Live dwell while compromised AND through reconciliation — re-sync from
      // the server each poll and tick locally between polls.
      if (res.data.current_dwell_seconds != null) {
        dwellSeconds.value = res.data.current_dwell_seconds
        if (!dwellTimer) {
          dwellTimer = setInterval(() => { dwellSeconds.value += 1 }, 1000)
        }
      }

      // Reconciliation complete — freeze dwell at the verified value
      if (res.data.dwell_time_seconds != null) {
        if (dwellTimer) { clearInterval(dwellTimer); dwellTimer = null }
        dwellSeconds.value = res.data.dwell_time_seconds
      }

      // Track lateral movement window (Scenario 2)
      if (res.data.window_started_at && !res.data.window_ended_at) {
        windowSeconds.value = Math.floor(Date.now() / 1000) - res.data.window_started_at
      } else if (res.data.window_ended_at) {
        windowSeconds.value = res.data.window_ended_at - res.data.window_started_at
      }
    } catch { /* ignore */ }
  }

  async function fetchArgoCD() {
    try {
      const res = await axios.get('/api/argocd/state')
      argocdState.value = res.data
    } catch { /* ArgoCD may be starting */ }
  }

  async function runScenario(scenario, mode) {
    const res = await axios.post('/api/scenario/run', { scenario, mode })
    return res.data
  }

  async function restoreProtection() {
    // Dwell keeps counting until the backend confirms reconciliation; do not
    // freeze it here. The dwell timer is managed by fetchState polling.
    return (await axios.post('/api/scenario/restore')).data
  }

  async function runProof() {
    return (await axios.post('/api/scenario/proof')).data
  }

  async function resetScenario() {
    await axios.post('/api/scenario/reset')
    events.value      = []
    lastEventId.value = 0
    dwellSeconds.value = 0
    windowSeconds.value = 0
    scenarioState.value = { status: 'idle' }
  }

  return {
    events, scenarioState, argocdState, dwellSeconds, windowSeconds,
    isCompromised, isAttacking, isReconciling, isIdle, isComplete, needsReset, timelineEvents, securityPosture,
    startPolling, stopPolling,
    runScenario, restoreProtection, runProof, resetScenario
  }
})
