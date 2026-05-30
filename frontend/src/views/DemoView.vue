<template>
  <div class="min-h-screen bg-gray-950 text-white flex flex-col">

    <!-- Header -->
    <header class="border-b border-gray-800 px-6 py-3 flex items-center justify-between">
      <div class="flex items-center gap-3">
        <span class="text-xl">🔐</span>
        <span class="font-semibold text-white">SecOps GitOps Lab</span>
        <span class="text-gray-500 text-sm">|</span>
        <span class="text-gray-400 text-sm">{{ session.label }}</span>
      </div>
      <div class="flex items-center gap-4">
        <!-- Session timer -->
        <div class="text-sm" :class="sessionTimerClass">
          Session: {{ formatTime(session.remainingSeconds) }}
        </div>
        <button
          @click="handleEndSession"
          class="text-sm text-gray-400 hover:text-red-400 transition-colors border
                 border-gray-700 hover:border-red-700 px-3 py-1 rounded-lg"
        >
          End Session
        </button>
      </div>
    </header>

    <!-- Scenario selector -->
    <div class="border-b border-gray-800 px-6 py-3 flex items-center gap-4">
      <span class="text-sm text-gray-400">Scenario:</span>
      <button
        v-for="s in scenarios"
        :key="s.id"
        @click="selectedScenario = s.id"
        :class="[
          'px-4 py-1.5 rounded-lg text-sm font-medium transition-colors',
          selectedScenario === s.id
            ? 'bg-blue-600 text-white'
            : 'bg-gray-800 text-gray-400 hover:text-white'
        ]"
      >
        {{ s.label }}
      </button>
    </div>

    <!-- Three panels -->
    <div class="flex-1 grid grid-cols-3 gap-0 overflow-hidden" style="height: calc(100vh - 180px)">

      <!-- Panel 1: Attack Feed -->
      <div class="border-r border-gray-800 flex flex-col">
        <div class="px-4 py-2 bg-gray-900 border-b border-gray-800 flex items-center gap-2">
          <span class="w-2 h-2 rounded-full bg-red-500 animate-pulse"></span>
          <span class="text-xs font-semibold text-gray-300 uppercase tracking-wider">Attack Feed</span>
        </div>
        <div ref="feedEl" class="flex-1 overflow-y-auto p-3 space-y-2 font-mono text-xs">
          <div
            v-for="event in scenario.events"
            :key="event.id"
            :class="eventRowClass(event.severity)"
            class="p-2 rounded border"
          >
            <div class="flex items-start gap-2">
              <span :class="phaseBadgeClass(event.phase)"
                    class="shrink-0 px-1.5 py-0.5 rounded text-xs font-bold uppercase">
                {{ event.phase }}
              </span>
              <div class="flex-1 min-w-0">
                <div class="font-semibold text-white truncate">{{ event.title }}</div>
                <div class="text-gray-400 mt-0.5 leading-relaxed whitespace-normal">
                  {{ event.explanation }}
                </div>
                <div class="text-gray-600 mt-1">{{ formatTs(event.created_at) }}</div>
              </div>
            </div>
          </div>
          <div v-if="!scenario.events.length" class="text-gray-600 text-center py-8">
            No events yet — run a scenario to begin
          </div>
        </div>
      </div>

      <!-- Panel 2: System State (Git vs Live) -->
      <div class="border-r border-gray-800 flex flex-col">
        <div class="px-4 py-2 bg-gray-900 border-b border-gray-800 flex items-center gap-2">
          <span class="w-2 h-2 rounded-full"
                :class="systemHealthColor"></span>
          <span class="text-xs font-semibold text-gray-300 uppercase tracking-wider">System State</span>
        </div>
        <div class="flex-1 overflow-y-auto p-3 space-y-3">
          <div v-for="app in scenario.argocdState.apps || []" :key="app.name">
            <div class="flex items-center justify-between mb-1.5">
              <span class="text-xs font-semibold text-gray-300">{{ app.name }}</span>
              <div class="flex gap-1.5">
                <span :class="syncBadgeClass(app.syncStatus)"
                      class="text-xs px-2 py-0.5 rounded font-medium">
                  {{ app.syncStatus || '—' }}
                </span>
                <span v-if="app.suspended"
                      class="text-xs px-2 py-0.5 rounded font-medium bg-orange-900 text-orange-300">
                  SUSPENDED
                </span>
              </div>
            </div>
            <!-- Resources -->
            <div class="space-y-1">
              <div
                v-for="r in app.resources || []"
                :key="`${r.kind}/${r.name}`"
                class="flex items-center gap-2 text-xs py-0.5"
              >
                <span :class="r.status === 'Synced' ? 'text-green-500' : 'text-red-500'">
                  {{ r.status === 'Synced' ? '✓' : '✗' }}
                </span>
                <span class="text-gray-500">{{ r.kind }}</span>
                <span class="text-gray-300 truncate">{{ r.name }}</span>
              </div>
            </div>
          </div>
          <div v-if="!scenario.argocdState.apps?.length" class="text-gray-600 text-center py-8 text-xs">
            Connecting to ArgoCD...
          </div>
        </div>
      </div>

      <!-- Panel 3: Impact / Mitigation -->
      <div class="flex flex-col">
        <div class="px-4 py-2 bg-gray-900 border-b border-gray-800">
          <span class="text-xs font-semibold text-gray-300 uppercase tracking-wider">
            {{ scenario.isCompromised ? 'Impact' : 'Mitigation' }}
          </span>
        </div>
        <div class="flex-1 overflow-y-auto p-3">

          <!-- Compromised cluster warning (Scenario 1 Allow Attack) -->
          <div v-if="scenario.isCompromised"
               class="border border-red-700 bg-red-950 rounded-xl p-4 mb-3">
            <div class="flex items-center gap-2 mb-3">
              <span class="text-red-400 text-lg">⚠</span>
              <span class="font-bold text-red-300 uppercase tracking-wide text-sm">
                Cluster Compromised
              </span>
            </div>
            <div class="text-red-200 text-2xl font-mono font-bold mb-3">
              {{ formatDwell(scenario.dwellSeconds) }}
            </div>
            <p class="text-red-300 text-xs mb-3">
              Attacker has cluster-admin access. ArgoCD sync is suspended.
              No automatic recovery will occur.
            </p>
            <div class="text-xs text-red-400 space-y-1 mb-4">
              <div>In a real incident you would need to:</div>
              <div class="ml-2">1. Revoke the compromised token</div>
              <div class="ml-2">2. Rotate cluster certificates</div>
              <div class="ml-2">3. Audit what was accessed</div>
              <div class="ml-2">4. Restore GitOps sync manually</div>
            </div>
            <button
              @click="handleRestore"
              :disabled="restoring"
              class="w-full bg-red-600 hover:bg-red-500 disabled:bg-gray-700
                     text-white font-bold py-2.5 rounded-lg text-sm transition-colors"
            >
              {{ restoring ? 'Restoring...' : 'Restore Protection' }}
            </button>
          </div>

          <!-- Stolen data sample -->
          <StolenDataPanel v-if="stolenData" :data="stolenData" />

          <!-- Lateral movement window (Scenario 2) -->
          <div v-if="scenario.windowSeconds > 0 && !scenario.isIdle" class="mb-3">
            <div class="bg-orange-950 border border-orange-700 rounded-lg p-3">
              <div class="text-xs text-orange-300 font-semibold mb-1">
                Lateral Movement Window
              </div>
              <div class="text-orange-200 font-mono text-xl font-bold">
                {{ scenario.windowSeconds }}s
              </div>
              <div class="text-orange-400 text-xs mt-1">
                {{ scenario.scenarioState.window_ended_at ? 'Window closed — ArgoCD reconciled' : 'Window open — racing ArgoCD clock' }}
              </div>
            </div>
          </div>

          <!-- Idle state -->
          <div v-if="scenario.isIdle" class="text-gray-600 text-center py-8 text-xs">
            Run a scenario to see impact or mitigation details here
          </div>
        </div>
      </div>
    </div>

    <!-- Timeline bar -->
    <TimelineBar :events="scenario.timelineEvents" :dwell="scenario.dwellSeconds" />

    <!-- Controls -->
    <div class="border-t border-gray-800 px-6 py-3 flex items-center gap-3">
      <button
        @click="showModeModal = true"
        :disabled="!scenario.isIdle"
        class="bg-blue-600 hover:bg-blue-500 disabled:bg-gray-700 disabled:text-gray-500
               text-white font-semibold px-5 py-2 rounded-lg text-sm transition-colors"
      >
        <span v-if="scenario.isAttacking" class="flex items-center gap-2">
          <span class="w-3 h-3 border-2 border-gray-400 border-t-white rounded-full animate-spin"></span>
          Attack in progress...
        </span>
        <span v-else>▶ Run Scenario</span>
      </button>

      <button
        @click="handleReset"
        class="border border-gray-700 hover:border-gray-500 text-gray-400 hover:text-white
               px-4 py-2 rounded-lg text-sm transition-colors"
      >
        🔄 Reset to Safe State
      </button>
    </div>

    <!-- Mode selection modal -->
    <ModeModal
      v-if="showModeModal"
      :scenario="selectedScenario"
      @confirm="handleRunScenario"
      @cancel="showModeModal = false"
    />
  </div>
</template>

<script setup>
import { ref, computed, watch, nextTick, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { useSessionStore }  from '../stores/session'
import { useScenarioStore } from '../stores/scenario'
import TimelineBar   from '../components/TimelineBar.vue'
import ModeModal     from '../components/ModeModal.vue'
import StolenDataPanel from '../components/StolenDataPanel.vue'

const router   = useRouter()
const session  = useSessionStore()
const scenario = useScenarioStore()

const selectedScenario = ref('privilege-escalation')
const showModeModal    = ref(false)
const restoring        = ref(false)
const feedEl           = ref(null)

const scenarios = [
  { id: 'privilege-escalation',  label: '1. Privilege Escalation' },
  { id: 'network-policy-bypass', label: '2. Network Policy Bypass' }
]

// Stolen data from events
const stolenData = computed(() => {
  const e = scenario.events.find(ev =>
    ev.phase === 'IMPACT' && ev.explanation?.includes('stolen_data'))
  if (!e) return null
  try { return JSON.parse(e.explanation).data }
  catch { return null }
})

// Auto-scroll feed
watch(() => scenario.events.length, async () => {
  await nextTick()
  if (feedEl.value) feedEl.value.scrollTop = feedEl.value.scrollHeight
})

onMounted(() => scenario.startPolling())
onUnmounted(() => scenario.stopPolling())

// Session expiry check
const sessionTimerClass = computed(() => {
  if (session.remainingSeconds < 300) return 'text-red-400'
  if (session.remainingSeconds < 600) return 'text-yellow-400'
  return 'text-gray-400'
})

const systemHealthColor = computed(() => {
  const apps = scenario.argocdState.apps || []
  if (apps.some(a => a.suspended))         return 'bg-orange-500'
  if (apps.some(a => a.syncStatus !== 'Synced')) return 'bg-red-500 animate-pulse'
  return 'bg-green-500'
})

async function handleRunScenario({ mode }) {
  showModeModal.value = false
  await scenario.runScenario(selectedScenario.value, mode)
}

async function handleRestore() {
  restoring.value = true
  try {
    await scenario.restoreProtection()
    setTimeout(() => scenario.runProof(), 5000)
  } finally {
    restoring.value = false
  }
}

async function handleReset() {
  if (!confirm('Reset cluster to safe state? This will clear all events.')) return
  await scenario.resetScenario()
}

async function handleEndSession() {
  if (!confirm('End your session? The cluster will be reset if dirty.')) return
  await session.endSession()
  router.push('/')
}

// Helpers
function formatTime(s) {
  const m = Math.floor(s / 60)
  const sec = s % 60
  return `${m}:${sec.toString().padStart(2, '0')}`
}

function formatDwell(s) {
  const m = Math.floor(s / 60)
  const sec = s % 60
  return `${m}m ${sec.toString().padStart(2, '0')}s`
}

function formatTs(unixTs) {
  return new Date(unixTs * 1000).toLocaleTimeString()
}

function eventRowClass(severity) {
  return {
    'border-red-800 bg-red-950/30':    severity === 'CRITICAL',
    'border-yellow-800 bg-yellow-950/20': severity === 'WARNING',
    'border-green-800 bg-green-950/20':  severity === 'SUCCESS',
    'border-gray-800 bg-gray-900/30':    severity === 'INFO'
  }
}

function phaseBadgeClass(phase) {
  return {
    'bg-red-800 text-red-200':    ['ATTACK','IMPACT'].includes(phase),
    'bg-yellow-800 text-yellow-200': ['DETECT','WAITING'].includes(phase),
    'bg-green-800 text-green-200':  ['PROOF','RECONCILE','RESTORE'].includes(phase),
    'bg-blue-800 text-blue-200':    phase === 'SETUP'
  }
}

function syncBadgeClass(status) {
  return {
    'bg-green-900 text-green-300': status === 'Synced',
    'bg-red-900 text-red-300':     status === 'OutOfSync',
    'bg-gray-800 text-gray-400':   !status
  }
}
</script>
