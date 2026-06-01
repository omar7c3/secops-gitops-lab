<template>
  <div class="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
    <div class="bg-gray-900 border border-gray-700 rounded-xl w-full max-w-lg p-6">

      <h2 class="text-lg font-bold text-white mb-1">{{ scenario.label }}</h2>
      <p class="text-gray-400 text-sm mb-4">{{ scenario.tagline }}</p>

      <!-- Scenario context -->
      <div class="bg-gray-800/60 border border-gray-700 rounded-lg p-4 mb-5 space-y-3 text-xs">

        <div>
          <span class="text-gray-500 uppercase tracking-wider font-semibold">What happens</span>
          <p class="text-gray-300 mt-1 leading-relaxed">{{ scenario.what }}</p>
        </div>

        <div>
          <span class="text-gray-500 uppercase tracking-wider font-semibold">Controls in play</span>
          <div class="flex flex-wrap gap-1.5 mt-1">
            <span
              v-for="c in scenario.controls"
              :key="c"
              class="bg-blue-900/60 text-blue-300 border border-blue-800 px-2 py-0.5 rounded font-medium"
            >{{ c }}</span>
          </div>
        </div>

        <div>
          <span class="text-gray-500 uppercase tracking-wider font-semibold">Watch for</span>
          <p class="text-gray-300 mt-1 leading-relaxed">{{ scenario.watch }}</p>
        </div>

      </div>

      <!-- Mode buttons -->
      <button
        @click="confirm('controlled')"
        class="w-full mb-3 p-4 rounded-xl border border-green-700 bg-green-950/40
               hover:bg-green-950/70 text-left transition-colors"
      >
        <div class="flex items-center gap-2 mb-1">
          <span class="text-green-400 text-lg">🛡</span>
          <span class="font-semibold text-green-300">With Controls</span>
        </div>
        <p class="text-green-400/70 text-xs leading-relaxed">
          {{ scenario.withControls }}
        </p>
      </button>

      <button
        @click="confirm('uncontrolled')"
        class="w-full mb-4 p-4 rounded-xl border border-red-700 bg-red-950/40
               hover:bg-red-950/70 text-left transition-colors"
      >
        <div class="flex items-center gap-2 mb-1">
          <span class="text-red-400 text-lg">⚠</span>
          <span class="font-semibold text-red-300">Allow Attack</span>
        </div>
        <p class="text-red-400/70 text-xs leading-relaxed">
          {{ scenario.allowAttack }}
          <span v-if="isScenario1" class="block mt-1 font-semibold text-red-300">
            Requires manual restore — cluster stays compromised until you act.
          </span>
          <span v-else class="block mt-1 text-orange-300">
            ArgoCD auto-recovers in ~30 seconds. Window is bounded.
          </span>
        </p>
      </button>

      <button
        @click="$emit('cancel')"
        class="w-full text-gray-500 hover:text-gray-300 text-sm transition-colors py-2"
      >
        Cancel
      </button>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  scenario: { type: String, required: true }
})

const emit = defineEmits(['confirm', 'cancel'])

const isScenario1 = computed(() => props.scenario === 'privilege-escalation')

const SCENARIOS = {
  'privilege-escalation': {
    label:    'Scenario 1 — Privilege Escalation',
    tagline:  'Service account abuse → cluster-admin → node filesystem access',
    what:     'The target pod reads its mounted service account token and uses it to call the Kubernetes API as cluster-admin. It then deletes Kyverno admission policies, suspends ArgoCD sync, deploys a privileged pod with the node filesystem mounted, and exfiltrates cluster certificates.',
    controls: ['automountServiceAccountToken: false', 'Kyverno: no-privileged-containers', 'Kyverno: no-hostpath-mount', 'ArgoCD self-heal'],
    watch:    'Events Feed for each step. System State panel for ArgoCD sync status and drift. Impact panel for the dwell time clock and stolen data sample.',
    withControls: 'No token is mounted — attack is blocked at step 1 before any API call is made. Proof runs automatically to confirm the control holds.',
    allowAttack:  'SA is swapped to over-privileged-sa. Kyverno policies are deleted by the attacker. ArgoCD sync is suspended. Cluster stays compromised until you click Restore Protection.',
  },
  'network-policy-bypass': {
    label:    'Scenario 2 — NetworkPolicy Bypass',
    tagline:  'Scoped SA token → deny-all deleted → lateral movement window',
    what:     'The target pod reads a narrowly scoped SA token (NetworkPolicy admin only) and uses it to delete the namespace deny-all NetworkPolicy. With isolation gone, it probes internal services — the backend admin API, postgres, and ArgoCD — that were previously unreachable.',
    controls: ['Kyverno: protect-networkpolicies', 'ArgoCD auto-reconcile (~30s)', 'NetworkPolicy: deny-all'],
    watch:    'Events Feed for the Kyverno admission decision. System State panel for ArgoCD reconciling the deleted NetworkPolicy back. Impact panel for the lateral movement window timer.',
    withControls: 'SA is mounted so the attack can attempt the deletion. Kyverno blocks it at admission — lateral movement window is 0 seconds. Proof runs automatically.',
    allowAttack:  'Kyverno guard removed. NetworkPolicy deleted successfully. Internal services reachable. ArgoCD races to restore the policy — window is bounded by reconciliation time.',
  },
}

const scenario = computed(() => SCENARIOS[props.scenario])

function confirm(mode) {
  emit('confirm', { mode })
}
</script>
