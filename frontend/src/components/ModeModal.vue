<template>
  <div class="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
    <div class="bg-gray-900 border border-gray-700 rounded-xl w-full max-w-md p-6">

      <h2 class="text-lg font-bold text-white mb-1">Run Scenario</h2>
      <p class="text-gray-400 text-sm mb-6">
        {{ scenarioLabel }} — choose how to run it
      </p>

      <!-- With Controls -->
      <button
        @click="confirm('controlled')"
        class="w-full mb-3 p-4 rounded-xl border border-green-700 bg-green-950/40
               hover:bg-green-950/70 text-left transition-colors group"
      >
        <div class="flex items-center gap-2 mb-1">
          <span class="text-green-400 text-lg">🛡</span>
          <span class="font-semibold text-green-300">With Controls</span>
        </div>
        <p class="text-green-400/70 text-xs leading-relaxed">
          Kyverno policies and ArgoCD active. Attack will be blocked at the
          earliest possible step. Shows prevention in action.
        </p>
      </button>

      <!-- Allow Attack -->
      <button
        @click="confirm('uncontrolled')"
        class="w-full mb-4 p-4 rounded-xl border border-red-700 bg-red-950/40
               hover:bg-red-950/70 text-left transition-colors group"
      >
        <div class="flex items-center gap-2 mb-1">
          <span class="text-red-400 text-lg">⚠</span>
          <span class="font-semibold text-red-300">Allow Attack</span>
        </div>
        <p class="text-red-400/70 text-xs leading-relaxed">
          Controls temporarily disabled. Attack runs to completion.
          Shows full blast radius and what happens without protection.
          <span v-if="isScenario1" class="block mt-1 font-semibold text-red-300">
            Requires manual restore — cluster will remain compromised until you act.
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

const scenarioLabel = computed(() => {
  return isScenario1.value
    ? 'Scenario 1 — Privilege Escalation'
    : 'Scenario 2 — NetworkPolicy Bypass'
})

function confirm(mode) {
  emit('confirm', { mode })
}
</script>
