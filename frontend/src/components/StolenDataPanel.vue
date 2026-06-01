<template>
  <div class="bg-gray-900 border border-red-800 rounded-xl p-3 mb-3">
    <div class="flex items-center gap-2 mb-2">
      <span class="text-red-400">💀</span>
      <span class="text-xs font-bold text-red-300 uppercase tracking-wide">
        {{ title }}
      </span>
      <span class="text-xs text-gray-500">{{ subtitle }}</span>
    </div>
    <pre class="text-xs text-green-400 font-mono overflow-x-auto whitespace-pre-wrap
                leading-relaxed bg-black/40 rounded p-2">{{ data }}</pre>
  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  data:     { type: String, required: true },
  scenario: { type: String, default: '' }
})

// S2 doesn't exfiltrate data — it opens a network path to the DB. Frame it honestly.
const isNetwork = computed(() => props.scenario === 'network-policy-bypass')
const title     = computed(() => isNetwork.value ? 'Database Access Gained' : 'Stolen Data Sample')
const subtitle  = computed(() => isNetwork.value
  ? '(live — network path opened on this lab cluster)'
  : '(real data — captured live from this lab cluster)')
</script>
