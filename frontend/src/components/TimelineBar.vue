<template>
  <div class="border-t border-gray-800 bg-gray-900 px-6 py-2">
    <div class="flex items-center gap-1 overflow-x-auto">
      <span class="text-xs text-gray-500 shrink-0 mr-2">Timeline</span>
      <div
        v-for="(event, i) in events"
        :key="i"
        class="flex items-center gap-1 shrink-0"
      >
        <!-- Connector line -->
        <div v-if="i > 0" class="w-6 h-px bg-gray-700"></div>
        <!-- Milestone -->
        <div
          :class="[milestoneClass(event.phase), 'px-2 py-0.5 rounded text-xs font-medium whitespace-nowrap']"
          :title="event.explanation"
        >
          <span class="text-gray-500 mr-1">T+{{ relativeTime(event.created_at) }}</span>
          {{ event.title }}
        </div>
      </div>

      <!-- Dwell time badge -->
      <div v-if="dwell > 0" class="flex items-center gap-1 shrink-0">
        <div class="w-6 h-px bg-red-800"></div>
        <div class="px-2 py-0.5 rounded text-xs font-medium bg-red-900 text-red-300 whitespace-nowrap">
          Dwell: {{ formatDwell(dwell) }}
        </div>
      </div>

      <div v-if="!events.length" class="text-xs text-gray-600">
        Timeline will appear here as the scenario runs
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  events: { type: Array, default: () => [] },
  dwell:  { type: Number, default: 0 }
})

const startTime = computed(() => props.events[0]?.created_at || 0)

function relativeTime(ts) {
  const diff = ts - startTime.value
  if (diff < 60)  return `${diff}s`
  return `${Math.floor(diff / 60)}m${diff % 60}s`
}

function formatDwell(s) {
  return `${Math.floor(s / 60)}m ${(s % 60).toString().padStart(2, '0')}s`
}

function milestoneClass(phase) {
  const map = {
    SETUP:      'bg-blue-900 text-blue-300',
    ATTACK:     'bg-red-900 text-red-300',
    DETECT:     'bg-yellow-900 text-yellow-300',
    IMPACT:     'bg-red-950 text-red-400 border border-red-800',
    WAITING:    'bg-red-950 text-red-300 border border-red-700 animate-pulse',
    RESTORE:    'bg-orange-900 text-orange-300',
    RECONCILE:  'bg-blue-950 text-blue-300',
    PROOF:      'bg-green-900 text-green-300'
  }
  return map[phase] || 'bg-gray-800 text-gray-400'
}
</script>
