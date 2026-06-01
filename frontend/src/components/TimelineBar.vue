<template>
  <div class="border-b-2 border-gray-700 bg-gray-900 px-6 py-3 shrink-0">
    <!-- Header: title + legend -->
    <div class="flex items-center justify-between gap-4 mb-2 flex-wrap">
      <div class="flex items-center gap-2">
        <span class="text-sm font-bold uppercase tracking-wider text-gray-200">Attack Timeline</span>
        <span v-if="events.length" class="text-xs text-gray-500">{{ events.length }} events</span>
      </div>
      <!-- Phase legend -->
      <div class="flex items-center gap-x-3 gap-y-1 flex-wrap">
        <span
          v-for="p in legend"
          :key="p.phase"
          :title="p.desc"
          class="flex items-center gap-1.5 text-xs text-gray-400 cursor-help"
        >
          <span :class="[dotClass(p.phase), 'w-2.5 h-2.5 rounded-sm shrink-0']"></span>
          {{ p.label }}
        </span>
      </div>
    </div>

    <!-- Scrollable milestone track -->
    <div ref="track" class="flex items-center gap-1.5 overflow-x-auto pb-2 timeline-scroll">
      <div
        v-for="(event, i) in events"
        :key="i"
        class="flex items-center gap-1.5 shrink-0"
      >
        <!-- Connector line -->
        <div v-if="i > 0" class="w-8 h-0.5 bg-gray-600"></div>
        <!-- Milestone -->
        <div
          :class="[milestoneClass(event.phase), 'px-3 py-1.5 rounded-md text-sm font-semibold whitespace-nowrap shadow-sm']"
          :title="event.explanation"
        >
          <span class="opacity-60 mr-1.5 font-mono text-xs">T+{{ relativeTime(event.created_at) }}</span>
          {{ event.title }}
        </div>
      </div>

      <!-- Dwell time badge -->
      <div v-if="dwell > 0" class="flex items-center gap-1.5 shrink-0">
        <div class="w-8 h-0.5 bg-red-700"></div>
        <div class="px-3 py-1.5 rounded-md text-sm font-bold bg-red-800 text-red-100 whitespace-nowrap shadow-sm">
          ⏱ Dwell: {{ formatDwell(dwell) }}
        </div>
      </div>

      <div v-if="!events.length" class="text-sm text-gray-500 py-1.5">
        Timeline will appear here as the scenario runs
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, ref, watch, nextTick } from 'vue'

const props = defineProps({
  events: { type: Array, default: () => [] },
  dwell:  { type: Number, default: 0 }
})

const track = ref(null)

const legend = [
  { phase: 'SETUP',     label: 'Setup',       desc: 'Backend stages the scenario to mimic a real-world weakness (e.g. over-provisioned service account, misconfiguration, missing controls)' },
  { phase: 'ATTACK',    label: 'Attack',      desc: 'Attacker action from inside the cluster' },
  { phase: 'DETECT',    label: 'Detect',      desc: 'A security control caught or blocked the action' },
  { phase: 'IMPACT',    label: 'Impact',      desc: 'Consequence of a successful breach' },
  { phase: 'WAITING',   label: 'Compromised', desc: 'Cluster compromised — dwell time accruing, awaiting restore' },
  { phase: 'RESTORE',   label: 'Restore',     desc: 'Operator / SOC response' },
  { phase: 'RECONCILE', label: 'Reconcile',   desc: 'GitOps restores the cluster to desired state' },
  { phase: 'PROOF',     label: 'Proof',       desc: 'Attack re-run to prove controls now hold' }
]

const startTime = computed(() => props.events[0]?.created_at || 0)

// Auto-scroll the track to the newest milestone as events arrive
watch(() => props.events.length, async () => {
  await nextTick()
  if (track.value) track.value.scrollTo({ left: track.value.scrollWidth, behavior: 'smooth' })
})

function relativeTime(ts) {
  const diff = ts - startTime.value
  if (diff < 60)  return `${diff}s`
  return `${Math.floor(diff / 60)}m${diff % 60}s`
}

function formatDwell(s) {
  return `${Math.floor(s / 60)}m ${(s % 60).toString().padStart(2, '0')}s`
}

const COLORS = {
  SETUP:     { chip: 'bg-blue-900 text-blue-300',                              dot: 'bg-blue-500' },
  ATTACK:    { chip: 'bg-red-900 text-red-300',                                dot: 'bg-red-500' },
  DETECT:    { chip: 'bg-yellow-900 text-yellow-300',                          dot: 'bg-yellow-500' },
  IMPACT:    { chip: 'bg-red-950 text-red-400 border border-red-800',          dot: 'bg-red-700' },
  WAITING:   { chip: 'bg-red-950 text-red-300 border border-red-700 animate-pulse', dot: 'bg-red-600' },
  RESTORE:   { chip: 'bg-orange-900 text-orange-300',                          dot: 'bg-orange-500' },
  RECONCILE: { chip: 'bg-blue-950 text-blue-300',                              dot: 'bg-blue-400' },
  PROOF:     { chip: 'bg-green-900 text-green-300',                            dot: 'bg-green-500' }
}

function milestoneClass(phase) {
  return (COLORS[phase] || { chip: 'bg-gray-800 text-gray-400' }).chip
}
function dotClass(phase) {
  return (COLORS[phase] || { dot: 'bg-gray-500' }).dot
}
</script>

<style scoped>
/* Friendlier horizontal scrollbar for the timeline track */
.timeline-scroll {
  scrollbar-width: thin;
  scrollbar-color: #4b5563 transparent;
}
.timeline-scroll::-webkit-scrollbar {
  height: 8px;
}
.timeline-scroll::-webkit-scrollbar-track {
  background: transparent;
}
.timeline-scroll::-webkit-scrollbar-thumb {
  background: #4b5563;
  border-radius: 4px;
}
.timeline-scroll::-webkit-scrollbar-thumb:hover {
  background: #6b7280;
}
</style>
