<template>
  <div class="bg-gray-900 border border-red-800 rounded-xl p-3 mb-3">
    <div class="flex items-center gap-2 mb-2">
      <span class="text-red-400">💀</span>
      <span class="text-xs font-bold text-red-300 uppercase tracking-wide">
        Stolen Data Sample
      </span>
      <span class="text-xs text-gray-500">(fake — demo only)</span>
    </div>
    <pre class="text-xs text-green-400 font-mono overflow-x-auto whitespace-pre-wrap
                leading-relaxed bg-black/40 rounded p-2">{{ data }}</pre>
  </div>
</template>

<script setup>
defineProps({
  data: { type: String, required: true }
})
</script>
