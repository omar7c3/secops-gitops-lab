<template>
  <div class="min-h-screen bg-gray-950 flex items-center justify-center p-4">
    <div class="w-full max-w-md">

      <!-- Logo / Title -->
      <div class="text-center mb-8">
        <div class="text-4xl mb-3">🔐</div>
        <h1 class="text-2xl font-bold text-white">SecOps GitOps Lab</h1>
        <p class="text-gray-400 mt-2 text-sm">Enter your access token to begin the demo</p>
      </div>

      <!-- Token input card -->
      <div class="bg-gray-900 border border-gray-800 rounded-xl p-6">
        <form @submit.prevent="handleSubmit">
          <label class="block text-sm font-medium text-gray-300 mb-2">
            Access Token
          </label>
          <input
            v-model="token"
            type="text"
            placeholder="DEMO-XXXX-XXXX"
            :disabled="loading"
            class="w-full bg-gray-800 border border-gray-700 text-white rounded-lg px-4 py-3
                   font-mono text-lg tracking-widest placeholder-gray-600
                   focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent
                   disabled:opacity-50"
            autocomplete="off"
            spellcheck="false"
          />

          <!-- Error message -->
          <div v-if="error" class="mt-3 p-3 bg-red-900/50 border border-red-700 rounded-lg">
            <p class="text-red-300 text-sm">{{ error }}</p>
          </div>

          <!-- Submit -->
          <button
            type="submit"
            :disabled="loading || !token.trim()"
            class="mt-4 w-full bg-blue-600 hover:bg-blue-500 disabled:bg-gray-700
                   disabled:text-gray-500 text-white font-semibold py-3 rounded-lg
                   transition-colors duration-150"
          >
            <span v-if="loading" class="flex items-center justify-center gap-2">
              <svg class="animate-spin h-4 w-4" fill="none" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"/>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z"/>
              </svg>
              Validating...
            </span>
            <span v-else>Enter Demo</span>
          </button>
        </form>
      </div>

      <p class="text-center text-gray-600 text-xs mt-6">
        Need a token? Contact the demo owner.
      </p>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { useSessionStore } from '../stores/session'

const router  = useRouter()
const session = useSessionStore()
const token   = ref('')
const loading = ref(false)
const error   = ref('')

async function handleSubmit() {
  if (!token.value.trim()) return

  loading.value = true
  error.value   = ''

  try {
    await session.login(token.value.trim().toUpperCase())
    router.push('/demo')
  } catch (err) {
    const msg = err.response?.data?.message || err.response?.data?.error || 'Something went wrong. Please try again.'
    error.value = msg
  } finally {
    loading.value = false
  }
}
</script>
