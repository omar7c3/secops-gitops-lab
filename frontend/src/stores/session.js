// =============================================================================
// Pinia Store — Session
// Manages JWT, session timer, and token validation
// =============================================================================

import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import axios from 'axios'

export const useSessionStore = defineStore('session', () => {
  const jwt         = ref(localStorage.getItem('jwt') || null)
  const sessionId   = ref(localStorage.getItem('sessionId') || null)
  const expiresAt   = ref(parseInt(localStorage.getItem('expiresAt') || '0'))
  const label       = ref(localStorage.getItem('label') || '')

  // ── Reactive ticker — updates every second so countdown re-renders ──────────
  const now = ref(Math.floor(Date.now() / 1000))
  let ticker = null

  function startTicker() {
    if (ticker) return
    ticker = setInterval(() => {
      now.value = Math.floor(Date.now() / 1000)
      // Auto-clear if session expired
      if (now.value > expiresAt.value && jwt.value) {
        clearSession()
      }
    }, 1000)
  }

  function stopTicker() {
    if (ticker) { clearInterval(ticker); ticker = null }
  }

  const isActive = computed(() => {
    return !!jwt.value && now.value < expiresAt.value
  })

  const remainingSeconds = computed(() => {
    return Math.max(0, expiresAt.value - now.value)
  })

  // Validate token and create session
  async function login(token) {
    const res  = await axios.post('/api/token/validate', { token })
    const data = res.data

    jwt.value       = data.jwt
    sessionId.value = data.sessionId
    expiresAt.value = data.expiresAt
    label.value     = data.label

    localStorage.setItem('jwt',       data.jwt)
    localStorage.setItem('sessionId', data.sessionId)
    localStorage.setItem('expiresAt', data.expiresAt)
    localStorage.setItem('label',     data.label)

    axios.defaults.headers.common['Authorization'] = `Bearer ${data.jwt}`

    startTicker()
    return data
  }

  // End session explicitly
  async function endSession() {
    try {
      await axios.post('/api/session/end')
    } catch { /* ignore — clear locally regardless */ }
    clearSession()
  }

  function clearSession() {
    jwt.value       = null
    sessionId.value = null
    expiresAt.value = 0
    label.value     = ''

    localStorage.removeItem('jwt')
    localStorage.removeItem('sessionId')
    localStorage.removeItem('expiresAt')
    localStorage.removeItem('label')

    delete axios.defaults.headers.common['Authorization']
    stopTicker()
  }

  // Restore axios header and start ticker on page reload
  if (jwt.value && now.value < expiresAt.value) {
    axios.defaults.headers.common['Authorization'] = `Bearer ${jwt.value}`
    startTicker()
  } else if (jwt.value) {
    // Token in storage but already expired — clear it
    clearSession()
  }

  // ── Global 401 interceptor ────────────────────────────────────────────────
  // Any API call that returns 401 clears the session and redirects to /
  axios.interceptors.response.use(
    response => response,
    error => {
      if (error.response?.status === 401) {
        const url = error.config?.url || ''
        const isVisitorCall = !url.includes('/admin') &&
                              !url.includes('/token/validate') &&
                              !url.includes('/admin/auth')

        if (isVisitorCall && localStorage.getItem('jwt')) {
          clearSession()
          window.location.href = '/'
        }
      }
      return Promise.reject(error)
    }
  )

  return {
    jwt, sessionId, expiresAt, label,
    isActive, remainingSeconds,
    login, endSession, clearSession,
    startTicker, stopTicker
  }
})
