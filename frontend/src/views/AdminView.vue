<template>
  <div class="min-h-screen bg-gray-950 text-white p-6">
    <div class="max-w-5xl mx-auto">

      <div class="flex items-center justify-between mb-6">
        <h1 class="text-xl font-bold">Admin Dashboard</h1>
        <div class="flex items-center gap-3">
          <!-- Session expiry indicator -->
          <span v-if="authed" class="text-xs" :class="sessionIndicatorClass">
            Session: {{ sessionTimeRemaining }}
          </span>
          <button v-if="authed" @click="logout"
            class="text-xs text-gray-500 hover:text-red-400 border border-gray-700
                   hover:border-red-700 px-3 py-1 rounded-lg transition-colors">
            Logout
          </button>
          <div v-if="!authed" class="flex gap-2">
            <input
              v-model="password"
              type="password"
              placeholder="Admin password"
              @keyup.enter="login"
              class="bg-gray-800 border border-gray-700 text-white rounded-lg px-3 py-2 text-sm"
            />
            <button @click="login"
              class="bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded-lg text-sm">
              Login
            </button>
          </div>
        </div>
      </div>

      <div v-if="!authed" class="text-gray-500 text-center py-20">
        Enter admin password to access the dashboard
      </div>

      <div v-else class="space-y-6">

        <!-- Active Sessions -->
        <section>
          <h2 class="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">
            Active Sessions
          </h2>
          <div class="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
            <table class="w-full text-sm">
              <thead class="bg-gray-800 text-gray-400 text-xs uppercase">
                <tr>
                  <th class="px-4 py-2 text-left">Token</th>
                  <th class="px-4 py-2 text-left">Label</th>
                  <th class="px-4 py-2 text-left">IP</th>
                  <th class="px-4 py-2 text-left">Started</th>
                  <th class="px-4 py-2 text-left">Expires</th>
                  <th class="px-4 py-2 text-left">Action</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="s in data.activeSessions" :key="s.id"
                    class="border-t border-gray-800">
                  <td class="px-4 py-2 font-mono text-xs text-blue-300">{{ s.token_id }}</td>
                  <td class="px-4 py-2 text-gray-300">{{ s.label }}</td>
                  <td class="px-4 py-2 font-mono text-xs text-gray-400">{{ s.ip }}</td>
                  <td class="px-4 py-2 text-gray-400 text-xs">{{ formatTs(s.started_at) }}</td>
                  <td class="px-4 py-2 text-gray-400 text-xs">{{ formatTs(s.expires_at) }}</td>
                  <td class="px-4 py-2">
                    <button @click="releaseSession(s.id)"
                      class="text-xs text-red-400 hover:text-red-300 border border-red-800
                             hover:border-red-600 px-2 py-0.5 rounded">
                      Release
                    </button>
                  </td>
                </tr>
                <tr v-if="!data.activeSessions?.length">
                  <td colspan="6" class="px-4 py-4 text-gray-600 text-center text-xs">
                    No active sessions
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>

        <!-- Blocked Visitor Attempts -->
        <section>
          <h2 class="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">
            Blocked Visitor Attempts
          </h2>
          <div class="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
            <table class="w-full text-sm">
              <thead class="bg-gray-800 text-gray-400 text-xs uppercase">
                <tr>
                  <th class="px-4 py-2 text-left">Token</th>
                  <th class="px-4 py-2 text-left">IP</th>
                  <th class="px-4 py-2 text-left">Reason</th>
                  <th class="px-4 py-2 text-left">Time</th>
                  <th class="px-4 py-2 text-left">User Agent</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="a in data.blockedAttempts" :key="a.id"
                    class="border-t border-gray-800">
                  <td class="px-4 py-2 font-mono text-xs text-yellow-300">{{ a.token_id }}</td>
                  <td class="px-4 py-2 font-mono text-xs text-gray-400">{{ a.ip }}</td>
                  <td class="px-4 py-2 text-xs">
                    <span :class="reasonClass(parseDetail(a.detail)?.reason)"
                          class="px-2 py-0.5 rounded font-medium">
                      {{ parseDetail(a.detail)?.reason || '—' }}
                    </span>
                  </td>
                  <td class="px-4 py-2 text-gray-400 text-xs">{{ formatTs(a.created_at) }}</td>
                  <td class="px-4 py-2 text-gray-600 text-xs truncate max-w-xs">{{ a.user_agent }}</td>
                </tr>
                <tr v-if="!data.blockedAttempts?.length">
                  <td colspan="5" class="px-4 py-4 text-gray-600 text-center text-xs">
                    No blocked visitor attempts
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>

        <!-- Failed Admin Attempts -->
        <section>
          <h2 class="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">
            Failed Admin Attempts
          </h2>
          <div class="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
            <table class="w-full text-sm">
              <thead class="bg-gray-800 text-gray-400 text-xs uppercase">
                <tr>
                  <th class="px-4 py-2 text-left">IP</th>
                  <th class="px-4 py-2 text-left">Reason</th>
                  <th class="px-4 py-2 text-left">Path</th>
                  <th class="px-4 py-2 text-left">Time</th>
                  <th class="px-4 py-2 text-left">User Agent</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="a in data.failedAdminAttempts" :key="a.id"
                    class="border-t border-gray-800">
                  <td class="px-4 py-2 font-mono text-xs text-red-300">{{ a.ip }}</td>
                  <td class="px-4 py-2 text-xs">
                    <span class="px-2 py-0.5 rounded font-medium bg-red-900 text-red-300">
                      {{ parseDetail(a.detail)?.reason || 'wrong_password' }}
                    </span>
                  </td>
                  <td class="px-4 py-2 font-mono text-xs text-gray-400">
                    {{ parseDetail(a.detail)?.path || '—' }}
                  </td>
                  <td class="px-4 py-2 text-gray-400 text-xs">{{ formatTs(a.created_at) }}</td>
                  <td class="px-4 py-2 text-gray-600 text-xs truncate max-w-xs">{{ a.user_agent }}</td>
                </tr>
                <tr v-if="!data.failedAdminAttempts?.length">
                  <td colspan="5" class="px-4 py-4 text-gray-600 text-center text-xs">
                    No failed admin attempts
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>

        <!-- Generate Token -->
        <section>
          <h2 class="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">
            Generate Token
          </h2>
          <div class="bg-gray-900 border border-gray-800 rounded-xl p-4 flex gap-3">
            <input v-model="newLabel" placeholder="Label (e.g. John — Interview)"
              class="flex-1 bg-gray-800 border border-gray-700 text-white rounded-lg px-3 py-2 text-sm" />
            <input v-model="newExpiry" type="number" placeholder="Days" min="1" max="30"
              class="w-20 bg-gray-800 border border-gray-700 text-white rounded-lg px-3 py-2 text-sm" />
            <button @click="generateToken"
              class="bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded-lg text-sm whitespace-nowrap">
              Generate
            </button>
          </div>
          <div v-if="generatedToken"
               class="mt-2 p-3 bg-green-950 border border-green-700 rounded-lg flex items-center gap-3">
            <span class="font-mono font-bold text-green-300 text-lg tracking-widest">
              {{ generatedToken }}
            </span>
            <button @click="copy(generatedToken)"
              class="text-xs text-green-400 border border-green-700 px-2 py-0.5 rounded">
              Copy
            </button>
          </div>
        </section>

        <!-- Tokens list -->
        <section>
          <h2 class="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">
            All Tokens
          </h2>
          <div class="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
            <table class="w-full text-sm">
              <thead class="bg-gray-800 text-gray-400 text-xs uppercase">
                <tr>
                  <th class="px-4 py-2 text-left">Token</th>
                  <th class="px-4 py-2 text-left">Label</th>
                  <th class="px-4 py-2 text-left">Expires</th>
                  <th class="px-4 py-2 text-left">Uses</th>
                  <th class="px-4 py-2 text-left">Status</th>
                  <th class="px-4 py-2 text-left">Action</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="t in data.tokens" :key="t.id"
                    class="border-t border-gray-800">
                  <td class="px-4 py-2 font-mono text-xs text-blue-300">{{ t.id }}</td>
                  <td class="px-4 py-2 text-gray-300">{{ t.label }}</td>
                  <td class="px-4 py-2 text-gray-400 text-xs">{{ formatTs(t.expires_at) }}</td>
                  <td class="px-4 py-2 text-gray-400 text-xs">{{ t.session_count }}</td>
                  <td class="px-4 py-2">
                    <span v-if="t.revoked" class="text-xs px-2 py-0.5 rounded bg-gray-800 text-gray-500">
                      Revoked
                    </span>
                    <span v-else-if="isExpired(t)" class="text-xs px-2 py-0.5 rounded bg-gray-800 text-gray-500">
                      Expired
                    </span>
                    <span v-else class="text-xs px-2 py-0.5 rounded bg-green-900 text-green-300">
                      Active
                    </span>
                  </td>
                  <td class="px-4 py-2">
                    <button v-if="!t.revoked" @click="revokeToken(t.id)"
                      class="text-xs text-red-400 hover:text-red-300 border border-red-800
                             hover:border-red-600 px-2 py-0.5 rounded">
                      Revoke
                    </button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>

        <!-- Cluster reset -->
        <section>
          <h2 class="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">
            Cluster
          </h2>
          <button @click="clusterReset"
            class="border border-red-800 hover:border-red-600 text-red-400 hover:text-red-300
                   px-4 py-2 rounded-lg text-sm transition-colors">
            🔄 Force Cluster Reset
          </button>
        </section>

      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted, onUnmounted } from 'vue'
import axios from 'axios'

const authed   = ref(false)
const password = ref('')
const data     = reactive({
  activeSessions:      [],
  blockedAttempts:     [],
  failedAdminAttempts: [],
  tokens:              []
})
const newLabel       = ref('')
const newExpiry      = ref(7)
const generatedToken = ref('')

// ── Reactive ticker — forces countdown to re-render every second ──────────────
const nowMs      = ref(Date.now())
let tickerTimer  = null
let sessionTimer = null

function startTicker() {
  if (tickerTimer) return
  tickerTimer = setInterval(() => { nowMs.value = Date.now() }, 1000)
}

function stopTicker() {
  if (tickerTimer) { clearInterval(tickerTimer); tickerTimer = null }
}

// ── Session management ────────────────────────────────────────────────────────
const JWT_KEY    = 'adminJwt'
const EXPIRY_KEY = 'adminJwtExpiry'

const sessionTimeRemaining = computed(() => {
  const expiry    = parseInt(localStorage.getItem(EXPIRY_KEY) || '0')
  const remaining = Math.max(0, Math.floor((expiry - nowMs.value) / 1000))
  const h = Math.floor(remaining / 3600)
  const m = Math.floor((remaining % 3600) / 60)
  const s = remaining % 60
  if (h > 0) return `${h}h ${m}m`
  if (m > 0) return `${m}m ${s.toString().padStart(2, '0')}s`
  return `${s}s`
})

const sessionIndicatorClass = computed(() => {
  const expiry    = parseInt(localStorage.getItem(EXPIRY_KEY) || '0')
  const remaining = (expiry - nowMs.value) / 1000
  if (remaining < 300) return 'text-red-400'
  if (remaining < 600) return 'text-yellow-400'
  return 'text-gray-400'
})

function restoreSession() {
  const token  = localStorage.getItem(JWT_KEY)
  const expiry = parseInt(localStorage.getItem(EXPIRY_KEY) || '0')

  if (token && Date.now() < expiry) {
    axios.defaults.headers.common['Authorization'] = `Bearer ${token}`
    fetchDashboard()

    // Auto-logout when session expires
    const remaining = expiry - Date.now()
    sessionTimer = setTimeout(() => {
      logout()
    }, remaining)
  }
}

function saveSession(token, expiresIn) {
  const expiry = Date.now() + expiresIn * 1000
  localStorage.setItem(JWT_KEY, token)
  localStorage.setItem(EXPIRY_KEY, expiry.toString())

  // Auto-logout timer
  if (sessionTimer) clearTimeout(sessionTimer)
  sessionTimer = setTimeout(() => logout(), expiresIn * 1000)
}

function logout() {
  localStorage.removeItem(JWT_KEY)
  localStorage.removeItem(EXPIRY_KEY)
  delete axios.defaults.headers.common['Authorization']
  authed.value = false
  password.value = ''
  if (sessionTimer) clearTimeout(sessionTimer)
}

// ── Login ─────────────────────────────────────────────────────────────────────
async function login() {
  if (!password.value.trim()) return
  try {
    const res = await axios.post('/api/admin/auth', { password: password.value })
    saveSession(res.data.token, res.data.expiresIn)
    axios.defaults.headers.common['Authorization'] = `Bearer ${res.data.token}`
    await fetchDashboard()
  } catch {
    alert('Invalid admin password')
  }
}

async function fetchDashboard() {
  try {
    const res = await axios.get('/api/admin/dashboard')
    Object.assign(data, res.data)
    authed.value = true
  } catch (err) {
    if (err.response?.status === 401) {
      logout()
    }
  }
}

// ── Token management ──────────────────────────────────────────────────────────
async function generateToken() {
  if (!newLabel.value.trim()) return
  const res = await axios.post('/api/token/generate', {
    label: newLabel.value,
    expiryDays: parseInt(newExpiry.value)
  })
  generatedToken.value = res.data.token
  newLabel.value = ''
  await fetchDashboard()
}

async function revokeToken(tokenId) {
  if (!confirm(`Revoke token ${tokenId}?`)) return
  await axios.delete('/api/token/revoke', { data: { tokenId } })
  await fetchDashboard()
}

async function releaseSession(sessionId) {
  await axios.post('/api/admin/session/release', { sessionId })
  await fetchDashboard()
}

async function clusterReset() {
  if (!confirm('Force reset cluster to safe state?')) return
  await axios.post('/api/admin/cluster/reset')
  alert('Reset triggered')
}

function copy(text) { navigator.clipboard.writeText(text) }

function formatTs(ts) {
  return ts ? new Date(ts * 1000).toLocaleString() : '—'
}

function isExpired(token) {
  return token.expires_at < Date.now() / 1000
}

function parseDetail(detail) {
  try { return JSON.parse(detail) } catch { return {} }
}

function reasonClass(reason) {
  return {
    'bg-red-900 text-red-300':       reason === 'session_active',
    'bg-yellow-900 text-yellow-300': reason === 'token_expired',
    'bg-gray-800 text-gray-400':     !reason || reason === 'token_invalid'
  }
}

onMounted(() => { restoreSession(); startTicker() })
onUnmounted(() => { stopTicker(); if (sessionTimer) clearTimeout(sessionTimer) })
</script>
