import { createApp }    from 'vue'
import { createPinia }  from 'pinia'
import { createRouter, createWebHistory } from 'vue-router'
import App              from './App.vue'
import TokenGate        from './views/TokenGate.vue'
import DemoView         from './views/DemoView.vue'
import AdminView        from './views/AdminView.vue'
import './style.css'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/',      component: TokenGate  },
    { path: '/demo',  component: DemoView,  meta: { requiresAuth: true } },
    { path: '/admin', component: AdminView  }
  ]
})

// ── Auth guard — checks JWT exists AND is not expired ─────────────────────────
router.beforeEach((to) => {
  if (!to.meta.requiresAuth) return true

  const jwt       = localStorage.getItem('jwt')
  const expiresAt = parseInt(localStorage.getItem('expiresAt') || '0')

  // No token or token expired — clear storage and redirect to gate
  if (!jwt || Date.now() / 1000 > expiresAt) {
    localStorage.removeItem('jwt')
    localStorage.removeItem('sessionId')
    localStorage.removeItem('expiresAt')
    localStorage.removeItem('label')
    return '/'
  }
})

const app = createApp(App)
app.use(createPinia())
app.use(router)
app.mount('#app')
