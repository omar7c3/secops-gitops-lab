// =============================================================================
// Routes — /watchdog (admin only)
// =============================================================================

'use strict'

const express = require('express')
const { getWatchdogStatus } = require('../watchdog')
const router  = express.Router()

router.get('/status', (req, res) => {
  return res.json(getWatchdogStatus())
})

module.exports = router
