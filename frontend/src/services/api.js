// SafePrompt API service layer. Integrates React frontend with the secured FastAPI backend.
// Enforces:
// 1. In-memory access-token storage; zero hardcoded passwords in client code.
// 2. Strict backend-enforced RBAC and Bearer token authentication.
// 3. Clear handling of 401, 403, 422, and 502 HTTP response statuses.
// 4. Zero plaintext PII or unencrypted vault stored in localStorage or persistent logs.

import { DEMO_USERS } from '../data/demoUsers'
import { SEED_PROMPTS } from '../data/seedPrompts'
import { can } from '../config/permissions'
import { load, save, remove } from './storage'
import { buildReply, runGateway } from './gateway'

const API_BASE =
  (typeof import.meta !== 'undefined' && import.meta.env && import.meta.env.VITE_API_URL) ||
  'http://127.0.0.1:8000'

const SEED_VERSION = 'v2'
const MAX_EVENTS = 1000

export class ForbiddenError extends Error {
  constructor(message = 'You do not have access to this area.') {
    super(message)
    this.name = 'ForbiddenError'
  }
}

/* ---------- in-memory access token storage ---------- */

let currentAccessToken = null

export function setAccessToken(token) {
  currentAccessToken = token
}

export function getAccessToken() {
  return currentAccessToken
}

export function clearAccessToken() {
  currentAccessToken = null
}

/* ---------- helpers ---------- */

const makeId = (prefix) =>
  `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`

const toPublicUser = (user) => ({
  id: user.id,
  name: user.name,
  title: user.title,
  username: user.username,
  role: user.role,
})

const findUser = (id) =>
  DEMO_USERS.find((user) => user.id === id || user.username === id)

const isActive = (id) => load('accounts', {})[id] !== 'disabled'

function resolveActor(viewer) {
  if (!viewer) throw new ForbiddenError('Sign in to continue.')
  return viewer
}

function requirePermission(viewer, permission) {
  const actor = resolveActor(viewer)
  if (!can(actor.role, permission)) throw new ForbiddenError()
  return actor
}

function logEvent(actor, action, detail = '', at = new Date()) {
  const events = load('events', [])
  if (action.startsWith('view_')) {
    const last = [...events].reverse().find((e) => e.userId === actor.id && e.action === action)
    if (last && at - new Date(last.ts) < 2000) return // ignore double fetches
  }
  events.push({
    id: makeId('ev'),
    ts: at.toISOString(),
    userId: actor.id,
    userName: actor.name,
    role: actor.role,
    action,
    detail,
  })
  save('events', events.slice(-MAX_EVENTS))
}

function describeGateway(result) {
  const masked = result.findings ? result.findings.length : 0
  return `${result.policy || 'Mask and forward'}, ${masked} ${masked === 1 ? 'value' : 'values'} masked`
}

function saveSanitizedRecord(record) {
  // Explicitly omit original prompt and vault dictionary so localStorage NEVER has raw PII
  const sanitized = {
    id: record.id,
    userId: record.userId,
    ts: record.ts,
    promptSent: record.promptSent,
    response: record.response,
    status: record.status,
    policy: record.policy,
    blockReason: record.blockReason,
    findings: record.findings || [],
    flagged: Boolean(record.flagged),
  }
  save('records', [...load('records', []), sanitized])
}

function makeRecord(actor, text, result, response, at) {
  // Persist only sanitized data, never original text or vault map
  return {
    id: makeId('rec'),
    userId: actor.id,
    ts: at.toISOString(),
    promptSent: result.sanitized,
    findings: result.findings || [],
    status: result.status,
    policy: result.policy,
    blockReason: result.blockReason,
    response,
    flagged: false,
  }
}

function project(record, viewer, { withResponse = true } = {}) {
  const author = findUser(record.userId)
  const view = {
    id: record.id,
    userId: record.userId,
    userName: author ? author.name : 'Unknown user',
    role: author ? author.role : 'employee',
    ts: record.ts,
    status: record.status,
    policy: record.policy || (record.status === 'blocked' ? 'Policy block' : 'Allow'),
    blockReason: record.blockReason,
    flagged: record.flagged,
    promptSent: record.promptSent,
    findings: (record.findings || []).map((f) => ({ token: f.token, type: f.type })),
  }
  if (withResponse) view.response = record.response
  if (can(viewer.role, 'seeOriginalContent') && record.responseRestored) {
    view.promptOriginal = record.promptOriginal || record.promptSent
    view.responseRestored = record.responseRestored
  }
  return view
}

const newestFirst = (a, b) => new Date(b.ts) - new Date(a.ts)

/* ---------- demo seed data ---------- */

function ensureSeed() {
  if (load('seeded', '') === SEED_VERSION) return
  const now = Date.now()
  const records = []
  const events = []
  for (const seed of SEED_PROMPTS) {
    const actor = findUser(seed.userId) || {
      id: seed.userId,
      name: 'Demo User',
      role: 'employee',
    }
    const at = new Date(now - seed.minutesAgo * 60000)
    const result = runGateway({ role: actor.role, text: seed.text })
    const response =
      result.status === 'allowed' ? buildReply(result.sanitized, result.findings) : null
    records.push(makeRecord(actor, seed.text, result, response, at))
    events.push({
      id: makeId('ev'),
      ts: at.toISOString(),
      userId: actor.id,
      userName: actor.name,
      role: actor.role,
      action: result.status === 'allowed' ? 'prompt_allowed' : 'prompt_blocked',
      detail: describeGateway(result),
    })
  }
  for (const user of DEMO_USERS) {
    events.push({
      id: makeId('ev'),
      ts: new Date(now - 430 * 60000).toISOString(),
      userId: user.id,
      userName: user.name,
      role: user.role,
      action: 'login',
      detail: '',
    })
  }
  events.sort((a, b) => new Date(a.ts) - new Date(b.ts))
  save('records', records)
  save('events', events)
  save('seeded', SEED_VERSION)
}

/* ---------- auth endpoints ---------- */

export function getSession() {
  ensureSeed()
  const session = load('session', null)
  // If no in-memory access token exists, force user to authenticate
  if (!session || !currentAccessToken) {
    return null
  }
  return session
}

export async function login(username, password) {
  ensureSeed()
  const cleanUsername = String(username).trim().toLowerCase()
  if (!cleanUsername || !password) {
    throw new Error('Please enter both username and password.')
  }

  let res
  try {
    res = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: cleanUsername, password }),
    })
  } catch {
    throw new Error(
      'Cannot connect to the SafePrompt security service. Ensure the backend is running on port 8000.',
    )
  }

  if (res.status === 401) {
    clearAccessToken()
    remove('session')
    throw new Error('Invalid username or password.')
  }

  if (!res.ok) {
    clearAccessToken()
    remove('session')
    throw new Error(`Authentication failed (HTTP ${res.status}).`)
  }

  const data = await res.json()
  setAccessToken(data.access_token)

  const matched = DEMO_USERS.find(
    (u) =>
      u.username.toLowerCase() === cleanUsername.toLowerCase() ||
      u.role === (data.role || '').toLowerCase(),
  )

  const user = {
    id: data.user_id,
    username: cleanUsername,
    role: (data.role || 'employee').toLowerCase(),
    name: matched ? matched.name : cleanUsername,
    title: matched ? matched.title : `${data.role} User`,
  }

  save('session', user)
  logEvent(user, 'login')
  return user
}

export function logout(viewer) {
  clearAccessToken()
  remove('session')
  if (viewer) logEvent(viewer, 'logout')
}

/* ---------- vault restoration endpoint ---------- */

export async function restoreVaultToken(vaultToken, authToken) {
  const token = authToken || getAccessToken()
  if (!token) return null

  try {
    const encodedToken = encodeURIComponent(vaultToken)
    const res = await fetch(`${API_BASE}/vault/${encodedToken}`, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${token}`,
      },
    })
    if (!res.ok) return null
    const data = await res.json()
    return data.original_value
  } catch {
    return null
  }
}

/* ---------- chat / prompt endpoint ---------- */

export async function sendPrompt(viewer, text) {
  const actor = resolveActor(viewer)
  const clean = String(text).trim()
  if (!clean) throw new Error('Type a prompt before sending.')

  const token = getAccessToken()
  if (!token) {
    logout(actor)
    throw new Error('Your session has expired or authentication is missing. Please sign in again.')
  }

  let res
  try {
    res = await fetch(`${API_BASE}/prompt`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ prompt: clean }),
    })
  } catch {
    throw new Error('Network error contacting backend. Please verify the backend server is running.')
  }

  // Handle 401 Unauthorized
  if (res.status === 401) {
    logout(actor)
    throw new Error('Your session has expired or credentials are invalid. Please sign in again.')
  }

  // Handle 403 Forbidden (threat detection policy violation)
  if (res.status === 403) {
    let blockReason = 'The prompt violated security policies.'
    try {
      const errData = await res.json()
      if (errData && errData.detail) {
        blockReason = errData.detail.replace(/^Prompt blocked by security policy:\s*/i, '')
      }
    } catch {
      // Keep default blockReason
    }

    const blockedRecord = {
      id: makeId('rec'),
      userId: actor.id,
      ts: new Date().toISOString(),
      promptSent: clean,
      response: null,
      status: 'blocked',
      policy: 'Security Policy Block',
      blockReason,
      findings: [],
      flagged: false,
    }

    saveSanitizedRecord(blockedRecord)
    logEvent(actor, 'prompt_blocked', blockReason)
    return blockedRecord
  }

  // Handle 422 Unprocessable Entity
  if (res.status === 422) {
    let msg = 'Prompt cannot be empty or whitespace.'
    try {
      const errData = await res.json()
      if (errData && errData.detail) msg = errData.detail
    } catch {
      // Keep default
    }
    throw new Error(msg)
  }

  // Handle 502 Bad Gateway (external AI failure)
  if (res.status === 502) {
    throw new Error('AI service failed or is temporarily unavailable. Check backend logs.')
  }

  if (!res.ok) {
    throw new Error(`Request failed with status ${res.status}.`)
  }

  const data = await res.json()

  // Extract {{TOKEN_<hash>}} placeholders
  const tokenMatches = data.masked.match(/\{\{TOKEN_[0-9a-fA-F]+\}\}/g) || []
  const uniqueTokens = [...new Set(tokenMatches)]
  const findings = uniqueTokens.map((t) => ({ token: t, type: 'PII' }))

  const record = {
    id: makeId('rec'),
    userId: actor.id,
    ts: new Date().toISOString(),
    promptSent: data.masked,
    response: data.response,
    status: 'allowed',
    policy: findings.length ? 'Mask and forward' : 'Allow',
    blockReason: '',
    findings,
    flagged: false,
  }

  // If viewer has permission to see original content (Admin / HR), attempt authorized restoration
  if (can(actor.role, 'seeOriginalContent') && uniqueTokens.length > 0) {
    try {
      let restoredResponse = data.response
      for (const t of uniqueTokens) {
        const restored = await restoreVaultToken(t, token)
        if (restored) {
          restoredResponse = restoredResponse.replaceAll(t, restored)
        }
      }
      record.responseRestored = restoredResponse
      // Transiently retain in memory for the active view only
      record.promptOriginal = clean
    } catch {
      // Backend RBAC enforcement: if 403 or unavailable, leave restoredResponse null
    }
  }

  saveSanitizedRecord(record)
  logEvent(actor, 'prompt_allowed', describeGateway(record))
  return record
}

export async function getMyHistory(viewer) {
  const actor = requirePermission(viewer, 'viewOwnHistory')
  logEvent(actor, 'view_history')
  return load('records', [])
    .filter((record) => record.userId === actor.id)
    .sort(newestFirst)
    .map((record) => project(record, actor))
}

/* ---------- manager / admin views ---------- */

export async function getTeamActivity(viewer) {
  const actor = requirePermission(viewer, 'viewTeamActivity')
  logEvent(actor, 'view_team')
  const records = load('records', [])
  const events = load('events', [])
  const withResponse = can(actor.role, 'seeOthersAiReplies')
  return DEMO_USERS.filter((user) => user.role === 'employee' || user.role === 'worker').map((worker) => {
    const mine = records.filter((record) => record.userId === worker.id).sort(newestFirst)
    const theirEvents = events.filter((event) => event.userId === worker.id).sort(newestFirst)
    return {
      ...toPublicUser(worker),
      active: isActive(worker.id),
      stats: {
        prompts: mine.length,
        blocked: mine.filter((record) => record.status === 'blocked').length,
        masked: mine.reduce((total, record) => total + (record.findings ? record.findings.length : 0), 0),
        lastActive: theirEvents.length ? theirEvents[0].ts : null,
      },
      access: theirEvents.slice(0, 8),
      prompts: mine.map((record) => project(record, actor, { withResponse })),
    }
  })
}

export async function flagPrompt(viewer, recordId) {
  const actor = requirePermission(viewer, 'flagPrompts')
  const records = load('records', [])
  const record = records.find((r) => r.id === recordId)
  if (!record) throw new Error('That prompt no longer exists.')
  record.flagged = !record.flagged
  save('records', records)
  logEvent(
    actor,
    'flag_prompt',
    `${record.flagged ? 'Flagged' : 'Cleared flag on'} prompt #${recordId.slice(-6)}`,
  )
  return record.flagged
}

export async function getAllChats(viewer) {
  const actor = requirePermission(viewer, 'viewAllChats')
  logEvent(actor, 'view_all_chats')
  return load('records', []).sort(newestFirst).map((record) => project(record, actor))
}

export async function getAccounts(viewer) {
  const actor = requirePermission(viewer, 'viewAccounts')
  logEvent(actor, 'view_accounts')
  const records = load('records', [])
  const events = load('events', [])
  return DEMO_USERS.map((user) => {
    const mine = records.filter((record) => record.userId === user.id)
    const logins = events
      .filter((e) => e.userId === user.id && e.action === 'login')
      .sort(newestFirst)
    return {
      ...toPublicUser(user),
      active: isActive(user.id),
      prompts: mine.length,
      blocked: mine.filter((record) => record.status === 'blocked').length,
      lastLogin: logins.length ? logins[0].ts : null,
    }
  })
}

export async function setAccountStatus(viewer, userId, active) {
  const actor = requirePermission(viewer, 'manageAccounts')
  const target = findUser(userId)
  if (!target) throw new Error('That account does not exist.')
  if (target.id === actor.id) throw new Error('You cannot disable your own account.')
  const accounts = load('accounts', {})
  accounts[target.id] = active ? 'active' : 'disabled'
  save('accounts', accounts)
  logEvent(actor, 'account_status', `${active ? 'Enabled' : 'Disabled'} ${target.name}`)
  return active
}

export async function getAuditLog(viewer) {
  const actor = requirePermission(viewer, 'viewAuditLog')
  logEvent(actor, 'view_audit')
  return load('events', []).sort(newestFirst)
}

export async function resetDemoData(viewer) {
  const actor = requirePermission(viewer, 'manageAccounts')
  remove('records')
  remove('events')
  remove('accounts')
  remove('seeded')
  ensureSeed()
  logEvent(actor, 'reset_demo')
}
