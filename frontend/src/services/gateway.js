// Mock of the SafePrompt gateway pipeline: detect, apply policy, mask, call AI.
// In the real system this all happens on the backend. It lives here only so the
// demo works without a server. Detection is pattern-based and will miss things.

const RULES = [
  { type: 'EMAIL', patterns: [/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g] },
  { type: 'API_KEY', patterns: [/\b(?:sk|pk|api|key|token)[-_][A-Za-z0-9_-]{12,}\b/gi] },
  { type: 'CARD', patterns: [/\b(?:\d{4}[ -]?){3}\d{4}\b/g] },
  { type: 'AADHAAR', patterns: [/\b\d{4}\s\d{4}\s\d{4}\b/g] },
  {
    type: 'SALARY',
    patterns: [/(?:₹\s?|\bRs\.?\s?|\bINR\s?)\d[\d,]*(?:\.\d+)?(?:\s?(?:lakhs?|crore|k))?/gi],
  },
  {
    type: 'FILE_PATH',
    patterns: [/(?:[A-Za-z]:\\|\.{0,2}\/)?(?:[\w.-]+[\\/])+[\w.-]+\.(?:jsx?|tsx?|py|java|go|rb|env|json|ya?ml|sql)\b/g],
  },
  { type: 'CUSTOMER_ID', patterns: [/\b(?:CUST|CID|EMP)[-_]?\d{3,}\b/g] },
  {
    // A title or label followed by a name, e.g. "Customer Rahul Sharma".
    // Only the name (the trailing group) is masked.
    type: 'PERSON',
    trailingGroup: true,
    patterns: [/\b(?:Customer|Employee|Client|Mr\.?|Ms\.?|Mrs\.?|Dr\.?)\s+([A-Z][a-z]+(?:\s[A-Z][a-z]+)+)/g],
  },
  {
    type: 'PERSON',
    patterns: [/\b(?:Rahul|Priya|Amit|Anita|Vikram|Sneha|Arjun|Neha|Rohan|Asha)\s[A-Z][a-z]+\b/g],
  },
]

const THREATS = [
  {
    type: 'PROMPT_INJECTION',
    policy: 'Block prompt injection',
    reason: 'The prompt tries to override instructions or reveal the system prompt.',
    patterns: [
      /ignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|prompts|rules)/i,
      /disregard\s+(?:the\s+)?(?:system|previous)\s+(?:prompt|instructions)/i,
      /you\s+are\s+now\s+(?:dan|in\s+developer\s+mode)/i,
      /(?:reveal|show|print|repeat|leak)\b.{0,40}\b(?:system|hidden)\s+(?:prompt|instructions)/i,
    ],
  },
  {
    type: 'POLICY_BYPASS',
    policy: 'Block policy bypass',
    reason: 'The prompt tries to get around enterprise safety filters.',
    patterns: [
      /(?:bypass|disable|turn\s+off|circumvent|jailbreak)\b.{0,40}\b(?:filters?|polic(?:y|ies)|safety|guardrails?|restrictions?)/i,
      /pretend\s+(?:there\s+are\s+)?no\s+(?:rules|restrictions)/i,
    ],
  },
  {
    type: 'SYSTEM_DATA_EXTRACTION',
    policy: 'Block system data extraction',
    reason: 'The prompt asks for internal architecture or configuration data.',
    patterns: [
      /(?:internal|backend)\s+(?:architecture|configuration|config)/i,
      /(?:list|show|dump|print)\b.{0,30}\b(?:environment\s+variables|env\s+vars|database\s+credentials|config\s+files?)/i,
    ],
  },
]

const INDIVIDUAL_COMPENSATION =
  /\b(?:what(?:'s|’s| is)|show|tell me|give me|find|look up|fetch)\b.{0,40}\b(?:salary|compensation|ctc)\b/i
const AGGREGATE = /\b(?:average|avg|median|trends?|range|distribution|by\s+department)\b/i

const TOKEN_PATTERN = /\[[A-Z_]+_\d+\]/g

export function detect(text) {
  const hits = []
  RULES.forEach((rule, priority) => {
    rule.patterns.forEach((pattern) => {
      for (const match of text.matchAll(pattern)) {
        const value = rule.trailingGroup ? match[1] : match[0]
        const start = match.index + match[0].length - value.length
        hits.push({ type: rule.type, start, end: start + value.length, value, priority })
      }
    })
  })
  hits.sort(
    (a, b) => a.start - b.start || a.priority - b.priority || b.end - b.start - (a.end - a.start),
  )
  const kept = []
  let cursor = 0
  for (const hit of hits) {
    if (hit.start >= cursor) {
      kept.push(hit)
      cursor = hit.end
    }
  }
  return kept
}

export function mask(text, hits) {
  const counters = {}
  const tokenByValue = {}
  const vault = {}
  const findings = []
  let sanitized = ''
  let cursor = 0
  for (const hit of hits) {
    const key = `${hit.type}:${hit.value.toLowerCase()}`
    let token = tokenByValue[key]
    if (!token) {
      counters[hit.type] = (counters[hit.type] || 0) + 1
      token = `[${hit.type}_${counters[hit.type]}]`
      tokenByValue[key] = token
      vault[token] = hit.value
      findings.push({ token, type: hit.type })
    }
    sanitized += text.slice(cursor, hit.start) + token
    cursor = hit.end
  }
  sanitized += text.slice(cursor)
  return { sanitized, vault, findings }
}

// Unknown or altered tokens are left as they are, never guessed.
export function restore(text, vault) {
  return text.replace(TOKEN_PATTERN, (token) => vault[token] ?? token)
}

function checkThreats(text) {
  return THREATS.find((threat) => threat.patterns.some((pattern) => pattern.test(text)))
}

function checkRbac(role, text) {
  if (role !== 'worker') return null
  if (INDIVIDUAL_COMPENSATION.test(text) && !AGGREGATE.test(text)) {
    return {
      policy: 'Role policy: individual compensation',
      reason: 'Workers cannot request individual compensation records.',
    }
  }
  return null
}

export function runGateway({ role, text }) {
  const { sanitized, vault, findings } = mask(text, detect(text))
  const threat = checkThreats(text)
  const rbac = threat ? null : checkRbac(role, text)
  const blocker = threat || rbac
  if (blocker) {
    return {
      status: 'blocked',
      policy: blocker.policy,
      blockReason: blocker.reason,
      sanitized,
      vault,
      findings,
    }
  }
  return {
    status: 'allowed',
    policy: findings.length ? 'Mask and forward' : 'Allow',
    blockReason: '',
    sanitized,
    vault,
    findings,
  }
}

// Stand-in for the external AI service. It only ever receives sanitized text.
export function buildReply(sanitized, findings) {
  const tokens = findings.map((finding) => finding.token)
  const lead = tokens.length
    ? `I can help with that. I’ll refer to ${tokens.join(', ')} exactly as written so the details stay protected.`
    : 'I can help with that.'
  const words = sanitized.split(/\s+/)
  const excerpt = words.length > 40 ? `${words.slice(0, 40).join(' ')}…` : sanitized
  return `${lead}\n\nHere is a first draft based on your request:\n\n“${excerpt}”\n\nTell me which tone or format you want next.`
}

export function callExternalAi(sanitized, findings) {
  return new Promise((resolve) => {
    setTimeout(() => resolve(buildReply(sanitized, findings)), 700)
  })
}
