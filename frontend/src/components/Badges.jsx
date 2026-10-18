import { ROLE_LABELS } from '../config/permissions'

const ROLE_STYLES = {
  admin: 'bg-amber-100 text-amber-900 ring-amber-300',
  manager: 'bg-indigo-100 text-indigo-900 ring-indigo-300',
  worker: 'bg-teal-100 text-teal-900 ring-teal-300',
}

export function RoleBadge({ role }) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${ROLE_STYLES[role] ?? ROLE_STYLES.worker}`}
    >
      {ROLE_LABELS[role] ?? role}
    </span>
  )
}

export function StatusBadge({ status }) {
  const blocked = status === 'blocked'
  return (
    <span
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${
        blocked
          ? 'bg-rose-50 text-rose-800 ring-rose-300'
          : 'bg-slate-100 text-slate-700 ring-slate-300'
      }`}
    >
      {blocked ? 'Blocked' : 'Allowed'}
    </span>
  )
}

export function FlagBadge() {
  return (
    <span className="inline-flex items-center rounded-full bg-amber-50 px-2 py-0.5 text-xs font-medium text-amber-900 ring-1 ring-inset ring-amber-400">
      Flagged for review
    </span>
  )
}
