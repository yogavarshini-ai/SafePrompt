import { useState } from 'react'
import PageHeader from '../components/PageHeader'
import { RoleBadge } from '../components/Badges'
import { EmptyState, ErrorMessage, Loading } from '../components/StateMessage'
import { useLoad } from '../hooks/useLoad'
import { getAuditLog } from '../services/api'
import { ACTION_LABELS } from '../config/actions'
import { formatTime, plural } from '../lib/format'

export default function AuditPage({ user }) {
  const { data, error, loading } = useLoad(() => getAuditLog(user))
  const [role, setRole] = useState('all')

  const rows = (data ?? []).filter((event) => role === 'all' || event.role === role)

  return (
    <div className="mx-auto max-w-4xl">
      <PageHeader
        title="Audit log"
        description="Every sign-in, prompt, block and admin action. Entries are append-only and never contain raw sensitive values."
      >
        <div>
          <label htmlFor="audit-role" className="sr-only">
            Filter by role
          </label>
          <select
            id="audit-role"
            value={role}
            onChange={(event) => setRole(event.target.value)}
            className="rounded-md border border-slate-300 bg-white px-3 py-2 text-sm"
          >
            <option value="all">All roles</option>
            <option value="admin">Administrators</option>
            <option value="manager">Managers</option>
            <option value="worker">Workers</option>
          </select>
        </div>
      </PageHeader>

      {loading ? <Loading /> : null}
      {error ? <ErrorMessage message={error} /> : null}
      {data ? <p className="mb-3 text-sm text-slate-600">{plural(rows.length, 'entry', 'entries')} shown</p> : null}
      {data && rows.length === 0 ? <EmptyState title="No entries for this role" /> : null}

      {rows.length > 0 ? (
        <div className="overflow-x-auto rounded-md border border-slate-200 bg-white">
          <table className="w-full min-w-[40rem] text-left text-sm">
            <thead className="border-b border-slate-200 bg-slate-50 text-xs text-slate-600">
              <tr>
                <th scope="col" className="px-4 py-3 font-medium">Time</th>
                <th scope="col" className="px-4 py-3 font-medium">Person</th>
                <th scope="col" className="px-4 py-3 font-medium">Action</th>
                <th scope="col" className="px-4 py-3 font-medium">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200">
              {rows.map((event) => (
                <tr key={event.id}>
                  <td className="whitespace-nowrap px-4 py-2.5 text-slate-600">{formatTime(event.ts)}</td>
                  <td className="px-4 py-2.5">
                    <span className="mr-2 font-medium text-slate-900">{event.userName}</span>
                    <RoleBadge role={event.role} />
                  </td>
                  <td className="px-4 py-2.5">{ACTION_LABELS[event.action] ?? event.action}</td>
                  <td className="px-4 py-2.5 text-slate-600">{event.detail || 'None'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </div>
  )
}
