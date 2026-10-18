import { useState } from 'react'
import PageHeader from '../components/PageHeader'
import { RoleBadge } from '../components/Badges'
import { ErrorMessage, Loading } from '../components/StateMessage'
import { useLoad } from '../hooks/useLoad'
import { getAccounts, resetDemoData, setAccountStatus } from '../services/api'
import { formatTime } from '../lib/format'

export default function AccountsPage({ user }) {
  const { data, error, loading, setData, reload } = useLoad(() => getAccounts(user))
  const [actionError, setActionError] = useState('')

  async function toggle(account) {
    setActionError('')
    try {
      const active = await setAccountStatus(user, account.id, !account.active)
      setData((current) => current.map((item) => (item.id === account.id ? { ...item, active } : item)))
    } catch (err) {
      setActionError(err.message)
    }
  }

  async function handleReset() {
    if (!window.confirm('Reset all demo chats, activity and account statuses to their starting state?')) return
    setActionError('')
    try {
      await resetDemoData(user)
      reload()
    } catch (err) {
      setActionError(err.message)
    }
  }

  return (
    <div className="mx-auto max-w-4xl">
      <PageHeader
        title="Accounts"
        description="Everyone who can sign in. Disabling an account blocks sign-in immediately."
      >
        <button
          type="button"
          onClick={handleReset}
          className="rounded-md border border-slate-300 bg-white px-3 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50"
        >
          Reset demo data
        </button>
      </PageHeader>

      {loading ? <Loading /> : null}
      {error ? <ErrorMessage message={error} /> : null}
      {actionError ? (
        <div className="mb-4">
          <ErrorMessage message={actionError} />
        </div>
      ) : null}

      {data ? (
        <div className="overflow-x-auto rounded-md border border-slate-200 bg-white">
          <table className="w-full min-w-[40rem] text-left text-sm">
            <thead className="border-b border-slate-200 bg-slate-50 text-xs text-slate-600">
              <tr>
                <th scope="col" className="px-4 py-3 font-medium">Person</th>
                <th scope="col" className="px-4 py-3 font-medium">Role</th>
                <th scope="col" className="px-4 py-3 font-medium">Prompts</th>
                <th scope="col" className="px-4 py-3 font-medium">Blocked</th>
                <th scope="col" className="px-4 py-3 font-medium">Last sign-in</th>
                <th scope="col" className="px-4 py-3 font-medium">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200">
              {data.map((account) => (
                <tr key={account.id}>
                  <td className="px-4 py-3">
                    <p className="font-medium text-slate-900">{account.name}</p>
                    <p className="font-mono text-xs text-slate-500">{account.username}</p>
                  </td>
                  <td className="px-4 py-3">
                    <RoleBadge role={account.role} />
                  </td>
                  <td className="px-4 py-3 tabular-nums">{account.prompts}</td>
                  <td className="px-4 py-3 tabular-nums">{account.blocked}</td>
                  <td className="px-4 py-3 text-slate-600">{formatTime(account.lastLogin)}</td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-3">
                      <span className={account.active ? 'text-slate-800' : 'font-medium text-rose-800'}>
                        {account.active ? 'Active' : 'Disabled'}
                      </span>
                      {account.id !== user.id ? (
                        <button
                          type="button"
                          onClick={() => toggle(account)}
                          className="rounded-md border border-slate-300 px-2.5 py-1 text-xs font-medium text-slate-700 hover:bg-slate-50"
                        >
                          {account.active ? 'Disable' : 'Enable'}
                        </button>
                      ) : (
                        <span className="text-xs text-slate-500">You</span>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </div>
  )
}
