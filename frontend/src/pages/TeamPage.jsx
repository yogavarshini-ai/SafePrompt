import { useState } from 'react'
import PageHeader from '../components/PageHeader'
import ChatRecord from '../components/ChatRecord'
import { EmptyState, ErrorMessage, Loading } from '../components/StateMessage'
import { useLoad } from '../hooks/useLoad'
import { flagPrompt, getTeamActivity } from '../services/api'
import { ACTION_LABELS } from '../config/actions'
import { can } from '../config/permissions'
import { formatTime } from '../lib/format'

function Stat({ label, value }) {
  return (
    <div className="rounded-md border border-slate-200 bg-white px-4 py-3">
      <p className="text-2xl font-semibold tabular-nums">{value}</p>
      <p className="text-xs text-slate-500">{label}</p>
    </div>
  )
}

export default function TeamPage({ user }) {
  const { data, error, loading, setData } = useLoad(() => getTeamActivity(user))
  const [selectedId, setSelectedId] = useState(null)
  const [actionError, setActionError] = useState('')
  const canFlag = can(user.role, 'flagPrompts')

  const workers = data ?? []
  const selected = workers.find((worker) => worker.id === selectedId) ?? workers[0]

  async function handleFlag(recordId) {
    setActionError('')
    try {
      const flagged = await flagPrompt(user, recordId)
      setData((current) =>
        current.map((worker) => ({
          ...worker,
          prompts: worker.prompts.map((prompt) => (prompt.id === recordId ? { ...prompt, flagged } : prompt)),
        })),
      )
    } catch (err) {
      setActionError(err.message)
    }
  }

  return (
    <div className="mx-auto max-w-5xl">
      <PageHeader
        title="Team activity"
        description="See which workers are active, what they accessed and what they typed. Prompts are shown masked, as the AI service received them. AI replies are not shown."
      />
      {loading ? <Loading /> : null}
      {error ? <ErrorMessage message={error} /> : null}
      {actionError ? <ErrorMessage message={actionError} /> : null}
      {data && workers.length === 0 ? <EmptyState title="No workers yet" /> : null}

      {selected ? (
        <div className="grid gap-6 md:grid-cols-[14rem_1fr]">
          <nav aria-label="Workers" className="flex gap-2 overflow-x-auto md:flex-col">
            {workers.map((worker) => {
              const active = worker.id === selected.id
              return (
                <button
                  key={worker.id}
                  type="button"
                  onClick={() => setSelectedId(worker.id)}
                  aria-current={active ? 'true' : undefined}
                  className={`rounded-md border px-3 py-2 text-left ${
                    active ? 'border-[#0b1220] bg-white' : 'border-slate-200 bg-white hover:bg-slate-50'
                  }`}
                >
                  <span className="block text-sm font-semibold text-slate-900">{worker.name}</span>
                  <span className="block text-xs text-slate-500">{worker.title}</span>
                </button>
              )
            })}
          </nav>

          <div className="min-w-0 space-y-8">
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              <Stat label="Prompts sent" value={selected.stats.prompts} />
              <Stat label="Blocked" value={selected.stats.blocked} />
              <Stat label="Values masked" value={selected.stats.masked} />
              <Stat label="Last active" value={selected.stats.lastActive ? formatTime(selected.stats.lastActive) : 'Never'} />
            </div>

            <section aria-labelledby="access-heading">
              <h2 id="access-heading" className="text-base font-semibold">
                What {selected.name} accessed
              </h2>
              <ul className="mt-3 divide-y divide-slate-200 rounded-md border border-slate-200 bg-white">
                {selected.access.map((event) => (
                  <li key={event.id} className="flex flex-wrap items-baseline justify-between gap-2 px-4 py-2.5 text-sm">
                    <span>
                      <span className="font-medium text-slate-900">{ACTION_LABELS[event.action] ?? event.action}</span>
                      {event.detail ? <span className="text-slate-500">, {event.detail}</span> : null}
                    </span>
                    <time className="text-xs text-slate-500" dateTime={event.ts}>
                      {formatTime(event.ts)}
                    </time>
                  </li>
                ))}
              </ul>
            </section>

            <section aria-labelledby="prompts-heading">
              <h2 id="prompts-heading" className="text-base font-semibold">
                What {selected.name} typed
              </h2>
              {selected.prompts.length === 0 ? (
                <div className="mt-3">
                  <EmptyState title="No prompts yet" />
                </div>
              ) : (
                <div className="mt-3 space-y-4">
                  {selected.prompts.map((prompt) => (
                    <ChatRecord key={prompt.id} record={prompt} onFlag={canFlag ? handleFlag : undefined} />
                  ))}
                </div>
              )}
            </section>
          </div>
        </div>
      ) : null}
    </div>
  )
}
