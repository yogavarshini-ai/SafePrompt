import { useMemo, useState } from 'react'
import PageHeader from '../components/PageHeader'
import ChatRecord from '../components/ChatRecord'
import { EmptyState, ErrorMessage, Loading } from '../components/StateMessage'
import { useLoad } from '../hooks/useLoad'
import { flagPrompt, getAllChats } from '../services/api'
import { plural } from '../lib/format'

const selectClass = 'rounded-md border border-slate-300 bg-white px-3 py-2 text-sm'

export default function AllChatsPage({ user }) {
  const { data, error, loading, setData } = useLoad(() => getAllChats(user))
  const [author, setAuthor] = useState('all')
  const [filter, setFilter] = useState('all')
  const [query, setQuery] = useState('')
  const [actionError, setActionError] = useState('')

  const authors = useMemo(() => {
    const seen = new Map()
    ;(data ?? []).forEach((record) => seen.set(record.userId, record.userName))
    return [...seen.entries()]
  }, [data])

  const visible = (data ?? []).filter((record) => {
    if (author !== 'all' && record.userId !== author) return false
    if (filter === 'blocked' && record.status !== 'blocked') return false
    if (filter === 'flagged' && !record.flagged) return false
    if (filter === 'masked' && record.findings.length === 0) return false
    const text = query.trim().toLowerCase()
    if (text && !`${record.promptOriginal} ${record.responseRestored ?? ''}`.toLowerCase().includes(text)) {
      return false
    }
    return true
  })

  async function handleFlag(recordId) {
    setActionError('')
    try {
      const flagged = await flagPrompt(user, recordId)
      setData((current) => current.map((record) => (record.id === recordId ? { ...record, flagged } : record)))
    } catch (err) {
      setActionError(err.message)
    }
  }

  return (
    <div className="mx-auto max-w-4xl">
      <PageHeader
        title="All chats"
        description="The complete history for every account, unmasked. Use the toggle on an entry to see what the AI service received."
      />

      <div className="mb-5 flex flex-wrap gap-3">
        <label className="sr-only" htmlFor="filter-author">
          Filter by person
        </label>
        <select id="filter-author" value={author} onChange={(e) => setAuthor(e.target.value)} className={selectClass}>
          <option value="all">Everyone</option>
          {authors.map(([id, name]) => (
            <option key={id} value={id}>
              {name}
            </option>
          ))}
        </select>
        <label className="sr-only" htmlFor="filter-status">
          Filter by outcome
        </label>
        <select id="filter-status" value={filter} onChange={(e) => setFilter(e.target.value)} className={selectClass}>
          <option value="all">All outcomes</option>
          <option value="masked">With masked values</option>
          <option value="blocked">Blocked</option>
          <option value="flagged">Flagged for review</option>
        </select>
        <label className="sr-only" htmlFor="filter-search">
          Search chats
        </label>
        <input
          id="filter-search"
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search prompts and replies"
          className={`${selectClass} min-w-56 flex-1`}
        />
      </div>

      {loading ? <Loading /> : null}
      {error ? <ErrorMessage message={error} /> : null}
      {actionError ? <ErrorMessage message={actionError} /> : null}
      {data ? <p className="mb-3 text-sm text-slate-600">{plural(visible.length, 'chat')} shown</p> : null}
      {data && visible.length === 0 ? (
        <EmptyState title="No chats match" hint="Clear a filter or change the search text." />
      ) : null}
      <div className="space-y-4">
        {visible.map((record) => (
          <ChatRecord key={record.id} record={record} showAuthor onFlag={handleFlag} />
        ))}
      </div>
    </div>
  )
}
