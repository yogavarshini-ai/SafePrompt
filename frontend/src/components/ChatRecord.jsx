import { useState } from 'react'
import RedactedText from './RedactedText'
import { FlagBadge, RoleBadge, StatusBadge } from './Badges'
import { formatTime } from '../lib/format'

// One entry in a chat ledger. Admin records carry `promptOriginal`, so the
// unmasked view and the toggle only appear for them.
export default function ChatRecord({ record, showAuthor = false, onFlag }) {
  const isAdminView = record.promptOriginal !== undefined
  const [showOriginal, setShowOriginal] = useState(true)
  const unmasked = isAdminView && showOriginal

  const rail =
    record.status === 'blocked'
      ? 'border-l-rose-500'
      : record.findings.length > 0
        ? 'border-l-[#0b1220]'
        : 'border-l-slate-300'

  return (
    <article className={`rounded-md border border-slate-200 border-l-4 bg-white p-4 ${rail}`}>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        {showAuthor ? (
          <>
            <span className="text-sm font-semibold text-slate-900">{record.userName}</span>
            <RoleBadge role={record.role} />
          </>
        ) : null}
        <StatusBadge status={record.status} />
        {record.flagged ? <FlagBadge /> : null}
        <time className="text-xs text-slate-500" dateTime={record.ts}>
          {formatTime(record.ts)}
        </time>
        <div className="ml-auto flex items-center gap-2">
          {isAdminView ? (
            <button
              type="button"
              onClick={() => setShowOriginal((value) => !value)}
              className="rounded-md border border-slate-300 px-2.5 py-1 text-xs font-medium text-slate-700 hover:bg-slate-50"
            >
              {showOriginal ? 'Show masked view' : 'Show original'}
            </button>
          ) : null}
          {onFlag ? (
            <button
              type="button"
              onClick={() => onFlag(record.id)}
              className="rounded-md border border-slate-300 px-2.5 py-1 text-xs font-medium text-slate-700 hover:bg-slate-50"
            >
              {record.flagged ? 'Clear flag' : 'Flag for review'}
            </button>
          ) : null}
        </div>
      </div>

      <p className="mt-3 text-xs font-medium text-slate-500">
        {unmasked ? 'Prompt as typed' : 'Prompt as sent to the AI'}
      </p>
      <p className="mt-1 text-sm leading-6 text-slate-900">
        {unmasked ? (
          <span className="whitespace-pre-wrap break-words">{record.promptOriginal}</span>
        ) : (
          <RedactedText text={record.promptSent} />
        )}
      </p>

      {record.status === 'blocked' ? (
        <p className="mt-3 rounded-md bg-rose-50 px-3 py-2 text-sm text-rose-900">
          <span className="font-medium">{record.policy}.</span> {record.blockReason} Nothing was sent to the AI
          service.
        </p>
      ) : null}

      {'response' in record && record.response ? (
        <>
          <p className="mt-3 text-xs font-medium text-slate-500">AI reply</p>
          <p className="mt-1 text-sm leading-6 text-slate-800">
            {unmasked ? (
              <span className="whitespace-pre-wrap break-words">{record.responseRestored}</span>
            ) : (
              <RedactedText text={record.response} />
            )}
          </p>
        </>
      ) : null}

      {record.findings.length > 0 ? (
        <ul className="mt-3 flex flex-wrap gap-2">
          {record.findings.map((finding) => (
            <li
              key={finding.token}
              className="rounded-md bg-slate-100 px-2 py-1 font-mono text-xs text-slate-700"
            >
              {finding.token}
              {unmasked && finding.original ? ` = ${finding.original}` : ''}
            </li>
          ))}
        </ul>
      ) : null}
    </article>
  )
}
