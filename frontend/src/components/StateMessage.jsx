export function Loading({ label = 'Loading…' }) {
  return (
    <p role="status" className="py-10 text-sm text-slate-500">
      {label}
    </p>
  )
}

export function ErrorMessage({ message }) {
  return (
    <p role="alert" className="rounded-md border border-rose-300 bg-rose-50 px-4 py-3 text-sm text-rose-900">
      {message}
    </p>
  )
}

export function EmptyState({ title, hint }) {
  return (
    <div className="rounded-md border border-dashed border-slate-300 bg-white px-6 py-10 text-center">
      <p className="text-sm font-medium text-slate-800">{title}</p>
      {hint ? <p className="mt-1 text-sm text-slate-500">{hint}</p> : null}
    </div>
  )
}
