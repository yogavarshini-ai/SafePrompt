import { RoleBadge } from './Badges'

export default function Layout({ routes, current, onNavigate, user, onLogout, children }) {
  return (
    <div className="flex min-h-screen flex-col md:flex-row">
      <aside className="flex shrink-0 flex-col gap-4 border-b border-slate-200 bg-white p-4 md:w-64 md:border-r md:border-b-0">
        <div className="flex items-center gap-2.5">
          <span aria-hidden="true" className="grid h-8 w-8 place-items-center rounded-lg bg-[#0b1220]">
            <span className="block h-1.5 w-4 rounded-[1px] bg-slate-100" />
          </span>
          <span className="text-lg font-semibold tracking-tight text-slate-900">SafePrompt</span>
        </div>

        <nav aria-label="Main" className="flex gap-1 overflow-x-auto md:flex-col">
          {routes.map((route) => {
            const active = route.path === current
            return (
              <button
                key={route.path}
                type="button"
                onClick={() => onNavigate(route.path)}
                aria-current={active ? 'page' : undefined}
                className={`whitespace-nowrap rounded-md px-3 py-2 text-left text-sm font-medium ${
                  active ? 'bg-[#0b1220] text-white' : 'text-slate-700 hover:bg-slate-100'
                }`}
              >
                {route.label}
              </button>
            )
          })}
        </nav>

        <div className="mt-auto flex items-center justify-between gap-3 border-t border-slate-200 pt-4 md:flex-col md:items-start">
          <div>
            <p className="text-sm font-semibold text-slate-900">{user.name}</p>
            <p className="text-xs text-slate-500">{user.title}</p>
            <div className="mt-2">
              <RoleBadge role={user.role} />
            </div>
          </div>
          <button
            type="button"
            onClick={onLogout}
            className="rounded-md border border-slate-300 px-3 py-1.5 text-sm font-medium text-slate-700 hover:bg-slate-50"
          >
            Sign out
          </button>
        </div>
      </aside>

      <main className="min-w-0 flex-1 p-4 sm:p-8">{children}</main>
    </div>
  )
}
