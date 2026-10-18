import { useState } from 'react'
import { useAuth } from '../auth/useAuth'
import { DEMO_USERS } from '../data/demoUsers'
import { RoleBadge } from '../components/Badges'
import RedactedText from '../components/RedactedText'

export default function LoginPage() {
  const { login } = useAuth()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function handleSubmit(event) {
    event.preventDefault()
    setError('')
    setBusy(true)
    try {
      await login(username, password)
    } catch (err) {
      setError(err.message)
      setBusy(false)
    }
  }

  function fillDemo(user) {
    setUsername(user.username)
    setPassword('')
    setError('')
    const pwInput = document.getElementById('password')
    if (pwInput) pwInput.focus()
  }

  return (
    <div className="grid min-h-screen lg:grid-cols-[1.1fr_1fr]">
      <section className="flex flex-col justify-center gap-8 px-6 py-12 sm:px-12 lg:px-20">
        <div className="flex items-center gap-2.5">
          <span aria-hidden="true" className="grid h-9 w-9 place-items-center rounded-lg bg-[#0b1220]">
            <span className="block h-1.5 w-5 rounded-[1px] bg-slate-100" />
          </span>
          <span className="text-xl font-semibold tracking-tight">SafePrompt</span>
        </div>

        <div className="max-w-xl">
          <h1 className="text-4xl font-semibold leading-tight tracking-tight sm:text-5xl">
            Use AI at work without sending the sensitive parts.
          </h1>
          <p className="mt-4 text-base leading-7 text-slate-600">
            SafePrompt sits between your team and external AI services. It masks personal, financial and
            technical secrets before a prompt leaves the network.
          </p>
        </div>

        <div className="max-w-xl rounded-md border border-slate-200 bg-white p-5">
          <p className="text-xs font-medium text-slate-500">What you type</p>
          <p className="mt-1 text-lg leading-8">
            Customer <span className="redact">Rahul Sharma</span>, salary <span className="redact">₹12,00,000</span>
          </p>
          <p className="mt-4 text-xs font-medium text-slate-500">What the AI service receives</p>
          <p className="mt-1 text-lg leading-8">
            <RedactedText text="Customer [PERSON_1], salary [SALARY_1]" />
          </p>
        </div>
      </section>

      <section className="flex items-center justify-center bg-white px-6 py-12 lg:border-l lg:border-slate-200">
        <div className="w-full max-w-sm">
          <h2 className="text-2xl font-semibold tracking-tight">Sign in</h2>
          <p className="mt-1 text-sm text-slate-600">Use one of the demo accounts below.</p>

          <form onSubmit={handleSubmit} className="mt-6 space-y-4" noValidate>
            <div>
              <label htmlFor="username" className="block text-sm font-medium text-slate-800">
                Username
              </label>
              <input
                id="username"
                name="username"
                type="text"
                autoComplete="username"
                autoCapitalize="none"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                className="mt-1 w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
                required
              />
            </div>
            <div>
              <label htmlFor="password" className="block text-sm font-medium text-slate-800">
                Password
              </label>
              <input
                id="password"
                name="password"
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                className="mt-1 w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
                required
              />
            </div>

            {error ? (
              <p role="alert" className="rounded-md border border-rose-300 bg-rose-50 px-3 py-2 text-sm text-rose-900">
                {error}
              </p>
            ) : null}

            <button
              type="submit"
              disabled={busy || !username || !password}
              className="w-full rounded-md bg-[#0b1220] px-4 py-2.5 text-sm font-semibold text-white hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {busy ? 'Signing in…' : 'Sign in'}
            </button>
          </form>

          <div className="mt-8">
            <p className="text-sm font-medium text-slate-800">Demo accounts</p>
            <ul className="mt-2 divide-y divide-slate-200 rounded-md border border-slate-200">
              {DEMO_USERS.map((user) => (
                <li key={user.id}>
                  <button
                    type="button"
                    onClick={() => fillDemo(user)}
                    className="flex w-full items-center justify-between gap-3 px-3 py-2.5 text-left hover:bg-slate-50"
                  >
                    <span>
                      <span className="block text-sm font-medium text-slate-900">{user.name}</span>
                      <span className="block font-mono text-xs text-slate-500">
                        {user.username}
                      </span>
                    </span>
                    <RoleBadge role={user.role} />
                  </button>
                </li>
              ))}
            </ul>
            <p className="mt-2 text-xs text-slate-500">
              Selecting an account fills the username. Authenticate using credentials configured in backend/.env.
            </p>
          </div>
        </div>
      </section>
    </div>
  )
}
