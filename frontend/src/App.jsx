import { useEffect, useMemo } from 'react'
import { useAuth } from './auth/useAuth'
import { routesFor } from './config/routes'
import { useHashRoute } from './router/useHashRoute'
import Layout from './components/Layout'
import LoginPage from './pages/LoginPage'
import ChatPage from './pages/ChatPage'
import HistoryPage from './pages/HistoryPage'
import TeamPage from './pages/TeamPage'
import AllChatsPage from './pages/AllChatsPage'
import AccountsPage from './pages/AccountsPage'
import AuditPage from './pages/AuditPage'

const PAGES = {
  chat: ChatPage,
  history: HistoryPage,
  team: TeamPage,
  'all-chats': AllChatsPage,
  accounts: AccountsPage,
  audit: AuditPage,
}

export default function App() {
  const { user, logout } = useAuth()
  const [route, navigate] = useHashRoute()
  const routes = useMemo(() => (user ? routesFor(user.role) : []), [user])

  // Route guard: a role can only open pages in its own route list. Typing a
  // forbidden URL (for example #/audit as a worker) sends you back to the first
  // allowed page. The service layer enforces the same rules on the data.
  const allowed = routes.find((item) => item.path === route)
  const current = allowed ?? routes[0]

  useEffect(() => {
    if (user && current && current.path !== route) navigate(current.path)
  }, [user, current, route, navigate])

  if (!user) return <LoginPage />

  const Page = PAGES[current.path]
  return (
    <Layout routes={routes} current={current.path} onNavigate={navigate} user={user} onLogout={logout}>
      <Page key={`${user.id}:${current.path}`} user={user} />
    </Layout>
  )
}
