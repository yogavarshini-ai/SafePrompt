import { useCallback, useMemo, useState } from 'react'
import { AuthContext } from './authContext'
import { getSession, login as apiLogin, logout as apiLogout } from '../services/api'

export default function AuthProvider({ children }) {
  const [user, setUser] = useState(() => getSession())

  const login = useCallback(async (username, password) => {
    const signedIn = await apiLogin(username, password)
    setUser(signedIn)
    return signedIn
  }, [])

  const logout = useCallback(() => {
    if (user) apiLogout(user)
    window.location.hash = ''
    setUser(null)
  }, [user])

  const value = useMemo(() => ({ user, login, logout }), [user, login, logout])

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
