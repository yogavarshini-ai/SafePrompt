import { useCallback, useEffect, useState } from 'react'

const readHash = () => window.location.hash.replace(/^#\/?/, '')

// A tiny hash router. It avoids adding react-router, so package.json and
// package-lock.json stay exactly as they are.
export function useHashRoute() {
  const [route, setRoute] = useState(readHash)

  useEffect(() => {
    const onChange = () => setRoute(readHash())
    window.addEventListener('hashchange', onChange)
    return () => window.removeEventListener('hashchange', onChange)
  }, [])

  const navigate = useCallback((path) => {
    window.location.hash = `/${path}`
  }, [])

  return [route, navigate]
}
