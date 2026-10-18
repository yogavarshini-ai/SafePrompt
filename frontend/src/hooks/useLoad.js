import { useCallback, useEffect, useState } from 'react'

// Runs an async loader when the page opens and tracks loading, error and data.
// Pages remount on navigation, so the loader only needs to run on mount and
// whenever `reload()` is called.
export function useLoad(loader) {
  const [state, setState] = useState({ data: null, error: '', loading: true })
  const [tick, setTick] = useState(0)

  useEffect(() => {
    let cancelled = false
    loader().then(
      (data) => {
        if (!cancelled) setState({ data, error: '', loading: false })
      },
      (error) => {
        if (!cancelled) setState({ data: null, error: error.message, loading: false })
      },
    )
    return () => {
      cancelled = true
    }
  }, [tick])

  const setData = useCallback((updater) => {
    setState((current) => ({
      ...current,
      data: typeof updater === 'function' ? updater(current.data) : updater,
    }))
  }, [])

  const reload = useCallback(() => setTick((value) => value + 1), [])

  return { ...state, setData, reload }
}
