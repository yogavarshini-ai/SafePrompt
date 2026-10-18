const PREFIX = 'safeprompt.'

export function load(key, fallback) {
  try {
    const raw = window.localStorage.getItem(PREFIX + key)
    return raw ? JSON.parse(raw) : fallback
  } catch {
    return fallback
  }
}

export function save(key, value) {
  try {
    window.localStorage.setItem(PREFIX + key, JSON.stringify(value))
  } catch {
    // Storage can be full or blocked. The demo keeps working for this page load.
  }
}

export function remove(key) {
  try {
    window.localStorage.removeItem(PREFIX + key)
  } catch {
    // Nothing to clean up if storage is unavailable.
  }
}
