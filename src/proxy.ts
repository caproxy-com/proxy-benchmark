/**
 * Proxy string parsing. Both common formats are accepted:
 *
 *   http://user:pass@host:port     URL form
 *   http://host:port:user:pass     the form most provider dashboards export
 *   host:port                      no auth
 *
 * socks5:// is accepted too. The password may contain colons, so everything
 * after the third part is joined back.
 */

export interface ProxyConfig {
  server: string
  username?: string
  password?: string
}

export function parseProxy(raw: string): ProxyConfig | null {
  const s = raw.trim()
  if (!s) return null

  const scheme = /^(https?|socks5):\/\//i.exec(s)?.[1]?.toLowerCase() ?? 'http'
  const bare = s.replace(/^(https?|socks5):\/\//i, '')

  if (bare.includes('@')) {
    try {
      const u = new URL(`${scheme}://${bare}`)
      const proxy: ProxyConfig = { server: `${scheme}://${u.host}` }
      if (u.username) proxy.username = decodeURIComponent(u.username)
      if (u.password) proxy.password = decodeURIComponent(u.password)
      return proxy
    } catch {
      return null
    }
  }

  // host:port[:user:pass]; the password may contain colons.
  const parts = bare.split(':')
  if (parts.length < 2) return null
  const [host, port, user, ...rest] = parts
  if (!host || !/^\d+$/.test(port)) return null

  const proxy: ProxyConfig = { server: `${scheme}://${host}:${port}` }
  if (user) {
    proxy.username = user
    proxy.password = rest.join(':')
  }
  return proxy
}
