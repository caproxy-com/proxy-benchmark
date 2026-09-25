import { request } from 'playwright'
import { readFile, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { execFile } from 'node:child_process'
import { join } from 'node:path'
import type { ProxyConfig } from './proxy.js'

/**
 * Checks on top of the main run (core.ts). The main run answers "does the proxy
 * work and whose network is it"; buyers choose proxies by more than that:
 *
 *   sites     — do Zillow and Reddit let you in. Both decide by the IP's reputation
 *               and answer a plain request: Zillow blocks our own datacenter server
 *               and lets clean residential IPs through; Reddit answers 403
 *               "blocked by network security". So the result is about the proxy,
 *               not the client. Not tested, because they would measure our client
 *               or nothing at all: Amazon (showed a CAPTCHA to almost every proxy IP,
 *               so it did not tell providers apart), Google (/sorry/ even without a
 *               proxy), Walmart, Etsy, Target, Booking (block any non-browser),
 *               Craigslist (lets everyone in), Instagram, Cloudflare.
 *   anonymity — does the proxy add headers that reveal it or our IP (httpbin
 *               over plain HTTP: inside TLS a proxy can't see or add headers).
 *   speed     — three 2 MB downloads, transfer time only (see speed()).
 *   latency   — on an already open connection (see warmConn()).
 *   lists     — how many exit IPs are on FireHOL level 1-3 public abuse lists.
 *   pool      — how many distinct /24 subnets and networks (ASN) per run.
 *
 * About 10 MB of traffic in total, 6 MB of it the speed test.
 */

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36'
const HEADERS = { 'user-agent': UA, 'accept-language': 'en-US,en;q=0.9', accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' }
const SITE_TRIES = 8
const SPEED_URL = 'https://caproxy.com/1/test-data/2mb.bin'
const SPEED_TRIES = 3

export interface SiteTry { ok: boolean; why: string; ms: number | null }
export interface Extra {
  sites: Record<string, SiteTry[]>
  speedMbps: Array<number | null>
  anonymity: 'elite' | 'anonymous' | 'transparent' | null
  anonHeaders: string[]
  blocklisted: number
  checkedIps: number
  /** Which exit IPs are listed — masked, for the per-IP table. */
  listedMasked?: string[]
  /** Requests over an already open connection: conn — connection number, reused — curl did not open a new one. */
  warm?: Array<{ conn: number; n: number; ms: number | null; reused: boolean; ip: string | null; same: boolean | null }>
  subnets24: number
  asns: number
}

const errWhy = (e: any): string => {
  const m = String(e?.message ?? e)
  return /timeout/i.test(m) ? 'timeout' : /TLS|SSL|secure/i.test(m) ? 'TLS error' : 'network error'
}

async function plainSite(proxy: ProxyConfig, url: string, judge: (status: number, body: string, finalUrl: string) => SiteTry['why'] | null): Promise<SiteTry> {
  const ctx = await request.newContext({ proxy, timeout: 30_000, extraHTTPHeaders: HEADERS })
  const t = Date.now()
  try {
    const res = await ctx.get(url, { maxRedirects: 5 })
    const body = await res.text().catch(() => '')
    const why = judge(res.status(), body, res.url())
    return { ok: why === null, why: why ?? 'ok', ms: Date.now() - t }
  } catch (e) {
    return { ok: false, why: errWhy(e), ms: null }
  } finally {
    await ctx.dispose().catch(() => {})
  }
}


const reddit = (p: ProxyConfig) => plainSite(p, 'https://www.reddit.com/r/programming/', (st, body) =>
  /blocked by network security|whoa there, pardner/i.test(body) ? 'blocked'
    : st === 429 ? 'rate limited' : st >= 400 ? `HTTP ${st}` : null)

const zillow = (p: ProxyConfig) => plainSite(p, 'https://www.zillow.com/homes/for_sale/', (st, body) =>
  /px-captcha|Access to this page has been denied|Press & Hold/i.test(body) ? 'blocked'
    : st === 429 ? 'rate limited' : st === 403 ? 'blocked' : st >= 400 ? `HTTP ${st}`
    : body.length < 20_000 ? 'no page' : null)

async function anonymity(proxy: ProxyConfig, ourIp: string): Promise<{ level: Extra['anonymity']; headers: string[] }> {
  const REVEAL = ['via', 'x-forwarded-for', 'forwarded', 'x-real-ip', 'x-proxy-id', 'proxy-connection', 'x-forwarded-host', 'client-ip']
  let worst: Extra['anonymity'] = null
  const seen = new Set<string>()
  for (let i = 0; i < 3; i++) {
    const ctx = await request.newContext({ proxy, timeout: 20_000 })
    try {
      const res = await ctx.get('http://httpbin.org/get')
      if (res.status() >= 400) continue
      const j: any = await res.json().catch(() => null)
      if (!j) continue
      const h: Record<string, string> = Object.fromEntries(Object.entries(j.headers ?? {}).map(([k, v]) => [k.toLowerCase(), String(v)]))
      const leak = ourIp && (String(j.origin ?? '').includes(ourIp) || Object.values(h).some(v => v.includes(ourIp)))
      const found = REVEAL.filter(k => k in h)
      found.forEach(k => seen.add(k))
      const level = leak ? 'transparent' : found.length ? 'anonymous' : 'elite'
      const order = { elite: 0, anonymous: 1, transparent: 2 } as const
      if (!worst || order[level] > order[worst]) worst = level
    } catch { /* no answer — this try doesn't count */ } finally {
      await ctx.dispose().catch(() => {})
    }
  }
  return { level: worst, headers: [...seen] }
}

/**
 * Speed is transfer time only, first byte to last (curl: time_total −
 * time_starttransfer). Timing the whole download included the proxy connect and
 * TLS — 2-3 round trips of 0.6-0.8 s — so on 1 MB most of the time was connection
 * setup and the result measured latency, not bandwidth. 2 MB because TCP has not
 * ramped up yet on 1 MB.
 */
function speed(proxy: ProxyConfig): Promise<number | null> {
  const args = ['-s', '-o', '/dev/null', '--max-time', '60',
    '-w', '%{http_code} %{size_download} %{time_starttransfer} %{time_total}',
    '--proxy', proxy.server.replace(/^socks5:/, 'socks5h:')]
  if (proxy.username) args.push('--proxy-user', `${proxy.username}:${proxy.password ?? ''}`)
  args.push(`${SPEED_URL}?r=${Math.random().toString(36).slice(2)}`)
  return new Promise(resolve => {
    execFile('curl', args, { timeout: 70_000 }, (_err, stdout) => {
      const [code, size, ttfb, total] = String(stdout ?? '').trim().split(' ').map(Number)
      const transfer = total - ttfb
      resolve(code < 400 && size > 1_000_000 && transfer > 0 ? Math.round((size * 8 / 1e6 / transfer) * 10) / 10 : null)
    })
  })
}

/**
 * Latency on an already open connection. The main run opens a new connection
 * for every request — that is the number for "a fresh IP every request". People
 * who work inside one session or with static IPs send requests over an open
 * connection, and for them that number is 2-4x too high. curl, given ten URLs of
 * one host in one call, keeps them on one connection and reports num_connects:
 * 0 means the connection was reused. The first request of every connection
 * (the one that connects) is not counted.
 */
const WARM_CONNS = 3
const WARM_REQS = 10
const WARM_URL = 'https://api.ipify.org/?format=json'

function warmConn(proxy: ProxyConfig, conn: number): Promise<NonNullable<Extra['warm']>> {
  const args = ['-s', '--max-time', '90', '--proxy', proxy.server.replace(/^socks5:/, 'socks5h:')]
  if (proxy.username) args.push('--proxy-user', `${proxy.username}:${proxy.password ?? ''}`)
  for (let i = 0; i < WARM_REQS; i++) args.push('-w', '\t%{time_total}\t%{num_connects}\t%{http_code}\n', WARM_URL)
  return new Promise(resolve => {
    execFile('curl', args, { timeout: 100_000 }, (_err, stdout) => {
      let first: string | null = null
      const rows = String(stdout ?? '').split('\n').filter(Boolean).map((line, n) => {
        const [body, t, c, code] = line.split('\t')
        const ip = (body.match(/"ip":"([^"]+)"/) ?? [])[1] ?? null
        const ok = Number(code) < 400 && !!ip
        if (n === 0) first = ip
        // Full addresses are compared here and never stored: stored IPs are masked.
        const same = n === 0 || !ip || !first ? null : ip === first
        return { conn, n: n + 1, ms: ok ? Math.round(Number(t) * 1000) : null, reused: Number(c) === 0, same,
          ip: ip ? (ip.includes(':') ? ip.split(':').slice(0, 3).join(':') + ':x' : ip.replace(/\.\d+$/, '.x')) : null }
      })
      resolve(rows)
    })
  })
}

/* ─── FireHOL lists: downloaded once a day, cached in the OS temp dir ─── */
const LISTS = ['firehol_level1', 'firehol_level2', 'firehol_level3']
let ranges: Array<[number, number]> | null = null

const ipNum = (ip: string): number | null => {
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(ip)
  return m ? ((+m[1] << 24) >>> 0) + (+m[2] << 16) + (+m[3] << 8) + +m[4] : null
}

async function loadRanges(): Promise<Array<[number, number]>> {
  if (ranges) return ranges
  const out: Array<[number, number]> = []
  for (const name of LISTS) {
    const file = join(tmpdir(), `${name}.netset`)
    let text = ''
    const fresh = await stat(file).then(s => Date.now() - s.mtimeMs < 864e5).catch(() => false)
    if (fresh) text = await readFile(file, 'utf8')
    else {
      try {
        const r = await fetch(`https://iplists.firehol.org/files/${name}.netset`)
        if (r.ok) { text = await r.text(); await writeFile(file, text).catch(() => {}) }
      } catch { /* list unavailable — check against the ones we have */ }
      if (!text) text = await readFile(file, 'utf8').catch(() => '')
    }
    for (const line of text.split('\n')) {
      const m = /^(\d+\.\d+\.\d+\.\d+)(?:\/(\d+))?$/.exec(line.trim())
      if (!m) continue
      const base = ipNum(m[1]); if (base === null) continue
      const bits = m[2] ? +m[2] : 32
      const size = 2 ** (32 - bits)
      const start = base - (base % size)
      out.push([start, start + size - 1])
    }
  }
  ranges = out
  return out
}

export async function blocklisted(ips: string[]): Promise<{ listed: number; checked: number; which: string[] }> {
  const rs = await loadRanges()
  if (!rs.length) return { listed: 0, checked: 0, which: [] }
  let listed = 0, checked = 0
  const which: string[] = []
  for (const ip of new Set(ips)) {
    const n = ipNum(ip); if (n === null) continue
    checked++
    if (rs.some(([a, b]) => n >= a && n <= b)) { listed++; which.push(ip.replace(/\.\d+$/, '.x')) }
  }
  return { listed, checked, which }
}

export async function runExtra(list: ProxyConfig[], exits: Array<{ ip: string; org: string | null }>, ourIp: string): Promise<Extra> {
  const pick = (i: number) => list[i % list.length]
  const sites: Record<string, SiteTry[]> = { zillow: [], reddit: [] }
  for (let i = 0; i < SITE_TRIES; i++) {
    sites.zillow.push(await zillow(pick(i)))
    sites.reddit.push(await reddit(pick(i + 1)))
  }
  const speedMbps: Array<number | null> = []
  for (let i = 0; i < SPEED_TRIES; i++) speedMbps.push(await speed(pick(i)))
  const warm: NonNullable<Extra['warm']> = []
  for (let c = 0; c < WARM_CONNS; c++) warm.push(...await warmConn(pick(c), c + 1))
  const anon = await anonymity(pick(0), ourIp)
  const bl = await blocklisted(exits.map(x => x.ip))
  const v4 = exits.map(x => x.ip).filter(ip => ipNum(ip) !== null)
  return {
    sites, speedMbps, anonymity: anon.level, anonHeaders: anon.headers,
    blocklisted: bl.listed, checkedIps: bl.checked, listedMasked: bl.which, warm,
    subnets24: new Set(v4.map(ip => ip.replace(/\.\d+$/, ''))).size,
    asns: new Set(exits.map(x => (x.org ?? '').split(' ')[0]).filter(a => /^AS\d+$/.test(a))).size,
  }
}
