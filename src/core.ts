import { request } from 'playwright'
import type { ProxyConfig } from './proxy.js'
import { runExtra, type Extra } from './extra.js'

/**
 * caproxy proxy benchmark — the exact code caproxy.com runs for the "Our Test" section
 * of its provider reviews. The site calls runTest() and stores the result; the
 * CLI (cli.ts) calls the same function and prints it.
 *
 * Main run: N requests, every one on a new connection (keep-alive would pin one
 * exit IP and we would be measuring a node, not the rotation). With several proxy
 * lines (sessions, static IPs) we cycle through them.
 */

/** Methodology version. Changes whenever what or how we measure changes. */
export const METHOD_VERSION = '2026-09-25'

/** Answers with exit IP, country and network (ASN) in one request. */
export const MEASURE_TARGET = 'https://ipinfo.io/json'

/**
 * Only the IP. Used for 3 of every 4 requests (ipinfo's free tier is ~50k
 * requests a month) and as a fallback when ipinfo answers 429: its limit is per
 * exit IP, and on shared mobile IPs other people use it up. The proxy worked, so
 * that must not count as a failure.
 */
export const FALLBACK_TARGET = 'https://api.ipify.org/?format=json'

/** Every ENRICH_EVERY-th request goes to ipinfo for country and network. */
export const ENRICH_EVERY = 4

/**
 * 200 requests for rotating proxies: with 50, "49 of 50" means anywhere between
 * ~90% and ~99.6% with 95% confidence, and 95% vs 99% can't be told apart; with
 * 200 the interval is about ±2%. Static proxies get 50 — on caproxy.com every
 * static IP is additionally checked once a day.
 */
export const SAMPLES_ROTATING = 200
export const SAMPLES_STATIC = 50

/**
 * Hosting and cloud networks. An address from one of these on a "residential"
 * proxy is a datacenter posing as a home connection. The list is manual and
 * deliberately incomplete: the share is a lower bound, it can't overstate.
 */
export const HOSTING = /hosting|\bcloud|data ?cent|datacenter|\bserver|\bvps\b|colocation|ovh|hetzner|digitalocean|amazon|\baws\b|microsoft|azure|google cloud|linode|akamai|vultr|choopa|contabo|leaseweb|m247|datacamp|cdn77|psychz|quadranet|hostinger|oracle|alibaba|tencent|scaleway|ionos|g-core|gcore|zenlayer|hostroyale|stark industries|servers\.com|selectel|timeweb|aeza|pq hosting/i

/** The last IPv4 octet and the IPv6 tail are hidden: a residential exit IP is somebody's home. */
export function maskIp(ip: string): string {
  if (/^\d+\.\d+\.\d+\.\d+$/.test(ip)) return ip.replace(/\.\d+$/, '.x')
  const parts = ip.split(':').filter(Boolean)
  return parts.length > 3 ? parts.slice(0, 3).join(':') + ':x' : ip
}

/** Failure reason in two words, without hosts or logins from the Playwright error text. */
export function errKind(msg: string): string {
  if (/timeout|timed out/i.test(msg)) return 'timeout'
  if (/TLS|secure|SSL/i.test(msg)) return 'TLS error'
  if (/ECONNREFUSED|refused/i.test(msg)) return 'connection refused'
  if (/ECONNRESET|socket hang up|disconnected/i.test(msg)) return 'connection reset'
  if (/407|auth/i.test(msg)) return 'proxy auth'
  return 'network error'
}

export const percentile = (sorted: number[], p: number): number =>
  sorted.length === 0 ? 0 : sorted[Math.min(sorted.length - 1, Math.floor((sorted.length - 1) * p))]

export const pct = (part: number, whole: number): number => whole ? Math.round((part / whole) * 1000) / 10 : 0

export interface LogRow { n: number; line: number; ok: boolean; ms: number | null; ip: string | null; cc: string | null; org: string | null; err: string | null }
export type Metric = [kind: string, value: number, unit: string]

export interface TestOptions {
  /** Static proxies (ISP, static residential, dedicated): no rotation metric, 50 requests. */
  isStatic: boolean
  samples?: number
  /** ISO-2 country the provider promised for these IPs; enables geo_match. */
  countryClaim?: string | null
  /** Skip the extra checks (sites, speed, anonymity, lists, open connection). */
  skipExtra?: boolean
  /**
   * Called when a site blocked every try of this run. That may be the proxy — or
   * the site starting to block any automated client, which a single run can't
   * tell apart. Return true if the site let proxies in during recent runs
   * (caproxy.com checks for any successful visit within 48 hours). Default: no
   * evidence, the site is not scored.
   */
  siteAdmittedRecently?: (site: string) => Promise<boolean>
}

export interface TestResult {
  method: string
  samples: number
  ok: number
  lastError: string
  log: LogRow[]
  /** Full exit IPs — kept in memory only, never written anywhere. */
  exits: Array<{ ip: string; org: string | null; cc: string | null }>
  successRate: number
  latencyP50: number
  latencyP90: number
  uniqueIpShare: number
  hostingShare: number
  countries: string[]
  extra: Extra | null
  /** All metrics as [kind, value, unit], the same rows caproxy.com stores. */
  metrics: Metric[]
}

export async function runTest(list: ProxyConfig[], opts: TestOptions): Promise<TestResult> {
  if (!list.length) throw new Error('no proxy lines to test')
  const samples = opts.samples ?? (opts.isStatic ? SAMPLES_STATIC : SAMPLES_ROTATING)

  const times: number[] = []
  const ips: string[] = []
  const orgs: string[] = []   // only answers where the network is known (ipinfo)
  const countries = new Set<string>()
  let ok = 0
  let lastError = ''
  const log: LogRow[] = []
  const exits: TestResult['exits'] = []

  for (let i = 0; i < samples; i++) {
    const line = i % list.length
    const ctx = await request.newContext({ proxy: list[line], timeout: 20_000 })
    const started = Date.now()
    try {
      let res = await ctx.get(i % ENRICH_EVERY === 0 ? MEASURE_TARGET : FALLBACK_TARGET, { headers: { accept: 'application/json' } })
      let ms = Date.now() - started
      if (res.status() === 429) {
        const again = Date.now()
        res = await ctx.get(FALLBACK_TARGET, { headers: { accept: 'application/json' } })
        ms = Date.now() - again
      }
      if (res.status() < 400) {
        const j: any = await res.json().catch(() => null)
        if (j && typeof j.ip === 'string') {
          const org = j.org !== undefined ? String(j.org ?? '') : null
          const cc = j.country ? String(j.country) : null
          ok++; times.push(ms); ips.push(j.ip)
          if (org !== null) orgs.push(org)
          if (cc) countries.add(cc)
          exits.push({ ip: j.ip, org, cc })
          log.push({ n: i + 1, line, ok: true, ms, ip: maskIp(j.ip), cc, org, err: null })
        } else { lastError = 'not JSON'; log.push({ n: i + 1, line, ok: false, ms: null, ip: null, cc: null, org: null, err: 'not JSON' }) }
      } else { lastError = `HTTP ${res.status()}`; log.push({ n: i + 1, line, ok: false, ms: null, ip: null, cc: null, org: null, err: `HTTP ${res.status()}` }) }
    } catch (e: any) {
      lastError = String(e?.message ?? e).split('\n')[0].slice(0, 120)
      log.push({ n: i + 1, line, ok: false, ms: null, ip: null, cc: null, org: null, err: errKind(lastError) })
    }
    await ctx.dispose().catch(() => {})
  }

  times.sort((a, b) => a - b)
  const result: TestResult = {
    method: METHOD_VERSION, samples, ok, lastError, log, exits,
    successRate: pct(ok, samples),
    latencyP50: percentile(times, 0.5),
    latencyP90: percentile(times, 0.9),
    uniqueIpShare: pct(new Set(ips).size, ok),
    hostingShare: pct(orgs.filter(o => HOSTING.test(o)).length, orgs.length),
    countries: [...countries].sort(),
    extra: null,
    metrics: [],
  }
  // Nothing answered: most likely the access is dead, not the provider. No
  // metrics — otherwise "0% success" would be published.
  if (ok === 0) return result

  if (!opts.skipExtra) {
    try {
      const ourIp = await fetch('https://api.ipify.org').then(r => r.text()).catch(() => '')
      result.extra = await runExtra(list, exits, ourIp.trim())
    } catch (e: any) {
      console.log(`[proxytest] extra checks failed: ${String(e?.message ?? e).split('\n')[0]}`)
    }
  }
  result.metrics = await computeMetrics(result, list.length, opts)
  return result
}

async function computeMetrics(r: TestResult, lines: number, opts: TestOptions): Promise<Metric[]> {
  const rows: Metric[] = [
    ['success_rate', r.successRate, '%'],
    ['latency_p50', r.latencyP50, 'ms'],
    ['latency_p90', r.latencyP90, 'ms'],
  ]
  const known = r.log.filter(x => x.ok && x.org !== null).length
  if (known >= 10) rows.push(['hosting_share', r.hostingShare, '%'])
  // Rotation is only visible through one gateway. Several lines are pinned
  // sessions or static IPs, where a repeated IP is how the product works.
  if (lines === 1 && !opts.isStatic) rows.push(['unique_ips', r.uniqueIpShare, '%'])

  const extra = r.extra
  if (extra) {
    for (const [site, tries] of Object.entries(extra.sites)) {
      if (tries.length && !tries.some(t => t.ok)) {
        const admitted = opts.siteAdmittedRecently ? await opts.siteAdmittedRecently(site) : false
        if (!admitted) extra.sites[site] = []
      }
    }
    for (const [site, tries] of Object.entries(extra.sites)) {
      // "no page" is neither a block nor a pass. Fewer than three judged tries is not a result.
      const judged = tries.filter(t => t.why !== 'no page')
      if (judged.length >= 3) rows.push([`site_${site}`, pct(judged.filter(t => t.ok).length, judged.length), '%'])
    }
    const sp = extra.speedMbps.filter((x): x is number => x !== null).sort((a, b) => a - b)
    if (sp.length) rows.push(['throughput_mbps', sp[Math.floor((sp.length - 1) / 2)], 'Mbit/s'])
    if (extra.anonymity) rows.push(['anonymity', { transparent: 0, anonymous: 1, elite: 2 }[extra.anonymity], 'level'])
    if (extra.checkedIps) rows.push(['blocklist_share', pct(extra.blocklisted, extra.checkedIps), '%'])
    // Open connection: reused requests only, the first of each connection excluded.
    const warmMs = (extra.warm ?? []).filter(w => w.reused && w.ms !== null).map(w => w.ms as number).sort((a, b) => a - b)
    if (warmMs.length >= 10) {
      rows.push(['latency_warm_p50', warmMs[Math.floor((warmMs.length - 1) / 2)], 'ms'])
      let same = 0, total = 0
      for (const w of extra.warm ?? []) {
        if (w.n === 1 || !w.reused || w.same === null) continue
        total++; if (w.same) same++
      }
      if (total) rows.push(['warm_ip_kept', pct(same, total), '%'])
    }
    if (extra.subnets24) rows.push(['subnets_24', extra.subnets24, 'count'])
    if (extra.asns) rows.push(['asn_count', extra.asns, 'count'])
  }
  if (opts.countryClaim && r.exits.length) {
    const claim = opts.countryClaim.toUpperCase()
    rows.push(['geo_match', pct(r.exits.filter(x => (x.cc ?? '').toUpperCase() === claim).length, r.exits.length), '%'])
  }
  return rows
}
