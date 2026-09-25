#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs'
import { parseProxy } from './proxy.js'
import { METHOD_VERSION, runTest, type TestResult } from './core.js'

/**
 * Command line for the caproxy proxy benchmark.
 *
 *   node dist/cli.js --proxy host:port:user:pass [--proxy ...]
 *   node dist/cli.js --file proxies.txt --static --country DE --csv out.csv
 *
 *   --proxy LINE   a proxy line (repeatable)
 *   --file PATH    proxy lines, one per line
 *   --static       static proxies (ISP, static residential, dedicated): 50 requests, no rotation metric
 *   --samples N    override the number of requests
 *   --country XX   ISO-2 country the provider promised; enables geo_match
 *   --skip-extra   only the main run (no sites, speed, anonymity, lists, open connection)
 *   --ipv6         IPv6-only proxies: IPv6 endpoints; sites and anonymity are skipped (no IPv6 there)
 *   --csv PATH     write every request of the run as CSV (same format as caproxy.com)
 *   --json         print the full result as JSON instead of the summary
 */

function args(argv: string[]) {
  const o: { proxies: string[]; isStatic: boolean; samples?: number; country?: string; skipExtra: boolean; ipv6?: boolean; csv?: string; json: boolean } =
    { proxies: [], isStatic: false, skipExtra: false, json: false }
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a === '--proxy') o.proxies.push(argv[++i])
    else if (a === '--file') o.proxies.push(...readFileSync(argv[++i], 'utf8').split(/\r?\n/).map(s => s.trim()).filter(s => s && !s.startsWith('#')))
    else if (a === '--static') o.isStatic = true
    else if (a === '--ipv6') o.ipv6 = true
    else if (a === '--samples') o.samples = Number(argv[++i])
    else if (a === '--country') o.country = String(argv[++i]).toUpperCase()
    else if (a === '--skip-extra') o.skipExtra = true
    else if (a === '--csv') o.csv = argv[++i]
    else if (a === '--json') o.json = true
    else if (a === '-h' || a === '--help') { console.log(readFileSync(new URL(import.meta.url)).toString().match(/\/\*\*([\s\S]*?)\*\//)?.[1] ?? ''); process.exit(0) }
    else throw new Error(`unknown argument: ${a}`)
  }
  return o
}

const esc = (v: unknown) => {
  const s = v === null || v === undefined ? '' : String(v)
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
}

/** The same CSV caproxy.com serves at /1/test-data/?run=ID. */
export function toCsv(r: TestResult): string {
  const out: string[] = []
  const row = (...c: unknown[]) => out.push(c.map(esc).join(','))
  row(`# caproxy proxy benchmark, method ${METHOD_VERSION}, ${new Date().toISOString()}; every request to ipinfo.io (exit IP, country, network), api.ipify.org (IP only) when ipinfo refuses`)
  row('request', 'result', 'response_ms', 'exit_ip_masked', 'country', 'network', 'error')
  for (const x of r.log) row(x.n, x.ok ? 'ok' : 'fail', x.ms, x.ip, x.cc, x.org, x.err)
  const e = r.extra
  if (e) {
    out.push('')
    row('check', 'try', 'result', 'response_ms', 'detail')
    for (const [site, tries] of Object.entries(e.sites)) tries.forEach((t, i) => row(`site:${site}`, i + 1, t.ok ? 'ok' : 'fail', t.ms, t.why))
    for (const w of e.warm ?? []) row(`open connection #${w.conn}`, w.n, w.ms === null ? 'fail' : 'ok', w.ms,
      `${w.reused ? 'reused connection' : 'new connection'}${w.ip ? ', ' + w.ip : ''}${w.same === false ? ', IP changed' : ''}`)
    e.speedMbps.forEach((v, i) => row('download 2 MB', i + 1, v === null ? 'fail' : 'ok', '', v === null ? '' : `${v} Mbit/s`))
    row('anonymity', '', e.anonymity ?? '', '', e.anonHeaders.join(' '))
    row('FireHOL blocklists', '', `${e.blocklisted} of ${e.checkedIps} IPs listed`, '', 'firehol_level1-3')
    row('pool', '', `${e.subnets24} /24 subnets, ${e.asns} ASNs`, '', '')
  }
  return out.join('\n') + '\n'
}

async function main() {
  const o = args(process.argv.slice(2))
  const list = o.proxies.map(parseProxy).filter((p): p is NonNullable<typeof p> => !!p)
  if (!list.length) throw new Error('give at least one --proxy or --file (see --help)')
  console.error(`caproxy proxy benchmark ${METHOD_VERSION}: ${list.length} proxy line(s), ${o.isStatic ? 'static' : 'rotating'}…`)
  const r = await runTest(list, { isStatic: o.isStatic, samples: o.samples, countryClaim: o.country, skipExtra: o.skipExtra, ipv6: o.ipv6 })
  if (o.csv) { writeFileSync(o.csv, toCsv(r)); console.error(`CSV written to ${o.csv}`) }
  if (o.json) {
    const { exits: _hidden, ...rest } = r   // full exit IPs are never printed
    console.log(JSON.stringify(rest, null, 2))
  } else {
    console.log(`\n${r.ok} of ${r.samples} requests answered; countries seen: ${r.countries.join(', ') || '—'}`)
    for (const [k, v, u] of r.metrics) console.log(`  ${k.padEnd(18)} ${String(v).padStart(8)} ${u}`)
  }
  process.exit(0)
}

main().catch(e => { console.error(String(e?.message ?? e)); process.exit(1) })
