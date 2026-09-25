# caproxy proxy benchmark

The exact code [caproxy.com](https://caproxy.com/) runs for the **“Our Test”** section of its proxy provider reviews. Not a re-implementation: the site imports these same files. If you run it against the same proxies, you are running our test.

Every number on a review page comes with the raw data of its run (CSV, link under the results). This repository lets you check how those numbers are produced and reproduce them yourself.

## What it measures

| metric | how |
|---|---|
| **success rate** | 200 requests through the proxy (50 for static proxies), each on a **new connection**. A request succeeds if an answer comes back within 20 s. |
| **response time, new connection** | median and 90th percentile of those requests. This is your number if you need a fresh IP on every request. |
| **response time, open connection** | 3 connections × 10 requests with `curl` on one connection each; `num_connects = 0` proves the connection was reused; the first request of each connection is not counted. Your number for sessions and static IPs. Also reports whether the IP stayed the same within a connection. |
| **speed** | three 2 MB downloads through the proxy, **transfer time only** (`time_total − time_starttransfer`), connection setup excluded. Median. |
| **unique IPs** | share of distinct exit IPs among successful requests — rotating gateways only (not for pinned sessions or static IPs). |
| **IPs from datacenter networks** | exit network names (ASN, from ipinfo.io) matched against a list of hosting and cloud companies. A **lower bound**: the list is incomplete, so it can understate but not overstate. Meaningful for residential and mobile proxies only. |
| **abuse blocklists** | exit IPs matched against [FireHOL](https://iplists.firehol.org/) level 1–3. |
| **IP pool diversity** | distinct /24 subnets and distinct networks (ASN) per run. |
| **anonymity** | over plain HTTP via httpbin.org: `transparent` if our own IP leaks, `anonymous` if headers such as `Via` or `X-Forwarded-For` reveal a proxy, `elite` otherwise. |
| **Zillow** | 8 plain requests. Zillow decides by IP reputation: it blocks our own datacenter server and lets clean residential IPs through, so the result is about the proxy, not the client. A block page counts as blocked; a page that did not load is not counted; fewer than 3 judged requests → not scored. If a site blocks every request of a run, it is scored only when there is evidence it admits proxies at all (`siteAdmittedRecently`; caproxy.com checks for any successful visit within 48 hours) — otherwise a site blocking every bot can't be told apart from a bad provider. |
| **Reddit** | 8 plain requests; Reddit blocks bad IPs outright with “blocked by network security”. |
| **country as promised** | with `--country XX`: share of answers that exit in that country. |

Every request of the main run goes to ipinfo.io (exit IP, country, network). ipinfo's free limit is per client IP, i.e. per proxy exit, so a rotating pool doesn't spend a common quota; when an exit has used it up (busy shared mobile IPs), the request is repeated to api.ipify.org (IP only) and still counts. Countries and networks are computed from the ipinfo answers.

### What is deliberately not tested

- **Amazon** showed a CAPTCHA to almost every proxy IP we tried (residential, mobile and datacenter alike), so it did not tell providers apart.
- **Walmart, Etsy, Target, Booking** block any non-browser client from any IP; **Craigslist** lets everyone in, including our datacenter server.
- **Google** shows its `/sorry/` CAPTCHA to our headless browser even without a proxy — it detects automation, not the IP, so a Google score would say nothing about proxies.
- **Instagram** without login serves the same page to everyone.
- **Cloudflare** challenges any non-browser client, which again tests the client, not the proxy.

## Run it

Needs Node.js 20+ and `curl` on the PATH.

```bash
git clone https://github.com/caproxy-com/proxy-benchmark.git
cd proxy-benchmark
npm install
npm run build

# rotating gateway
node dist/cli.js --proxy "gate.example.com:7000:user:pass" --csv run.csv

# static IPs, promised to be German, one per line in a file
node dist/cli.js --file static.txt --static --country DE --csv run.csv
```

Options: `--proxy LINE` (repeatable), `--file PATH`, `--static`, `--samples N`, `--country XX`, `--skip-extra` (main run only), `--csv PATH`, `--json`.

Proxy lines: `host:port:user:pass`, `http://user:pass@host:port`, `socks5://…`.

A full run uses about 10 MB of proxy traffic (6 MB of it the speed test) and takes 3–5 minutes.

## Reading the numbers

- Response times depend on **where you run from**. caproxy.com runs from a server in London; compare numbers between providers measured from the same place, not with other people's tests.
- Speed is one connection through one exit — for residential proxies that is somebody's home connection. It varies a lot between runs; caproxy.com repeats the test monthly.
- In the CSV the last part of every IP is hidden (`203.0.113.x`). Residential proxies exit through real people's connections. Full IPs are only held in memory to match blocklists and never written.

## Versions

The methodology version is `METHOD_VERSION` in `src/core.ts` and is stored with every run on caproxy.com. History and comparisons on the site only use runs of the same version. Each version is tagged here as `method-<version>`.

| version | change |
|---|---|
| 2026-09-24 | 200 requests for rotating proxies, ipinfo every 4th request, Amazon (browser, with control) and Reddit, speed, anonymity, FireHOL |
| 2026-09-24.2 | speed as transfer time only (curl, 2 MB); Amazon and Reddit: 8 visits, wait for logo or CAPTCHA, control up to 3 tries; open-connection latency |
| 2026-09-25 | Amazon replaced with Zillow (plain requests, decides by IP reputation); no browser needed any more |
| 2026-09-25.2 | every request to ipinfo (was every 4th): countries and datacenter share from all exits, not ~50; latency is now ipinfo's for all requests |
| 2026-09-25.3 | hosting list: Amazon matched by company name (`Amazon.com`, `Amazon Technologies`, `Amazon Data Services`) — the bare word also caught AMAZONET, a Brazilian home ISP |

## Using it responsibly

The test sends a handful of requests to public sites (a few per run to Zillow and Reddit, more to ipinfo.io, api.ipify.org and httpbin.org) and downloads 6 MB from caproxy.com for the speed test. Keep it at that scale and respect those sites' terms. Only test proxies you are allowed to use.

## Disagree with a result?

If you are a provider and think a number on caproxy.com is wrong, run this test yourself and send us the CSV: <https://caproxy.com/en/about-us/>. If our test is at fault, we fix the test and say so.

## License

MIT — see [LICENSE](LICENSE).
