# VirusTotal Community

Free-tier VirusTotal v3 API enrichment and pivots for VINEYARD. Every plugin uses **the
analyst's own VirusTotal API key** — it is declared as a `secret: true` config value and stored in
the OS keychain (desktop) or session storage (web), and is sent only as the `x-apikey` header to
`www.virustotal.com` through the plugin's declared `network` allowlist.

Scoped to what a **free community key can actually read**, verified against one. Endpoints a
community key is refused are not in this pack at all — see below. A `403` from a key with even
fewer privileges is still skipped and counted per item, never fatal.

## Plugins

| identifier | What it does |
|---|---|
| `vt_ip_report` | IP reputation: country, ASN, owner → updates `infrastructure.ip_address`, creates/links `infrastructure.autonomous_system` via `announced by`. |
| `vt_domain_report` | Domain WHOIS: registrar, registration and expiry dates, raw WHOIS → updates `infrastructure.domain`, creates `infrastructure.whois_record` via `has whois`. |
| `vt_url_report` | URL reputation: HTTP status, page title, final URL, last serving IP → updates `web.url`, creates/links the serving `infrastructure.ip_address` via `resolves to`. |
| `vt_file_report` | File hashes (SHA-256/1/MD5): detection counts, type, tags. A selected `threat.file_hash` is enriched **in place** (even if it only held an MD5); a `threat.malware` that named the hash gets a `has hash` edge to the File Hash node. Hashes can also be pasted in. |
| `vt_pivot_resolutions` | IP↔domain resolution fan-out (`GET /…/resolutions`) → creates the missing side and links both ways via `resolves to`. |
| `vt_pivot_relations` | Domain subdomains (`GET /domains/{d}/subdomains`) → creates each subdomain and links it back via `subdomain of`. (Shown as **VT Subdomains**.) |

### What a community key actually reaches

Measured 2026-08-14 against a key whose `GET /users/{key}` reports **zero** granted privileges.
Worth stating how to repeat it, because an earlier pass measured with a Google Threat Intelligence
key by mistake and concluded the opposite — `GET /users/{key}` is what tells the two apart
(`privileges`, and `quotas.api_requests_hourly`: 240 for community, 600,000 for that GTI key).

```
200                                       403 ForbiddenError
/ip_addresses/{ip}                        /urls/{id}/redirects_to
/domains/{d}                              /urls/{id}/contacted_domains
/urls/{id}
/files/{hash}                             The error body names it:
/ip_addresses/{ip}/resolutions              {"error":{"code":"ForbiddenError",...},
/domains/{d}/resolutions                     "meta":{"relationship":"redirects_to"}}
/domains/{d}/subdomains
/urls/{id}/last_serving_ip_address
```

**The two 403 relationships were removed from this pack, not skipped at runtime.** On the tier this
pack is named for they are two guaranteed-wasted requests per URL out of an hourly 240, and a
"2 relation(s) skipped" line on every single run. They belong in a paid-key pack.

Every *attribute* these plugins read is present on a community key. What a paid key adds
(`threat_severity`, `exiftool`, `identified_brands`, `first_seen_itw_date`) is not read here.

A malformed value comes back `400 InvalidArgumentError` (measured on `999.999.999.999`), handled
per item — one bad node in a selection does not end the run.

## The analyst's key

- `config: api_key` (`secret: true`, `optional: false`). A paid key works here unchanged — it
  simply reaches more than this pack asks for.
- Sent as `x-apikey` on every request. Never logged, never part of params, never a URL query
  string (the v3 API has no key query parameter).

## Platform / CORS

`primary: desktop`. Measured: VirusTotal sends **no** `access-control-allow-*` header on any
response (an `OPTIONS` preflight returns 200 with none), so a browser blocks every reply. Inside
the desktop shell the main process writes the missing headers for origins a pack declared, so
`ctx.net.fetch` reaches VT directly. On web the plugins refuse up front with that reason rather
than letting an opaque `Failed to fetch` reach the analyst — the WhatsMyName pattern.

## Rate limits & failures

- The community allowance is published by `GET /users/{key}`: **240/hour, 500/day, 15,500/month**
  — not the "4 requests per minute" that gets repeated everywhere. Measured: eight back-to-back
  requests were all served `200`, and VT sends no `retry-after` or `x-ratelimit-*` header. So the
  429 backoff (15 s / 30 s / 60 s, 3 attempts, abortable so Cancel is not dead for a minute) is for
  a short-term throttle; after that the run stops and says the allowance is hourly, because no wait
  a run can afford will clear an hour-long bucket.
- Errors are decoded from the v3 envelope `{"error": {"code", "message"}}`. What ends the **run**:
  a rejected key (`401`), reported as such rather than as N mystery misses. What is logged and
  stepped over **per item**: `404` (no record), `400 InvalidArgumentError` (malformed value),
  `403 ForbiddenError` (this key may not read that).
- Graph writes are **staged**: nothing reaches the API until the analyst reviews and commits, and
  `updateNode` is passed a **delta** — the fields this run filled, never a full node snapshot,
  which the host would fill-merge over another run's newer values at commit.
- Every plugin **relates what it learned to the node it was run on**, and `test-plugin.mjs` pins
  that per plugin. `createNode` de-dups on type + the type's identity property, so a report handed
  to `createNode` reaches the selected node only when the two already share that value — which is
  how the file report used to drop a whole VirusTotal report onto a new, unconnected node whenever
  the selected File Hash held just an MD5.

## Build & test & publish

```bash
npx tsc --noEmit        # type-check (esbuild does NOT type-check; run this first)
node build.mjs          # esbuild → dist/pack.mjs (requires node + npx)
node gen-manifest.mjs   # regenerate plugins/virustotal-community.manifest.json from dist
node test-plugin.mjs    # 112 assertions against dist/pack.mjs — run AFTER build + gen-manifest
```

Then commit `dist/pack.mjs` + `plugins/*.manifest.json` (build artifacts only, like every pack
repo), publish to GitHub, and pin the commit SHA in the registry repo's
**`packs/run.vineyard.pluginpacks.virustotal_community.json`** — never in
`registry/community-pluginpacks.json`, which CI regenerates from `packs/` on every push and which
will silently revert an edit made there inside the same workflow run.

## License

Apache-2.0
