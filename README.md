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
| `vt_ip_report` | **Verdict block** + country, ASN, owner → `infrastructure.ip_address`. If the case already holds them, enriches and links the `autonomous_system` (`announced by`), the announced `netblock` (`within netblock`) and that block's `whois_record` (`has whois`) — see *Derived objects*. |
| `vt_domain_report` | **Verdict block** + vendor categories, registrar, registration/expiry → `infrastructure.domain`. Creates one `dns_record` per record VT last resolved (`has record`) and the serving `certificate` (`has certificate`); fills an existing `whois_record` (`has whois`). |
| `vt_url_report` | **Verdict block** + categories, threat names, HTTP status, page title, final URL, `domain` → `web.url`. Links the serving `ip_address` (`resolves to`), the redirect chain (`redirects to`), the hosts the page reached (`has domain`) and the served content's SHA-256 (`has hash`). |
| `vt_file_report` | Detection counts **and the malware names the engines gave**, reputation, file type/magic, tags, ssdeep + TLSH. A selected `threat.file_hash` is enriched **in place** (even if it only held an MD5); a `threat.malware` that named the hash gets `has hash`. The suggested threat label becomes a `malware` family node via `classified as`. |
| `vt_pivot_resolutions` | IP↔domain resolution fan-out (`GET /…/resolutions`) → creates the missing side **with the detection counts the resolution carries for it** and links both ways via `resolves to`. |
| `vt_pivot_relations` | Domain subdomains (`GET /domains/{d}/subdomains`) → creates each subdomain **with the full report VirusTotal returns for it** (verdict block, registrar, dates, categories) and links it back via `subdomain of`. (Shown as **VT Subdomains**.) |

### The verdict block — what actually gets kept

The pack used to fold three fields off an IP report (country, ASN, owner) and drop the rest. The
rest included **all 91 engine verdicts, the detection counts, the reputation and the community
votes** — which is the report. A full IP report is ~40 KB of engine rows and RDAP, far too much to
store, so each report plugin writes a selection onto the node it was run on:

| field | from | why it is worth a field |
|---|---|---|
| `vt_malicious` / `vt_suspicious` / `vt_harmless` / `vt_undetected` | `last_analysis_stats` | the headline |
| `vt_detections` | `last_analysis_results` | **the engines that flagged it, by name and verdict** — `Fortinet: malware, SOCRadar: malicious, …`. Engines that said clean or unrated are dropped; that is ~85 of 91 rows and all of the noise |
| `vt_reputation`, `vt_votes` | `reputation`, `total_votes` | the community's own score |
| `vt_categories` | `categories` | the distinct vendor content categories (domain/URL) |
| `vt_tags`, `vt_analyzed` | `tags`, `last_analysis_date` | VT's own labels, and how stale this is |

`jarm` is deliberately **not** kept: it fingerprints a TLS listener on one port, which is a
different thing from the address or the name the field would sit on.

Keys are `vt_`-prefixed and **not declared by the typepacks**, deliberately: a typepack describes an
entity, while these record one vendor's opinion of it at one moment. The host passes undeclared keys
through and the property panel renders them (the Wayback pack stores `wayback_timestamp` the same
way), so the prefix is what keeps them unmistakably VirusTotal's rather than the graph's own claim.

A run that finds anything says so in its summary (`1 FLAGGED by VirusTotal`) and logs which engines,
rather than leaving it in a count nobody reads.

### Derived objects are not minted

`autonomous_system`, `netblock` and `whois_record` are **enriched and linked when the case already
holds them, and skipped when it does not.** They are not what the analyst asked about — they are
context the report happens to mention — and minting one per lookup turns a case into a pile of
infrastructure nobody put there. Nothing is lost by skipping them: the ASN, the owner and the
country stay on the IP node either way, and a pack that does own that layer (RDAP, IP Intelligence)
creates them properly.

### Relationship pages return reports, not ids

`/domains/{d}/subdomains` hands back a **complete domain report per subdomain** — registrar,
registration and expiry dates, analysis stats, per-engine results, reputation, categories — and
`/…/resolutions` carries the analysis stats for both ends of every resolution. Reading only the name
off those and creating a bare node threw away 120 reports that had already been fetched, and then
cost the analyst a second lookup per subdomain out of the same hourly 240 to learn what was already
in hand. Both fan-outs now fold the embedded report into the node they create, at no extra request.

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
"2 relation(s) skipped" line on every single run.

**Their data is still collected, from the free report body.** A URL report carries
`redirection_chain` and `outgoing_links` as plain attributes — the same two facts as `redirects_to`
and `contacted_domains`, in a response already paid for. `vt_url_report` turns them into
`redirects to` and `has domain` edges at no extra request.

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
- Every created node carries the fields its type declares **required** — `createNode` validates
  with `requireDeclared` and *throws*, which ends the whole run rather than skipping one node.
  `threat.malware.malware_type` is the one that bit: a required enum whose vocabulary only partly
  overlaps VirusTotal's own categories ("trojan" is a member, "virus" is not), so the pack maps the
  most-agreed category that IS a member and falls back to `other`. Every node this pack writes was
  put through the app's own `validateNodeData` against the published typepacks — 130 creates and
  4 updates, zero violations.
- A file already in the case is found by **sha256, then sha1, then md5** — strongest first. The
  host's own de-dup only ever compares the sha256 (the type's identity), so a node holding just an
  MD5 is invisible to it and the report would land on a duplicate.
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
node test-plugin.mjs    # 185 assertions against dist/pack.mjs — run AFTER build + gen-manifest
```

Then commit `dist/pack.mjs` + `plugins/*.manifest.json` (build artifacts only, like every pack
repo), publish to GitHub, and pin the commit SHA in the registry repo's
**`packs/run.vineyard.pluginpacks.virustotal_community.json`** — never in
`registry/community-pluginpacks.json`, which CI regenerates from `packs/` on every push and which
will silently revert an edit made there inside the same workflow run.

## License

Apache-2.0
