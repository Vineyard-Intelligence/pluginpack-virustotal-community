# VirusTotal Community

Free-tier VirusTotal v3 API enrichment and pivots for VINEYARD. Every plugin uses **the
analyst's own VirusTotal API key**, sent only to `www.virustotal.com`.

Scoped to what a **free community key can actually read**. Endpoints a community key is refused are
not in this pack at all — see below. A `403` from a key with even fewer privileges is still skipped
and counted per item, never fatal.

## Plugins

| identifier | What it does |
|---|---|
| `vt_ip_report` | **Verdict block** + country, ASN, owner → `infrastructure.ip_address`. If the project already holds them, enriches and links the `autonomous_system` (`announced by`), the announced `netblock` (`within netblock`) and that block's `whois_record` (`has whois`) — see *Derived objects*. |
| `vt_domain_report` | **Verdict block** + vendor categories, registrar, registration/expiry → `infrastructure.domain`. Creates one `dns_record` per record VT last resolved (`has record`) and the serving `certificate` (`has certificate`); fills an existing `whois_record` (`has whois`). |
| `vt_url_report` | **Verdict block** + categories, threat names, HTTP status, page title, final URL, `domain` → `web.url`. Links the serving `ip_address` (`resolves to`), the redirect chain (`redirects to`), the hosts the page reached (`has domain`) and the served content's SHA-256 (`has hash`). |
| `vt_file_report` | Detection counts **and the malware names the engines gave**, reputation, file type/magic, tags, ssdeep + TLSH. A selected `threat.file_hash` is enriched **in place** (even if it only held an MD5); a `threat.malware` that named the hash gets `has hash`. The suggested threat label becomes a `malware` family node via `classified as`. |
| `vt_passive_dns` | **VT Passive DNS** — IP↔domain resolution fan-out (`GET /…/resolutions`) → creates the missing side **with the detection counts the resolution carries for it** and links domain → IP via `resolves to`. |
| `vt_subdomains` | **VT Subdomains** — domain subdomains (`GET /domains/{d}/subdomains`) → creates each subdomain **with the full report VirusTotal returns for it** (verdict block, registrar, dates, categories) and links it back via `subdomain of`. |

### The verdict block — what actually gets kept

A full IP report is ~40 KB of engine rows and RDAP, far too much to store, so each report plugin
writes a selection onto the node it was run on:

| field | from | why it is worth a field |
|---|---|---|
| `vt_malicious` / `vt_suspicious` / `vt_harmless` / `vt_undetected` | `last_analysis_stats` | the headline |
| `vt_detections` | `last_analysis_results` | **the engines that flagged it, by name and verdict** — `Fortinet: malware, SOCRadar: malicious, …`. Engines that said clean or unrated are dropped |
| `vt_reputation`, `vt_votes` | `reputation`, `total_votes` | the community's own score |
| `vt_categories` | `categories` | the distinct vendor content categories (domain/URL) |
| `vt_tags`, `vt_analyzed` | `tags`, `last_analysis_date` | VT's own labels, and how stale this is |

`jarm` is deliberately **not** kept: it fingerprints a TLS listener on one port, not the address or
name the field would sit on.

Keys are `vt_`-prefixed and **not declared by the typepacks**: they record one vendor's opinion at
one moment, not the entity itself. The property panel still shows them.

A run that finds anything says so in its summary (`1 FLAGGED by VirusTotal`) and logs which engines.

### Derived objects are not minted

`autonomous_system`, `netblock` and `whois_record` are **enriched and linked when the project already
holds them, and skipped when it does not** — they are context the report mentions, not what the
analyst asked about. The ASN, the owner and the country stay on the IP node either way, and a pack
that owns that layer (RDAP, IP Intelligence) creates them.

### Relationship pages return reports, not ids

`/domains/{d}/subdomains` hands back a **complete domain report per subdomain**, and `/…/resolutions`
carries the analysis stats for both ends of every resolution. Both fan-outs fold that embedded report
into the node they create, at no extra request.

### What a community key actually reaches

The pack reads only endpoints a community key is served: IP, domain, URL and file reports, IP and
domain resolutions, domain subdomains, and a URL's last serving IP address.

**The URL relationships `redirects_to` and `contacted_domains` return `403` on a community key, so
they are not in this pack.** Their data is still collected: a URL report carries `redirection_chain`
and `outgoing_links` as plain attributes, and `vt_url_report` turns them into `redirects to` and
`has domain` edges at no extra request.

Every *attribute* these plugins read is present on a community key. What a paid key adds
(`threat_severity`, `exiftool`, `identified_brands`, `first_seen_itw_date`) is not read here.

## The analyst's key

- `config: api_key` (`secret: true`, `optional: false`). A paid key works here unchanged — it
  simply reaches more than this pack asks for.

## Platform / CORS

`primary: desktop`. VirusTotal sends no CORS headers, so a browser cannot read its replies. On web
the plugins refuse up front with that reason.

## Rate limits & failures

- The community allowance is **240/hour, 500/day, 15,500/month** (published by `GET /users/{key}`).
  A `429` is retried with backoff (15 s / 30 s / 60 s, 3 attempts, cancellable); after that the run
  stops and says the allowance is hourly.
- What ends the **run**: a rejected key (`401`), reported as such. What is logged and stepped over
  **per item**: `404` (no record), `400 InvalidArgumentError` (malformed value),
  `403 ForbiddenError` (this key may not read that).
- Graph writes are **staged**: nothing is written until the analyst reviews and commits.
- `threat.malware.malware_type` is set to the most-agreed VirusTotal category that is in the type's
  vocabulary ("trojan" is, "virus" is not), falling back to `other`.
- A file already in the project is found by **sha256, then sha1, then md5** — strongest first — so a
  node holding just an MD5 is enriched rather than duplicated.
- Every plugin **relates what it learned to the node it was run on**.

## Build & test & publish

```bash
npx tsc --noEmit        # type-check (esbuild does NOT type-check; run this first)
node build.mjs          # esbuild → dist/pack.mjs (requires node + npx)
node gen-manifest.mjs   # regenerate plugins/virustotal-community.manifest.json from dist
node test-plugin.mjs    # 185 assertions against dist/pack.mjs — run AFTER build + gen-manifest
```

Then commit `dist/pack.mjs` + `plugins/*.manifest.json`, publish to GitHub, and pin the commit SHA
in the registry repo's **`packs/run.vineyard.pluginpacks.virustotal_community.json`** — not in
`registry/community-pluginpacks.json`, which CI regenerates.

## License

Apache-2.0
