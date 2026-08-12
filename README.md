# VirusTotal Community

Free-tier VirusTotal v3 API enrichment and pivots for VINEYARD. Every plugin uses **the
analyst's own VirusTotal API key** — it is declared as a `secret: true` config value and stored in
the OS keychain (desktop) or session storage (web), and is sent only as the `x-apikey` header to
`www.virustotal.com` through the plugin's declared `network` allowlist.

Paid-tier features live in the separate **pluginpack-virustotal-intelligence** pack. Anything here
that a free key answers with `403 Forbidden` is skipped gracefully and counted, never fatal.

## Plugins

| identifier | What it does |
|---|---|
| `vt_ip_report` | IP reputation: country, ASN, owner → updates `infrastructure.ip_address`, creates/link `infrastructure.autonomous_system` via `announced by`. |
| `vt_domain_report` | Domain reputation/WHOIS: registrar, registration date, expiry (parsed from raw WHOIS) → updates `infrastructure.domain`, creates `infrastructure.whois_record` via `has whois`. |
| `vt_url_report` | URL reputation: HTTP status, page title, final URL, last serving IP → updates `web.url`, creates/links the serving `infrastructure.ip_address` via `resolves to`. |
| `vt_file_report` | File hashes (SHA-256/1/MD5): detection counts, type, tags → creates `threat.file_hash` nodes. Hash-first, so it does not need a filename. |
| `vt_pivot_resolutions` | IP↔domain resolution fan-out (`GET /…/resolutions`, free tier) → creates the missing side and links both ways via `resolves to`. |
| `vt_pivot_relations` | Domain subdomains (`GET /domains/{d}/subdomains`, free tier) + URL `redirects_to`/`contacted_domains` (**premium-gated** — skipped and counted on 403). |

## The analyst's key

- `config: api_key` (`secret: true`, `optional: false`) — same key name as the intelligence pack,
  so a paid key works here unchanged.
- Sent as `x-apikey` on every request. Never logged, never part of params, never a URL query
  string (the v3 API has no key query parameter).

## Platform / CORS

`primary: desktop`. VirusTotal's docs never mention CORS and ship no browser samples, so plain
browser fetch is not assumed to work. Inside the desktop shell the main process rewrites CORS
response headers, so `ctx.net.fetch` reaches VT directly. In the web build the plugins fail
loudly ("requires the desktop app") rather than returning a clean miss — the WhatsMyName pattern.

## Rate limits & failures

- Free keys are heavily rate-limited (community figure ≈4 req/min; the docs publish no table).
  Every request is followed by 429 backoff: `Retry-After` when given, else 0.7–2 s jitter, up to
  3 attempts per request. Runs over large selections are slow by design.
- Errors are decoded from the v3 envelope `{"error": {"code", "message"}}` and surfaced as
  progress messages: `AuthenticationRequiredError`, `WrongCredentialsError` (bad key),
  `QuotaExceededError` (429), `ForbiddenError` (premium-gated relationship — skipped, counted).
- Graph writes are **staged**: nothing reaches the API until the analyst reviews and commits.

## Build & publish

```bash
npx tsc --noEmit        # type-check (esbuild does NOT type-check; run this first)
node build.mjs          # esbuild → dist/pack.mjs (requires node + npx)
node gen-manifest.mjs   # regenerate plugins/virustotal-community.manifest.json from dist
```

Then commit `dist/pack.mjs` + `plugins/*.manifest.json` (build artifacts only, like every pack
repo), publish to GitHub, and pin the commit SHA in `registry/community-pluginpacks.json`.

## License

Apache-2.0
