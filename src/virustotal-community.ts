// VirusTotal Community — free-tier v3 API enrichment and pivots for VINEYARD.
//
// KEY MODEL: every plugin uses the ANALYST'S OWN VirusTotal API key. It is declared as a
// `secret: true` config value (`api_key`) and sent only as the `x-apikey` header on calls to
// www.virustotal.com through the manifest's `network` allowlist — never in a URL, never as a
// param. A paid key works here unchanged — it simply reaches more than this pack asks for.
//
// FREE-TIER BOUNDARY — MEASURED 2026-08-14 with a key whose `GET /users/{key}` reports ZERO
// granted privileges (the check worth repeating before trusting any of this: a Google Threat
// Intelligence key answers 200 to things a community key does not, so "it worked for me" proves
// nothing about the tier this pack is for).
//
//   200 on a community key          | 403 ForbiddenError on a community key
//   ------------------------------- | -------------------------------------
//   /ip_addresses/{ip}              | /urls/{id}/redirects_to
//   /domains/{d}                    | /urls/{id}/contacted_domains
//   /urls/{id}                      |
//   /files/{hash}                   | ← both REMOVED from this pack rather than
//   /ip_addresses/{ip}/resolutions  |   attempted-and-skipped: on this tier they are
//   /domains/{d}/resolutions        |   two guaranteed-wasted requests per URL.
//   /domains/{d}/subdomains         |
//   /urls/{id}/last_serving_ip_address
//
// Every attribute these plugins read is present on a community key; what a paid key adds
// (threat_severity, exiftool, identified_brands, …) is not read here.
//
// PLATFORM: desktop-only in practice. MEASURED: VirusTotal answers no `access-control-allow-*`
// header at all (an OPTIONS preflight returns 200 with none), so a browser blocks every response.
// The desktop shell's main process writes the missing headers for origins a pack declared, so
// ctx.net.fetch reaches VT there. vtGet refuses up front on web with that reason, rather than
// letting the analyst read an opaque "Failed to fetch" (the WhatsMyName pattern).
//
// QUOTA: the community allowance is published by `GET /users/{key}` as 240/hour, 500/day,
// 15,500/month — NOT the "4 requests per minute" that gets repeated everywhere. Measured: eight
// back-to-back requests were all served 200, and VT sends no `retry-after` or `x-ratelimit-*`
// header. So the backoff (15 s / 30 s / 60 s, or `Retry-After` if one ever appears) is for a
// short-term throttle, and the throw that follows three failed attempts says the allowance is
// hourly — because no wait a plugin run can afford will clear an hour-long bucket.
//
// Graph writes are STAGED: nothing reaches the API until the analyst reviews and commits.
import { definePlugin, definePluginPack } from './sdk';
import type {
    ConfigValue,
    GraphScope,
    HostContext,
    GraphNode,
    NetworkScope,
    PluginManifest,
    RunResult,
    VineyardPluginPack,
} from './sdk';

const VT_BASE = 'https://www.virustotal.com/api/v3';
const API_KEY_LABEL = 'VirusTotal API Key';

// ---- shared manifest fragments ---------------------------------------------------------------
// Explicit annotations, not `as const`: literals widen to `string`/`string[]` inside a shared
// constant, and the manifest types are literal unions (GraphScope, HttpMethod, ConfigValue) that
// a widened string would not be assignable to. Annotating pins the literal types.
const PLATFORMS: PluginManifest['platforms'] = {
    primary: 'desktop',
    web: { runtime: 'sandbox-js', entry: 'dist/pack.mjs' },
    desktop: { runtime: 'sandbox-js', entry: 'dist/pack.mjs', min_app_version: '0.1.0' },
};
const NET_SCOPE: NetworkScope[] = [
    {
        endpoint: VT_BASE,
        methods: ['GET'],
        purpose: "VirusTotal v3 reports and relationships (free tier) — the analyst's own key via the x-apikey header.",
    },
];
const API_KEY_CONFIG: ConfigValue = {
    key: 'api_key',
    label: API_KEY_LABEL,
    type: 'string',
    secret: true,
    optional: false,
};
const GRAPH_SCOPES: GraphScope[] = ['node:read', 'node:create', 'node:update', 'edge:create'];
const LIFECYCLE: NonNullable<PluginManifest['lifecycle']> = {
    persistence: 'opt-in',
    controls: ['progress', 'cancel'],
    progress: 'determinate',
};

// ---- tiny utilities -------------------------------------------------------------------------

const abortErr = () => new Error('cancelled');

/** A wait that Cancel can cut short. A bare setTimeout leaves the run unresponsive for the whole
 *  backoff, which at 60 s reads as a hang. */
const sleep = (ms: number, signal?: AbortSignal): Promise<void> =>
    new Promise((resolve, reject) => {
        const timer = setTimeout(finish, ms);
        function finish() {
            signal?.removeEventListener('abort', onAbort);
            resolve();
        }
        function onAbort() {
            clearTimeout(timer);
            reject(abortErr());
        }
        signal?.addEventListener('abort', onAbort, { once: true });
    });

const DOMAIN_RE = /^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$/;
const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
/** A sanity screen on values VT hands back, not a parser. The colon is what keeps a bare hex
 *  string ("deadbeef") from becoming an ip_address node. */
const isIp = (v: string): boolean => IPV4_RE.test(v) || (v.includes(':') && /^[0-9a-fA-F:]+$/.test(v));

function vtKey(ctx: HostContext): string {
    const k = ctx.config?.api_key;
    if (typeof k !== 'string' || !k.trim()) {
        throw new Error(`${API_KEY_LABEL} is not set — configure it in the plugin settings first`);
    }
    return k.trim();
}

/** A decoded v3 error: `{"error": {"code", "message"}}` (introduction-errors page). */
class VtError extends Error {
    constructor(
        readonly status: number,
        readonly code: string,
        msg: string,
    ) {
        super(`${code}: ${msg} (HTTP ${status})`);
    }
}

/** 429 backoff: 15 s, 30 s, 60 s, or whatever `Retry-After` asks for — capped, so one hostile
 *  header cannot park a run for an hour. See QUOTA at the top for why this cannot be longer. */
const backoffMs = (attempt: number, retryAfterSec: number): number =>
    Math.min(60_000, Number.isFinite(retryAfterSec) && retryAfterSec > 0 ? retryAfterSec * 1000 : 15_000 * 2 ** attempt);

/**
 * One GET against the v3 API with `x-apikey`. 429 is retried up to 3 times (see backoffMs); other
 * non-2xx throw a decoded VtError, except 401 — a rejected key is the run's problem, not an item's,
 * so it ends the run with a message that names the cause instead of an error code.
 */
async function vtGet(ctx: HostContext, path: string): Promise<unknown> {
    if (ctx.signal?.aborted) throw abortErr();
    // Measured: VT sends no access-control-* headers, so in the web build every one of these calls
    // dies as a bare "Failed to fetch" with nothing pointing at the cause.
    if (ctx.run?.platform && ctx.run.platform !== 'desktop') {
        throw new Error('VirusTotal sends no CORS headers — this pack only works in the VINEYARD desktop app');
    }
    const key = vtKey(ctx);
    for (let attempt = 0; ; attempt++) {
        if (ctx.signal?.aborted) throw abortErr();
        const res = await ctx.net!.fetch!(VT_BASE + path, { method: 'GET', headers: { 'x-apikey': key } });
        if (res.status === 429) {
            if (attempt < 3) {
                const waitMs = backoffMs(attempt, Number(res.headers?.['retry-after'] ?? NaN));
                ctx.progress?.log?.(`quota exceeded — waiting ${Math.round(waitMs / 1000)}s before retrying`);
                await sleep(waitMs, ctx.signal);
                continue;
            }
            // Still throttled after ~105 s. The community allowance is hourly and daily, so the
            // answer is "come back later", not "press Run again" — say which.
            throw new Error(
                'VirusTotal quota exhausted (a community key allows 240 requests/hour and 500/day). Waiting will not help within this run — retry later, or run this over a smaller selection.',
            );
        }
        if (res.status >= 200 && res.status < 300) return res.json();
        let code = `HTTP ${res.status}`;
        let msg = '';
        try {
            const j = (await res.json()) as { error?: { code?: string; message?: string } };
            if (j?.error?.code) code = j.error.code;
            if (j?.error?.message) msg = j.error.message;
        } catch {
            /* non-JSON error body — fall back to the status line */
        }
        if (res.status === 401) throw new Error(`VirusTotal rejected this API key (${code})`);
        throw new VtError(res.status, code, msg);
    }
}

/**
 * Why this ONE item was skipped, or null when the error has to end the whole run.
 *
 * 400 is the one that mattered: VT answers `InvalidArgumentError` for a malformed IP/domain/URL id
 * (measured on `/ip_addresses/999.999.999.999`), and treating it as fatal meant a single typo'd
 * node in a selection killed every node after it.
 */
function itemMiss(e: unknown): string | null {
    if (!(e instanceof VtError)) return null;
    if (e.status === 404) return 'no VirusTotal record';
    if (e.status === 400) return `rejected by VirusTotal (${e.code})`;
    if (e.status === 403) return `not readable with this key (${e.code})`;
    return null;
}

/**
 * Walk a cursor-paginated relationship/collection (limit 40/page, meta.cursor) up to maxItems.
 *
 * The cap is SAID OUT LOUD when it bites. 8.8.8.8 has 200 resolutions and this returns 120; a run
 * that reports "120 hostname(s)" without a word about the rest reads as "that is all of them",
 * which is a different and false claim.
 */
async function vtPaged(
    ctx: HostContext,
    path: string,
    maxItems = 120,
): Promise<Array<Record<string, unknown>>> {
    const out: Array<Record<string, unknown>> = [];
    let cursor: string | undefined;
    while (!ctx.signal?.aborted) {
        const sep = path.includes('?') ? '&' : '?';
        const suffix = `limit=40${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`;
        const body = (await vtGet(ctx, `${path}${sep}${suffix}`)) as {
            data?: Array<Record<string, unknown>>;
            meta?: { cursor?: string };
        };
        const batch = Array.isArray(body?.data) ? body.data : [];
        out.push(...batch);
        if (!batch.length) break;
        if (out.length >= maxItems) {
            // A cursor here means VT still has pages; without one the cap and the total coincide.
            if (body?.meta?.cursor) {
                ctx.progress?.log?.(`${path}: stopped at the first ${maxItems} — VirusTotal has more`);
            }
            break;
        }
        cursor = body?.meta?.cursor;
        if (!cursor) break;
    }
    return out.slice(0, maxItems);
}

/** The v3 URL object id: base64url of the URL with padding stripped (urls.md recommends this). */
function urlId(u: string): string {
    const bytes = new TextEncoder().encode(u);
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Unix seconds → ISO-8601 (typepack `datetime` fields). */
function datetimeFromUnix(sec: unknown): string | undefined {
    return typeof sec === 'number' && Number.isFinite(sec) && sec > 0
        ? new Date(sec * 1000).toISOString()
        : undefined;
}

/** Unix seconds → YYYY-MM-DD (typepack `date` fields). */
function dateFromUnix(sec: unknown): string | undefined {
    return datetimeFromUnix(sec)?.slice(0, 10);
}

/** Accept 32/40/64-hex hashes, tolerating an optional `sha256:`/`0x` prefix. */
function normalizeHash(v: string): string | null {
    let s = v.trim().toLowerCase();
    s = s.replace(/^(sha256|sha1|md5)[:=]?\s*/, '').replace(/^0x/, '');
    if (!/^[a-f0-9]+$/.test(s)) return null;
    if (s.length === 32 || s.length === 40 || s.length === 64) return s;
    return null;
}

async function selectedNodesOfTypes(ctx: HostContext, types: string[]): Promise<GraphNode[]> {
    const out: GraphNode[] = [];
    for (const id of ctx.input.selection ?? []) {
        if (ctx.signal?.aborted) throw abortErr();
        const n = await ctx.graph?.get?.(id);
        if (n && types.includes(n.type)) out.push(n);
    }
    return out;
}

/**
 * updateNode takes a DELTA — the fields THIS run filled, and nothing else.
 *
 * The host stages a plugin's `data` as a delta and fill-merges it onto whatever is live at commit
 * time. Passing `{ ...node.data, ...patch }` re-submits every field as it looked when this run
 * started, so a field another run changed in between is silently rolled back at commit. That is
 * the "plugin A's value overwritten by plugin B" bug, and it is why `node` is not spread here.
 */
async function updateNode(ctx: HostContext, node: GraphNode, patch: Record<string, unknown>): Promise<void> {
    await ctx.graph!.updateNode!(node.id, patch);
}

async function ensureNode(ctx: HostContext, type: string, data: Record<string, unknown>): Promise<GraphNode> {
    return ctx.graph!.createNode!({ type, data });
}

async function ensureEdge(ctx: HostContext, from: string, to: string, label: string): Promise<void> {
    await ctx.graph!.createEdge!({ from, to, label });
}

// =============================================================================================
// 1. vt_ip_report — IP reputation / ASN enrichment
// =============================================================================================
export const vtIpReport = definePlugin({
    manifest: {
        identifier: 'run.vineyard.plugins.vt_ip_report',
        content_type: 'vineyard:plugin',
        name: 'VT IP Report',
        version: '1.1.0',
        description:
            "For each selected IP Address, queries VirusTotal's free-tier IP report (country, ASN, owner) and folds it into the node; creates an Autonomous System node for the ASN and links it with an 'announced by' edge. Uses the analyst's own VirusTotal API key (x-apikey). Desktop only (VT sends no CORS headers).",
        icon: 'radar',
        platforms: PLATFORMS,
        io: {
            consumes: [{ typepack: 'run.vineyard.typepacks.infrastructure', category: 'infrastructure', name: 'ip_address' }],
            produces: [{ typepack: 'run.vineyard.typepacks.infrastructure', category: 'infrastructure', name: 'autonomous_system' }],
        },
        scopes: {
            graph: GRAPH_SCOPES,
            network: NET_SCOPE,
            config: [API_KEY_CONFIG],
        },
        lifecycle: LIFECYCLE,
    },
    async run(ctx): Promise<RunResult> {
        const nodes = await selectedNodesOfTypes(ctx, ['infrastructure.ip_address']);
        if (!nodes.length) return { summary: 'Select one or more IP Address nodes first', counts: { checked: 0, enriched: 0, asns: 0, misses: 0 } };
        let enriched = 0;
        let asns = 0;
        let misses = 0;
        for (let i = 0; i < nodes.length; i++) {
            if (ctx.signal?.aborted) throw abortErr();
            const n = nodes[i];
            const ip = String(n.data.ip_address ?? '').trim();
            ctx.progress?.set?.({ percent: Math.round((i / nodes.length) * 100), message: `Checking ${ip}` });
            let body: any;
            try {
                body = await vtGet(ctx, `/ip_addresses/${encodeURIComponent(ip)}`);
            } catch (e) {
                const why = itemMiss(e);
                if (!why) throw e;
                misses++;
                ctx.progress?.log?.(`${ip}: ${why}`);
                continue;
            }
            const attrs = body?.data?.attributes ?? {};
            const patch: Record<string, unknown> = {};
            if (typeof attrs.country === 'string' && /^[A-Za-z]{2}$/.test(attrs.country)) patch.country_code = attrs.country.toUpperCase();
            if (typeof attrs.asn === 'number' && Number.isFinite(attrs.asn)) patch.asn = `AS${attrs.asn}`;
            if (typeof attrs.as_owner === 'string' && attrs.as_owner) patch.organization = attrs.as_owner;
            if (Object.keys(patch).length) {
                await updateNode(ctx, n, patch);
                enriched++;
            }
            if (typeof attrs.asn === 'number' && Number.isFinite(attrs.asn)) {
                // No country_code on the AS node. `attrs.country` is where THIS IP geolocates;
                // autonomous_system.country_code is declared "country of registration", and the AS
                // node's identity is the ASN alone — so one Cloudflare IP in Seoul would otherwise
                // rewrite AS13335's registered country for every pack that reads it.
                const asData: Record<string, unknown> = { autonomous_system_number: attrs.asn };
                if (typeof attrs.as_owner === 'string' && attrs.as_owner) asData.autonomous_system_name = attrs.as_owner;
                const asNode = await ensureNode(ctx, 'infrastructure.autonomous_system', asData);
                await ensureEdge(ctx, n.id, asNode.id, 'announced by');
                asns++;
            }
        }
        const summary = `${enriched} of ${nodes.length} IP(s) enriched${asns ? `, ${asns} ASN link(s) added` : ''}${misses ? `, ${misses} skipped` : ''}`;
        ctx.progress?.set?.({ percent: 100, message: summary });
        return { summary, counts: { checked: nodes.length, enriched, asns, misses } };
    },
});

// =============================================================================================
// 2. vt_domain_report — domain reputation / WHOIS enrichment
// =============================================================================================
export const vtDomainReport = definePlugin({
    manifest: {
        identifier: 'run.vineyard.plugins.vt_domain_report',
        content_type: 'vineyard:plugin',
        name: 'VT Domain Report',
        version: '1.1.0',
        description:
            "For each selected Domain, queries VirusTotal's free-tier domain report (registrar, registration and expiry dates, raw WHOIS) and folds registrar/created/expiry into the node; creates a WHOIS Record node carrying the same dates plus the raw WHOIS text and links it with a 'has whois' edge. Uses the analyst's own VirusTotal API key. Desktop only.",
        icon: 'globe',
        platforms: PLATFORMS,
        io: {
            consumes: [{ typepack: 'run.vineyard.typepacks.infrastructure', category: 'infrastructure', name: 'domain' }],
            produces: [{ typepack: 'run.vineyard.typepacks.infrastructure', category: 'infrastructure', name: 'whois_record' }],
        },
        scopes: {
            graph: GRAPH_SCOPES,
            network: NET_SCOPE,
            config: [API_KEY_CONFIG],
        },
        lifecycle: LIFECYCLE,
    },
    async run(ctx): Promise<RunResult> {
        const nodes = await selectedNodesOfTypes(ctx, ['infrastructure.domain']);
        if (!nodes.length) return { summary: 'Select one or more Domain nodes first', counts: { checked: 0, enriched: 0, whois: 0, misses: 0 } };
        let enriched = 0;
        let whois = 0;
        let misses = 0;
        for (let i = 0; i < nodes.length; i++) {
            if (ctx.signal?.aborted) throw abortErr();
            const n = nodes[i];
            const d = String(n.data.domain_name ?? '').trim();
            ctx.progress?.set?.({ percent: Math.round((i / nodes.length) * 100), message: `Checking ${d}` });
            let body: any;
            try {
                body = await vtGet(ctx, `/domains/${encodeURIComponent(d)}`);
            } catch (e) {
                const why = itemMiss(e);
                if (!why) throw e;
                misses++;
                ctx.progress?.log?.(`${d}: ${why}`);
                continue;
            }
            const attrs = body?.data?.attributes ?? {};
            const patch: Record<string, unknown> = {};
            if (typeof attrs.registrar === 'string' && attrs.registrar) patch.registrar = attrs.registrar;
            const created = dateFromUnix(attrs.creation_date);
            if (created) patch.created_date = created;
            // `expiration_date` is a plain unix field on the report. This used to be scraped out of
            // the raw WHOIS text by matching `Registrar Registration Expiration Date:` — a
            // registrar-specific label that the standard gTLD spelling (`Registry Expiry Date:`)
            // and every ccTLD variant miss, so expiry was blank for most domains for no reason.
            const expires = dateFromUnix(attrs.expiration_date);
            if (expires) patch.expiration_date = expires;
            if (Object.keys(patch).length) {
                await updateNode(ctx, n, patch);
                enriched++;
            }
            const raw = typeof attrs.whois === 'string' ? attrs.whois : undefined;
            if (raw || attrs.registrar || created) {
                const whoisData: Record<string, unknown> = { subject: d };
                if (typeof attrs.registrar === 'string' && attrs.registrar) whoisData.registrar = attrs.registrar;
                if (created) whoisData.created_at = created;
                if (expires) whoisData.expires_at = expires;
                if (raw) whoisData.raw = raw;
                const wNode = await ensureNode(ctx, 'infrastructure.whois_record', whoisData);
                await ensureEdge(ctx, n.id, wNode.id, 'has whois');
                whois++;
            }
        }
        const summary = `${enriched} of ${nodes.length} domain(s) enriched${whois ? `, ${whois} WHOIS record(s) added` : ''}${misses ? `, ${misses} skipped` : ''}`;
        ctx.progress?.set?.({ percent: 100, message: summary });
        return { summary, counts: { checked: nodes.length, enriched, whois, misses } };
    },
});

// =============================================================================================
// 3. vt_url_report — URL reputation + last serving IP
// =============================================================================================
export const vtUrlReport = definePlugin({
    manifest: {
        identifier: 'run.vineyard.plugins.vt_url_report',
        content_type: 'vineyard:plugin',
        name: 'VT URL Report',
        version: '1.1.0',
        description:
            "For each selected URL, queries VirusTotal's free-tier URL report (HTTP status, page title, final URL) and folds it into the node; also resolves the last serving IP (a free-tier relationship) and links it with a 'resolves to' edge. Uses the analyst's own VirusTotal API key. Desktop only.",
        icon: 'link',
        platforms: PLATFORMS,
        io: {
            consumes: [{ typepack: 'run.vineyard.typepacks.infrastructure', category: 'web', name: 'url' }],
            produces: [{ typepack: 'run.vineyard.typepacks.infrastructure', category: 'infrastructure', name: 'ip_address' }],
        },
        scopes: {
            graph: GRAPH_SCOPES,
            network: NET_SCOPE,
            config: [API_KEY_CONFIG],
        },
        lifecycle: LIFECYCLE,
    },
    async run(ctx): Promise<RunResult> {
        const nodes = await selectedNodesOfTypes(ctx, ['web.url']);
        if (!nodes.length) return { summary: 'Select one or more URL nodes first', counts: { checked: 0, enriched: 0, ips: 0, misses: 0 } };
        let enriched = 0;
        let ips = 0;
        let misses = 0;
        for (let i = 0; i < nodes.length; i++) {
            if (ctx.signal?.aborted) throw abortErr();
            const n = nodes[i];
            const u = String(n.data.url ?? '').trim();
            let parsed: URL;
            try {
                parsed = new URL(u);
            } catch {
                misses++;
                ctx.progress?.log?.(`${u}: not a valid URL`);
                continue;
            }
            const id = urlId(parsed.href);
            ctx.progress?.set?.({ percent: Math.round((i / nodes.length) * 100), message: `Checking ${parsed.href}` });
            let body: any;
            try {
                body = await vtGet(ctx, `/urls/${id}`);
            } catch (e) {
                const why = itemMiss(e);
                if (!why) throw e;
                misses++;
                ctx.progress?.log?.(`${parsed.href}: ${why}`);
                continue;
            }
            const attrs = body?.data?.attributes ?? {};
            const patch: Record<string, unknown> = {};
            // web.url.http_status is declared 100..599 and the host REFUSES a write outside it, so
            // VT's 0 for "seen but never fetched" would take the whole run down with it.
            if (typeof attrs.last_http_response_code === 'number' && attrs.last_http_response_code >= 100 && attrs.last_http_response_code <= 599) {
                patch.http_status = attrs.last_http_response_code;
            }
            if (typeof attrs.title === 'string' && attrs.title) patch.page_title = attrs.title;
            if (typeof attrs.last_final_url === 'string' && attrs.last_final_url) patch.final_url = attrs.last_final_url;
            if (Object.keys(patch).length) {
                await updateNode(ctx, n, patch);
                enriched++;
            }
            // last_serving_ip_address — one-to-one relationship, measured 200 on a free key.
            try {
                const rel = (await vtGet(ctx, `/urls/${id}/last_serving_ip_address`)) as {
                    data?: { id?: string };
                };
                const ip = rel?.data?.id;
                if (typeof ip === 'string' && isIp(ip)) {
                    const ipNode = await ensureNode(ctx, 'infrastructure.ip_address', { ip_address: ip });
                    await ensureEdge(ctx, n.id, ipNode.id, 'resolves to');
                    ips++;
                }
            } catch (e) {
                const why = itemMiss(e);
                if (!why) throw e;
                ctx.progress?.log?.(`${parsed.href}: last serving IP — ${why}`);
            }
        }
        const summary = `${enriched} of ${nodes.length} URL(s) enriched${ips ? `, ${ips} serving IP(s) linked` : ''}${misses ? `, ${misses} skipped` : ''}`;
        ctx.progress?.set?.({ percent: 100, message: summary });
        return { summary, counts: { checked: nodes.length, enriched, ips, misses } };
    },
});

// =============================================================================================
// 4. vt_file_report — hashes → threat.file_hash nodes
// =============================================================================================
export const vtFileReport = definePlugin({
    manifest: {
        identifier: 'run.vineyard.plugins.vt_file_report',
        content_type: 'vineyard:plugin',
        name: 'VT File Report',
        version: '1.1.0',
        description:
            "Looks up SHA-256 / SHA-1 / MD5 hashes on VirusTotal's file report — detection counts, vendor type description, tags and submission stats. A selected File Hash node is enriched in place (even when it only carried an MD5); anything else that named the hash, such as a Malware node, gets a 'has hash' edge to the File Hash node. Hashes can also be pasted into the Run dialog. Uses the analyst's own VirusTotal API key. Desktop only.",
        icon: 'file-digit',
        platforms: PLATFORMS,
        params: {
            type: 'object',
            properties: {
                hashes: {
                    type: 'string',
                    title: 'Hashes',
                    description:
                        'Optional. SHA-256 / SHA-1 / MD5 hashes — one per line or comma-separated. Used in addition to any selected nodes that carry a hash.',
                },
            },
        },
        io: {
            // `malware` is here because the hash-harvesting loop reads `hash_sha256`/`hash_sha1`/
            // `hash_md5`, which are threat.malware's property names — and `consumes` is what the Run
            // dialog filters targets by, so leaving it out made that half of the loop unreachable
            // from the UI (an agent passing node_ids could still hit it).
            consumes: [
                { typepack: 'run.vineyard.typepacks.threat', category: 'threat', name: 'file_hash' },
                { typepack: 'run.vineyard.typepacks.threat', category: 'threat', name: 'malware' },
            ],
            produces: [{ typepack: 'run.vineyard.typepacks.threat', category: 'threat', name: 'file_hash' }],
        },
        scopes: {
            graph: GRAPH_SCOPES,
            network: NET_SCOPE,
            config: [API_KEY_CONFIG],
        },
        lifecycle: LIFECYCLE,
    },
    async run(ctx): Promise<RunResult> {
        const seen = new Set<string>();
        // WHICH NODE each hash came off. Without this the report is written to a node the analyst
        // never selected: `createNode` de-dups on type + sha256, which only coincides with the
        // source when the source is ALREADY a file_hash that ALREADY carries the sha256. A
        // file_hash holding just an md5, or a malware node holding `hash_sha256` (a key this very
        // loop reads), matched nothing — so everything VirusTotal returned landed on a brand-new,
        // unconnected node while the selected one stayed empty. It reads as "the run threw the
        // data away", and from where the analyst is sitting it did.
        const sources = new Map<string, GraphNode[]>();
        const remember = (h: string, n: GraphNode) => sources.set(h, [...(sources.get(h) ?? []), n]);
        for (const id of ctx.input.selection ?? []) {
            if (ctx.signal?.aborted) throw abortErr();
            const n = await ctx.graph?.get?.(id);
            if (!n) continue;
            for (const k of ['sha256', 'sha1', 'md5', 'hash_sha256', 'hash_sha1', 'hash_md5']) {
                const v = (n.data as Record<string, unknown>)?.[k];
                if (typeof v === 'string') {
                    const h = normalizeHash(v);
                    if (h) {
                        seen.add(h);
                        remember(h, n);
                        break;
                    }
                }
            }
        }
        const hashesParam = ctx.params?.hashes;
        if (typeof hashesParam === 'string') {
            for (const part of hashesParam.split(/[\s,]+/)) {
                const h = normalizeHash(part);
                if (h) seen.add(h);
            }
        }
        const hashes = [...seen];
        if (!hashes.length) {
            return { summary: 'No hashes — select nodes carrying a hash or enter hashes in the Run dialog', counts: { checked: 0, created: 0, enriched: 0, linked: 0, misses: 0 } };
        }
        let enriched = 0;
        let linked = 0;
        let created = 0;
        let misses = 0;
        // Every hash of a file already fetched. A report pasted into the dialog routinely lists the
        // md5 AND the sha256 of the same sample; without this each costs one of a free key's four
        // requests per minute, and the run reports "2 file(s)" for one file.
        const fetched = new Set<string>();
        for (let i = 0; i < hashes.length; i++) {
            if (ctx.signal?.aborted) throw abortErr();
            const hash = hashes[i];
            if (fetched.has(hash)) continue;
            ctx.progress?.set?.({ percent: Math.round((i / hashes.length) * 100), message: `Looking up ${hash}` });
            let body: any;
            try {
                body = await vtGet(ctx, `/files/${hash}`);
            } catch (e) {
                const why = itemMiss(e);
                if (!why) throw e;
                misses++;
                ctx.progress?.log?.(`${hash}: ${why === 'no VirusTotal record' ? 'unknown file on VirusTotal' : why}`);
                continue;
            }
            const attrs = body?.data?.attributes ?? {};
            const stats = attrs.last_analysis_stats ?? {};
            // threat.file_hash's identity IS the SHA-256, and the host refuses anything that is not
            // 64 hex. Looking a file up BY its md5 would otherwise put the md5 in the sha256 field.
            const sha256 = typeof attrs.sha256 === 'string' ? attrs.sha256 : hash;
            if (!/^[a-f0-9]{64}$/i.test(sha256)) {
                misses++;
                ctx.progress?.log?.(`${hash}: VirusTotal returned no SHA-256 for this file`);
                continue;
            }
            for (const h of [attrs.sha256, attrs.sha1, attrs.md5]) {
                if (typeof h === 'string') fetched.add(h.toLowerCase());
            }
            const data: Record<string, unknown> = { sha256 };
            if (typeof attrs.sha1 === 'string') data.sha1 = attrs.sha1;
            if (typeof attrs.md5 === 'string') data.md5 = attrs.md5;
            if (typeof attrs.size === 'number') data.size = attrs.size;
            if (typeof attrs.type_description === 'string' && attrs.type_description) data.type_description = attrs.type_description;
            if (Array.isArray(attrs.tags) && attrs.tags.length) data.tags = attrs.tags.join(', ');
            if (typeof stats.malicious === 'number') data.malicious_count = stats.malicious;
            if (typeof stats.suspicious === 'number') data.suspicious_count = stats.suspicious;
            if (typeof stats.undetected === 'number') data.undetected_count = stats.undetected;
            if (typeof attrs.times_submitted === 'number') data.times_submitted = attrs.times_submitted;
            const firstSeen = datetimeFromUnix(attrs.first_submission_date); // declared `datetime`, not `date`
            if (firstSeen) data.first_seen = firstSeen;

            // Relate the report to whatever the analyst actually selected. Every node that carried
            // ANY of this file's three hashes counts, not just the one whose hash was looked up —
            // the `fetched` de-dup above means the other two never get their own turn.
            const owners = [attrs.sha256, attrs.sha1, attrs.md5, hash].flatMap((h) =>
                typeof h === 'string' ? sources.get(h.toLowerCase()) ?? [] : [],
            );
            const byId = new Map(owners.map((n) => [n.id, n]));
            // A selected file_hash IS this file — enrich it in place. Creating instead would hand
            // back a second file_hash node whenever the selected one lacked the sha256, leaving the
            // analyst with a duplicate and an untouched original.
            const selfNodes = [...byId.values()].filter((n) => n.type === 'threat.file_hash');
            for (const n of selfNodes) {
                await updateNode(ctx, n, data);
                enriched++;
            }
            // Nothing selected was the file itself, so the file needs a node of its own; anything
            // else that named the hash (a malware node's hash_sha256, say) links to it.
            const fileNode = selfNodes.length ? selfNodes[0] : await ensureNode(ctx, 'threat.file_hash', data);
            if (!selfNodes.length) created++;
            for (const n of byId.values()) {
                if (n.type === 'threat.file_hash') continue; // enriched in place above — same entity
                await ensureEdge(ctx, n.id, fileNode.id, 'has hash');
                linked++;
            }
        }
        const total = created + enriched;
        const summary = `${total} file(s) looked up${enriched ? `, ${enriched} folded into the selected node(s)` : ''}${
            linked ? `, ${linked} link(s) added` : ''
        }${misses ? `, ${misses} skipped` : ''}`;
        ctx.progress?.set?.({ percent: 100, message: summary });
        return { summary, counts: { checked: hashes.length, created, enriched, linked, misses } };
    },
});

// =============================================================================================
// 5. vt_pivot_resolutions — IP ↔ domain resolution fan-out (free tier)
// =============================================================================================
export const vtPivotResolutions = definePlugin({
    manifest: {
        identifier: 'run.vineyard.plugins.vt_pivot_resolutions',
        content_type: 'vineyard:plugin',
        name: 'VT Pivot Resolutions',
        version: '1.1.0',
        description:
            "For each selected IP Address or Domain, fans out VirusTotal's free-tier resolutions (hostnames an IP served, IPs a domain resolved to) and creates the missing nodes, linking both directions with 'resolves to' edges. Uses the analyst's own VirusTotal API key. Desktop only.",
        icon: 'git-fork',
        platforms: PLATFORMS,
        io: {
            consumes: [
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'infrastructure', name: 'ip_address' },
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'infrastructure', name: 'domain' },
            ],
            produces: [
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'infrastructure', name: 'domain' },
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'infrastructure', name: 'ip_address' },
            ],
        },
        scopes: {
            graph: GRAPH_SCOPES,
            network: NET_SCOPE,
            config: [API_KEY_CONFIG],
        },
        lifecycle: LIFECYCLE,
    },
    async run(ctx): Promise<RunResult> {
        const nodes = await selectedNodesOfTypes(ctx, ['infrastructure.ip_address', 'infrastructure.domain']);
        if (!nodes.length) return { summary: 'Select one or more IP Address or Domain nodes first', counts: { checked: 0, hosts: 0, ips: 0, edges: 0 } };
        let hosts = 0;
        let ips = 0;
        let edges = 0;
        for (let i = 0; i < nodes.length; i++) {
            if (ctx.signal?.aborted) throw abortErr();
            const n = nodes[i];
            ctx.progress?.set?.({ percent: Math.round((i / nodes.length) * 100), message: `Pivoting ${n.type}` });
            if (n.type === 'infrastructure.ip_address') {
                const ip = String(n.data.ip_address ?? '').trim();
                try {
                    const res = await vtPaged(ctx, `/ip_addresses/${encodeURIComponent(ip)}/resolutions`);
                    for (const r of res) {
                        if (ctx.signal?.aborted) throw abortErr();
                        const host = r.attributes as Record<string, unknown> | undefined;
                        const hostName = typeof host?.host_name === 'string' ? host.host_name : undefined;
                        if (hostName && DOMAIN_RE.test(hostName)) {
                            const dNode = await ensureNode(ctx, 'infrastructure.domain', { domain_name: hostName });
                            await ensureEdge(ctx, dNode.id, n.id, 'resolves to');
                            hosts++;
                            edges++;
                        }
                    }
                } catch (e) {
                    const why = itemMiss(e);
                    if (!why) throw e;
                    ctx.progress?.log?.(`${ip}: resolutions — ${why}`);
                }
            } else {
                const d = String(n.data.domain_name ?? '').trim();
                try {
                    const res = await vtPaged(ctx, `/domains/${encodeURIComponent(d)}/resolutions`);
                    for (const r of res) {
                        if (ctx.signal?.aborted) throw abortErr();
                        const attrs = r.attributes as Record<string, unknown> | undefined;
                        const addr = typeof attrs?.ip_address === 'string' ? attrs.ip_address : undefined;
                        if (addr && isIp(addr)) {
                            const ipNode = await ensureNode(ctx, 'infrastructure.ip_address', { ip_address: addr });
                            await ensureEdge(ctx, n.id, ipNode.id, 'resolves to');
                            ips++;
                            edges++;
                        }
                    }
                } catch (e) {
                    const why = itemMiss(e);
                    if (!why) throw e;
                    ctx.progress?.log?.(`${d}: resolutions — ${why}`);
                }
            }
        }
        const summary = `${hosts} hostname(s) under IP(s) + ${ips} IP(s) under domain(s) — ${edges} edge(s)`;
        ctx.progress?.set?.({ percent: 100, message: summary });
        return { summary, counts: { checked: nodes.length, hosts, ips, edges } };
    },
});

// =============================================================================================
// 6. vt_pivot_relations — domain subdomain fan-out
//
// This used to also fan URLs out over `redirects_to` and `contacted_domains`. Both are 403
// ForbiddenError on a community key (measured; the body even names the relationship in
// `meta.relationship`), so on the tier this pack is FOR they were two guaranteed-wasted requests
// per URL and a "2 relation(s) skipped" line on every run. Removed rather than skipped — a
// capability an analyst can never exercise is not a graceful degradation, it is a dead menu entry
// that costs quota to discover. They belong in a paid-key pack.
// =============================================================================================
export const vtPivotRelations = definePlugin({
    manifest: {
        identifier: 'run.vineyard.plugins.vt_pivot_relations',
        content_type: 'vineyard:plugin',
        name: 'VT Subdomains',
        version: '1.1.0',
        description:
            "For each selected Domain, fans out the subdomains VirusTotal knows about and links each one back with a 'subdomain of' edge. Answers on a free community key. Uses the analyst's own VirusTotal API key. Desktop only.",
        icon: 'git-branch',
        platforms: PLATFORMS,
        io: {
            consumes: [
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'infrastructure', name: 'domain' },
            ],
            produces: [
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'infrastructure', name: 'domain' },
            ],
        },
        scopes: {
            graph: GRAPH_SCOPES,
            network: NET_SCOPE,
            config: [API_KEY_CONFIG],
        },
        lifecycle: LIFECYCLE,
    },
    async run(ctx): Promise<RunResult> {
        const nodes = await selectedNodesOfTypes(ctx, ['infrastructure.domain']);
        if (!nodes.length) return { summary: 'Select one or more Domain nodes first', counts: { checked: 0, subdomains: 0, skipped: 0, edges: 0 } };
        let subdomains = 0;
        let skipped = 0;
        let edges = 0;
        for (let i = 0; i < nodes.length; i++) {
            if (ctx.signal?.aborted) throw abortErr();
            const n = nodes[i];
            const d = String(n.data.domain_name ?? '').trim();
            ctx.progress?.set?.({ percent: Math.round((i / nodes.length) * 100), message: `Subdomains of ${d}` });
            try {
                const res = await vtPaged(ctx, `/domains/${encodeURIComponent(d)}/subdomains`);
                for (const r of res) {
                    if (ctx.signal?.aborted) throw abortErr();
                    const sub = typeof r.id === 'string' ? r.id : undefined;
                    // A wildcard name ("*.example.com") fails infrastructure.domain's declared
                    // format, and one refused write ends the run — DOMAIN_RE screens it out here.
                    if (sub && DOMAIN_RE.test(sub)) {
                        const subNode = await ensureNode(ctx, 'infrastructure.domain', { domain_name: sub });
                        await ensureEdge(ctx, subNode.id, n.id, 'subdomain of');
                        subdomains++;
                        edges++;
                    }
                }
            } catch (e) {
                const why = itemMiss(e);
                if (!why) throw e;
                skipped++;
                ctx.progress?.log?.(`${d}: subdomains — ${why}`);
            }
        }
        const summary = `${subdomains} subdomain(s) under ${nodes.length} domain(s)${skipped ? ` — ${skipped} skipped` : ''}`;
        ctx.progress?.set?.({ percent: 100, message: summary });
        return { summary, counts: { checked: nodes.length, subdomains, skipped, edges } };
    },
});

// =============================================================================================
// Pack
// =============================================================================================
// Declared as a variable with an explicit type, not a literal argument: VineyardPluginPack's
// interface omits author/license/icon/platforms (a fresh object literal would trip the
// excess-property check), and a bare variable would widen content_type to plain `string` (a
// literal-union mismatch). The annotation pins the literal and keeps the extra metadata, which
// gen-manifest.mjs spreads into the catalog JSON.
const pack: VineyardPluginPack & {
    author: { name: string; url: string };
    license: string;
    icon: string;
    platforms: PluginManifest['platforms'];
} = {
    identifier: 'run.vineyard.pluginpacks.virustotal_community',
    content_type: 'vineyard:pluginpack',
    name: 'VirusTotal Community',
    version: '1.1.0',
    description:
        "VirusTotal v3 enrichment and pivots using the analyst's own API key, scoped to what a free community key can actually read (verified against one): IP/domain/URL reports, file-hash reports, passive-DNS resolutions and subdomain fan-out. Relationships that need a paid key are not included rather than attempted and skipped. Desktop only (VirusTotal answers no CORS headers).",
    author: { name: 'VINEYARD', url: 'https://vineyard.run' },
    license: 'Apache-2.0',
    icon: 'radar',
    platforms: PLATFORMS,
    plugins: [vtIpReport, vtDomainReport, vtUrlReport, vtFileReport, vtPivotResolutions, vtPivotRelations],
};

export const virustotalCommunityPack = definePluginPack(pack);
export default virustotalCommunityPack;
