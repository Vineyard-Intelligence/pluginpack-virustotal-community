// VirusTotal Community — free-tier v3 API enrichment and pivots for VINEYARD.
//
// KEY MODEL: every plugin uses the ANALYST'S OWN VirusTotal API key. It is declared as a
// `secret: true` config value (`api_key`) and sent only as the `x-apikey` header on calls to
// www.virustotal.com through the manifest's `network` allowlist — never in a URL, never as a
// param. The same key name is used by pluginpack-virustotal-intelligence, so a paid key works
// here unchanged.
//
// FREE-TIER BOUNDARY (verified against the docs):
//   • IP / domain / URL / file reports                     — Everyone
//   • /{obj}/{id}/resolutions (IP + domain)                — Everyone
//   • /domains/{d}/subdomains                              — Everyone
//   • /urls/{id}/redirects_to, /urls/{id}/contacted_domains — Premium ONLY → attempted, and
//     skipped+counted on 403 (never fatal). Paid features live in the intelligence pack.
//
// PLATFORM: desktop-primary. The docs never mention CORS and ship no browser samples, so a plain
// browser fetch is not assumed to work; the desktop shell's main process rewrites CORS headers,
// so ctx.net.fetch reaches VT there. In the web build these plugins fail loudly rather than
// returning a clean miss (the WhatsMyName pattern).
//
// QUOTA: free keys are heavily rate-limited. Every request retries 429 with `Retry-After` when
// present, else 0.7–2 s jitter, up to 3 attempts. Errors decode from the v3 envelope
// {"error": {"code", "message"}} and surface as progress messages.
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

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));
const abortErr = () => new Error('cancelled');
const DOMAIN_RE = /^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$/;
const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV6_RE = /^[0-9a-fA-F:]+$/;

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

/**
 * One GET against the v3 API with `x-apikey`. 429 is retried (Retry-After header, else 0.7–2 s
 * jitter) up to 3 times; other non-2xx throw a decoded VtError.
 */
async function vtGet(ctx: HostContext, path: string): Promise<unknown> {
    if (ctx.signal?.aborted) throw abortErr();
    const key = vtKey(ctx);
    let attempt = 0;
    for (;;) {
        if (ctx.signal?.aborted) throw abortErr();
        const res = await ctx.net!.fetch!(VT_BASE + path, { method: 'GET', headers: { 'x-apikey': key } });
        if (res.status === 429 && attempt < 3) {
            const ra = Number(res.headers?.['retry-after'] ?? NaN);
            const waitMs = Number.isFinite(ra) && ra > 0 ? ra * 1000 : 700 + Math.random() * 1300;
            ctx.progress?.log?.(`quota exceeded — waiting ${Math.max(1, Math.round(waitMs / 1000))}s before retrying`);
            await sleep(Math.min(waitMs, 60_000));
            attempt++;
            continue;
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
        throw new VtError(res.status, code, msg);
    }
}

/** Walk a cursor-paginated relationship/collection (limit 40/page, meta.cursor) up to maxItems. */
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
        if (!batch.length || out.length >= maxItems) break;
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

/** Unix seconds → YYYY-MM-DD (typepack `date` fields). */
function dateFromUnix(sec: unknown): string | undefined {
    return typeof sec === 'number' && Number.isFinite(sec) && sec > 0
        ? new Date(sec * 1000).toISOString().slice(0, 10)
        : undefined;
}

/** Accept 32/40/64-hex hashes, tolerating an optional `sha256:`/`0x` prefix. */
function normalizeHash(v: string): string | null {
    let s = v.trim().toLowerCase();
    s = s.replace(/^(sha256|sha1|md5)[:=]?\s*/, '').replace(/^0x/, '');
    if (!/^[a-f0-9]+$/.test(s)) return null;
    if (s.length === 32 || s.length === 40 || s.length === 64) return s;
    return null;
}

/** The `Registrar Registration Expiration Date:` line inside VT's raw WHOIS text. */
function whoisExpiry(raw: unknown): string | undefined {
    if (typeof raw !== 'string') return undefined;
    const m = raw.match(/Registrar Registration Expiration Date:\s*(\d{4}-\d{2}-\d{2})/i);
    return m?.[1];
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

/** updateNode is PATCH-style: the plugin passes the FULL merged data. */
async function updateNode(ctx: HostContext, node: GraphNode, patch: Record<string, unknown>): Promise<void> {
    await ctx.graph!.updateNode!(node.id, { ...node.data, ...patch });
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
        version: '1.0.0',
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
                if (e instanceof VtError && (e.status === 404 || e.status === 403)) {
                    misses++;
                    ctx.progress?.log?.(`${ip}: ${e.status === 404 ? 'no VirusTotal record' : e.message}`);
                    continue;
                }
                throw e;
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
                const asData: Record<string, unknown> = { autonomous_system_number: attrs.asn };
                if (typeof attrs.as_owner === 'string' && attrs.as_owner) asData.autonomous_system_name = attrs.as_owner;
                if (typeof attrs.country === 'string' && /^[A-Za-z]{2}$/.test(attrs.country)) asData.country_code = attrs.country.toUpperCase();
                const asNode = await ensureNode(ctx, 'infrastructure.autonomous_system', asData);
                await ensureEdge(ctx, n.id, asNode.id, 'announced by');
                asns++;
            }
        }
        const summary = `${enriched} of ${nodes.length} IP(s) enriched${asns ? `, ${asns} ASN link(s) added` : ''}${misses ? `, ${misses} without a VT record` : ''}`;
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
        version: '1.0.0',
        description:
            "For each selected Domain, queries VirusTotal's free-tier domain report (registrar, registration date, raw WHOIS) and folds registrar/created date into the node; creates a WHOIS Record node with expiry parsed from the WHOIS text and links it with a 'has whois' edge. Uses the analyst's own VirusTotal API key. Desktop only.",
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
                if (e instanceof VtError && (e.status === 404 || e.status === 403)) {
                    misses++;
                    ctx.progress?.log?.(`${d}: ${e.status === 404 ? 'no VirusTotal record' : e.message}`);
                    continue;
                }
                throw e;
            }
            const attrs = body?.data?.attributes ?? {};
            const patch: Record<string, unknown> = {};
            if (typeof attrs.registrar === 'string' && attrs.registrar) patch.registrar = attrs.registrar;
            const created = dateFromUnix(attrs.creation_date);
            if (created) patch.created_date = created;
            if (Object.keys(patch).length) {
                await updateNode(ctx, n, patch);
                enriched++;
            }
            const raw = typeof attrs.whois === 'string' ? attrs.whois : undefined;
            if (raw || attrs.registrar || created) {
                const whoisData: Record<string, unknown> = { subject: d };
                if (typeof attrs.registrar === 'string' && attrs.registrar) whoisData.registrar = attrs.registrar;
                if (created) whoisData.created_at = created;
                const expiry = whoisExpiry(raw);
                if (expiry) whoisData.expires_at = expiry;
                if (raw) whoisData.raw = raw;
                const wNode = await ensureNode(ctx, 'infrastructure.whois_record', whoisData);
                await ensureEdge(ctx, n.id, wNode.id, 'has whois');
                whois++;
            }
        }
        const summary = `${enriched} of ${nodes.length} domain(s) enriched${whois ? `, ${whois} WHOIS record(s) added` : ''}${misses ? `, ${misses} without a VT record` : ''}`;
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
        version: '1.0.0',
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
                if (e instanceof VtError && (e.status === 404 || e.status === 403)) {
                    misses++;
                    ctx.progress?.log?.(`${parsed.href}: ${e.status === 404 ? 'no VirusTotal record' : e.message}`);
                    continue;
                }
                throw e;
            }
            const attrs = body?.data?.attributes ?? {};
            const patch: Record<string, unknown> = {};
            if (typeof attrs.last_http_response_code === 'number') patch.http_status = attrs.last_http_response_code;
            if (typeof attrs.title === 'string' && attrs.title) patch.page_title = attrs.title;
            if (typeof attrs.last_final_url === 'string' && attrs.last_final_url) patch.final_url = attrs.last_final_url;
            if (Object.keys(patch).length) {
                await updateNode(ctx, n, patch);
                enriched++;
            }
            // last_serving_ip_address — one-to-one relationship, free tier.
            try {
                const rel = (await vtGet(ctx, `/urls/${id}/last_serving_ip_address`)) as {
                    data?: { id?: string };
                };
                const ip = rel?.data?.id;
                if (typeof ip === 'string' && (IPV4_RE.test(ip) || IPV6_RE.test(ip))) {
                    const ipNode = await ensureNode(ctx, 'infrastructure.ip_address', { ip_address: ip });
                    await ensureEdge(ctx, n.id, ipNode.id, 'resolves to');
                    ips++;
                }
            } catch (e) {
                if (e instanceof VtError && (e.status === 403 || e.status === 404)) {
                    ctx.progress?.log?.(`${parsed.href}: last serving IP ${e.status === 403 ? 'not available on this key' : 'not found'}`);
                } else {
                    throw e;
                }
            }
        }
        const summary = `${enriched} of ${nodes.length} URL(s) enriched${ips ? `, ${ips} serving IP(s) linked` : ''}${misses ? `, ${misses} without a VT record` : ''}`;
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
        version: '1.0.0',
        description:
            "Looks up SHA-256 / SHA-1 / MD5 hashes on VirusTotal's free-tier file report and creates one File Hash node per file with detection counts, vendor type description, tags and submission stats. Hashes come from selected nodes carrying them or from the text input. Uses the analyst's own VirusTotal API key. Desktop only.",
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
            consumes: [{ typepack: 'run.vineyard.typepacks.threat', category: 'threat', name: 'file_hash' }],
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
            return { summary: 'No hashes — select nodes carrying a hash or enter hashes in the Run dialog', counts: { checked: 0, created: 0, misses: 0 } };
        }
        let created = 0;
        let misses = 0;
        for (let i = 0; i < hashes.length; i++) {
            if (ctx.signal?.aborted) throw abortErr();
            const hash = hashes[i];
            ctx.progress?.set?.({ percent: Math.round((i / hashes.length) * 100), message: `Looking up ${hash}` });
            let body: any;
            try {
                body = await vtGet(ctx, `/files/${hash}`);
            } catch (e) {
                if (e instanceof VtError && (e.status === 404 || e.status === 403)) {
                    misses++;
                    ctx.progress?.log?.(`${hash}: ${e.status === 404 ? 'unknown file on VirusTotal' : e.message}`);
                    continue;
                }
                throw e;
            }
            const attrs = body?.data?.attributes ?? {};
            const stats = attrs.last_analysis_stats ?? {};
            const data: Record<string, unknown> = {
                sha256: typeof attrs.sha256 === 'string' ? attrs.sha256 : hash,
            };
            if (typeof attrs.sha1 === 'string') data.sha1 = attrs.sha1;
            if (typeof attrs.md5 === 'string') data.md5 = attrs.md5;
            if (typeof attrs.size === 'number') data.size = attrs.size;
            if (typeof attrs.type_description === 'string' && attrs.type_description) data.type_description = attrs.type_description;
            if (Array.isArray(attrs.tags) && attrs.tags.length) data.tags = attrs.tags.join(', ');
            if (typeof stats.malicious === 'number') data.malicious_count = stats.malicious;
            if (typeof stats.suspicious === 'number') data.suspicious_count = stats.suspicious;
            if (typeof stats.undetected === 'number') data.undetected_count = stats.undetected;
            if (typeof attrs.times_submitted === 'number') data.times_submitted = attrs.times_submitted;
            const firstSeen = dateFromUnix(attrs.first_submission_date);
            if (firstSeen) data.first_seen = firstSeen;
            await ensureNode(ctx, 'threat.file_hash', data);
            created++;
        }
        const summary = `${created} file(s) looked up${misses ? `, ${misses} unknown to VirusTotal` : ''}`;
        ctx.progress?.set?.({ percent: 100, message: summary });
        return { summary, counts: { checked: hashes.length, created, misses } };
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
        version: '1.0.0',
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
                    if (e instanceof VtError && (e.status === 403 || e.status === 404)) {
                        ctx.progress?.log?.(`${ip}: resolutions ${e.status === 403 ? 'not available on this key' : 'not found'}`);
                    } else {
                        throw e;
                    }
                }
            } else {
                const d = String(n.data.domain_name ?? '').trim();
                try {
                    const res = await vtPaged(ctx, `/domains/${encodeURIComponent(d)}/resolutions`);
                    for (const r of res) {
                        if (ctx.signal?.aborted) throw abortErr();
                        const attrs = r.attributes as Record<string, unknown> | undefined;
                        const addr = typeof attrs?.ip_address === 'string' ? attrs.ip_address : undefined;
                        if (addr && (IPV4_RE.test(addr) || IPV6_RE.test(addr))) {
                            const ipNode = await ensureNode(ctx, 'infrastructure.ip_address', { ip_address: addr });
                            await ensureEdge(ctx, n.id, ipNode.id, 'resolves to');
                            ips++;
                            edges++;
                        }
                    }
                } catch (e) {
                    if (e instanceof VtError && (e.status === 403 || e.status === 404)) {
                        ctx.progress?.log?.(`${d}: resolutions ${e.status === 403 ? 'not available on this key' : 'not found'}`);
                    } else {
                        throw e;
                    }
                }
            }
        }
        const summary = `${hosts} hostname(s) under IP(s) + ${ips} IP(s) under domain(s) — ${edges} edge(s)`;
        ctx.progress?.set?.({ percent: 100, message: summary });
        return { summary, counts: { checked: nodes.length, hosts, ips, edges } };
    },
});

// =============================================================================================
// 6. vt_pivot_relations — subdomains (free) + URL redirects/contacted domains (premium-gated)
// =============================================================================================
export const vtPivotRelations = definePlugin({
    manifest: {
        identifier: 'run.vineyard.plugins.vt_pivot_relations',
        content_type: 'vineyard:plugin',
        name: 'VT Pivot Relations',
        version: '1.0.0',
        description:
            "For each selected Domain, fans out its subdomains (free tier) with 'subdomain of' edges. For each selected URL, attempts 'redirects to' and 'has domain' fan-out — those two relationships are premium-only on VirusTotal and are skipped (and counted) when the key answers 403. Uses the analyst's own VirusTotal API key. Desktop only.",
        icon: 'git-branch',
        platforms: PLATFORMS,
        io: {
            consumes: [
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'infrastructure', name: 'domain' },
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'web', name: 'url' },
            ],
            produces: [
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'infrastructure', name: 'domain' },
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'web', name: 'url' },
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
        const nodes = await selectedNodesOfTypes(ctx, ['infrastructure.domain', 'web.url']);
        if (!nodes.length) return { summary: 'Select one or more Domain or URL nodes first', counts: { checked: 0, subdomains: 0, redirects: 0, contacted: 0, skipped: 0, edges: 0 } };
        let subdomains = 0;
        let redirects = 0;
        let contacted = 0;
        let skipped = 0;
        let edges = 0;
        for (let i = 0; i < nodes.length; i++) {
            if (ctx.signal?.aborted) throw abortErr();
            const n = nodes[i];
            ctx.progress?.set?.({ percent: Math.round((i / nodes.length) * 100), message: `Pivoting ${n.type}` });
            if (n.type === 'infrastructure.domain') {
                const d = String(n.data.domain_name ?? '').trim();
                try {
                    const res = await vtPaged(ctx, `/domains/${encodeURIComponent(d)}/subdomains`);
                    for (const r of res) {
                        if (ctx.signal?.aborted) throw abortErr();
                        const sub = typeof r.id === 'string' ? r.id : undefined;
                        if (sub && DOMAIN_RE.test(sub)) {
                            const subNode = await ensureNode(ctx, 'infrastructure.domain', { domain_name: sub });
                            await ensureEdge(ctx, subNode.id, n.id, 'subdomain of');
                            subdomains++;
                            edges++;
                        }
                    }
                } catch (e) {
                    if (e instanceof VtError && (e.status === 403 || e.status === 404)) {
                        skipped++;
                        ctx.progress?.log?.(`${d}: subdomains ${e.status === 403 ? 'not available on this key' : 'not found'}`);
                    } else {
                        throw e;
                    }
                }
            } else {
                const u = String(n.data.url ?? '').trim();
                let parsed: URL;
                try {
                    parsed = new URL(u);
                } catch {
                    skipped++;
                    ctx.progress?.log?.(`${u}: not a valid URL`);
                    continue;
                }
                const id = urlId(parsed.href);
                // redirects_to — premium-only; degrade on 403.
                try {
                    const res = await vtPaged(ctx, `/urls/${id}/redirects_to`);
                    for (const r of res) {
                        if (ctx.signal?.aborted) throw abortErr();
                        const attrs = r.attributes as Record<string, unknown> | undefined;
                        const target = typeof attrs?.url === 'string' ? attrs.url : undefined;
                        if (target) {
                            const uNode = await ensureNode(ctx, 'web.url', { url: target });
                            await ensureEdge(ctx, n.id, uNode.id, 'redirects to');
                            redirects++;
                            edges++;
                        }
                    }
                } catch (e) {
                    if (e instanceof VtError && (e.status === 403 || e.status === 404)) {
                        skipped++;
                        ctx.progress?.log?.(`${parsed.href}: redirects ${e.status === 403 ? 'premium-only — skipped' : 'not found'}`);
                    } else {
                        throw e;
                    }
                }
                // contacted_domains — premium-only; degrade on 403.
                try {
                    const res = await vtPaged(ctx, `/urls/${id}/contacted_domains`);
                    for (const r of res) {
                        if (ctx.signal?.aborted) throw abortErr();
                        const dom = typeof r.id === 'string' ? r.id : undefined;
                        if (dom && DOMAIN_RE.test(dom)) {
                            const dNode = await ensureNode(ctx, 'infrastructure.domain', { domain_name: dom });
                            await ensureEdge(ctx, n.id, dNode.id, 'has domain');
                            contacted++;
                            edges++;
                        }
                    }
                } catch (e) {
                    if (e instanceof VtError && (e.status === 403 || e.status === 404)) {
                        skipped++;
                        ctx.progress?.log?.(`${parsed.href}: contacted domains ${e.status === 403 ? 'premium-only — skipped' : 'not found'}`);
                    } else {
                        throw e;
                    }
                }
            }
        }
        const summary = `${subdomains} subdomain(s), ${redirects} redirect(s), ${contacted} contacted domain(s)${skipped ? ` — ${skipped} relation(s) skipped (premium/not found)` : ''}`;
        ctx.progress?.set?.({ percent: 100, message: summary });
        return { summary, counts: { checked: nodes.length, subdomains, redirects, contacted, skipped, edges } };
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
    version: '1.0.0',
    description:
        "Free-tier VirusTotal v3 enrichment and pivots using the analyst's own API key: IP/domain/URL reputation, file-hash reports, and resolution/subdomain relationship fan-out. Desktop only (VirusTotal answers no CORS headers). Paid-tier features live in pluginpack-virustotal-intelligence.",
    author: { name: 'VINEYARD', url: 'https://vineyard.run' },
    license: 'Apache-2.0',
    icon: 'radar',
    platforms: PLATFORMS,
    plugins: [vtIpReport, vtDomainReport, vtUrlReport, vtFileReport, vtPivotResolutions, vtPivotRelations],
};

export const virustotalCommunityPack = definePluginPack(pack);
export default virustotalCommunityPack;
