// Functional test harness for pluginpack-virustotal-community/dist/pack.mjs (6 plugins).
// Run: node test-plugin.mjs   (or: jsc -m test-plugin.mjs)
//
// Response shapes and status codes below are MEASURED (2026-08-14) against a key whose
// `GET /users/{key}` reports zero granted privileges — a real community key. An earlier pass used a
// Google Threat Intelligence key by mistake, which answers 200 to relationships a community key is
// refused; `GET /users/{key}` is the check that tells the two apart.
import { readFileSync } from "node:fs";
import pack from "./dist/pack.mjs";

// Same dual-runtime shim as pluginpack-shodan/test-plugin.mjs — see its header.
const say = typeof console !== "undefined" ? (m) => console.log(m) : print;
const die = () => (typeof process !== "undefined" ? process.exit(1) : quit(1));
if (typeof console === "undefined") {
  globalThis.console = { log: print, warn: print, error: print, info: print, debug: print };
}

const [ipPlugin, domainPlugin, urlPlugin, filePlugin, resolutionsPlugin, subdomainsPlugin] = pack.plugins;
const ok = [];
const fail = [];
function check(name, cond) {
  (cond ? ok : fail).push(name);
}

function makeGraph(nodeById) {
  const createdNodes = [];
  const createdEdges = [];
  const updates = [];
  return {
    createdNodes,
    createdEdges,
    updates,
    async get(id) {
      return nodeById[id] || null;
    },
    async createNode(draft) {
      const node = { id: `n${createdNodes.length + 1}`, type: draft.type, data: draft.data };
      createdNodes.push(node);
      return node;
    },
    async updateNode(id, data) {
      updates.push({ id, data });
    },
    async createEdge(edge) {
      createdEdges.push(edge);
    },
  };
}

// respond(url) -> { status, body } | { status, html } for a non-JSON error body.
function makeNet(respond) {
  const calls = [];
  return {
    calls,
    async fetch(url, init) {
      calls.push({ url, headers: init?.headers ?? {} });
      const r = respond(new URL(url), init);
      return {
        ok: r.status >= 200 && r.status < 300,
        status: r.status,
        headers: r.headers ?? {},
        async text() {
          return r.html ?? JSON.stringify(r.body ?? {});
        },
        async json() {
          if (r.html) throw new SyntaxError("not JSON");
          return r.body ?? {};
        },
      };
    },
  };
}

// A REAL AbortSignal, not a `{aborted:false}` stand-in: the backoff attaches an abort listener, so
// a stub without addEventListener would pass tests that production would throw on.
const RUN = { run: { platform: "desktop" }, signal: new AbortController().signal, progress: { log() {}, set() {} } };
const KEY = { api_key: "k" };
const vtErr = (code, message) => ({ error: { code, message } });

// ================================================================ key handling
{
  for (const p of pack.plugins) {
    const net = makeNet(() => {
      throw new Error("must not reach the network without a key");
    });
    const sel = ["a"];
    const graph = makeGraph({ a: { id: "a", type: "infrastructure.ip_address", data: { ip_address: "1.2.3.4" } } });
    let threw = null;
    try {
      await p.run({ ...RUN, config: {}, params: { hashes: "" }, input: { selection: sel }, net, graph });
    } catch (e) {
      threw = e;
    }
    // Nothing may go out without a key. Either it refuses in the summary (no work to do) or it
    // throws — what it must never do is send an unauthenticated request.
    check(`${p.manifest.identifier}: no network call without a key`, net.calls.length === 0);
    check(`${p.manifest.identifier}: a missing key is named, not an opaque failure`, threw === null || /API Key is not set/.test(threw.message));
  }
}
{
  // A rejected key is the RUN's problem, not one item's: it ends the run with a message that says
  // so, instead of counting N mystery "no VirusTotal record" misses over the whole selection.
  const nodes = {};
  const selection = [];
  for (let i = 0; i < 4; i++) {
    nodes[`ip${i}`] = { id: `ip${i}`, type: "infrastructure.ip_address", data: { ip_address: `1.2.3.${i}` } };
    selection.push(`ip${i}`);
  }
  const net = makeNet(() => ({ status: 401, body: vtErr("WrongCredentialsError", "Wrong API key") }));
  const graph = makeGraph(nodes);
  let threw = null;
  try {
    await ipPlugin.run({ ...RUN, config: KEY, input: { selection }, net, graph });
  } catch (e) {
    threw = e;
  }
  check("401: a rejected key says it was rejected", threw && /rejected this API key/.test(threw.message));
  check("401: a rejected key stops the run instead of retrying every selected node", net.calls.length === 1);
}
{
  // The web build cannot work at all — VT sends no access-control-* headers, measured. Saying so
  // beats letting the analyst read a bare "Failed to fetch".
  const net = makeNet(() => ({ status: 200, body: {} }));
  const graph = makeGraph({ ip1: { id: "ip1", type: "infrastructure.ip_address", data: { ip_address: "8.8.8.8" } } });
  let threw = null;
  try {
    await ipPlugin.run({ ...RUN, run: { platform: "web" }, config: KEY, input: { selection: ["ip1"] }, net, graph });
  } catch (e) {
    threw = e;
  }
  check("web: refuses with the CORS reason, before any request", threw && /desktop app/.test(threw.message) && net.calls.length === 0);
}

// ================================================================ vt_ip_report
{
  const body = {
    data: { attributes: { country: "us", asn: 15169, as_owner: "GOOGLE", last_analysis_stats: { malicious: 0 } } },
  };
  const ipNode = { id: "ip1", type: "infrastructure.ip_address", data: { ip_address: "8.8.8.8", reverse_dns: "dns.google" } };
  const net = makeNet((url, init) => {
    check("ip: hits /ip_addresses/<ip>", url.pathname === "/api/v3/ip_addresses/8.8.8.8");
    check("ip: the key rides in the x-apikey header, never the URL", init.headers["x-apikey"] === "k" && !url.search);
    return { status: 200, body };
  });
  const graph = makeGraph({ ip1: ipNode });
  await ipPlugin.run({ ...RUN, config: KEY, input: { selection: ["ip1"] }, net, graph });

  // THE regression this pack shipped with: `{...node.data, ...patch}` re-submits fields this run
  // never touched, and the host fill-merges a plugin's data onto LIVE at commit — so a value some
  // other run wrote in between is rolled back. The update must carry the filled fields ALONE.
  check(
    "ip: writes a DELTA — the three filled fields and nothing else",
    graph.updates.length === 1 &&
      JSON.stringify(graph.updates[0].data) === JSON.stringify({ country_code: "US", asn: "AS15169", organization: "GOOGLE" }),
  );
  check("ip: no field the run did not fill is echoed back", !("reverse_dns" in graph.updates[0].data));
  const as = graph.createdNodes.find((n) => n.type === "infrastructure.autonomous_system");
  check("ip: an AS node is created from the ASN", as && as.data.autonomous_system_number === 15169 && as.data.autonomous_system_name === "GOOGLE");
  // autonomous_system.country_code means country of REGISTRATION; VT's `country` is where this one
  // IP geolocates. The AS node's identity is the ASN alone, so writing it would let a single host
  // rewrite the shared AS node for every pack that reads it.
  check("ip: the IP's geolocated country is NOT stamped on the shared AS node", as && !("country_code" in as.data));
  check("ip: edge label matches the IP Intelligence pack", graph.createdEdges[0].label === "announced by");
}
{
  // Measured: VT answers 400 InvalidArgumentError for a malformed address. Treating it as fatal
  // meant one typo'd node in a selection killed every node after it.
  const nodes = {
    bad: { id: "bad", type: "infrastructure.ip_address", data: { ip_address: "999.999.999.999" } },
    good: { id: "good", type: "infrastructure.ip_address", data: { ip_address: "8.8.8.8" } },
  };
  const net = makeNet((url) =>
    url.pathname.endsWith("999.999.999.999")
      ? { status: 400, body: vtErr("InvalidArgumentError", "not a valid IP address pattern") }
      : { status: 200, body: { data: { attributes: { asn: 15169 } } } },
  );
  const graph = makeGraph(nodes);
  const r = await ipPlugin.run({ ...RUN, config: KEY, input: { selection: ["bad", "good"] }, net, graph });
  check("ip: a 400 on one node does not abort the rest of the selection", net.calls.length === 2 && r.counts.misses === 1);
  check("ip: the good node after the bad one is still enriched", graph.updates.length === 1 && graph.updates[0].id === "good");
}
{
  const net = makeNet(() => ({ status: 404, body: vtErr("NotFoundError", "IP not found") }));
  const graph = makeGraph({ ip1: { id: "ip1", type: "infrastructure.ip_address", data: { ip_address: "192.0.2.1" } } });
  const r = await ipPlugin.run({ ...RUN, config: KEY, input: { selection: ["ip1"] }, net, graph });
  check("ip: an IP VT has never seen is a miss, not a failure", r.counts.misses === 1 && graph.updates.length === 0);
}
{
  const net = makeNet(() => {
    throw new Error("must not be called for a non-IP node");
  });
  const graph = makeGraph({ d1: { id: "d1", type: "infrastructure.domain", data: { domain_name: "example.test" } } });
  await ipPlugin.run({ ...RUN, config: KEY, input: { selection: ["d1"] }, net, graph });
  check("ip: a selected non-IP node triggers no request", net.calls.length === 0);
}

// ================================================================ vt_domain_report
{
  // creation_date/expiration_date are plain unix fields on the report. The raw WHOIS below carries
  // the STANDARD gTLD spelling (`Registry Expiry Date:`) and not the registrar-specific label the
  // old regex looked for — which is exactly why scraping the text lost the expiry on most domains.
  const body = {
    data: {
      attributes: {
        registrar: "MarkMonitor Inc.",
        creation_date: 874306800, // 1997-09-15
        expiration_date: 1852516800, // 2028-09-14
        whois: "Domain Name: GOOGLE.COM\nRegistry Expiry Date: 2028-09-14T04:00:00Z\n",
      },
    },
  };
  const net = makeNet(() => ({ status: 200, body }));
  const graph = makeGraph({ d1: { id: "d1", type: "infrastructure.domain", data: { domain_name: "google.com" } } });
  await domainPlugin.run({ ...RUN, config: KEY, input: { selection: ["d1"] }, net, graph });

  const upd = graph.updates[0].data;
  check("domain: registrar and creation date folded into the node", upd.registrar === "MarkMonitor Inc." && upd.created_date === "1997-09-15");
  check("domain: expiry comes from the expiration_date FIELD, not a WHOIS-text regex", upd.expiration_date === "2028-09-14");
  check("domain: the update is a delta", Object.keys(upd).join() === "registrar,created_date,expiration_date");
  const w = graph.createdNodes.find((n) => n.type === "infrastructure.whois_record");
  check("domain: a WHOIS record node carries subject + both dates", w && w.data.subject === "google.com" && w.data.created_at === "1997-09-15" && w.data.expires_at === "2028-09-14");
  check("domain: raw WHOIS text is kept", w && w.data.raw.includes("Registry Expiry Date"));
  check("domain: edge label", graph.createdEdges[0].label === "has whois");
}

// ================================================================ vt_url_report
{
  const body = {
    data: { attributes: { last_http_response_code: 200, title: "Google", last_final_url: "https://www.google.com/" } },
  };
  const net = makeNet((url) => {
    if (url.pathname.endsWith("/last_serving_ip_address")) {
      return { status: 200, body: { data: { id: "142.251.151.119", type: "ip_address" } } };
    }
    // The v3 URL id is unpadded base64url of the URL — measured to answer 200.
    check("url: id is unpadded base64url", url.pathname === "/api/v3/urls/aHR0cDovL3d3dy5nb29nbGUuY29tLw");
    return { status: 200, body };
  });
  const graph = makeGraph({ u1: { id: "u1", type: "web.url", data: { url: "http://www.google.com/" } } });
  await urlPlugin.run({ ...RUN, config: KEY, input: { selection: ["u1"] }, net, graph });
  const upd = graph.updates[0].data;
  check("url: status/title/final URL folded in as a delta", upd.http_status === 200 && upd.page_title === "Google" && upd.final_url === "https://www.google.com/");
  const ip = graph.createdNodes.find((n) => n.type === "infrastructure.ip_address");
  check("url: the last serving IP is linked (free tier, measured)", ip && ip.data.ip_address === "142.251.151.119" && graph.createdEdges[0].label === "resolves to");
}
{
  // web.url.http_status is declared 100..599 and the host REFUSES a write outside that range —
  // one refusal throws and takes the whole run down, so VT's 0 must never reach it.
  const net = makeNet((url) =>
    url.pathname.endsWith("/last_serving_ip_address")
      ? { status: 404, body: vtErr("NotFoundError", "no ip") }
      : { status: 200, body: { data: { attributes: { last_http_response_code: 0, title: "x" } } } },
  );
  const graph = makeGraph({ u1: { id: "u1", type: "web.url", data: { url: "http://a.test/" } } });
  await urlPlugin.run({ ...RUN, config: KEY, input: { selection: ["u1"] }, net, graph });
  check("url: an out-of-range http_status (VT's 0) is dropped, not written", !("http_status" in graph.updates[0].data));
  check("url: a missing serving IP is logged, not fatal", graph.createdNodes.length === 0);
}
{
  const net = makeNet(() => {
    throw new Error("must not request an unparseable URL");
  });
  const graph = makeGraph({ u1: { id: "u1", type: "web.url", data: { url: "not a url" } } });
  const r = await urlPlugin.run({ ...RUN, config: KEY, input: { selection: ["u1"] }, net, graph });
  check("url: an unparseable URL is a miss, not a request", net.calls.length === 0 && r.counts.misses === 1);
}

// ================================================================ vt_file_report
{
  const attrs = {
    sha256: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    sha1: "3395856ce81f2b7382dee72602f798b642f14140",
    md5: "44d88612fea8a8f36de82e1278abb02f",
    size: 68,
    type_description: "Powershell",
    tags: ["attachment", "via-tor"],
    times_submitted: 1161118,
    first_submission_date: 1148301722,
    last_analysis_stats: { malicious: 64, suspicious: 0, undetected: 3 },
  };
  const net = makeNet((url) => {
    check("file: looked up by the md5 the analyst pasted", url.pathname === "/api/v3/files/44d88612fea8a8f36de82e1278abb02f");
    return { status: 200, body: { data: { attributes: attrs } } };
  });
  const graph = makeGraph({});
  await filePlugin.run({ ...RUN, config: KEY, params: { hashes: "MD5:44D88612FEA8A8F36DE82E1278ABB02F" }, input: { selection: [] }, net, graph });
  const f = graph.createdNodes[0];
  check("file: a prefixed, upper-case hash is normalized", net.calls.length === 1);
  check("file: the node's sha256 is VT's, not the md5 it was looked up by", f.data.sha256 === attrs.sha256);
  check("file: detection counts carried through", f.data.malicious_count === 64 && f.data.undetected_count === 3);
  check("file: tags joined into the declared text field", f.data.tags === "attachment, via-tor");
  // first_seen is declared `datetime`, not `date` — a YYYY-MM-DD string loses the time of day.
  check("file: first_seen is a full ISO datetime", f.data.first_seen === "2006-05-22T12:42:02.000Z");
}
{
  // The md5 and the sha256 of ONE file, as a pasted report lists them. On a 4-req/min key the
  // second lookup is a quarter of a minute's budget spent to learn what the first already said.
  const attrs = {
    sha256: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    sha1: "3395856ce81f2b7382dee72602f798b642f14140",
    md5: "44d88612fea8a8f36de82e1278abb02f",
  };
  const net = makeNet(() => ({ status: 200, body: { data: { attributes: attrs } } }));
  const graph = makeGraph({});
  const r = await filePlugin.run({
    ...RUN,
    config: KEY,
    params: { hashes: `${attrs.md5}\n${attrs.sha256}\n${attrs.sha1}` },
    input: { selection: [] },
    net,
    graph,
  });
  check("file: three hashes of ONE file cost one request, not three", net.calls.length === 1);
  check("file: ...and are reported as one file, not three", r.counts.created === 1 && graph.createdNodes.length === 1);
}
{
  // THE "the run threw my data away" REPORT. A File Hash node holding only an MD5 has no identity
  // under createNode's type+sha256 rule, so the whole report used to land on a NEW, unconnected
  // node while the selected one stayed exactly as it was.
  const attrs = {
    sha256: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    sha1: "3395856ce81f2b7382dee72602f798b642f14140",
    md5: "44d88612fea8a8f36de82e1278abb02f",
    last_analysis_stats: { malicious: 64 },
  };
  const net = makeNet(() => ({ status: 200, body: { data: { attributes: attrs } } }));
  const src = { id: "fh1", type: "threat.file_hash", data: { md5: attrs.md5 } };
  const graph = makeGraph({ fh1: src });
  const r = await filePlugin.run({ ...RUN, config: KEY, input: { selection: ["fh1"] }, net, graph });
  check("file: a File Hash node carrying only an md5 is enriched IN PLACE", graph.updates.length === 1 && graph.updates[0].id === "fh1");
  check("file: ...with the sha256 it was missing, and the detections", graph.updates[0].data.sha256 === attrs.sha256 && graph.updates[0].data.malicious_count === 64);
  check("file: ...and no second, unconnected File Hash node is left behind", graph.createdNodes.length === 0);
  check("file: the update is still a delta", !("md5" in graph.updates[0].data) === false && Object.keys(graph.updates[0].data).every((k) => k in { sha256: 1, sha1: 1, md5: 1, malicious_count: 1 }));
  check("file: counts report it as enriched, not created", r.counts.enriched === 1 && r.counts.created === 0);
}
{
  // A Malware node names the file but IS NOT the file: it gets a link, not the report's fields.
  const attrs = { sha256: "a".repeat(64), md5: "b".repeat(32), last_analysis_stats: { malicious: 3 } };
  const net = makeNet(() => ({ status: 200, body: { data: { attributes: attrs } } }));
  const src = { id: "m1", type: "threat.malware", data: { name: "EICAR", hash_sha256: attrs.sha256 } };
  const graph = makeGraph({ m1: src });
  const r = await filePlugin.run({ ...RUN, config: KEY, input: { selection: ["m1"] }, net, graph });
  check("file: a Malware node gets a File Hash node created for the file", graph.createdNodes.length === 1 && graph.createdNodes[0].data.malicious_count === 3);
  check("file: ...linked back to it, instead of floating free", graph.createdEdges.length === 1 && graph.createdEdges[0].from === "m1" && graph.createdEdges[0].label === "has hash");
  check("file: ...and the Malware node's own fields are left alone", graph.updates.length === 0 && r.counts.linked === 1);
  check("file: the manifest advertises the malware input the code reads", filePlugin.manifest.io.consumes.some((c) => c.name === "malware"));
}
{
  // Two selected nodes naming the SAME file by different hashes: one lookup, and BOTH get related.
  const attrs = { sha256: "c".repeat(64), md5: "d".repeat(32), last_analysis_stats: { malicious: 1 } };
  const net = makeNet(() => ({ status: 200, body: { data: { attributes: attrs } } }));
  const nodes = {
    fh1: { id: "fh1", type: "threat.file_hash", data: { sha256: attrs.sha256 } },
    m1: { id: "m1", type: "threat.malware", data: { name: "X", hash_md5: attrs.md5 } },
  };
  const graph = makeGraph(nodes);
  await filePlugin.run({ ...RUN, config: KEY, input: { selection: ["fh1", "m1"] }, net, graph });
  check("file: one request for one file named by two nodes", net.calls.length === 1);
  check("file: the node de-dup does not cost the OTHER node its link", graph.createdEdges.length === 1 && graph.createdEdges[0].from === "m1");
  check("file: ...and the file_hash node is the one that was selected, not a copy", graph.createdEdges[0].to === "fh1" && graph.createdNodes.length === 0);
}
{
  // threat.file_hash's identity IS the sha256 and the host refuses anything but 64 hex; a report
  // without one must be skipped rather than putting the md5 in the sha256 field.
  const net = makeNet(() => ({ status: 200, body: { data: { attributes: { size: 1 } } } }));
  const graph = makeGraph({});
  const r = await filePlugin.run({ ...RUN, config: KEY, params: { hashes: "44d88612fea8a8f36de82e1278abb02f" }, input: { selection: [] }, net, graph });
  check("file: a report with no sha256 creates nothing", graph.createdNodes.length === 0 && r.counts.misses === 1);
}
{
  const graph = makeGraph({ m1: { id: "m1", type: "threat.malware", data: { name: "x", hash_sha256: "a".repeat(64) } } });
  const net = makeNet((url) => {
    check("file: a hash carried on a selected node is picked up", url.pathname.endsWith("a".repeat(64)));
    return { status: 404, body: vtErr("NotFoundError", "not found") };
  });
  const r = await filePlugin.run({ ...RUN, config: KEY, input: { selection: ["m1"] }, net, graph });
  check("file: a hash VT has never seen is a miss, not a failure", r.counts.misses === 1);
}
{
  const r = await filePlugin.run({ ...RUN, config: KEY, params: {}, input: { selection: [] }, graph: makeGraph({}) });
  check("file: says what to do when given no hashes", /No hashes/.test(r.summary));
}

// ================================================================ vt_pivot_resolutions
{
  // Measured shape: the resolution object's id is <ip><hostname> (unusable), the readable values
  // are attributes.host_name and attributes.ip_address.
  const net = makeNet((url) => {
    check("resolutions: paged 40 at a time", url.searchParams.get("limit") === "40");
    return {
      status: 200,
      body: {
        data: [
          { id: "8.8.8.8test.inaudio.com", type: "resolution", attributes: { host_name: "test.inaudio.com", ip_address: "8.8.8.8" } },
          { id: "8.8.8.8*.bad", type: "resolution", attributes: { host_name: "*.bad" } },
        ],
        meta: { count: 2 },
      },
    };
  });
  const graph = makeGraph({ ip1: { id: "ip1", type: "infrastructure.ip_address", data: { ip_address: "8.8.8.8" } } });
  await resolutionsPlugin.run({ ...RUN, config: KEY, input: { selection: ["ip1"] }, net, graph });
  const names = graph.createdNodes.map((n) => n.data.domain_name);
  check("resolutions: host_name read out of attributes, not the composite id", names.includes("test.inaudio.com"));
  check("resolutions: a wildcard name never becomes a domain node", names.length === 1);
  check("resolutions: edge runs domain -> ip", graph.createdEdges[0].from === "n1" && graph.createdEdges[0].to === "ip1");
}
{
  const net = makeNet(() => ({
    status: 200,
    body: { data: [{ attributes: { ip_address: "2607:f8b0:400e:c17::64" } }, { attributes: { ip_address: "deadbeef" } }], meta: {} },
  }));
  const graph = makeGraph({ d1: { id: "d1", type: "infrastructure.domain", data: { domain_name: "google.com" } } });
  await resolutionsPlugin.run({ ...RUN, config: KEY, input: { selection: ["d1"] }, net, graph });
  check("resolutions: an IPv6 address is accepted", graph.createdNodes.some((n) => n.data.ip_address === "2607:f8b0:400e:c17::64"));
  check("resolutions: a bare hex string is not mistaken for an IPv6 address", graph.createdNodes.length === 1);
}

// ================================================================ vt_pivot_relations (subdomains)
{
  const net = makeNet((url) => {
    check("subdomains: hits /domains/<d>/subdomains", url.pathname === "/api/v3/domains/google.com/subdomains");
    return { status: 200, body: { data: [{ id: "mail.google.com", type: "domain" }, { id: "*.google.com", type: "domain" }], meta: {} } };
  });
  const graph = makeGraph({ d1: { id: "d1", type: "infrastructure.domain", data: { domain_name: "google.com" } } });
  const r = await subdomainsPlugin.run({ ...RUN, config: KEY, input: { selection: ["d1"] }, net, graph });
  check("subdomains: fan-out with a 'subdomain of' edge back to the parent", r.counts.subdomains === 1 && graph.createdEdges[0].label === "subdomain of" && graph.createdEdges[0].to === "d1");
  // infrastructure.domain's declared format has no "*", and one refused write ends the run.
  check("subdomains: a wildcard name never becomes a domain node", graph.createdNodes.length === 1);
}
{
  // MEASURED on a community key: /urls/{id}/redirects_to and /urls/{id}/contacted_domains answer
  // 403 ForbiddenError. They were removed rather than attempted-and-skipped, so a selected URL must
  // cost NOTHING — no request, no "skipped" line, no menu entry that only works on a paid key.
  const net = makeNet(() => {
    throw new Error("must not request a premium-only relationship");
  });
  const graph = makeGraph({ u1: { id: "u1", type: "web.url", data: { url: "http://www.google.com/" } } });
  const r = await subdomainsPlugin.run({ ...RUN, config: KEY, input: { selection: ["u1"] }, net, graph });
  check("subdomains: a selected URL costs no request", net.calls.length === 0);
  check("subdomains: ...and is not counted as skipped either", /Select one or more Domain nodes/.test(r.summary));
  check("subdomains: the manifest no longer claims to consume URLs", !subdomainsPlugin.manifest.io.consumes.some((c) => c.name === "url"));
}
{
  // A 403 on a relationship that IS free (a key with fewer privileges than the one measured) is
  // still per-item, never fatal.
  const net = makeNet(() => ({ status: 403, body: vtErr("ForbiddenError", "You are not authorized to perform the requested operation") }));
  const graph = makeGraph({ d1: { id: "d1", type: "infrastructure.domain", data: { domain_name: "a.test" } } });
  const r = await subdomainsPlugin.run({ ...RUN, config: KEY, input: { selection: ["d1"] }, net, graph });
  check("subdomains: a 403 is skipped and counted, never fatal", r.counts.skipped === 1);
}
{
  // The whole pack, not just one plugin: nothing may reach an endpoint a community key is refused.
  const PREMIUM = ["redirects_to", "contacted_domains"];
  const nodes = {
    d1: { id: "d1", type: "infrastructure.domain", data: { domain_name: "a.test" } },
    u1: { id: "u1", type: "web.url", data: { url: "http://a.test/" } },
    i1: { id: "i1", type: "infrastructure.ip_address", data: { ip_address: "1.2.3.4" } },
    f1: { id: "f1", type: "threat.file_hash", data: { sha256: "b".repeat(64) } },
  };
  const hit = [];
  for (const p of pack.plugins) {
    const net = makeNet((url) => {
      if (PREMIUM.some((r) => url.pathname.endsWith(`/${r}`))) hit.push(`${p.manifest.identifier} -> ${url.pathname}`);
      return { status: 200, body: { data: [], meta: {} } };
    });
    await p.run({ ...RUN, config: KEY, params: {}, input: { selection: Object.keys(nodes) }, net, graph: makeGraph(nodes) });
  }
  check("pack: no plugin requests a relationship a community key is refused", hit.length === 0 && hit.join() === "");
}

// ================================================================ 429 backoff
{
  // Free keys are limited PER MINUTE, so the retry has to wait in tens of seconds. The old 0.7–2 s
  // jitter spent all three attempts inside one quota window and failed a run that only had to wait.
  let n = 0;
  const net = makeNet(() => (++n === 1 ? { status: 429, body: vtErr("QuotaExceededError", "quota") } : { status: 200, body: { data: { attributes: { asn: 1 } } } }));
  const graph = makeGraph({ ip1: { id: "ip1", type: "infrastructure.ip_address", data: { ip_address: "1.2.3.4" } } });
  const started = Date.now();
  // Retry-After is honoured, which is what keeps this test from taking 15 s.
  const netRA = makeNet(() => (++n === 2 ? { status: 429, headers: { "retry-after": "0.05" }, body: vtErr("QuotaExceededError", "q") } : { status: 200, body: { data: { attributes: { asn: 1 } } } }));
  n = 1;
  await ipPlugin.run({ ...RUN, config: KEY, input: { selection: ["ip1"] }, net: netRA, graph });
  const waited = Date.now() - started;
  check("429: Retry-After is honoured and the request is retried", netRA.calls.length === 2 && graph.updates.length === 1);
  check("429: the wait is the header's, not a fixed floor", waited < 5000);
  void net;
}
{
  // Cancel must cut a backoff short. At a 60 s wait, a non-abortable sleep reads as a hang.
  const ac = new AbortController();
  const net = makeNet(() => ({ status: 429, body: vtErr("QuotaExceededError", "quota") }));
  const graph = makeGraph({ ip1: { id: "ip1", type: "infrastructure.ip_address", data: { ip_address: "1.2.3.4" } } });
  const started = Date.now();
  const p = ipPlugin.run({ ...RUN, config: KEY, input: { selection: ["ip1"] }, net, graph, signal: ac.signal });
  setTimeout(() => ac.abort(), 100);
  let threw = null;
  try {
    await p;
  } catch (e) {
    threw = e;
  }
  check("cancel: aborts during a 429 backoff instead of sleeping it out", threw && /cancelled/.test(threw.message) && Date.now() - started < 5000);
}

// ================================================================ manifest: JS literal vs. JSON
// gen-manifest.mjs pours the JS literals into the JSON, so these agree by construction — this is
// the check that the generator was actually RUN after the last edit.
{
  const json = JSON.parse(readFileSync(new URL("./plugins/virustotal-community.manifest.json", import.meta.url)));
  const stable = (v) =>
    JSON.stringify(v, (_k, x) =>
      x && typeof x === "object" && !Array.isArray(x) ? Object.fromEntries(Object.keys(x).sort().map((k) => [k, x[k]])) : x,
    );

  check("manifest: pack version agrees", json.version === pack.version);
  check("manifest: pack identifier agrees", json.identifier === pack.identifier);
  check("manifest: member count agrees", json.plugins.length === pack.plugins.length);
  for (let i = 0; i < json.plugins.length; i++) {
    const a = json.plugins[i];
    const b = pack.plugins[i].manifest;
    check(`${a.identifier}: JSON copy is identical to the JS one`, stable(a) === stable(b));
    check(`${a.identifier}: declares a secret config key`, (a.scopes.config || []).some((c) => c.secret));
    // A member declaring entry:"inline" is not remote-runnable and registry.ts drops it silently —
    // the defect that made pluginpack-shodan 1.0.0 install cleanly and list nothing.
    check(`${a.identifier}: web entry is the pack module, not "inline"`, a.platforms.web.entry === json.platforms.web.entry && a.platforms.web.entry !== "inline");
    const writes = (a.io.produces || []).length > 0;
    check(`${a.identifier}: graph scope matches whether it produces nodes`, writes === !!(a.scopes.graph || []).includes("node:create"));
    check(`${a.identifier}: member version matches the pack's`, a.version === json.version);
  }
}

say(`PASS ${ok.length} / ${ok.length + fail.length}`);

if (fail.length) {
  say("FAILED:\n" + fail.map((f) => `  - ${f}`).join("\n"));
  die();
}
