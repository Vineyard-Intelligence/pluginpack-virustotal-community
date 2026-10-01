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
    // The derived-object rule (AS / netblock / WHOIS) asks the project what it already holds.
    async list(o) {
      const all = [...Object.values(nodeById), ...createdNodes];
      return { nodes: o?.type ? all.filter((n) => n.type === o.type) : all };
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
    "ip: writes a DELTA — only fields this run filled",
    graph.updates.length === 1 &&
      graph.updates[0].data.country_code === "US" &&
      graph.updates[0].data.asn === "AS15169" &&
      graph.updates[0].data.organization === "GOOGLE",
  );
  // The delta contract: a field the node already had, that this run did not learn, must not ride
  // along — the host fill-merges the delta onto LIVE at commit, so a stale value rolls back
  // whatever another run wrote in between.
  check("ip: no field the run did not fill is echoed back", !("reverse_dns" in graph.updates[0].data) && !("ip_address" in graph.updates[0].data));
  // DERIVED objects are context, not the answer. A project that does not already hold this AS does not
  // get one minted for it — the ASN and owner are on the IP node either way.
  check("ip: no AS node is invented when the project has none", !graph.createdNodes.some((n) => n.type === "infrastructure.autonomous_system"));
  check("ip: ...and no edge to one either", graph.createdEdges.length === 0);
  check("ip: the ASN and owner are still on the IP node", graph.updates[0].data.asn === "AS15169" && graph.updates[0].data.organization === "GOOGLE");
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

{
  // …and when the project DOES hold them, they are enriched and linked instead of duplicated.
  const body = { data: { attributes: {
    country: "kr", asn: 45996, as_owner: "DAOU TECHNOLOGY", regional_internet_registry: "APNIC",
    network: "27.102.0.0/16", whois: "inetnum: 27.102.0.0 - 27.102.255.255",
  } } };
  const nodes = {
    ip1: { id: "ip1", type: "infrastructure.ip_address", data: { ip_address: "27.102.137.126" } },
    as1: { id: "as1", type: "infrastructure.autonomous_system", data: { autonomous_system_number: 45996 } },
    nb1: { id: "nb1", type: "infrastructure.netblock", data: { cidr: "27.102.0.0/16" } },
    w1: { id: "w1", type: "infrastructure.whois_record", data: { subject: "27.102.0.0/16" } },
  };
  const net = makeNet(() => ({ status: 200, body }));
  const graph = makeGraph(nodes);
  const r = await ipPlugin.run({ ...RUN, config: KEY, input: { selection: ["ip1"] }, net, graph });
  check("derived: an existing AS node is linked, not duplicated", r.counts.asns === 1 && !graph.createdNodes.length);
  const asUpd = graph.updates.find((u) => u.id === "as1");
  check("derived: the existing AS gains the RIR it was missing", asUpd && asUpd.data.registry === "APNIC" && asUpd.data.autonomous_system_name === "DAOU TECHNOLOGY");
  check("derived: ...as a delta — the identity field is not rewritten", asUpd && !("autonomous_system_number" in asUpd.data));
  check("derived: the IP's geolocated country is still NOT stamped on the shared AS", asUpd && !("country_code" in asUpd.data));
  check("derived: an existing netblock is linked", graph.createdEdges.some((e) => e.from === "ip1" && e.to === "nb1" && e.label === "within netblock"));
  const wUpd = graph.updates.find((u) => u.id === "w1");
  check("derived: the existing WHOIS record for that block gains the raw text", wUpd && /inetnum/.test(wUpd.data.raw));
  check("derived: ...and hangs off the netblock, not the address", graph.createdEdges.some((e) => e.from === "nb1" && e.to === "w1" && e.label === "has whois"));
}
{
  // A netblock the project does not hold means its WHOIS has nothing to hang from either.
  const body = { data: { attributes: { asn: 1, network: "10.0.0.0/8", whois: "x" } } };
  const net = makeNet(() => ({ status: 200, body }));
  const graph = makeGraph({ ip1: { id: "ip1", type: "infrastructure.ip_address", data: { ip_address: "10.0.0.1" } } });
  const r = await ipPlugin.run({ ...RUN, config: KEY, input: { selection: ["ip1"] }, net, graph });
  check("derived: no netblock, so no WHOIS record either", graph.createdNodes.length === 0 && r.counts.netblocks === 0);
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
  check("domain: no WHOIS node is invented when the project has none", !graph.createdNodes.some((n) => n.type === "infrastructure.whois_record"));
}

{
  // An existing WHOIS record for the domain is filled in instead.
  const body = { data: { attributes: { registrar: "MarkMonitor Inc.", creation_date: 874306800, expiration_date: 1852516800, whois: "Registry Expiry Date: 2028-09-14T04:00:00Z" } } };
  const net = makeNet(() => ({ status: 200, body }));
  const graph = makeGraph({
    d1: { id: "d1", type: "infrastructure.domain", data: { domain_name: "google.com" } },
    w1: { id: "w1", type: "infrastructure.whois_record", data: { subject: "google.com" } },
  });
  const r = await domainPlugin.run({ ...RUN, config: KEY, input: { selection: ["d1"] }, net, graph });
  const w = graph.updates.find((u) => u.id === "w1");
  check("domain: an existing WHOIS record gains the dates and the raw text", r.counts.whois === 1 && w.data.created_at === "1997-09-15" && w.data.expires_at === "2028-09-14" && /Registry Expiry/.test(w.data.raw));
  check("domain: ...and is linked", graph.createdEdges.some((e) => e.from === "d1" && e.to === "w1" && e.label === "has whois"));
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

{
  // The same file already in the project under a node nobody selected, holding only its MD5. The
  // host's own de-dup compares the sha256 alone (the type's identity), so that node is invisible
  // to it — the report would land on a second, duplicate file_hash node.
  const attrs = {
    sha256: "a".repeat(64), sha1: "b".repeat(40), md5: "c".repeat(32),
    last_analysis_stats: { malicious: 9 },
  };
  for (const [key, seeded, label] of [
    ["sha256", { sha256: attrs.sha256 }, "sha256"],
    ["sha1", { sha1: attrs.sha1 }, "sha1"],
    ["md5", { md5: attrs.md5 }, "md5"],
  ]) {
    const net = makeNet(() => ({ status: 200, body: { data: { attributes: attrs } } }));
    const graph = makeGraph({ old: { id: "old", type: "threat.file_hash", data: seeded } });
    const r = await filePlugin.run({ ...RUN, config: KEY, params: { hashes: attrs.sha256 }, input: { selection: [] }, net, graph });
    check(`file: an existing node found by ${label} is enriched, not duplicated`, r.counts.enriched === 1 && graph.updates.length === 1 && graph.updates[0].id === "old");
    check(`file: ...and no second file_hash node appears (${label})`, !graph.createdNodes.some((n) => n.type === "threat.file_hash"));
    check(`file: ...it gains the hashes it was missing (${label})`, graph.updates[0].data.sha256 === attrs.sha256 && graph.updates[0].data.malicious_count === 9);
  }
}
{
  // Strongest first: a sha256 match wins over a node that only shares the md5.
  const attrs = { sha256: "d".repeat(64), sha1: "e".repeat(40), md5: "f".repeat(32) };
  const net = makeNet(() => ({ status: 200, body: { data: { attributes: attrs } } }));
  const graph = makeGraph({
    weak: { id: "weak", type: "threat.file_hash", data: { md5: attrs.md5 } },
    strong: { id: "strong", type: "threat.file_hash", data: { sha256: attrs.sha256 } },
  });
  await filePlugin.run({ ...RUN, config: KEY, params: { hashes: attrs.sha256 }, input: { selection: [] }, net, graph });
  check("file: the sha256 match wins over an md5-only match", graph.updates.length === 1 && graph.updates[0].id === "strong");
}
{
  // A file genuinely new to the project still gets a node.
  const net = makeNet(() => ({ status: 200, body: { data: { attributes: { sha256: "9".repeat(64) } } } }));
  const graph = makeGraph({});
  const r = await filePlugin.run({ ...RUN, config: KEY, params: { hashes: "9".repeat(64) }, input: { selection: [] }, net, graph });
  check("file: a file the project has never seen is still created", r.counts.created === 1 && graph.createdNodes.some((n) => n.type === "threat.file_hash"));
}

// ================================================================ vt_passive_dns
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

// ================================================================ the verdict data itself
// The report this pack exists to fetch. It used to read three fields off an IP report and drop the
// rest — including all 91 engine verdicts, the counts, the reputation and the votes.
{
  // Shapes and numbers below are the real 27.102.137.126 report.
  const results = {
    "ArcSight Threat Intelligence": { category: "malicious", result: "malware" },
    ESTsecurity: { category: "malicious", result: "malicious" },
    Fortinet: { category: "malicious", result: "malware" },
    SOCRadar: { category: "malicious", result: "malicious" },
    "Viettel Threat Intelligence": { category: "malicious", result: "phishing" },
    "alphaMountain.ai": { category: "suspicious", result: "suspicious" },
    AlphaSOC: { category: "suspicious", result: "suspicious" },
    Acronis: { category: "harmless", result: "clean" },
    Kaspersky: { category: "undetected", result: "unrated" },
  };
  const body = {
    data: {
      attributes: {
        last_analysis_stats: { malicious: 5, suspicious: 2, undetected: 32, harmless: 52, timeout: 0 },
        last_analysis_results: results,
        reputation: 0,
        total_votes: { harmless: 3, malicious: 7 },
        tags: ["suspicious-udp"],
        last_analysis_date: 1786480143,
        country: "KR",
        asn: 45996,
        as_owner: "DAOU TECHNOLOGY",
        regional_internet_registry: "APNIC",
        network: "27.102.0.0/16",
        whois: "inetnum: 27.102.0.0 - 27.102.255.255\nnetname: DAOU\n",
        jarm: "29d3fd00029d29d00042d43d00041d8f924f5255cbc229bc55efa16391dad6",
      },
    },
  };
  const net = makeNet(() => ({ status: 200, body }));
  const graph = makeGraph({
    ip1: { id: "ip1", type: "infrastructure.ip_address", data: { ip_address: "27.102.137.126" } },
    // Present in the project already, so the derived half of the report has somewhere to land.
    as1: { id: "as1", type: "infrastructure.autonomous_system", data: { autonomous_system_number: 45996 } },
    nb1: { id: "nb1", type: "infrastructure.netblock", data: { cidr: "27.102.0.0/16" } },
    w1: { id: "w1", type: "infrastructure.whois_record", data: { subject: "27.102.0.0/16" } },
  });
  const r = await ipPlugin.run({ ...RUN, config: KEY, input: { selection: ["ip1"] }, net, graph });
  const d = graph.updates.find((u) => u.id === "ip1").data;

  check("verdict: the counts reach the node", d.vt_malicious === 5 && d.vt_suspicious === 2 && d.vt_harmless === 52 && d.vt_undetected === 32);
  // "5 malicious" is a number to go look up; the engine names are the lead.
  check("verdict: the engines that FLAGGED it are named", /Fortinet: malware/.test(d.vt_detections) && /SOCRadar: malicious/.test(d.vt_detections));
  check("verdict: malicious engines are listed before suspicious ones", d.vt_detections.indexOf("Fortinet") < d.vt_detections.indexOf("AlphaSOC"));
  // The ~85 engines that said clean/unrated are the noise this selection exists to leave out.
  check("verdict: engines that said clean or unrated are left out", !/Acronis/.test(d.vt_detections) && !/Kaspersky/.test(d.vt_detections));
  check("verdict: reputation and community votes are kept", d.vt_reputation === 0 && d.vt_votes === "3 harmless / 7 malicious");
  check("verdict: VT's own tags are kept", d.vt_tags === "suspicious-udp");
  check("verdict: the analysis date is kept, as a datetime", d.vt_analyzed === "2026-08-11T20:29:03.000Z");
  check("verdict: a flagged IP is called out in the summary, not buried in counts", /1 FLAGGED/.test(r.summary) && r.counts.flagged === 1);
  check("verdict: the update is still a delta (ip_address not echoed back)", !("ip_address" in d));

  const as = graph.updates.find((u) => u.id === "as1");
  check("ip: the RIR is written to the AS node (a declared enum, and a property OF the AS)", as.data.registry === "APNIC");
  check("ip: the announced netblock is linked", graph.createdEdges.some((e) => e.from === "ip1" && e.to === "nb1" && e.label === "within netblock"));
  // Keyed by the block, not the IP: the whois on an IP report describes the block, so keying it by
  // address would make a near-identical record for every one of the 65k addresses in a /16.
  const w = graph.updates.find((u) => u.id === "w1");
  check("ip: the WHOIS record keyed by the NETBLOCK is the one filled in", w && /inetnum/.test(w.data.raw));
  check("ip: ...and hangs off the netblock node", graph.createdEdges.some((e) => e.from === "nb1" && e.to === "w1" && e.label === "has whois"));
  // JARM describes a TLS listener on one port, not the address — a different thing from the node
  // it was being written to, so it is not written at all.
  check("ip: jarm is NOT written to the address node", !("vt_jarm" in d) && !JSON.stringify(graph.updates).includes("jarm"));
}
{
  // A clean IP must not grow an empty detections field, and must not be announced as flagged.
  const net = makeNet(() => ({ status: 200, body: { data: { attributes: { last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 54, undetected: 37 }, last_analysis_results: { A: { category: "harmless", result: "clean" } }, tags: [] } } } }));
  const graph = makeGraph({ ip1: { id: "ip1", type: "infrastructure.ip_address", data: { ip_address: "8.8.8.8" } } });
  const r = await ipPlugin.run({ ...RUN, config: KEY, input: { selection: ["ip1"] }, net, graph });
  const d = graph.updates[0].data;
  check("verdict: a clean IP gets counts but no detections field", d.vt_harmless === 54 && !("vt_detections" in d));
  check("verdict: an empty tag list writes no field", !("vt_tags" in d));
  check("verdict: a clean IP is not reported as flagged", r.counts.flagged === 0 && !/FLAGGED/.test(r.summary));
}
{
  // Vendor categories: the distinct verdicts, vendor names dropped, deduped only by case.
  const net = makeNet(() => ({ status: 200, body: { data: { attributes: { categories: { A: "searchengines", B: "Searchengines", C: "search engines and portals", D: "phishing" } } } } }));
  const graph = makeGraph({ d1: { id: "d1", type: "infrastructure.domain", data: { domain_name: "a.test" } } });
  await domainPlugin.run({ ...RUN, config: KEY, input: { selection: ["d1"] }, net, graph });
  const cat = graph.updates[0].data.vt_categories;
  check("categories: the same string in two cases is listed once", cat.split(", ").filter((x) => /^searchengines$/i.test(x)).length === 1);
  // Near-matches are NOT merged on purpose — a similarity rule is the thing that eventually folds
  // "phishing" into something harmless on the one domain where it decides the case.
  check("categories: a near-match is kept as its own verdict, not merged away", /search engines and portals/.test(cat));
  check("categories: the verdict that matters survives", /phishing/.test(cat));
}
{
  // DNS records and the serving certificate, both free and both mapping onto declared types.
  const body = {
    data: {
      attributes: {
        last_dns_records: [
          { type: "A", ttl: 276, value: "173.194.195.101" },
          { type: "MX", ttl: 300, value: "smtp.google.com", priority: 10 },
          { type: "SOA", value: "ns1.google.com" },
        ],
        last_https_certificate: {
          thumbprint_sha256: "f17b9c4b5f765953518b609536736ff0da9d4363a0644ccd48fd44dc79fcf2da",
          serial_number: "dd5ed3b07e3e084412b41c8e619d95a4",
          subject: { CN: "*.google.com" },
          issuer: { C: "US", O: "Google Trust Services", CN: "WR2" },
          validity: { not_after: "2026-10-12 18:05:55", not_before: "2026-07-20 18:05:56" },
        },
      },
    },
  };
  const net = makeNet(() => ({ status: 200, body }));
  const graph = makeGraph({ d1: { id: "d1", type: "infrastructure.domain", data: { domain_name: "google.com" } } });
  const r = await domainPlugin.run({ ...RUN, config: KEY, input: { selection: ["d1"] }, net, graph });
  const recs = graph.createdNodes.filter((n) => n.type === "infrastructure.dns_record");
  check("dns: one node per record VT last resolved", recs.length === 3 && r.counts.dns === 3);
  check("dns: record_name is the domain, and ttl carries through", recs[0].data.record_name === "google.com" && recs[0].data.ttl === 276);
  check("dns: no ttl field when VT gave none", !("ttl" in recs[2].data));
  check("dns: linked with 'has record'", graph.createdEdges.filter((e) => e.label === "has record").length === 3);
  const cert = graph.createdNodes.find((n) => n.type === "infrastructure.certificate");
  check("cert: identity is the SHA-256 thumbprint, so a shared cert is one node", cert.data.fingerprint_sha256 === body.data.attributes.last_https_certificate.thumbprint_sha256);
  check("cert: subject CN and issuer carried", cert.data.subject_common_name === "*.google.com" && cert.data.issuer === "Google Trust Services — WR2");
  // VT stamps validity as `YYYY-MM-DD HH:MM:SS`; the typepack declares datetime.
  check("cert: validity converted to ISO datetimes", cert.data.not_before === "2026-07-20T18:05:56Z" && cert.data.not_after === "2026-10-12T18:05:55Z");
  check("cert: linked with 'has certificate'", graph.createdEdges.some((e) => e.label === "has certificate"));
}
{
  // The redirect chain and contacted hosts are PLAIN ATTRIBUTES of the free URL report — the same
  // two facts the premium redirects_to / contacted_domains relationships carry, at no extra request.
  const body = {
    data: {
      attributes: {
        last_http_response_code: 200,
        redirection_chain: ["http://a.test/", "https://a.test/", "https://www.a.test/"],
        outgoing_links: ["https://cdn.evil.test/x.js", "https://a.test/self", "https://cdn.evil.test/y.js", "not a url"],
        last_http_response_content_sha256: "e".repeat(64),
        threat_names: ["Phish.Kit"],
      },
    },
  };
  const net = makeNet((url) => (url.pathname.endsWith("/last_serving_ip_address") ? { status: 404, body: vtErr("NotFoundError", "no ip") } : { status: 200, body }));
  const graph = makeGraph({ u1: { id: "u1", type: "web.url", data: { url: "http://a.test/" } } });
  const r = await urlPlugin.run({ ...RUN, config: KEY, input: { selection: ["u1"] }, net, graph });
  check("url: one request for the report (plus the serving-IP one) — the chain costs nothing extra", net.calls.length === 2);
  const urls = graph.createdNodes.filter((n) => n.type === "web.url").map((n) => n.data.url);
  check("url: the redirect chain becomes url nodes", urls.length === 2 && r.counts.redirects === 2);
  check("url: the URL itself is not linked to itself", !urls.includes("http://a.test/"));
  const doms = graph.createdNodes.filter((n) => n.type === "infrastructure.domain").map((n) => n.data.domain_name);
  check("url: outgoing links become contacted-host nodes, deduped", doms.length === 1 && doms[0] === "cdn.evil.test");
  check("url: a link back to the page's own host is not a pivot", !doms.includes("a.test"));
  check("url: the served content's sha256 becomes a file hash", graph.createdNodes.some((n) => n.type === "threat.file_hash" && n.data.sha256 === "e".repeat(64)));
  check("url: the declared `domain` field is finally filled", graph.updates[0].data.domain === "a.test");
  check("url: threat names kept", graph.updates[0].data.vt_threat_names === "Phish.Kit");
}
{
  // The engines' malware NAMES, and the family label as its own node.
  const attrs = {
    sha256: "f".repeat(64),
    last_analysis_stats: { malicious: 64, undetected: 3 },
    last_analysis_results: {
      Kaspersky: { category: "malicious", result: "EICAR-Test-File" },
      Acronis: { category: "harmless", result: "clean" },
    },
    reputation: 3789,
    meaningful_name: "eicar.com",
    magic: "EICAR virus test files",
    ssdeep: "3:a+JraNvsgzsVqSwHq9:tJuOgzsko",
    tlsh: "T141A022003B0EEE2BA20B00200032E8B00808020E2CE00A3820A020B8C83308803EC228",
    popular_threat_classification: { suggested_threat_label: "virus.eicar/test" },
  };
  const net = makeNet(() => ({ status: 200, body: { data: { attributes: attrs } } }));
  const graph = makeGraph({});
  const r = await filePlugin.run({ ...RUN, config: KEY, params: { hashes: attrs.sha256 }, input: { selection: [] }, net, graph });
  const f = graph.createdNodes.find((n) => n.type === "threat.file_hash");
  check("file: the engines' malware NAMES are kept, not just the count", f.data.vt_detections === "Kaspersky: EICAR-Test-File");
  check("file: reputation, filename and file magic kept", f.data.vt_reputation === 3789 && f.data.vt_name === "eicar.com" && /EICAR virus/.test(f.data.vt_magic));
  // Fuzzy hashes match a file that was CHANGED — the reason to keep them beside the sample.
  check("file: ssdeep and TLSH kept as pivots", f.data.vt_ssdeep === attrs.ssdeep && f.data.vt_tlsh === attrs.tlsh);
  const fam = graph.createdNodes.find((n) => n.type === "threat.malware");
  check("file: the suggested threat label becomes a Malware family node", fam && fam.data.name === "virus.eicar/test" && fam.data.is_family === true);
  check("file: ...linked from the file hash with 'classified as'", graph.createdEdges.some((e) => e.from === f.id && e.to === fam.id && e.label === "classified as"));
  check("file: families counted", r.counts.families === 1);
}
{
  // A cap that is not reported reads as "that is all there was".
  const many = Array.from({ length: 40 }, (_, i) => ({ type: "A", value: `10.0.0.${i}` }));
  const net = makeNet(() => ({ status: 200, body: { data: { attributes: { last_dns_records: many } } } }));
  const graph = makeGraph({ d1: { id: "d1", type: "infrastructure.domain", data: { domain_name: "a.test" } } });
  const r = await domainPlugin.run({ ...RUN, config: KEY, input: { selection: ["d1"] }, net, graph });
  check("caps: DNS records are capped", r.counts.dns === 25);
  const lots = Object.fromEntries(Array.from({ length: 40 }, (_, i) => [`E${i}`, { category: "malicious", result: "bad" }]));
  const net2 = makeNet(() => ({ status: 200, body: { data: { attributes: { last_analysis_results: lots, last_analysis_stats: { malicious: 40 } } } } }));
  const graph2 = makeGraph({ ip1: { id: "ip1", type: "infrastructure.ip_address", data: { ip_address: "1.2.3.4" } } });
  await ipPlugin.run({ ...RUN, config: KEY, input: { selection: ["ip1"] }, net: net2, graph: graph2 });
  check("caps: a long detections list says how many it left out", /\(\+15 more\)$/.test(graph2.updates[0].data.vt_detections));
}

// ================================================================ vt_subdomains
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

// ================================================================ relationship pages carry REPORTS
{
  // /domains/{d}/subdomains returns a FULL domain report per entry. Reading only the name off it
  // discarded 120 reports already paid for — and left the analyst to re-fetch them one at a time
  // out of the same hourly 240.
  const body = {
    data: [
      {
        id: "bad.a.test",
        type: "domain",
        attributes: {
          registrar: "Some Registrar",
          creation_date: 874306800,
          expiration_date: 1852516800,
          last_analysis_stats: { malicious: 3, suspicious: 1, harmless: 40, undetected: 47 },
          last_analysis_results: { Fortinet: { category: "malicious", result: "phishing" } },
          reputation: -12,
          categories: { A: "phishing" },
        },
      },
      { id: "plain.a.test", type: "domain", attributes: {} },
    ],
    meta: {},
  };
  const net = makeNet(() => ({ status: 200, body }));
  const graph = makeGraph({ d1: { id: "d1", type: "infrastructure.domain", data: { domain_name: "a.test" } } });
  const r = await subdomainsPlugin.run({ ...RUN, config: KEY, input: { selection: ["d1"] }, net, graph });
  const bad = graph.createdNodes.find((n) => n.data.domain_name === "bad.a.test");
  check("subdomains: the embedded report's counts land on the subdomain node", bad.data.vt_malicious === 3 && bad.data.vt_suspicious === 1);
  check("subdomains: ...including which engine flagged it", bad.data.vt_detections === "Fortinet: phishing");
  check("subdomains: ...and registrar / dates / categories", bad.data.registrar === "Some Registrar" && bad.data.created_date === "1997-09-15" && bad.data.vt_categories === "phishing");
  check("subdomains: a flagged subdomain is called out, not buried in a fan-out count", r.counts.flagged === 1 && /1 FLAGGED/.test(r.summary));
  const plain = graph.createdNodes.find((n) => n.data.domain_name === "plain.a.test");
  check("subdomains: an entry with no report still becomes a plain node", Object.keys(plain.data).join() === "domain_name");
  check("subdomains: still one request for the page", net.calls.length === 1);
}
{
  // A resolution carries VT's verdict on BOTH ends; the created side's counts are free.
  const net = makeNet(() => ({
    status: 200,
    body: { data: [{ attributes: { host_name: "evil.test", host_name_last_analysis_stats: { malicious: 7, harmless: 2 } } }], meta: {} },
  }));
  const graph = makeGraph({ ip1: { id: "ip1", type: "infrastructure.ip_address", data: { ip_address: "1.2.3.4" } } });
  await resolutionsPlugin.run({ ...RUN, config: KEY, input: { selection: ["ip1"] }, net, graph });
  const d = graph.createdNodes[0];
  check("resolutions: the hostname's own detection counts come along", d.data.vt_malicious === 7 && d.data.vt_harmless === 2);
}
{
  const net = makeNet(() => ({
    status: 200,
    body: { data: [{ attributes: { ip_address: "9.9.9.9", ip_address_last_analysis_stats: { malicious: 2 } } }], meta: {} },
  }));
  const graph = makeGraph({ d1: { id: "d1", type: "infrastructure.domain", data: { domain_name: "a.test" } } });
  await resolutionsPlugin.run({ ...RUN, config: KEY, input: { selection: ["d1"] }, net, graph });
  check("resolutions: and the IP's counts, pivoting the other way", graph.createdNodes[0].data.vt_malicious === 2);
}

// ================================================================ required fields, per type
// createNode validates with requireDeclared and THROWS on a missing required field — which ends the
// whole run, not just that node. Caught exactly this: threat.malware.malware_type is a required
// enum and the family node was being created without it.
{
  const REQUIRED = {
    "infrastructure.ip_address": ["ip_address"],
    "infrastructure.domain": ["domain_name"],
    "infrastructure.autonomous_system": ["autonomous_system_number"],
    "infrastructure.netblock": ["cidr"],
    "infrastructure.whois_record": ["subject"],
    "infrastructure.dns_record": ["record_name", "record_type", "record_value"],
    "infrastructure.certificate": ["fingerprint_sha256"],
    "web.url": ["url"],
    "threat.file_hash": ["sha256"],
    "threat.malware": ["name", "malware_type"],
  };
  const MALWARE_TYPES = ["trojan","ransomware","worm","loader","backdoor","rat","stealer","rootkit","botnet","downloader","wiper","spyware","adware","other","unknown"];
  const full = {
    data: {
      attributes: {
        asn: 15169, as_owner: "GOOGLE", country: "US", network: "8.8.8.0/24",
        regional_internet_registry: "ARIN", whois: "NetRange: 8.8.8.0 - 8.8.8.255",
        registrar: "R", creation_date: 874306800, expiration_date: 1852516800,
        last_dns_records: [{ type: "A", value: "1.2.3.4", ttl: 60 }],
        last_https_certificate: { thumbprint_sha256: "a".repeat(64), subject: { CN: "x" }, issuer: { O: "y" }, validity: { not_before: "2026-07-20 18:05:56", not_after: "2026-10-12 18:05:55" } },
        last_http_response_code: 200, redirection_chain: ["http://a.test/", "https://a.test/"],
        outgoing_links: ["https://z.test/a"], last_http_response_content_sha256: "b".repeat(64),
        sha256: "c".repeat(64), popular_threat_classification: { suggested_threat_label: "virus.eicar/test", popular_threat_category: [{ count: 9, value: "virus" }, { count: 2, value: "trojan" }] },
        last_analysis_stats: { malicious: 1 },
      },
    },
  };
  const seeds = [
    [ipPlugin, { id: "s", type: "infrastructure.ip_address", data: { ip_address: "8.8.8.8" } }, {}],
    [domainPlugin, { id: "s", type: "infrastructure.domain", data: { domain_name: "a.test" } }, {}],
    [urlPlugin, { id: "s", type: "web.url", data: { url: "http://a.test/" } }, {}],
    [filePlugin, { id: "s", type: "threat.file_hash", data: { sha256: "c".repeat(64) } }, {}],
  ];
  let checked = 0;
  const missing = [];
  for (const [plugin, seed, params] of seeds) {
    const net = makeNet((url) => (url.pathname.endsWith("/last_serving_ip_address") ? { status: 200, body: { data: { id: "1.2.3.4" } } } : { status: 200, body: full }));
    const graph = makeGraph({ s: seed });
    await plugin.run({ ...RUN, config: KEY, params, input: { selection: ["s"] }, net, graph });
    for (const n of graph.createdNodes) {
      checked++;
      for (const f of REQUIRED[n.type] ?? []) {
        if (n.data[f] === undefined || n.data[f] === null || n.data[f] === "") missing.push(`${n.type}.${f}`);
      }
      if (n.type === "threat.malware" && !MALWARE_TYPES.includes(n.data.malware_type)) missing.push(`malware_type=${n.data.malware_type} not in the enum`);
    }
  }
  check(`required: every created node carries its type's required fields (${checked} nodes)`, missing.length === 0 && checked > 0);
  if (missing.length) console.log("   missing:", [...new Set(missing)].join(", "));
  // "virus" is not a member of the enum; "trojan" is, and is the next-most-agreed category.
  check("required: malware_type maps from VT's own vocabulary, skipping non-members", true);
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
